# BUGS & TODO

Personal working file. Gitignored — this is the scratchpad, not the front page.

Two lists: things that are broken, and things that don't exist yet. Ordered by how
much they hurt, not by how hard they are.

---

# Part 1 — Bugs

## ~~B1. SYN scan trusts any packet that arrives~~ — FIXED
`scanners/syn.py:21-25`

**Fixed:** reply is now checked against `src_port`/`dst_port` before being
believed, and a non-matching packet no longer ends the probe — the read loop keeps
listening until the deadline.

A raw `IPPROTO_TCP` socket receives **every** TCP packet the kernel hands up, not
just replies to your probe. Browser traffic, SSH, an open Discord tab — all of it
lands in `recvfrom()`. The first packet that happens to have flags `0x012` gets
recorded as your port being open, whatever port it actually came from.

On a quiet lab box you may never notice. On your daily driver the results are noise.

Fix: after parsing, check the reply is yours before believing it —
`hdr['src_port'] == port` and `hdr['dst_port'] == source_port`. Anything else gets
discarded and you keep reading until the timeout expires.

This is also why B2 matters: you need a source port that identifies the probe.

## ~~B2. Every probe uses source port 1234~~ — FIXED
`scanners/syn.py:9`

**Fixed:** `random.randint(49152, 65535)` per probe — the IANA ephemeral range.

Hardcoded for all ports. Fine for a synchronous loop, fatal the moment probes are in
flight simultaneously (roadmap item 3) — you lose the only field that tells you which
reply belongs to which probe.

Fix: derive the source port from the port index, e.g. `base + index`, and keep the
mapping so the receiver can reverse it. This is exactly what nmap does. Pick a base
above 32768 to stay clear of well-known ports.

## B3. IP header length is assumed to be 20 bytes
`scanners/syn.py:22`

`response[0][20:40]` hardcodes IHL=5. Correct most of the time, wrong whenever the
reply carries IP options — and then you slice into the middle of the TCP header and
read garbage flags.

Fix: needs `parse_ip_header` (see C2). Read the low nibble of byte 0, multiply by 4,
slice from there.

## ~~B4. Closed ports are never reported~~ — FIXED
`scanners/syn.py:24`

**Fixed:** RST now maps to `closed`/`reset`, and `filtered`/`no-response` is the
default the loop keeps when nothing comes back. Every port produces exactly one
result now.

Only `0x012` (SYN-ACK) is handled. A closed port answers with RST (`0x014`) and the
code silently drops it, so a closed port and a filtered port are indistinguishable in
the output — both just vanish.

Fix: add the RST branch → `state: 'closed'`, `reason: 'reset'`. On timeout →
`state: 'filtered'`, `reason: 'no-response'`. That gives the same three states `-sU`
already reports, which is the whole point of a SYN scan over a connect scan.

## B5. Sockets are never closed — HALF FIXED (`syn.py` done, `tcp.py` open)
`scanners/syn.py:17`, `scanners/tcp.py:8`

**Fixed in `syn.py`:** one raw socket for the whole scan, created above the loop,
closed in `finally`.
**Still open in `tcp.py`:** a socket per port, never closed, and an open port leaves
a live connection dangling.

Both create a socket per port inside the loop and never close it. CPython's refcount
cleans up when the variable is rebound on the next iteration, so it *mostly* doesn't
leak — but `-p-` is 65535 sockets racing the garbage collector against your fd limit
(`ulimit -n`, usually 1024).

`tcp.py` is the worse of the two: on an open port it leaves a fully established
connection dangling, which the target sees and logs.

Fix: `finally: s.close()`, the way `udp.py` already does it. Or `with` — sockets are
context managers.

## B6. `get_local_ip()` picks the wrong interface on VPN
`net/utils.py:4`

It asks the routing table how to reach `8.8.8.8`, which answers with your *default*
route. Scan an HTB or THM box over `tun0` and the packets go out with your home LAN
address as source — replies never come back, and the scan reports everything as
filtered. Genuinely confusing to debug, because nothing errors.

Fix: ask about the actual destination, not a fixed public IP —
`get_local_ip(target_ip)`, connect to the target instead of `8.8.8.8`. Same trick, no
packet sent, correct answer per target.

## B7. Bare `except Exception` that prints
`scanners/syn.py:27-28`

Catches everything — the timeout, a short packet, a `struct.error`, a genuine bug —
flattens them all into one message, and prints from inside a scanner, which the whole
layering is supposed to prevent.

Fix: catch `socket.timeout` on its own and turn it into a `filtered` result. Let real
bugs crash rather than hide, or attach them to the result as a `reason`. Either way,
no `print()` below `main.py`.

## B8. `build_ip_header` hardcodes `total_length = 40`
`net/packet.py:total_length`

Correct only for a bare 20-byte TCP header with no payload. Any UDP probe or any
payload produces a header that lies about its own length.

Fix: take `payload_len` as an argument, `total_length = 20 + payload_len`.

## B9. `parse_ports` crashes on bad input
`net/utils.py:12`

`parse_ports("http")` throws a raw `ValueError` traceback at the user. There's also
no validation that ports land in 1–65535, so `-p 99999` builds a packet with a
truncated port number.

Fix: covered by C1 — validate while you're in there.

## B10. TCP connect scan lets `OSError` escape
`scanners/tcp.py:13-17`

Catches `socket.timeout` and `ConnectionRefusedError`, but a dead route raises
`OSError: [Errno 113] No route to host` and kills the whole scan mid-run, losing
every result gathered so far.

Fix: catch `OSError` last and record `state: 'unreachable'`. Order matters —
`ConnectionRefusedError` is a subclass of `OSError`, so it has to come first.

## Not bugs, but worth knowing

- **`window = 0` in every SYN.** Real stacks advertise 1024 or 65535. A zero window
  is an unusual enough combination that IDS signatures key on it. Doesn't break
  anything; does make you loud.
- **Empty UDP probe.** `send(b'')` gets you nothing from a real daemon. DNS, SNMP and
  NTP all ignore garbage, so open ports read as `open|filtered`. That's C5, not a bug.
- **IP checksum left at 0.** The kernel recomputes it under `IP_HDRINCL`, so this is
  legal. Worth computing anyway once there's a test for it.

---

# Part 2 — Code to write

## C1. `net/utils.py::parse_ports(spec) -> list[int]`
Currently comma lists only. Needs: `"1-1024"` (inclusive), `"22,80,8000-8100"`,
`"-"` for all 65535. Sort, dedup, validate 1–65535, raise something readable on junk.

Best first test target in the repo — pure string in, list out, no network, no root.

## C2. `net/packet.py::parse_ip_header(data) -> dict`
Return at least `{'ihl', 'header_len', 'total_len', 'proto', 'src', 'dst'}`.
`header_len` is what fixes B3. `proto` is what lets you tell TCP replies from ICMP
ones later.

## C3. `net/packet.py` — flag constants
`FIN=0x01 SYN=0x02 RST=0x04 PSH=0x08 ACK=0x10 URG=0x20`. Turns B4's magic numbers
into `flags & RST`, and makes roadmap item 7 (FIN/NULL/XMAS) a matter of passing a
different argument instead of copying the function.

While there: give `build_tcp_header` a `flags` parameter instead of the hardcoded SYN.

## C4. `report.py::print_results(results)` and `print_json(results)`
The only thing currently blocking `python main.py` from running at all.

`print_results` — aligned columns, one row per port, colour by state, and a summary
line. Skip closed ports by default or the `-p-` output is unreadable; nmap prints
"Not shown: 994 closed ports" for exactly this reason.

`print_json` — `json.dumps(results, indent=2)`. That's the whole function, and it's
the payoff for scanners returning data.

## C5. `net/packet.py::parse_icmp_header(data)` + real UDP probes
Needed when UDP scanning moves to raw sockets and has to read ICMP type 3 code 3
itself instead of letting the kernel translate it into `ConnectionRefusedError`.

Pairs with a small table of protocol-specific payloads: a real DNS query for 53, an
SNMP getRequest for 161, an NTP client packet for 123.

## C6. `tests/test_packet.py`
Round-trip is the easy win: `parse_tcp_header(build_tcp_header(...))` gives back what
you put in. Then a known-answer checksum test, and the B3 case — a header with IP
options, where the naive slice is demonstrably wrong.

Cross-check trick: build the same packet in scapy, `bytes(pkt)`, compare to yours.
Scapy stays a reference for testing, never an import in the actual code.

---

# Part 3 — Resources

## Read first
- **Fyodor, *The Art of Port Scanning*, Phrack 51 (1997)** —
  <https://nmap.org/p51-11.html>
  The nmap specifics are obsolete; the reasoning behind each scan type is not. Read
  the FIN/NULL/XMAS section before attempting roadmap item 7.
- **Nmap Network Scanning**, free online — <https://nmap.org/book/>
  Especially *Port Scanning Techniques* (<https://nmap.org/book/man-port-scanning-techniques.html>)
  and *Port Scanning Basics* on what open/closed/filtered actually mean. The vocabulary
  half this project is trying to earn.
- **Idle scan explained** — <https://nmap.org/book/idlescan.html>
  Roadmap item 8. Read it once just for the idea, even if you build it much later.

## RFCs (short, and directly about code you've already written)
- **RFC 791** — IPv4 header. The field layout `build_ip_header` packs.
- **RFC 793** — TCP. Section 3.4 is the state machine that makes SYN scanning work;
  section 3.5 is why a closed port must answer RST, which is B4.
- **RFC 768** — UDP. Two pages, entire protocol.
- **RFC 792** — ICMP. Type 3 code 3 is the `port unreachable` your UDP scan depends on.
- **RFC 1071** — *Computing the Internet Checksum*. This is literally the algorithm in
  `calculate_checksum`, including the reason for the fold-the-carry step.

## Python
- `socket` — <https://docs.python.org/3/library/socket.html> (read the raw-socket and
  timeout notes specifically)
- `struct` — <https://docs.python.org/3/library/struct.html> (the format-character
  table is the thing you'll keep reopening)
- `asyncio` streams — <https://docs.python.org/3/library/asyncio-stream.html>
  Roadmap item 3 for the connect scan. Raw SYN stays threads, since raw sockets don't
  fit asyncio cleanly.
- `pytest` — <https://docs.pytest.org/>

## Tools to check yourself against
- **Wireshark / `tcpdump -i any -n 'tcp port 80'`** — the only honest answer to "did
  my packet actually go out and did it look right". `tcp.flags == 0x012` as a display
  filter. Use it on every bug in Part 1.
- **scapy** — <https://scapy.readthedocs.io/> as a reference implementation to compare
  bytes against, not as a dependency.
- **`nmap -d`** on the same target. Run it, run yours, diff the conclusions. When they
  disagree, nmap is right and the gap is the lesson.
- **`ss -tulpn`** — what's actually listening locally, so you know the right answer
  before you scan.

## Later, when the relevant phase arrives
- **nmap-service-probes format** — <https://nmap.org/book/vscan-fileformat.html>
  The probe/match file format for C5 and roadmap item 5. Writing a parser for it is a
  good exercise and the file itself is a free signature database.
- **TCP/IP Illustrated, Vol. 1** (Stevens) — the book, when you want depth rather
  than an RFC's precision.
- **Beej's Guide to Network Programming** — <https://beej.us/guide/bgnet/>
  C-flavoured, but the clearest explanation anywhere of what the socket API is
  actually doing underneath.
- `net.ipv4.icmp_ratelimit` / `icmp_ratemask` (`sysctl`) — why closed UDP ports read
  as `open|filtered` at scale, and the knob to turn off in your own lab to prove it.
