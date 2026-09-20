# pymap

A network mapper written from scratch in Python. No scapy, no wrappers around nmap,
no library doing the interesting part for me. Just `socket`, `struct`, and the RFCs.

## Why

Because nmap is a genuinely brilliant piece of engineering and I want to understand
why.

Anyone can memorize flags. `-sS -Pn -T4 --top-ports 1000` rolls off the fingers after
a week of CTFs, and you learn nothing. The moment something behaves strangely — a
filtered port that answers, a scan that hangs, a service that lies about itself — the
flags stop helping. What helps is knowing what actually goes out on the wire.

So I'm building my own. Badly at first. The point isn't the tool, it's the bytes.

## Where this came from

The initial code is lifted straight out of my learning repo,
[python_without_ai](https://github.com/cybermaksx/python_without_ai), where I write
everything by hand to actually learn it. It outgrew a folder called `scanners/`, so
it lives here now.

The git history over there is ugly on purpose. Commits like "yesterday i had skill
issues, but today i don't" are staying exactly where they are.

## Layout

The original was one 180-line file that parsed argv at import time and printed from
inside the scan loop. That works right up until you want to test it, or output JSON,
or reuse a header builder. So it got taken apart:

```
main.py              argv, dispatch, exit code. The only file that runs anything.
report.py            turns results into text or JSON. Owns every print.
net/
  packet.py          bytes in, bytes out. Builds and parses IP/TCP headers.
  utils.py           local IP lookup, port-spec parsing.
scanners/
  tcp.py             -sT   connect scan
  syn.py             -sS   raw SYN scan
  udp.py             -sU   UDP scan
tests/               pytest, mostly against net/packet.py
network_mapper.py    the original single file, kept for reference
```

Dependencies flow strictly downward — `main` knows everyone, scanners know `net`,
and `net` knows nothing but the standard library. If something in `net/` ever needs
to import from `scanners/`, the layering is wrong and I put the code in the wrong
place.

Two rules that make the rest work:

**Scanners return data, they don't print.** Every scan hands back a list of
dictionaries:

```python
{'port': 80, 'proto': 'tcp', 'state': 'open', 'reason': 'syn-ack'}
```

which is why `--json` costs one function instead of a rewrite, and why a test can
check a result without parsing stdout.

**Nothing happens at import time.** `import net.packet` opens no sockets, parses no
argv, prints no ASCII art. Header building is pure functions over bytes, so the
interesting half of this project is testable without root and without a network.

## State of things

Honest status, not marketing:

| Scan | Flag | Status |
| --- | --- | --- |
| TCP connect | `-sT` | Works. Slow and loud, like a full handshake should be. |
| UDP | `-sU` | Works. Correctly separates open / open\|filtered / closed. |
| SYN | `-sS` | Works. Hand-built packets, matched replies, all three states. |

The SYN scanner assembles its own IP and TCP headers and computes the checksum over
the pseudo-header, which is the part I actually wanted to learn. Then it has to do
the job the kernel normally does for you: a raw socket hands up every TCP packet on
the machine, so each probe carries a random ephemeral source port and every reply is
checked against it before being believed. Anything else is discarded and it keeps
listening until the port's deadline runs out.

SYN-ACK means open, RST means closed, silence means something ate the packet and
didn't admit it — that last one is `filtered`, and it's usually the most interesting
of the three.

What's left is written down in `BUGS.md` rather than quietly patched out, because
that's where the learning is. The reply parser still assumes a 20-byte IP header,
which is only true without IP options.

`-sS` needs root. Raw sockets are not for everyone, and that's the kernel doing its
job, not a bug in this.

## Usage

```bash
python main.py -sT -p 22,80,443 192.168.1.10
python main.py -sU -p 53,123,161 192.168.1.10
sudo python main.py -sS -p 1-1024 192.168.1.10
python main.py -sT -p 80,443 192.168.1.10 --json
```

Python 3, standard library only. Nothing to install.

## Roadmap

Rough order, written for future me:

1. Proper target and port parsing — CIDR ranges, `1-1024`, `-p-`.
2. Host discovery. ARP on the local segment, ICMP echo beyond it.
3. **Decouple the sender from the receiver.** This is the real one. Right now every
   scan is "send, block, wait, repeat," which is why 1000 filtered ports take an
   afternoon. One thread blasting probes, one sniffing replies, matched up by source
   port. Everything else is features; this is architecture.
4. Adaptive timing. Measure RTT instead of hardcoding three seconds and hoping.
5. Service detection. Protocol-specific probes and a signature match, because an
   empty UDP datagram gets you nothing from a real daemon.
6. Machine-readable output. Half of nmap's value is that other tools can eat its XML.
7. FIN / NULL / XMAS and ACK scans, for the RFC 793 edge cases that make firewalls
   show themselves.
8. Idle scan, eventually. Scanning a target through a third host's IP ID counter
   without sending it a single packet from your own address is the most elegant idea
   in this entire field and I want to have implemented it once.
9. OS fingerprinting. Realistically never, but it's on the list.

## What this is not

This is not an nmap replacement, and it never will be. nmap is close to thirty years
of work, a Lua scripting engine, and thousands of hand-curated OS fingerprints.
Competing with that would be stupid.

This is a scanner I understand down to the last byte. Different goal.

## Scope

Point it at your own lab, or at boxes you've been invited to touch. Scanning things
you don't own is someone else's hobby and someone else's legal problem.

## License

MIT. See [LICENSE](LICENSE).

---

Recommended reading if any of this looks interesting:
Fyodor, *The Art of Port Scanning*, Phrack 51 (1997) —
[nmap.org/p51-11.html](https://nmap.org/p51-11.html). The nmap specifics are long
obsolete. The reasoning is not.
