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

## State of things

| Scan | Flag | Status |
| --- | --- | --- |
| TCP connect | `-sT` | Works. Slow and loud, like a full handshake should be. |
| UDP | `-sU` | Works. Correctly separates open / open\|filtered / closed. |
| SYN | `-sS` | Builds real packets by hand. Currently broken in ways I know about. |

The SYN scanner assembles its own IP and TCP headers, computes the checksum over the
pseudo-header, and sends it through a raw socket. It also sends the same packet to
every port and doesn't check whether the reply belongs to the scan at all. Both of
these are getting fixed. Leaving the bug documented instead of quietly patching it
out, because that's the part I learned the most from.

Requires root for `-sS` — raw sockets are not for everyone, and that's a feature of
the kernel, not a bug in this.

## Usage

```bash
python network_mapper.py -sT -p 22,80,443 192.168.1.10
python network_mapper.py -sU -p 53,123,161 192.168.1.10
sudo python network_mapper.py -sS -p 1-1024 192.168.1.10
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
