# Known bugs — to fix

## BUG 1 (critical): syn_scan scans only the LAST port, N times

**Where:** `network_mapper.py`, function `syn_scan()` — the two separate
`for port in ports_list:` loops.

**Symptom:** `-sS -p 22,80,443` does NOT scan 22, 80 and 443. It scans **443
three times** and never touches 22 or 80. Any multi-port SYN scan silently
probes only the last port in the list.

**Root cause:**
- The **first** loop builds `packet` (ip_header + tcp_header) and **reassigns it
  every iteration**, but never sends it inside that loop. When the loop ends,
  `packet` holds only the **last** port's bytes.
- The **second** loop then sends that **same `packet`** on every iteration, so
  every SYN carries the last port's destination port (it's baked into the
  tcp_header inside `packet`).
- Note: with `IP_HDRINCL` set, the `sendto(packet, (target_ip, 0))` address port
  (`0`) is ignored — the real destination port lives inside the packet bytes, so
  it's always the last port.

**How to verify:** run against a host with a known-open low port and a
known-closed high port, put the closed one last in `-p`. It'll report nothing,
even though the earlier port is open. Or watch it in Wireshark — every SYN goes
to the same dport.

**Fix direction (do it yourself):** the packet must be built AND sent for the
same port before moving on. Either
- build + send inside a single loop over `ports_list`, or
- in the first loop, append each per-port packet into a list/dict keyed by port,
  then in the second loop send the packet that matches the current port.

Whichever you pick, make sure the tcp_header's destination port matches the port
you're actually reporting on.

---

## BUG 2 (minor): wrong comment on the SYN-ACK flag check

**Where:** `syn_scan()`, `if flags == 0x012:` — comment says `# This is RST's bytes`.

`0x012` = `0b0000_1_0010` = **SYN(0x002) + ACK(0x010)** = SYN-ACK = **port open**.
The *code* is correct (SYN-ACK means open). The *comment* is wrong — this is not
RST. RST would be `0x004` (or SYN-ACK's absence / RST-ACK `0x014`).

Fix: correct the comment to say "SYN-ACK → port open". The logic stays.

---

*Found via a cold read-through of the code (no editor, explaining the mechanism
out loud). BUG 1 is the classic "generated code that was never traced by hand"
signature — worth tracing your own control flow on the raw-socket paths.*
