import socket

from net.packet import build_ip_header, build_tcp_header, parse_tcp_header


def syn_scan(target_ip, ports_list, my_ip):
    results = []
    for port in ports_list:
        source_port = 1234 # our source port

        tcp_header = build_tcp_header(source_port, port, my_ip, target_ip)
        ip_header = build_ip_header(my_ip, target_ip)

        packet = ip_header + tcp_header

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW , socket.IPPROTO_TCP) # SOCKRAW is important here because we don't want out system to touch this socket
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1) # Socket options : DON"T touch socket which we made
            s.settimeout(3) # Don't wait if answer didn't come in 3 seconds
            s.sendto(packet, (target_ip, 0))
            response = s.recvfrom(1024) #Max response length in bytes
            tcp = response[0][20:40] # We are getting TCP header from response
            hdr = parse_tcp_header(tcp)
            if hdr['flags'] == 0x012: # SYN-ACK
                results.append({'port': port, 'proto': 'tcp', 'state': 'open', 'reason': 'syn-ack'})

        except Exception as e:
            print(f"Error: {e}")

    return results
