import socket
import random
import time

from net.packet import build_ip_header, build_tcp_header, parse_tcp_header


def syn_scan(target_ip, ports_list, my_ip, timeout=3):
    results = []
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW , socket.IPPROTO_TCP) # SOCKRAW is important here because we don't want out system to touch this socke
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1) # Socket options : DON"T touch socket which we made
    
    
    

    try:
        for port in ports_list:
            source_port = random.randint(49152, 65535)  # our source port
            
            tcp_header = build_tcp_header(source_port, port, my_ip, target_ip)
            ip_header = build_ip_header(my_ip, target_ip)
            
            packet = ip_header + tcp_header
            
           # s.settimeout(3) # Don't wait if answer didn't come in 3 seconds
            s.sendto(packet, (target_ip, 0))
            deadline = time.monotonic() + timeout
            state = 'filtered'
            reason = 'no-response'

            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break

                s.settimeout(remaining)

                try:
                    response = s.recvfrom(1024) #Max response length in bytes

                except socket.timeout:
                    break

                tcp = response[0][20:40] # We are getting TCP header from response
                hdr = parse_tcp_header(tcp)

                if hdr['src_port'] != port or hdr['dst_port'] != source_port: #That's means that packet is on related to ours and we just continuing listening
                    continue


                if hdr['flags'] == 0x12:
                    state = 'open'
                    reason = 'syn + ackn'

                elif hdr['flags'] == 0x14:
                    state = 'closed'
                    reason = 'reset'
                break

            results.append({'port': port, 'proto': 'tcp', 'state': state, 'reason': reason})
            
            
                

    except Exception as e:
        print(f"Error: {e}")


    finally:
        s.close()

    return results
