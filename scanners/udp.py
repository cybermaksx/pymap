import socket


def udp_scan(target_ip, ports_list, timeout=3):
    results = []
    for port in ports_list:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.connect((target_ip, port))
            sock.send(b'')
            sock.recv(1024)
            results.append({'port': port, 'proto': 'udp', 'state': 'open', 'reason': 'udp-response'})
        except socket.timeout:
            results.append({'port': port, 'proto': 'udp', 'state': 'open|filtered', 'reason': 'no-response'})
        except ConnectionRefusedError:
            results.append({'port': port, 'proto': 'udp', 'state': 'closed', 'reason': 'icmp-port-unreachable'})
        finally:
            sock.close()

    return results
