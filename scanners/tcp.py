import socket


def tcp_connect_scan(target_ip, ports_list):
    results = []
    for port in ports_list:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target_ip, port))

            results.append({'port': port, 'proto': 'tcp', 'state': 'open', 'reason': 'syn-ack'})

        except socket.timeout:
            results.append({'port': port, 'proto': 'tcp', 'state': 'filtered', 'reason': 'no-response'})

        except ConnectionRefusedError:
            results.append({'port': port, 'proto': 'tcp', 'state': 'closed', 'reason': 'conn-refused'})

        except OsError:
            results.append({'port': port, 'proto': 'tcp', 'state': 'unreachable', 'reason': 'conn-refused' })



        finally:
            s.close()


    return results
