import socket

def tcp_scan(target_ip,ports_list):
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target_ip,port))

            print(f"[*]{port} is open")

        except socket.timeout:
            print("Target is unreacheble")


        except ConnectionRefusedError:
            print(f"{port} seems to be closed|filtered")

