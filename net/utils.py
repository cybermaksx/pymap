import socket


def get_local_ip(target_ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((target_ip, 22)) #Poor realisation # TODO change this to the output of the ip -a command
    my_ip = s.getsockname()[0]
    s.close()
    return my_ip


def parse_ports(spec):
    # TODO: ranges (1-1024), all ports (-), dedup, validate 1-65535
    return [int(p.strip()) for p in spec.split(',')]
