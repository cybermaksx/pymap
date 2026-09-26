import socket
import struct


def calculate_checksum(data):
    # If the number of bytes is odd, add a zero byte at the end to make it even
    if len(data) % 2 != 0:
        data += b'\x00'

    # Start with a sum of zero
    s = 0

    # Loop through the data, taking 2 bytes at a time
    for i in range(0, len(data), 2):
        # Combine two bytes into one 16-bit number (e.g. 0x01 and 0x02 -> 0x0102)
        word = (data[i] << 8) + data[i + 1]
        # Add that 16-bit number to the total sum
        s += word

    # If the sum is larger than 16 bits, take the overflow and add it back to the lower 16 bits
    s = (s >> 16) + (s & 0xFFFF)
    # Do it one more time in case there is still overflow after the first fold
    s += (s >> 16)

    # Flip all the bits (ones become zeros, zeros become ones) and keep only 16 bits
    return ~s & 0xFFFF


def build_tcp_header(source_port, dest_port, my_ip, target_ip):
    #TCP headers fileds
    seq = 0 #In the beggining seq should be 0
    ack = 0 #If seq = 0 ,ack = 0 as well
    urgent = 0
    offset_flags = (5 << 12) | 0x002 # size of our packet + SYN flag
    window = 0  # We are just scanning we don't need to accept anything
    checksum = 0 # we will use def for this later
    source_ip = socket.inet_aton(my_ip) #intet_aton converts our strings and ints to bytes
    dest_ip = socket.inet_aton(target_ip)

    tcp_header = struct.pack("!HHLLHHHH", source_port, dest_port, seq, ack, offset_flags, window, checksum, urgent)#converting to the big indian so the server can understand
    pseudo_header = struct.pack("!4s4sBBH", source_ip, dest_ip, 0, 6, len(tcp_header))
    checksum = calculate_checksum(pseudo_header + tcp_header)
    tcp_header = struct.pack("!HHLLHHHH", source_port, dest_port, seq, ack, offset_flags, window, checksum, urgent)

    return tcp_header


def build_ip_header(my_ip, target_ip):
    #Ip header fields
    ihl_version = 69  #Internet Header Length which is standart for each ip packet 4 because ipv 4 and 5 because we are using 5 blocks each 4 bytes which gives as 20 and 0100 0101  =  69
    tos = 0 #Type Of service or priority
    total_length = 20 + payload_len
    identification = 0 #ID of packet we need if it gets damaged however it will not because it's too small
    frag_offset = 0  # we will need this value only if our packet cuttet into pieces
    ttl = 64 # how many routers we can get trough
    protocol = 6 # tcp = 6
    checksum = 0
    source_ip = socket.inet_aton(my_ip)
    dest_ip = socket.inet_aton(target_ip)
    ip_header = struct.pack("!BBHHHBBH4s4s", ihl_version, tos, total_length, identification, frag_offset, ttl, protocol, checksum, source_ip, dest_ip)

    return ip_header


def parse_tcp_header(data):
    tcp_fields = struct.unpack("!HHLLHHHH", data) # Taking raw bytes back to the human readeble format
    return {
        'src_port': tcp_fields[0],
        'dst_port': tcp_fields[1],
        'seq': tcp_fields[2],
        'ack': tcp_fields[3],
        'flags': tcp_fields[4] & 0x1FF, # Now we only saving last 9 bytes which is very the flags that we need
        'window': tcp_fields[5],
    }


# TODO: parse_ip_header(data) -> read IHL from the first byte, don't assume 20
