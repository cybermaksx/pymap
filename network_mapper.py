import socket
import struct
import os
import argparse

print("""
\033[92m
    ███╗   ██╗███████╗████████╗    ███╗   ███╗ █████╗ ██████╗ ██████╗ ███████╗██████╗ 
    ████╗  ██║██╔════╝╚══██╔══╝    ████╗ ████║██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗
    ██╔██╗ ██║█████╗     ██║       ██╔████╔██║███████║██████╔╝██████╔╝█████╗  ██████╔╝
    ██║╚██╗██║██╔══╝     ██║       ██║╚██╔╝██║██╔══██║██╔═══╝ ██╔═══╝ ██╔══╝  ██╔══██╗
    ██║ ╚████║███████╗   ██║       ██║ ╚═╝ ██║██║  ██║██║     ██║     ███████╗██║  ██║
    ╚═╝  ╚═══╝╚══════╝   ╚═╝       ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
\033[0m
\033[90m    [ TCP / SYN Scanner ] [ Made by cybermaksx and EndU2 (He doesn't exist it is my Tyler Durden) ] [ v1.4 ]\033[0m
""")


#should work with argparse

parser = argparse.ArgumentParser(description="Let's Hack The Planet")

parser.add_argument("-p", "--ports", type=str, default='80,443,22,23,21,3305',help="Ports which you would like to scan")
parser.add_argument("-sS", action='store_true', help="SYN Scan")
parser.add_argument("-sT", action='store_true', help="TCP Scan")
parser.add_argument("-sU" , action='store_true', help="UDP_SCAN")
parser.add_argument("target", help="your target's ip")
args = parser.parse_args()
target_ip = args.target 
target_ports = args.ports

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
my_ip = s.getsockname()[0]
s.close()

ports_list = [int(p.strip()) for p in target_ports.split(',')]


def tcp_scan (target_ip, ports_list ):
   for port in ports_list:
        try: 
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target_ip,port))
        
            print (f"[*] {port}  is  open")
        except socket.timeout:
            print("Target is unreacheable")

        except ConnectionRefusedError:
            print (f"{port} seems to be closed | filtered")


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


def syn_scan(target_ip,ports_list):
    open_ports_found = False 
    for port in ports_list:
        source_port = 1234 # our source port
        #TCP headers fileds
        seq = 0 #In the beggining seq should be 0 
        ack = 0 #If seq = 0 ,ack = 0 as well
        urgent = 0
        offset_flags = (5 << 12) | 0x002 # size of our packet + SYN flag
        window = 0  # We are just scanning we don't need to accept anything
        checksum = 0 # we will use def for this later
        source_ip = socket.inet_aton(my_ip) #intet_aton converts our strings and ints to bytes
        dest_ip = socket.inet_aton(target_ip)  

        tcp_header = struct.pack("!HHLLHHHH", source_port, port, seq, ack, offset_flags, window, checksum, urgent)#converting to the big indian so the server can understand
        pseudo_header = struct.pack("!4s4sBBH", source_ip, dest_ip, 0, 6, len(tcp_header))
        checksum = calculate_checksum(pseudo_header + tcp_header)
        tcp_header = struct.pack("!HHLLHHHH", source_port, port, seq, ack, offset_flags, window, checksum, urgent)
    

        #Ip header fields
        ihl_version = 69  #Internet Header Length which is standart for each ip packet 4 because ipv 4 and 5 because we are using 5 blocks each 4 bytes which gives as 20 and 0100 0101  =  69 
        tos = 0 #Type Of service or priority  
        total_length = 40  # 20 bytes ip + 20 bytes tcp
        identification = 0 #ID of packet we need if it gets damaged however it will not because it's too small 
        frag_offset = 0  # we will need this value only if our packet cuttet into pieces
        ttl = 64 # how many routers we can get trough
        protocol = 6 # tcp = 6 
        checksum = 0 
        source_ip = socket.inet_aton(my_ip)
        dest_ip = socket.inet_aton(target_ip)
        ip_header = struct.pack("!BBHHHBBH4s4s", ihl_version, tos, total_length, identification, frag_offset, ttl, protocol, checksum, source_ip, dest_ip)

        packet = ip_header + tcp_header 
    

    
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW , socket.IPPROTO_TCP) # SOCKRAW is important here because we don't want out system to touch this socket
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1) # Socket options : DON"T touch socket which we made
            s.settimeout(3) # Don't wait if answer didn't come in 3 seconds
            s.sendto(packet, (target_ip, 0))
            response = s.recvfrom(1024) #Max response length in bytes
            tcp = response[0][20:40] # We are getting TCP header from response
            tcp_fields = struct.unpack("!HHLLHHHH", tcp) # Taking raw bytes back to the human readeble format 
            flags = tcp_fields[4] & 0x1FF # Now we only saving last 9 bytes which is very the flags that we need 
            if flags == 0x012: # SYN-ACK 
                print(f"[*] {port} Port is open")
                open_ports_found = True
                
        except Exception as e:
            print(f"Error: {e}")

    return open_ports_found 



def udp_scan(target_ip, ports_list, timeout=3):
    for port in ports_list:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.connect((target_ip, port))  
            sock.send(b'')
            sock.recv(1024)
            print(f"[+] Port {port}/udp is OPEN")          
        except socket.timeout:
            print(f"[?] Port {port}/udp is OPEN|FILTERED") 
        except ConnectionRefusedError:
            print(f"[-] Port {port}/udp is CLOSED")        
        finally:
            sock.close() 


def main(target_ip,ports_list):
    if args.sT == True:
        tcp_scan(target_ip, ports_list)

    elif args.sS == True:
        open_ports_found = syn_scan(target_ip , ports_list)
        if not open_ports_found:
            print("[*] No open ports have been found!")        

    elif args.sU == True:
        udp_scan(target_ip , ports_list)


    elif not args.sS and not args.sT:
        parser.print_help()
        exit() 
                 

if __name__ == '__main__':
    main(target_ip, ports_list)




