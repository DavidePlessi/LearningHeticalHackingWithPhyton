import scapy.all as scapy
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target', help='Target IP / IP range.')
    options = parser.parse_args()
    if not options.target:
        parser.error('[-] Please specify a target, use --help for more info.')
    return options


def print_result(client_list):
    print('   IP\t\t\t    AC Address')
    print('-----------------------------------------')

    for answer in client_list:
        print('{}\t\t{}'.format(answer["ip"], answer["mac"]))


def scan(ip):
    arp_requests = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp_requests
    # SRP allow us to use custom Ether
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return [{"ip": x[1].psrc, "mac": x[1].hwsrc} for x in answered_list]


if __name__ == '__main__':
    parameters = get_arguments()
    result = scan(parameters.target)
    print_result(result)
