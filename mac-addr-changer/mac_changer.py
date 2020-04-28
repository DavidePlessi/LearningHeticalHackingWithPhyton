import subprocess
import argparse
import re

MAC_ADDR_REGEXP = "[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}"


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', dest="interface", help='Interface to change its MAC')
    parser.add_argument('-m', '--mac', dest="new_mac", help='New MAC address')
    options_from_parser = parser.parse_args()
    if not options_from_parser.interface:
        parser.error('[-] Please specify an interface, use --help for more info.')
    if not options_from_parser.new_mac:
        parser.error('[-] Please specify a new mac, use --help for more info.')
    return options_from_parser


def change_mac(interface, new_mac_addr):
    print("[+] Changing the MAC address for {} to {}".format(interface, new_mac_addr))

    subprocess.call(['sudo', 'ip', 'link', 'set', 'dev', interface, 'down'])
    subprocess.call(['sudo', 'ip', 'link', 'set', 'dev', interface, 'address', new_mac_addr])
    subprocess.call(['sudo', 'ip', 'link', 'set', 'dev', interface, 'up'])


def get_current_mac(interface):
    result = str(subprocess.check_output(['ip', 'link', 'show', interface]))
    matches = re.search(MAC_ADDR_REGEXP, result)
    if not matches:
        print('[-] Could not read MAC address.')
        return None

    return matches.group(0)


if __name__ == '__main__':
    options = get_arguments()
    current_mac = get_current_mac(options.interface)
    if not current_mac:
        exit(1)

    print('Current MAC = ' + current_mac)
    change_mac(options.interface, options.new_mac)
    current_mac = get_current_mac(options.interface)
    if current_mac == options.new_mac:
        print('[+] MAC address was successfully changed to ' + current_mac)
    else:
        print('[-] MAC address did not get changed')
