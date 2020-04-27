import subprocess
import optparse


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option('-i', '--interface', dest="interface", help='Interface to change its MAC')
    parser.add_option('-m', '--mac', dest="new_mac", help='New MAC address')
    (options_from_parser, arguments) = parser.parse_args()
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


options = get_arguments()
change_mac(options.interface, options.new_mac)
