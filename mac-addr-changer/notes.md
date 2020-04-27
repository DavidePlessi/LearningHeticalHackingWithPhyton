# Hetical hacking
## Change mac address 
```
ip link show
sudo ip link set dev <your device here> down
sudo ip link set dev <your device here> address <your new mac address>
sudo ip link set dev <your device here> up
```