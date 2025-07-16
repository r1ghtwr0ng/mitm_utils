# MITM Utils (for CTFs)
Basic MITM (Man-In-The-Middle) python scripts and helper functions for solving some CTF challenges.

The `mitm_utils.py` file has a bunch of functions for doing common attacks on the ARP protocol and running a full MITM attack with TCP packet modification capabilities. You can adapt it to the UDP protocol with little trouble, I might extend it at some point myself.

## Usage
Running the script is fairly straightforward, it allows MITM between two targets. You can specify a certain text pattern to be replaced with another one. Keep in mind that if the length of the replacement is different from the initial text it might lead to TCP session dsync issues.
`python mitm_utils.py --target-1 10.0.0.1 --target-2 10.0.0.2 --iface eth0 --replace-pattern good --replace-with evil`

Get help: `python mitm_utils.py -h` (duh)

Scapy needs permissions to use raw sockets to spoof MAC addresses in Ethernet frames, so run as root (or give permissions another way). 

## Functions
`def tcp_listener(port=8888)`
Run a simple TCP listener on port 8888, print whatever data is received to STDOUT

`def arp_scan(ip, iface)`
Send ARP packets to a specified IP over the given interface, resolve the MAC or return None

`def arp_poison(target, address, iface="eth0", iterations=100)`
Poison the ARP table of a specified target, tricking it that the address argument has your interface's MAC

`def inject(pkt, replace_rule, iface)`
TCP packet manipulation callback, runs replacement rule if matching and sends off to relay

`def relay_mitm(pkt, payload, iface)`
Relay the MITM'd packet to the proper destination

`def mitm_flow(target_1, target_2, replace_dict, iface)`
Runs a full MITM attack flow

## TLDR
Overall its a bit all over the place but hopefully you find useful snippets or the full script. Mostly good for CTFs. I'll try to address issues where I can, PRs are welcome.

