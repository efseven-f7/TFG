from scapy.all import ARP, Ether, srp, sniff
from HID import HID
from db_communication import EXCLUDED_IPS, EXCLUDED_MACS, update_device_status, insert_device_data, get_config
from honeypot_manager import lanzar_honeypot, stop_honeypot, check_honeyd
import uuid
import socket

from port_scanner import scan_and_update_device

# Función para obtener la dirección IP de la propia máquina
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Conecta a un servidor de prueba (Google DNS) para obtener la IP local
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

# Get MAC address from it's own machine
LOCAL_MAC = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff)
                     for elements in range(0, 2*6, 8)][::-1])
EXCLUDED_MACS.append(LOCAL_MAC)

# Get IP address from it's own machine
LOCAL_IP = get_local_ip()
EXCLUDED_IPS.append(LOCAL_IP)

def first_scan(network_range, port_scan_interval):
    config = get_config()
    excluded_ips = EXCLUDED_IPS + config['whitelist_ips'].split(',')
    excluded_macs = EXCLUDED_MACS + config['whitelist_connections'].split(',')

    print(f"Escaneando la red {network_range}")
    arp = ARP(pdst=network_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]
    
    devices = []
    for sent, received in result:
        if received.psrc not in excluded_ips and received.hwsrc not in excluded_macs:
            insert_device_data(received.psrc, received.hwsrc)
            update_device_status(received.psrc, 'online')
            devices.append(HID(received.psrc, received.hwsrc, scan_and_update_device(received.psrc, received.hwsrc, port_scan_interval), 'online'))

    return devices

def check_new_host_up(q):
    config = get_config()
    excluded_ips = EXCLUDED_IPS + config['whitelist_ips'].split(',')
    excluded_macs = EXCLUDED_MACS + config['whitelist_connections'].split(',')

    def detect_new_host(pkt):
        if pkt.haslayer(ARP) and pkt[ARP].op == 1:  # who-has (request)
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            if ip not in excluded_ips and mac not in excluded_macs and check_honeyd():
                q.put(HID(ip, mac, None, 'online'))
                # print(f"Detected ARP request packet: {ip} ({mac})")

    sniff(prn=detect_new_host, filter="arp", store=0)

def check_online_hosts(running_honeypots, hosts_addrs):
    config = get_config()
    excluded_ips = EXCLUDED_IPS + config['whitelist_ips'].split(',')

    for host in hosts_addrs:
        if host.get_ip() not in excluded_ips and not host_is_up(host.get_ip()):
            print(f"The host with the IP address {host.get_ip()} is offline.")
            update_device_status(host.get_ip(), 'offline')
            hosts_addrs.remove(host)
            if host.get_ip() not in running_honeypots:
                running_honeypots = lanzar_honeypot(host, running_honeypots)
        elif host.get_ip() not in excluded_ips:
            update_device_status(host.get_ip(), 'online')

    return running_honeypots

def host_is_up(ip):
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]
    return len(result) > 0
