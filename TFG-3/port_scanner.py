#!/usr/bin/python3

from datetime import datetime, timedelta
from alive_progress import alive_bar
from scapy.all import IP, TCP, sr1, RandShort
from arp_scanner import EXCLUDED_IPS
from db_communication import get_device_data, update_device_services

def port_scan(target, ports, timeout=0.1):
    open_ports = []
    with alive_bar(len(ports), title=f"Checking ports in {target}") as bar:
        for port in ports:
            src_port = RandShort()
            response = sr1(IP(dst=target) / TCP(sport=src_port, dport=port, flags="S"), timeout=timeout, verbose=0)
            if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                sr1(IP(dst=target) / TCP(sport=src_port, dport=port, flags="R"), timeout=timeout, verbose=0)
                open_ports.append(port)
                print(f"OPEN: {port}")
            bar()
    return open_ports

def scan_and_update_device(ip, mac, scan_interval):
    ports = range(1, 1024)
    open_ports = []
    if ip not in EXCLUDED_IPS:
        device = get_device_data(ip, mac)
        if device and device[4] is not None:
            # Current time
            current_time = datetime.now()

            # Calculate time difference
            time_difference = current_time - device[4]

            # Check if the difference is at least one day
            if time_difference >= timedelta(days=1):
                open_ports = port_scan(ip, ports)
                update_device_services(ip, open_ports)
        elif device and device[4] is None:
            open_ports = port_scan(ip, ports)
            update_device_services(ip, open_ports)
        return open_ports
