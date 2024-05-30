#!/usr/bin/python3

import multiprocessing
import os
from scapy.all import *
from HID import HID
from db_communication import insert_device_data, update_device_status, update_honeypot_status
from honeypot_manager import lanzar_honeyd, tumbar_honeyd, tumbar_honeypot, verificar_honeyd, verificar_honeypot
from arp_scanner import first_scan, check_new_host_up, check_online_hosts
from network_management import allow_connections, allow_ips, allow_ports, flush_iptables
from port_scanner import scan_and_update_device

hosts_addrs = []
running_honeypots = []
timer = None
scan_interval = 600
p = None

def obtener_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def periodic_check():
    global running_honeypots
    global hosts_addrs
    global scan_interval

    print(f"Ejecutando el periodic_check ({scan_interval})")
    if verificar_honeyd():
        running_honeypots = check_online_hosts(running_honeypots, hosts_addrs)

    # Reestablecer el timer para ejecutar esta función cada 10 segundos
    timer = threading.Timer(scan_interval, periodic_check)
    timer.start()

def start_system(config):
    global hosts_addrs
    global running_honeypots
    global scan_interval
    global p 

    flush_iptables()
    allow_connections(config['whitelist_connections'])
    allow_ips(config['whitelist_ips'])

    honeypot_conf = os.path.abspath('/home/efseven/TFG-3/honeypots/honeypot.conf')
    honeyd_log = os.path.abspath('/home/efseven/TFG-3/logs/honeyd_log.txt')
    honeyd_serv_log = os.path.abspath('/home/efseven/TFG-3/logs/honeyd_serv_log.txt')
    scan_interval = int(config['scan_interval'])
    port_scan_interval = int(config['port_scan_interval'])

    hosts_addrs = first_scan(config['network_range'], port_scan_interval)
    running_honeypots = []

    lanzar_honeyd(config['network_range'], honeypot_conf, honeyd_log, honeyd_serv_log)

    q = multiprocessing.Queue()

    p = multiprocessing.Process(target=check_new_host_up, args=(q,))
    p.start()

    # Iniciar el timer al comenzar el main loop
    periodic_check()

    while True:
        while not q.empty():
            new_host = q.get()
            if isinstance(new_host, HID) and new_host.get_ip() != "0.0.0.0" and new_host.get_ip() not in running_honeypots:
                # print(f"{obtener_timestamp()} - Descubierto nuevo host -> {new_host.get_ip()}\n")
                new_host.set_status('online')
                insert_device_data(new_host.get_ip(), new_host.get_mac())
                new_host.set_services(scan_and_update_device(new_host.get_ip(), new_host.get_mac(), port_scan_interval))
                hosts_addrs.append(new_host)

            elif new_host and new_host.get_ip() in running_honeypots:
                print(f"{obtener_timestamp()} - Tumbando honeypot -> {new_host.get_ip()}\n")
                running_honeypots.remove(new_host.get_ip())
                new_host.set_status('online')
                tumbar_honeypot(new_host.get_ip())
                hosts_addrs.append(new_host)
            update_device_status(new_host.get_ip(), 'online')
            update_honeypot_status(new_host.get_ip(), 'offline')

def stop_system():
    global p

    if p is not None and p.is_alive():
        p.terminate()  # Forzamos la terminación del proceso
        p.join()
        p.close()

    if timer:
        timer.cancel()

    for honeypot in running_honeypots:
        if verificar_honeypot(honeypot):
            tumbar_honeypot(honeypot)

    if verificar_honeyd():
        tumbar_honeyd()

    print("System stopped.....")
    return 0