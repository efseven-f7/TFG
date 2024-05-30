#!/usr/bin/python3

import multiprocessing
import os
import threading
from datetime import datetime
from scapy.all import *
from HID import HID
from db_communication import insert_device_data, update_device_status, update_honeypot_status
from honeypot_manager import launch_honeyd, stop_honeyd, stop_honeypot, check_honeyd, check_honeypot
from arp_scanner import first_scan, check_new_host_up, check_online_hosts
from network_management import allow_connections, allow_ips, flush_iptables
from port_scanner import scan_and_update_device

# Global variables to manage hosts and honeypots
hosts_addrs = []
running_honeypots = []
timer = None
p = None

def get_timestamp():
    """Utility function to get the current timestamp formatted as a string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def periodic_check():
    """Periodic check to update honeypots based on network status."""
    global running_honeypots
    global hosts_addrs
    global timer

    # Check if the honeyd is running, update honeypots accordingly
    if check_honeyd():
        running_honeypots = check_online_hosts(running_honeypots, hosts_addrs)

    # Reset timer to continually execute this check
    timer = threading.Timer(scan_interval, periodic_check)
    timer.start()

def start_system(config):
    """Starts the monitoring and honeypot deployment system."""
    global hosts_addrs
    global running_honeypots
    global scan_interval
    global p

    # Reset network rules and allow specified connections and IPs
    flush_iptables()
    allow_connections(config['whitelist_connections'])
    allow_ips(config['whitelist_ips'])

    # Set up honeypot logging and configuration files
    honeypot_conf = os.path.abspath('honeypots/honeypot.conf')
    honeyd_log = os.path.abspath('logs/honeyd_log.txt')
    honeyd_serv_log = os.path.abspath('logs/honeyd_serv_log.txt')
    scan_interval = int(config['scan_interval'])
    port_scan_interval = int(config['port_scan_interval'])

    # Perform initial network scan and launch honeyd
    hosts_addrs = first_scan(config['network_range'], port_scan_interval)
    running_honeypots = []
    launch_honeyd(config['network_range'], honeypot_conf, honeyd_log, honeyd_serv_log)

    # Setup a multiprocessing queue and start a new process for monitoring new hosts
    q = multiprocessing.Queue()
    p = multiprocessing.Process(target=check_new_host_up, args=(q,))
    p.start()

    # Start periodic network checks
    periodic_check()

    # Continuous loop to process new hosts detected by the monitoring system
    while True:
        while not q.empty():
            new_host = q.get()
            if isinstance(new_host, HID) and new_host.get_ip() != "0.0.0.0" and new_host.get_ip() not in running_honeypots:
                new_host.set_status('online')
                insert_device_data(new_host.get_ip(), new_host.get_mac())
                new_host.set_services(scan_and_update_device(new_host.get_ip(), new_host.get_mac(), port_scan_interval))
                hosts_addrs.append(new_host)
            elif new_host and new_host.get_ip() in running_honeypots:
                print(f"{get_timestamp()} - Stopping honeypot -> {new_host.get_ip()}\n")
                running_honeypots.remove(new_host.get_ip())
                stop_honeypot(new_host.get_ip())
                hosts_addrs.append(new_host)
            update_device_status(new_host.get_ip(), 'online')
            update_honeypot_status(new_host.get_ip(), 'offline')

def stop_system():
    """Stops the monitoring and honeypot deployment system, cleaning up resources."""
    global p
    global timer

    # Terminate the process if it is still running
    try:
        if p is not None and p.is_alive():
            p.terminate()
            p.join()
            p.close()
    except Exception:
        pass

    # Cancel any scheduled timer
    if timer:
        timer.cancel()

    # Stop all running honeypots
    for honeypot in running_honeypots:
        if check_honeypot(honeypot):
            stop_honeypot(honeypot)

    # Stop honeyd if it's running
    if check_honeyd():
        stop_honeyd()

    print("System stopped.....")
    return 0

