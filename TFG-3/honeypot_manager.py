#!/usr/bin/python3

import subprocess
import time

from cupshelpers import getDevices
from db_communication import get_config, get_device_data, insert_or_update_honeypot_log, update_honeypot_status, update_device_status

def launch_honeyd(network_range, conf_file, log_file, serv_log_file):
    comando = f"honeyd -f {conf_file} -l {log_file} -s {serv_log_file} {network_range} > /dev/null"
    proceso = subprocess.Popen(comando, shell=True)
    time.sleep(2)  # Espera un poco para que Honeyd se inicie completamente

    # Verifica si Honeyd está en ejecución
    try:
        honeyd_pids = subprocess.check_output(["pidof", "honeyd"]).decode().split()
        honeyd_running = any("honeyd" in open(f"/proc/{pid}/cmdline").read().split('\x00') for pid in honeyd_pids)
        if honeyd_running:
            print("Honeyd se ha iniciado correctamente")
        else:
            print("Error: Honeyd no se ha iniciado correctamente")
    except subprocess.CalledProcessError:
        print("Error: Honeyd no se ha iniciado correctamente")

def stop_honeyd():
    try:
        honeyd_pids = subprocess.check_output(["pidof", "honeyd"]).decode().split()
        if honeyd_pids:
            subprocess.Popen(f'kill {honeyd_pids[0]}', shell=True)
            print("Exiting honeyd......")
    except subprocess.CalledProcessError:
        pass

def check_honeyd():
    try:
        honeyd_pids = subprocess.check_output(["pidof", "honeyd"]).decode().split()
        return any("honeyd" in open(f"/proc/{pid}/cmdline").read().split('\x00') for pid in honeyd_pids)
    except subprocess.CalledProcessError:
        return False

def check_honeypot(ip):
    try:
        # Revisa si la IP del honeypot está siendo manejada por honeyd
        output = subprocess.check_output(f"echo 'list template' | honeydctl | grep {ip}", shell=True)
        return ip in output.decode()
    except subprocess.CalledProcessError:
        return False

def lanzar_honeypot(hid, running_honeypots):
    device = get_device_data(hid.get_ip(), hid.get_mac())
    services = device[2].strip().split(',')

    config = get_config()
    # Checks if honeyd is running
    if not check_honeyd():
        print("Honeyd is not running")
        return running_honeypots

    # Check if the honeypot is already launched
    if check_honeypot(hid.get_ip()):
        print(f"Honeypot with IP {hid.get_ip()} is already launched.")
        if hid.get_ip() not in running_honeypots:
            running_honeypots.append(hid.get_ip())
        return running_honeypots

    try:
        subprocess.run(f"echo 'bind {hid.get_ip()} system' | honeydctl", shell=True, check=True)
        subprocess.run(f"echo 'set {hid.get_ip()} ethernet \"{hid.get_mac()}\"' | honeydctl", shell=True, check=True)
        if services:
            for service in services:
                if service in config['whitelist_ports']:
                    subprocess.run(f"echo 'add {hid.get_ip()} tcp port {service} \"sh /home/efseven/TFG-3/scripts/service.sh $ipsrc $sport $ipdst $dport\"' | honeydctl", 
                                   shell=True, check=True)
        time.sleep(1)
        print(f"Honeypot {hid.get_ip()} launched.")
        hid.set_status('offline')
        running_honeypots.append(hid.get_ip())
        insert_or_update_honeypot_log(hid.get_ip(), hid.get_mac(), None)
        update_honeypot_status(hid.get_ip(), "online")
        return running_honeypots
    except subprocess.CalledProcessError as e:
        print(f"Error launching the honeypot: {e}")

    return running_honeypots

def stop_honeypot(honeypot_ip):
    # Verifica si el honeypot ya está lanzado
    if check_honeypot(honeypot_ip):
        try:
            subprocess.run(f"echo 'delete {honeypot_ip}' | honeydctl", shell=True, check=True)
            time.sleep(1)
            while check_honeypot(honeypot_ip):
                subprocess.run(f"echo 'delete {honeypot_ip}' | honeydctl", shell=True, check=True)
            print(f"Honeypot {honeypot_ip} tumbado correctamente")
            update_honeypot_status(honeypot_ip, "offline")  # Actualiza el estado a 'offline'
        except subprocess.CalledProcessError as e:
            print(f"Error al tumbar el honeypot: {e}")
