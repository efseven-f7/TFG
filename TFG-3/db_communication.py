#!/usr/bin/python3

import datetime
import os
from mysql.connector import pooling, errors, Error
import uuid
import socket
import time

#10.10.10.1, 10.10.10.2, 10.10.10.254 are administrative IP addresses. For testing purposes I exclude them from the network scan.
EXCLUDED_IPS = ["0.0.0.0", "10.10.10.1", "10.10.10.2", "10.10.10.254"]
EXCLUDED_MACS = ["00:00:00:00:00:00"]

honeyd_log = os.path.abspath('logs/honeyd_log.txt')

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

config = {
    'whitelist_connections': [],
    'whitelist_ips': [],
    'whitelist_ports': [],
    'network_range' : '',
    'scan_interval' : 0,
    'port_scan_interval' : 0
}

db_config = {
    'host': 'localhost',
    'user': 'honeyd',
    'password': 'new_password',
    'database': 'honeypots_db',
    'use_pure': True
}

db_pool = pooling.MySQLConnectionPool(
    pool_name="mypool",
    pool_size=20,  # Aumenta el tamaño del pool si es necesario
    pool_reset_session=True,
    **db_config
)

# Obtener la dirección MAC de la propia máquina
LOCAL_MAC = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff)
                     for elements in range(0, 2*6, 8)][::-1])
EXCLUDED_MACS.append(LOCAL_MAC)

# Obtener la dirección IP de la propia máquina y añadirla a las IPs excluidas
LOCAL_IP = get_local_ip()
EXCLUDED_IPS.append(LOCAL_IP)

def get_db_connection():
    for _ in range(3):  # Intentar reconectar 3 veces
        try:
            return db_pool.get_connection()
        except errors.PoolError as e:
            print("Error al obtener la conexión a la base de datos: Pool agotado.", e)
        except errors.Error as e:
            print("Error al obtener la conexión a la base de datos:", e)
        time.sleep(1)  # Espera 1 segundo antes de reintentar
    return None

def get_timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def insert_device_data(ip, mac):
    if mac in EXCLUDED_MACS or ip in EXCLUDED_IPS:
        return

    conn = get_db_connection()
    if not conn:
        return

    try:
        cursor = conn.cursor()
        if check_if_device_exists(ip, mac):
            print(f"El dispositivo {ip} - {mac} ya está registrado en la base de datos.")
            cursor.close()
            conn.close()
            return
        cursor.execute("INSERT INTO devices (ip, mac, status) VALUES (%s, %s, %s)", (ip, mac, 'online'))
        conn.commit()
        cursor.close()
        conn.close()
        print("Datos del dispositivo insertados correctamente.")
    except errors.Error as e:
        print("Error al insertar datos del dispositivo:", e)
        if conn:
            conn.close()

def update_device_status(ip, status):
    if ip in EXCLUDED_IPS:
        return

    conn = get_db_connection()
    if not conn:
        return

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT status FROM devices WHERE ip = %s", (ip,))
        current_status = cursor.fetchone()
        if current_status and current_status[0] != status:
            cursor.execute("UPDATE devices SET status = %s WHERE ip = %s",
                           (status, ip))
            conn.commit()
            print(f"Estado del dispositivo {ip} actualizado a {status}.")
        cursor.close()
        conn.close()
    except errors.Error as e:
        print(f"Error al actualizar el estado del dispositivo {ip}: {e}")
        if conn:
            conn.close()

def insert_or_update_honeypot_log(honeypot_ip, honeypot_mac, log_data):
    if honeypot_mac in EXCLUDED_MACS or honeypot_ip in EXCLUDED_IPS:
        return

    conn = get_db_connection()
    if not conn:
        return

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM devices WHERE ip = %s AND mac = %s", (honeypot_ip, honeypot_mac))
        device = cursor.fetchone()
        if not device:
            cursor.close()
            conn.close()
            print("El dispositivo no se encontró en la base de datos.")
            return
        device_id = device[0]

        cursor.execute("SELECT id FROM honeypot_logs WHERE honeypot_id = %s", (device_id,))
        log = cursor.fetchone()
        
        if log:
            cursor.execute(
                "UPDATE honeypot_logs SET log_file = %s, timestamp = %s, status = %s WHERE id = %s",
                (log_data, get_timestamp(), "online", log[0])
            )
        else:
            cursor.execute(
                "INSERT INTO honeypot_logs (honeypot_id, timestamp, log_file, status) VALUES (%s, %s, %s, %s)",
                (device_id, get_timestamp(), log_data, "online")
            )
        conn.commit()
        cursor.close()
        conn.close()
    except errors.Error as e:
        print("Error al actualizar el log del honeypot:", e)
        if conn:
            conn.close()

def check_if_device_exists(ip, mac):
    conn = get_db_connection()
    if not conn:
        return None

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, services, last_updated, status FROM devices WHERE ip = %s AND mac = %s;", (ip, mac))
        result = cursor.fetchall()
        cursor.close()
        conn.close()
        return result
    except errors.Error as e:
        print("Error al verificar si el dispositivo existe:", e)
        if conn:
            conn.close()
        return None
    
def check_if_alert_exists(ip, port, timestamp):
    conn = get_db_connection()
    if not conn:
        return None

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT ip FROM alerts WHERE ip = %s AND port = %s AND timestamp = %s;", (ip, port, timestamp))
        result = cursor.fetchall()
        cursor.close()
        conn.close()
        return result
    except errors.Error as e:
        print("Error al verificar si la alerta existe:", e)
        if conn:
            conn.close()
        return None

def update_device_services(ip, services):
    conn = get_db_connection()
    if not conn:
        return

    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE devices SET services = %s, last_updated = %s WHERE ip = %s",
            (','.join(str(port) for port in services), get_timestamp(), ip)
        )
        conn.commit()
        cursor.close()
        conn.close()
        print("Servicios del dispositivo actualizados correctamente.")
    except errors.Error as e:
        print("Error al actualizar servicios del dispositivo:", e)
        if conn:
            conn.close()

def get_devices_data():
    conn = get_db_connection()
    if not conn:
        return []

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT ip, mac, services, status FROM devices")
        devices = cursor.fetchall()
        cursor.close()
        conn.close()
        return devices
    except errors.Error as e:
        print("Error al obtener datos de los dispositivos:", e)
        if conn:
            conn.close()
        return []
    
def get_device_data(ip, mac):
    conn = get_db_connection()
    if not conn:
        return []

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT ip, mac, services, status, last_updated FROM devices where ip = %s AND mac = %s", (ip, mac))
        device = cursor.fetchone()
        cursor.close()
        conn.close()
        return device
    except errors.Error as e:
        print("Error al obtener datos de los dispositivos:", e)
        if conn:
            conn.close()
        return []

def get_alert_by_id(alert_id):
    conn = get_db_connection()
    if not conn:
        return None

    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM alerts WHERE id = %s", (alert_id,))
        alert = cursor.fetchone()
        cursor.close()
        conn.close()
        return alert
    except errors.Error as e:
        print("Error retrieving alert by ID:", e)
        if conn:
            conn.close()
        return None

def get_alert_logs(ip, port, timestamp):
    logs = []
    log_path = os.path.abspath("logs/honeyd_serv_log.txt")
    with open(log_path, "r") as file:
        for line in file:
            aux_line = line.split()
            if len(aux_line) > 5 and ip in aux_line and port in aux_line[5]:
                logs.append({'timestamp': timestamp, 'message': line.strip()})
    return logs


def get_honeypots_data():
    conn = get_db_connection()
    if not conn:
        return []

    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT d.ip, d.mac, d.status, h.honeypot_id
            FROM honeypot_logs h
            JOIN devices d ON h.honeypot_id = d.id
            WHERE d.status = 'offline'
        """)
        honeypots = cursor.fetchall()
        cursor.close()
        conn.close()
        return honeypots
    except errors.Error as e:
        print("Error al obtener datos de los honeypots:", e)
        if conn:
            conn.close()
        return []

def get_honeypot_logs(ip, mac):
    logs = []
    with open(honeyd_log, "r") as file:
        for line in file:
            if ip in line or mac in line:
                logs.append(line.strip())
    return logs
    
def update_honeypot_status(ip, status):
    if ip in EXCLUDED_IPS:
        return

    conn = get_db_connection()
    if not conn:
        return

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM devices WHERE ip = %s", (ip,))
        device = cursor.fetchone()
        if not device:
            cursor.close()
            conn.close()
            print(f"El dispositivo con IP {ip} no se encontró en la base de datos.")
            return
        device_id = device[0]
        
        cursor.execute("UPDATE honeypot_logs SET status = %s, timestamp = %s WHERE honeypot_id = %s", 
                       (status, get_timestamp(), device_id))
        conn.commit()
        cursor.close()
        conn.close()
        print(f"Estado del honeypot {ip} actualizado a {status}.")
    except errors.Error as e:
        print(f"Error al actualizar el estado del honeypot {ip}: {e}")
        if conn:
            conn.close()

def get_all_devices():
    conn = get_db_connection()
    if not conn:
        return []

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM devices")
        devices = cursor.fetchall()
        cursor.close()
        conn.close()
        return devices
    except errors.Error as e:
        print("Error al obtener todos los dispositivos:", e)
        if conn:
            conn.close()
        return []

def get_config():
    conn = get_db_connection()
    if not conn:
        print("Error al obtener la conexión")
        return None

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT name, value FROM config")
        result = cursor.fetchall()
        for name, value in result:
            if name in config:
                config[name] = value
        cursor.close()
        conn.close()
    except errors.Error as e:
        print("Error al obtener la configuración:", e)
        if conn:
            conn.close()
    return config

def update_config(config):
    conn = get_db_connection()
    if not conn:
        return
    
    try:
        cursor = conn.cursor()
        for key, value in config.items():
            if key in ['whitelist_connections', 'whitelist_ips', 'whitelist_ports', 'monitored_services'] and isinstance(value, str):
                value = value.split(',')

            # Check if the key already exists in the config table
            cursor.execute("SELECT COUNT(*) FROM config WHERE name = %s", (key,))
            count = cursor.fetchone()[0]
            
            if count > 0:
                # If the key exists, update it
                cursor.execute("UPDATE config SET value = %s WHERE name = %s", (str(value), key))
            else:
                # If the key does not exist, insert it
                cursor.execute("INSERT INTO config (name, value) VALUES (%s, %s)", (key, str(value)))

        conn.commit()
        cursor.close()
        conn.close()
        print("Configuration updated successfully.")
    except errors.Error as e:
        print("Error updating configuration:", e)
        if conn:
            conn.close()

def insert_alert(ip, port, message, timestamp):
    try:
        conn = db_pool.get_connection()
        cursor = conn.cursor()
        query = "INSERT INTO alerts (ip, port, message, timestamp) VALUES (%s, %s, %s, %s)"
        cursor.execute(query, (ip, port, message, timestamp))
        conn.commit()
    except Error as e:
        print(f"Error al insertar la alerta: {e}")
    finally:
        cursor.close()
        conn.close()

def get_alerts():
    try:
        conn = db_pool.get_connection()
        cursor = conn.cursor(dictionary=True)
        query = "SELECT * FROM alerts ORDER BY timestamp DESC"
        cursor.execute(query)
        result = cursor.fetchall()
        return result
    except Error as e:
        print(f"Error al obtener las alertas: {e}")
    finally:
        cursor.close()
        conn.close()