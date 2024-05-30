import ipaddress
import os
import signal
import sys
from flask import Flask, render_template, request, redirect, url_for, jsonify
import datetime
import db_communication as db
from collections import Counter
import controller
import requests
from honeypot_manager import check_honeyd

app = Flask(__name__)

config = db.get_config()
honeyd_log = os.path.abspath('logs/honeyd_log.txt')

@app.route('/config', methods=['GET', 'POST'])
def system_config():
    global config
    if request.method == 'POST':
        config['network_range'] = request.form.get('network_range')
        config['whitelist_connections'] = request.form.get('whitelist_connections').strip()
        config['whitelist_ips'] = request.form.get('whitelist_ips').strip()
        config['whitelist_ports'] = request.form.get('whitelist_ports').strip()
        config['scan_interval'] = int(request.form.get('scan_interval'))
        config['port_scan_interval'] = int(request.form.get('port_scan_interval'))
        db.update_config(config)
        return redirect(url_for('system_config'))
    return render_template('config.html')

@app.route('/monitor')
def system_monitor():
    return render_template('monitor.html')

@app.route('/map')
def map():
    return render_template('map.html')

@app.route('/get_honeyd_activity_data')
def get_honeyd_activity_data():
    timestamps, _ = parse_log_file()
    activity_count = {timestamp.strftime('%Y-%m-%d %H:%M:%S'): count for timestamp, count in timestamps.items()}
    return jsonify(timestamps=list(activity_count.keys()), activity_counts=list(activity_count.values()))

@app.route('/get_devices_data')
def get_devices_data():
    if check_honeyd():
        devices = db.get_devices_data()
        return jsonify(devices)
    return jsonify()

@app.route('/get_honeypots_data')
def get_honeypots_data():
    if check_honeyd():
        honeypots = db.get_honeypots_data()
        return jsonify(honeypots)
    return jsonify()

@app.route('/get_honeyd_events_data')
def get_honeyd_events_data():
    _, event_counts = parse_log_file()
    return jsonify(event_types=list(event_counts.keys()), event_counts=list(event_counts.values()))

@app.route('/get_top_ips')
def get_top_ips():
    top_src_ips, top_dst_ips = get_top_ips_from_logs()
    return jsonify(top_src_ips=top_src_ips, top_dst_ips=top_dst_ips)

@app.route('/get_top_ports_services')
def get_top_ports_services():
    top_ports_services = get_top_ports_services_from_logs()
    return jsonify(top_ports_services=top_ports_services)

@app.route('/get_geolocation_data')
def get_geolocation_data():
    ip_locations = []

    top_src_ips, _ = get_top_ips_from_logs()
    for ip, _ in top_src_ips:
        try:
            response = requests.get(f"https://geolocation-db.com/json/{ip}&position=true").json()
            if response['latitude'] and response['longitude']:
                ip_locations.append({
                    'ip': ip,
                    'latitude': response['latitude'],
                    'longitude': response['longitude']
                })
        except Exception as e:
            print(f"Error getting the location para {ip}: {e}")

    return jsonify(ip_locations=ip_locations)

@app.route('/get_alerts')
def get_alerts():
    alerts = db.get_alerts()
    return jsonify(alerts=alerts)

@app.route('/alert/<int:alert_id>')
def alert_details(alert_id):
    alert = db.get_alert_by_id(alert_id)
    logs = db.get_alert_logs(alert['ip'], alert['port'], alert['timestamp'])
    return render_template('alert_details.html', alert=alert, logs=logs)

@app.route('/alert')
def alert():
    parse_log_file()
    return render_template('alert.html')

@app.route('/honeypot/<ip>/<mac>')
def honeypot_logs(ip, mac):
    logs = db.get_honeypot_logs(ip, mac)
    return render_template('honeypot.html', ip=ip, mac=mac, logs=logs)

def check_network_string(network_string):
    try:
        # Check if it's a valid IP address (IPv4 or IPv6)
        ip = ipaddress.ip_address(network_string)
        print(f"{network_string} is a valid IP address")
        return True
    except ValueError:
        pass

    try:
        # Check if it's a valid network (IPv4 or IPv6)
        network = ipaddress.ip_network(network_string, strict=False)
        if network_string == str(network.network_address):
            print(f"{network_string} is a valid network address")
            return True
        else:
            print(f"{network_string} is a valid network range")
            return True
    except ValueError:
        pass

    return False

def check_config(config):
    if not check_network_string(config['network_range']):
         print("Network range not valid")
         return False
    elif not db.get_db_connection():
         print("Database config not valid")
         return False
    # elif os.path.exists(config['honeyd_conf_file']) and os.path.exists(config['honeyd_log_file']) and os.path.exists(config['honeyd_log_file']):
    #     print("Honeyd file paths are not valid")
    #     return False
    return True

@app.route('/honeyd_status', methods=['GET'])
def honeyd_status():
    is_running = check_honeyd() 
    return jsonify({'isRunning': is_running})

@app.route('/start_system', methods=['POST'])
def start_system():
    # Add code to start the system
    config = db.get_config()

    if check_config(config):
        print("Config verificado correctamente")
        print("System starting.....")
        controller.start_system(config)
    else:
        print("ERROR: Comprobar config")
    return '', 204

@app.route('/stop_system', methods=['POST'])
def stop_system():
    print("Stopping the system....")
    # Add code to stop the system
    controller.stop_system()
    return '', 204

@app.route('/')
def index():
    honeypots = db.get_honeypots_data()
    return render_template('index.html', honeypots=honeypots)

def send_alert(ip, port, timestamp):
    message = f"A device with IP {ip} has connected to the honeypot on port {port}."
    db.insert_alert(ip, port, message, timestamp)
    # print(f"Alert - {timestamp}: {message}")

def parse_log_file():
    timestamps = {}
    event_counts = {
        'tcp': 0,
        'icmp': 0,
        'udp': 0,
        'other': 0
    }

    with open(honeyd_log, 'r') as file:
        for line in file:
            parts = line.split()
            if len(parts) >= 6:
                date_str = parts[0][:10]
                time_str = parts[0][11:19]
                timestamp_str = f"{date_str} {time_str.replace('-', ':', 2)}"
                try:
                    timestamp = datetime.datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                    timestamps[timestamp] = timestamps.get(timestamp, 0) + 1

                    protocol_info = parts[1].split('(')[0].lower()
                    if protocol_info in event_counts:
                        event_counts[protocol_info] += 1
                    else:
                        event_counts['other'] += 1

                    if len(parts) > 6 and protocol_info == 'tcp':
                        dst_port = parts[6].split(':')[0]
                        src_ip = parts[3]
                        if parts[2] == 'S' and not db.check_if_alert_exists(src_ip, dst_port, timestamp):
                            send_alert(src_ip, dst_port, timestamp)

                except ValueError as e:
                    print(f"Error parsing line: {line} - {e}")
                    continue

    return timestamps, event_counts

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def get_top_ips_from_logs():
    src_ips = Counter()
    dst_ips = Counter()
    excluded_network = ipaddress.ip_network("10.10.10.0/24")

    with open(honeyd_log, 'r') as file:
        for line in file:
            parts = line.split()
            if len(parts) >= 6:
                src_ip = parts[3]
                dst_ip = parts[5].split(':')[0]
                if is_valid_ip(src_ip) and not ipaddress.ip_address(src_ip) in excluded_network:
                    src_ips[src_ip] += 1
                if is_valid_ip(dst_ip) and ipaddress.ip_address(dst_ip) in excluded_network:
                    dst_ips[dst_ip] += 1

    top_src_ips = src_ips.most_common(10)
    top_dst_ips = dst_ips.most_common(10)

    return top_src_ips, top_dst_ips

def get_top_ports_services_from_logs():
    ports_services = Counter()

    with open(honeyd_log, 'r') as file:
        for line in file:
            parts = line.split()
            if len(parts) > 6:
                try:
                    protocol_info = parts[1].split('(')[0].lower()
                    dst_port = parts[6].split(':')[0]
                    service = f"{protocol_info}/{dst_port}"
                    ports_services[service] += 1

                except IndexError:
                    print(f"Error parsing line (IndexError): {line}")
                except Exception as e:
                    print(f"Unexpected error parsing line: {line} - {e}")

    top_ports_services = ports_services.most_common(10)

    return top_ports_services

def signal_handler(signal, frame):
    stop_system()
    sys.exit(0)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        if os.getuid() != 0:
            print("Please execute the system as root (sudo)")
            exit(1)
    except Exception as e:
        raise Exception(e)

    app.run(debug=False, threaded=True, port=8000, use_reloader=False)
    