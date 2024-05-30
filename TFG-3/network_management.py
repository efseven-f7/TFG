import subprocess

from arp_scanner import get_local_ip

def allow_connections(connections):
    if connections == "['']":
        return
    if isinstance(connections, str):
        connections = connections.strip("[]''").split(',')
    for connection in connections:
        connection = connection.split('-')
        try:
            connection[0] = connection[0].strip("[]'' ")
            connection[1] = connection[1].strip("[]'' ")
            # Command to add an iptables rule
            command1 = [
                'sudo', 'iptables', '-A', 'INPUT', '-s', connection[0], '-d', connection[1], '-j', 'ACCEPT'
            ]
            # Execute the command
            subprocess.run(command1, check=True)
            command2 = [
                'sudo', 'iptables', '-A', 'INPUT', '-s', connection[1], '-d', connection[0], '-j', 'ACCEPT'
            ]
            subprocess.run(command2, check=True)
            command3 = [
                'sudo', 'iptables', '-A', 'OUTPUT', '-s', connection[0], '-d', connection[1], '-j', 'ACCEPT'
            ]
            subprocess.run(command3, check=True)
            command4 = [
                'sudo', 'iptables', '-A', 'OUTPUT', '-s', connection[1], '-d', connection[0], '-j', 'ACCEPT'
            ]
            subprocess.run(command4, check=True)
            command5 = [
                'sudo', 'iptables', '-A', 'FORWARD', '-s', connection[0], '-d', connection[1], '-j', 'ACCEPT'
            ]
            subprocess.run(command5, check=True)
            command6 = [
                'sudo', 'iptables', '-A', 'FORWARD', '-s', connection[1], '-d', connection[0], '-j', 'ACCEPT'
            ]
            subprocess.run(command6, check=True)
            print(f"Successfully connection between {connection[0]} and the {connection[1]}.")
        except subprocess.CalledProcessError as e:
            print(f"Failed to allow the connection between {connection[0]} and the {connection[1]}.")
        except Exception as e:
            print(f"An error occurred: {e}")

def allow_ips(ips):
    if ips == "['']":
        return
    if isinstance(ips, str):
        ips = ips.strip("[]'\" ").split(',')
    for ip in ips:
        ip = ip.strip("[]''\"\" ")
        try:
            # Command to add an iptables rule
            command1 = [
                'sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'ACCEPT'
            ]
            command2 = [
                'sudo', 'iptables', '-A', 'INPUT', '-d', ip, '-j', 'ACCEPT'
            ]
            command3 = [
                'sudo', 'iptables', '-A', 'OUTPUT', '-s', ip, '-j', 'ACCEPT'
            ]
            command4 = [
                'sudo', 'iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'ACCEPT'
            ]
            command5 = [
                'sudo', 'iptables', '-A', 'FORWARD', '-s', ip, '-j', 'ACCEPT'
            ]
            command6 = [
                'sudo', 'iptables', '-A', 'FORWARD', '-d', ip, '-j', 'ACCEPT'
            ]
            # Execute the command
            subprocess.run(command1, check=True)
            subprocess.run(command2, check=True)
            subprocess.run(command3, check=True)
            subprocess.run(command4, check=True)
            subprocess.run(command5, check=True)
            subprocess.run(command6, check=True)
            print(f"Successfully allowed connection to and from {ip}.")
        except subprocess.CalledProcessError as e:
            print(f"Failed to allow the connection from and to {ip}.")
        except Exception as e:
            print(f"An error occurred: {e}")

def allow_ports(ports):
    if ports == "['']":
        return
    if isinstance(ports, str):
        ports = ports.strip("[]'\" ").split(',')
    for port in ports:
        port = port.strip("' ")
        try:
            # Command to add an iptables rule
            command1 = [
                'sudo', 'iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', port, '-j', 'ACCEPT'
            ]
            command2 = [
                'sudo', 'iptables', '-A', 'OUTPUT', '-p', 'tcp', '--dport', port, '-j', 'ACCEPT'
            ]
            command3 = [
                'sudo', 'iptables', '-A', 'FORWARD', '-p', 'tcp', '--dport', port, '-j', 'ACCEPT'
            ] 
            # Execute the command
            subprocess.run(command1, check=True)
            subprocess.run(command2, check=True)
            subprocess.run(command3, check=True)
            print(f"Connection to the {port} allowed.")
        except subprocess.CalledProcessError as e:
            print(f"Failed to allow the port {port}.")
        except Exception as e:
            print(f"An error occurred: {e}")

def flush_iptables():
    try:
        subprocess.run(['sudo', 'iptables', '-F'], check=True)
        subprocess.run(['sudo', 'iptables', '-X'], check=True)
        subprocess.run(['sudo', 'iptables', '-Z'], check=True)
        
        subprocess.run(['sudo', 'iptables', '-P', 'INPUT', 'DROP'], check=True)
        subprocess.run(['sudo', 'iptables', '-P', 'OUTPUT', 'DROP'], check=True)
        subprocess.run(['sudo', 'iptables', '-P', 'FORWARD', 'DROP'], check=True)

        print("All iptables rules have been removed and the default policies have been restored.")
        allow_ips(['127.0.0.1'])
    except subprocess.CalledProcessError as e:
        print(f"Error running iptables: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")