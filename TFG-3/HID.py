class HID:
    def __init__(self, ip, mac, services, status):
        self.ip = ip
        self.mac = mac
        self.services = services
        self.status = status

    def set_services(self, services):
        self.services = services

    def set_status(self, status):
        self.onlistatusne = status

    def get_ip(self):
        return self.ip

    def get_mac(self):
        return self.mac

    def get_services(self):
        return self.services

    def is_online(self):
        return self.status == 'online'

    def print(self):
        return f"{self.ip} - {self.mac}"

    def equals(self, other):
        return other.get_ip() == self.get_ip() and other.get_mac() == self.get_mac()
