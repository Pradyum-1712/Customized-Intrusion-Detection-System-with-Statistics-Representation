from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

sniff(prn=packet_callback, count=10, iface='en0')  # Replace 'en0' with your interface
def packet_callback(packet):
    if packet.haslayer('IP'):
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        print(f"Source: {src_ip} -> Destination: {dst_ip}")
attack_log = {}

def detect_attack(packet):
    if packet.haslayer('TCP') and packet['TCP'].flags == 'S':
        src_ip = packet['IP'].src
        if src_ip in attack_log:
            attack_log[src_ip] += 1
        else:
            attack_log[src_ip] = 1

        # Raise an alert if more than 20 SYN packets are detected from the same IP in a short time
        if attack_log[src_ip] > 20:
            print(f"[ALERT] Possible SYN flood detected from {src_ip}")
def packet_callback(packet):
    if packet.haslayer('IP'):
        detect_attack(packet)

sniff(prn=packet_callback, count=100, iface='en0')
import logging

logging.basicConfig(filename='ids_alerts.log', level=logging.INFO)

def detect_attack(packet):
    if packet.haslayer('TCP') and packet['TCP'].flags == 'S':
        src_ip = packet['IP'].src
        attack_log[src_ip] = attack_log.get(src_ip, 0) + 1

        if attack_log[src_ip] > 20:
            logging.info(f"[ALERT] SYN flood from {src_ip} at {packet.time}")
            print(f"[ALERT] Possible SYN flood detected from {src_ip}")
import matplotlib.pyplot as plt

def plot_attack_statistics():
    ips = list(attack_log.keys())
    counts = list(attack_log.values())

    plt.bar(ips, counts)
    plt.xlabel('IP Address')
    plt.ylabel('Number of Attacks Detected')
    plt.title('Detected Attacks by IP Address')
    plt.show()

plot_attack_statistics()