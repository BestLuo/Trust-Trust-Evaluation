import time
import psutil
import requests
import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP

INTERFACE = "br0"
API_URL = "http://127.0.0.1:8000/predict"

traffic_stats = {
    "tcp_count": 0, "udp_count": 0, "icmp_count": 0, "arp_count": 0,
    "syn_count": 0, "ack_count": 0, "fin_count": 0, "rst_count": 0, "psh_count": 0,
    "fragmented_count": 0, "packet_sizes": [],
    "src_ips": set(), "dst_ports": set()
}
lock = threading.Lock()

def packet_callback(packet):
    global traffic_stats
    with lock:
        traffic_stats["packet_sizes"].append(len(packet))
        if ARP in packet:
            traffic_stats["arp_count"] += 1
            return
        if IP in packet:
            traffic_stats["src_ips"].add(packet[IP].src)
            if packet[IP].flags == 'MF' or packet[IP].frag > 0:
                traffic_stats["fragmented_count"] += 1
            if TCP in packet:
                traffic_stats["tcp_count"] += 1
                traffic_stats["dst_ports"].add(packet[TCP].dport)
                flags = packet[TCP].flags
                if 'S' in flags: traffic_stats["syn_count"] += 1
                if 'A' in flags: traffic_stats["ack_count"] += 1
                if 'F' in flags: traffic_stats["fin_count"] += 1
                if 'R' in flags: traffic_stats["rst_count"] += 1
                if 'P' in flags: traffic_stats["psh_count"] += 1
            elif UDP in packet:
                traffic_stats["udp_count"] += 1
                if packet.haslayer(UDP): traffic_stats["dst_ports"].add(packet[UDP].dport)
            elif ICMP in packet:
                traffic_stats["icmp_count"] += 1

def start_sniffing():
    sniff(iface=INTERFACE, prn=packet_callback, store=0)

def main():
    global traffic_stats
    print(f"Agent running...")
    threading.Thread(target=start_sniffing, daemon=True).start()
    net_io_start = psutil.net_io_counters(pernic=True)[INTERFACE]

    while True:
        try:
            time.sleep(1)
            net_io_end = psutil.net_io_counters(pernic=True)[INTERFACE]
            
            
            bytes_in = net_io_end.bytes_recv - net_io_start.bytes_recv
            bytes_out = net_io_end.bytes_sent - net_io_start.bytes_sent
            packets_in = net_io_end.packets_recv - net_io_start.packets_recv
            packets_out = net_io_end.packets_sent - net_io_start.packets_sent
            net_io_start = net_io_end
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory().percent

            with lock:
                sizes = traffic_stats["packet_sizes"]
                avg_size = sum(sizes) / len(sizes) if sizes else 0
                total_pkts = len(sizes) if len(sizes) > 0 else 1
                
                
                arp_ratio = traffic_stats["arp_count"] / total_pkts
                tcp_c = traffic_stats["tcp_count"]
                syn_ratio = traffic_stats["syn_count"] / tcp_c if tcp_c > 0 else 0
                psh_ratio = traffic_stats["psh_count"] / tcp_c if tcp_c > 0 else 0
                
                total_l4 = traffic_stats["tcp_count"] + traffic_stats["udp_count"]
                port_div = len(traffic_stats["dst_ports"]) / total_l4 if total_l4 > 0 else 0

                payload = {
                    "cpu_usage": float(cpu), "mem_usage": float(mem),
                    "bytes_in": float(bytes_in), "bytes_out": float(bytes_out),
                    "packets_in": float(packets_in), "packets_out": float(packets_out),
                    "tcp_count": traffic_stats["tcp_count"],
                    "udp_count": traffic_stats["udp_count"],
                    "icmp_count": traffic_stats["icmp_count"],
                    "arp_count": traffic_stats["arp_count"],
                    "arp_ratio": float(arp_ratio),
                    "syn_count": traffic_stats["syn_count"],
                    "syn_ratio": float(syn_ratio),
                    "psh_count": traffic_stats["psh_count"],
                    "psh_ratio": float(psh_ratio),
                    "port_diversity": float(port_div),
                    "ack_count": traffic_stats["ack_count"],
                    "fin_count": traffic_stats["fin_count"],
                    "rst_count": traffic_stats["rst_count"],
                    "fragmented_count": traffic_stats["fragmented_count"],
                    "unique_src_ips": len(traffic_stats["src_ips"]),
                    "unique_dst_ports": len(traffic_stats["dst_ports"]),
                    "avg_packet_size": float(avg_size)
                }
                
                
                traffic_stats = {
                    "tcp_count": 0, "udp_count": 0, "icmp_count": 0, "arp_count": 0,
                    "syn_count": 0, "ack_count": 0, "fin_count": 0, "rst_count": 0, "psh_count": 0,
                    "fragmented_count": 0, "packet_sizes": [],
                    "src_ips": set(), "dst_ports": set()
                }

            try:
                response = requests.post(API_URL, json=payload, timeout=0.5)
                if response.status_code == 200:
                    res = response.json()
                    lvl = res['trust_level']
                    color = "\033[92m" if lvl == 3 else "\033[91m"
                    
                    print(f"[{time.strftime('%H:%M:%S')}] level: {color}{lvl}\033[0m ({res['description']}) | PSH%: {payload['psh_ratio']:.2f} | SYN%: {payload['syn_ratio']:.2f}")
            except Exception:
                pass

        except KeyboardInterrupt: break

if __name__ == "__main__":
    main()
