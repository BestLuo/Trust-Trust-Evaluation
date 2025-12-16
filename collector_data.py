import time
import psutil
import pandas as pd
import argparse
import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP


INTERFACE = "br0"
OUTPUT_FILE = "switch_trust_dataset.csv"


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

def collect_data(label, duration_seconds=60):
    global traffic_stats
    threading.Thread(target=start_sniffing, daemon=True).start()
    print(f"collect start | Label: {label} | Time: {duration_seconds}s")
    
    data_rows = []
    net_io_start = psutil.net_io_counters(pernic=True)[INTERFACE]
    
    try:
        for i in range(duration_seconds):
            time.sleep(1)
            net_io_end = psutil.net_io_counters(pernic=True)[INTERFACE]
            
            # 1. Physical layer features
            bytes_in = net_io_end.bytes_recv - net_io_start.bytes_recv
            bytes_out = net_io_end.bytes_sent - net_io_start.bytes_sent
            packets_in = net_io_end.packets_recv - net_io_start.packets_recv
            packets_out = net_io_end.packets_sent - net_io_start.packets_sent
            net_io_start = net_io_end
            
            # 2. Resource layer features
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory().percent
            
            # 3. Protocol layer features (Scapy)
            with lock:
                sizes = traffic_stats["packet_sizes"]
                avg_size = sum(sizes) / len(sizes) if sizes else 0
                total_pkts = len(sizes) if len(sizes) > 0 else 1
                
                # === Key feature calculation ===
                # ARP ratio: Extremely high during spoofing attacks
                arp_ratio = traffic_stats["arp_count"] / total_pkts
                
                # TCP ratio
                tcp_c = traffic_stats["tcp_count"]
                if tcp_c > 0:
                    syn_ratio = traffic_stats["syn_count"] / tcp_c # This value is high for DoS and blasting
                    psh_ratio = traffic_stats["psh_count"] / tcp_c # High during SSH interaction and low during blasting
                else:
                    syn_ratio = 0
                    psh_ratio = 0
                
                # Port divergence: High (near 1.0) during scanning, low during normal
                total_l4 = traffic_stats["tcp_count"] + traffic_stats["udp_count"]
                port_div = len(traffic_stats["dst_ports"]) / total_l4 if total_l4 > 0 else 0
                

                row = {
                    "cpu_usage": cpu, "mem_usage": mem,
                    "bytes_in": bytes_in, "bytes_out": bytes_out,
                    "packets_in": packets_in, "packets_out": packets_out,
                    "tcp_count": traffic_stats["tcp_count"],
                    "udp_count": traffic_stats["udp_count"],
                    "icmp_count": traffic_stats["icmp_count"],
                    "arp_count": traffic_stats["arp_count"],
                    "arp_ratio": arp_ratio,       
                    "syn_count": traffic_stats["syn_count"],
                    "syn_ratio": syn_ratio,       
                    "psh_count": traffic_stats["psh_count"],
                    "psh_ratio": psh_ratio,       
                    "port_diversity": port_div,   
                    "ack_count": traffic_stats["ack_count"],
                    "fin_count": traffic_stats["fin_count"],
                    "rst_count": traffic_stats["rst_count"],
                    "fragmented_count": traffic_stats["fragmented_count"],
                    "unique_src_ips": len(traffic_stats["src_ips"]),
                    "unique_dst_ports": len(traffic_stats["dst_ports"]),
                    "avg_packet_size": avg_size,
                    "label": label
                }
                
                
                traffic_stats = {
                    "tcp_count": 0, "udp_count": 0, "icmp_count": 0, "arp_count": 0,
                    "syn_count": 0, "ack_count": 0, "fin_count": 0, "rst_count": 0, "psh_count": 0,
                    "fragmented_count": 0, "packet_sizes": [],
                    "src_ips": set(), "dst_ports": set()
                }

            data_rows.append(row)
            if i % 5 == 0:
                print(f"[{i}s] Label:{label} | SYN%:{row['syn_ratio']:.2f} | PSH%:{row['psh_ratio']:.2f} | PortDiv:{row['port_diversity']:.2f}")

    except KeyboardInterrupt: pass
    
    
    df = pd.DataFrame(data_rows)
    df.to_csv(OUTPUT_FILE, mode='a', header=not pd.io.common.file_exists(OUTPUT_FILE), index=False)
    print(f"datas save success，lines: {len(df)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", type=int, required=True)
    parser.add_argument("--time", type=int, default=60)
    args = parser.parse_args()
    collect_data(args.label, args.time)
