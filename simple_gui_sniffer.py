import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, ARP, Raw, wrpcap, rdpcap
import time
import json
import numpy as np
import joblib  # Use joblib to load the scikit-learn model and scaler
import os


class PacketSnifferApp:
    def __init__(self, master):
        self.master = master
        master.title("Python Packet Sniffer")
        master.geometry("450x480")
        master.configure(bg="#2E2E2E")

        self.sniffing = False
        self.packets = []
        self.packet_count = 0
        self.total_bytes = 0
        self.protocol_stats = {
            "Ethernet": 0, "IP": 0, "TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "Other": 0
        }

        # Packet storage for export, including extracted features
        self.export_packets_data = []

        self.create_widgets()

        # --- Machine Learning Model Loading ---
        self.model = None
        self.scaler = None
        try:
            # Load the pre-trained KNN model and the scaler
            self.model = joblib.load('network_ids_knn_model.joblib')
            self.scaler = joblib.load('data_scaler.joblib')
            self.status_label.config(text="Status: Model and Scaler loaded successfully. Ready.")
            print("K-Nearest Neighbors model and scaler loaded.")
        except FileNotFoundError as e:
            self.status_label.config(text=f"Status: Error loading model or scaler: {e}. Running without ML detection.")
            messagebox.showwarning("Model Load Error",
                                   f"Could not load network_ids_knn_model.joblib or data_scaler.joblib: {e}\nML detection will be disabled.")
        except Exception as e:
            self.status_label.config(text=f"Status: An unexpected error occurred: {e}. Running without ML detection.")
            messagebox.showerror("Model Load Error",
                                 f"An unexpected error occurred loading ML files: {e}")

    def create_widgets(self):
        # Configure a custom style for smaller fonts
        style = ttk.Style()
        style.configure("Small.TLabel", font=("Arial", 8))
        style.configure("TLabelFrame.Label", font=("Arial", 9, "bold"))

        # --- Top Frame for Interface, Buttons, and Alerts ---
        top_frame = ttk.Frame(self.master, padding="2")
        top_frame.pack(side="top", fill="x", padx=2, pady=2)
        top_frame.columnconfigure(1, weight=1)
        top_frame.columnconfigure(3, weight=1)

        # Network Interface Selection and Alert Keyword on the same row for compactness
        ttk.Label(top_frame, text="Interface:").grid(row=0, column=0, padx=(2, 1), pady=1, sticky="w")
        self.interface_var = tk.StringVar()
        self.interface_dropdown = ttk.Combobox(top_frame, textvariable=self.interface_var, width=15)
        self.interface_dropdown.grid(row=0, column=1, padx=(0, 2), pady=1, sticky="ew")
        self.interface_dropdown['values'] = self.get_interfaces()
        if self.interface_dropdown['values']:
            self.interface_dropdown.set(self.interface_dropdown['values'][0])

        ttk.Label(top_frame, text="Alert Keyword:").grid(row=0, column=2, padx=(2, 1), pady=1, sticky="w")
        self.alert_keyword_var = tk.StringVar(value="sensitive")
        ttk.Entry(top_frame, textvariable=self.alert_keyword_var, width=15).grid(row=0, column=3, padx=(0, 2), pady=1,
                                                                                 sticky="ew")

        # Buttons
        button_frame = ttk.Frame(top_frame)
        button_frame.grid(row=1, column=0, columnspan=4, padx=2, pady=1, sticky="ew")
        button_frame.columnconfigure(0, weight=1)
        button_frame.columnconfigure(1, weight=1)
        button_frame.columnconfigure(2, weight=1)
        button_frame.columnconfigure(3, weight=1)

        self.start_button = ttk.Button(button_frame, text="Start", command=self.start_sniffing)
        self.start_button.grid(row=0, column=0, sticky="ew", padx=1)

        self.stop_button = ttk.Button(button_frame, text="Stop", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=1, sticky="ew", padx=1)

        self.export_button = ttk.Button(button_frame, text="Export", command=self.export_packets)
        self.export_button.grid(row=0, column=2, sticky="ew", padx=1)

        self.import_pcap_button = ttk.Button(button_frame, text="Import", command=self.import_pcap)
        self.import_pcap_button.grid(row=0, column=3, sticky="ew", padx=1)

        # Status Bar
        self.status_label = ttk.Label(self.master, text="Status: Ready", relief="sunken", anchor="w")
        self.status_label.pack(side="bottom", fill="x", ipady=1)

        # --- Main Content Area (Paned Window for resizable sections) ---
        main_pane = ttk.Panedwindow(self.master, orient=tk.HORIZONTAL)
        main_pane.pack(fill="both", expand=True, padx=2, pady=2)

        # Left Frame: Filters, Stats, Active Alerts
        left_frame = ttk.Frame(main_pane, padding="2")
        main_pane.add(left_frame, weight=1)

        # Packet Filters
        filter_frame = ttk.LabelFrame(left_frame, text="Packet Filters", padding="2")
        filter_frame.pack(fill="x", pady=2)
        filter_frame.columnconfigure(1, weight=1)

        ttk.Label(filter_frame, text="Source IP:").grid(row=0, column=0, padx=(2, 1), pady=1, sticky="w")
        self.src_ip_filter = ttk.Entry(filter_frame)
        self.src_ip_filter.grid(row=0, column=1, padx=(0, 2), pady=1, sticky="ew")

        ttk.Label(filter_frame, text="Destination IP:").grid(row=1, column=0, padx=(2, 1), pady=1, sticky="w")
        self.dst_ip_filter = ttk.Entry(filter_frame)
        self.dst_ip_filter.grid(row=1, column=1, padx=(0, 2), pady=1, sticky="ew")

        ttk.Label(filter_frame, text="Protocol:").grid(row=2, column=0, padx=(2, 1), pady=1, sticky="w")
        self.proto_filter = ttk.Entry(filter_frame)
        self.proto_filter.grid(row=2, column=1, padx=(0, 2), pady=1, sticky="ew")

        # Active Alerts Display
        alerts_frame = ttk.LabelFrame(left_frame, text="Active Alerts", padding="2")
        alerts_frame.pack(fill="both", expand=True, pady=2)
        self.alerts_text = scrolledtext.ScrolledText(alerts_frame, wrap=tk.WORD, height=6, bg="#1E1E1E", fg="#FFD700",
                                                     insertbackground="white")
        self.alerts_text.pack(fill="both", expand=True)
        self.alerts_text.insert(tk.END,
                                 "(Alerts typically trigger on plaintext data, won't work on encrypted traffic like HTTPS)\n")
        self.alerts_text.configure(state='disabled')

        # Protocol Statistics
        stats_frame = ttk.LabelFrame(left_frame, text="Protocol Statistics", padding="2")
        stats_frame.pack(fill="x", pady=2)
        stats_frame.columnconfigure(1, weight=1)

        self.stats_labels = {}
        row = 0
        for proto in ["Total", "Ethernet", "IP", "TCP", "UDP", "ICMP", "ARP"]:
            ttk.Label(stats_frame, text=f"{proto} Packets:", style="Small.TLabel").grid(row=row, column=0, padx=2, pady=1, sticky="w")
            self.stats_labels[f"{proto}_pkts"] = ttk.Label(stats_frame, text="0", style="Small.TLabel")
            self.stats_labels[f"{proto}_pkts"].grid(row=row, column=1, padx=2, pady=1, sticky="w")
            if proto in ["Total", "Ethernet", "IP", "TCP", "UDP", "ICMP", "ARP"]:
                ttk.Label(stats_frame, text=f"{proto} Bytes:", style="Small.TLabel").grid(row=row, column=2, padx=2, pady=1, sticky="w")
                self.stats_labels[f"{proto}_bytes"] = ttk.Label(stats_frame, text="0 KB", style="Small.TLabel")
                self.stats_labels[f"{proto}_bytes"].grid(row=row, column=3, padx=2, pady=1, sticky="w")
            row += 1

        self.update_stats_display()

        # Right Frame: Captured Packets Display
        right_frame = ttk.Frame(main_pane, padding="2")
        main_pane.add(right_frame, weight=2)

        ttk.Label(right_frame, text="Captured Packets:").pack(side="top", fill="x", pady=2)
        self.packet_list_text = scrolledtext.ScrolledText(right_frame, wrap=tk.WORD, bg="#1E1E1E", fg="white",
                                                         insertbackground="white")
        self.packet_list_text.pack(fill="both", expand=True)
        self.packet_list_text.configure(state='disabled')

    def get_interfaces(self):
        try:
            from scapy.all import get_if_list
            return get_if_list()
        except Exception:
            return ["eth0", "wlan0", "lo", "\\Device\\NPF_{...}"]

    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.status_label.config(text="Status: Sniffing...")

            self.packets = []
            self.packet_count = 0
            self.total_bytes = 0
            self.protocol_stats = {k: 0 for k in self.protocol_stats}
            self.export_packets_data = []

            self.packet_list_text.configure(state='normal')
            self.packet_list_text.delete(1.0, tk.END)
            self.packet_list_text.configure(state='disabled')
            self.alerts_text.configure(state='normal')
            self.alerts_text.delete(1.0, tk.END)
            self.alerts_text.insert(tk.END,
                                     "(Alerts typically trigger on plaintext data, won't work on encrypted traffic like HTTPS)\n")
            self.alerts_text.configure(state='disabled')
            self.update_stats_display()

            self.sniff_thread = threading.Thread(target=self._sniff_packets, daemon=True)
            self.sniff_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_label.config(text="Status: Sniffer stopped.")

    def get_bpf_filter(self):
        src_ip = self.src_ip_filter.get().strip()
        dst_ip = self.dst_ip_filter.get().strip()
        protocol = self.proto_filter.get().strip().lower()
        filters = []
        if src_ip:
            filters.append(f"src host {src_ip}")
        if dst_ip:
            filters.append(f"dst host {dst_ip}")
        if protocol:
            if protocol in ["tcp", "udp", "icmp", "arp"]:
                filters.append(protocol)
            elif protocol == "ip":
                filters.append("ip")
            else:
                filters.append(protocol)
        return " and ".join(filters) if filters else ""

    def _sniff_packets(self):
        interface = self.interface_var.get()
        bpf_filter = self.get_bpf_filter()
        try:
            sniff(iface=interface, prn=self._process_packet, store=0, stop_filter=lambda x: not self.sniffing,
                  filter=bpf_filter)
        except Exception as e:
            self.master.after(0, lambda: messagebox.showerror("Sniffing Error",
                                                              f"Error sniffing on {interface}: {e}\n\nPlease check interface name and permissions (run as admin/root)."))
            self.master.after(0, self.stop_sniffing)

    def _process_packet(self, packet):
        if not self.sniffing:
            return
        self.packet_count += 1
        self.total_bytes += len(packet)

        self.protocol_stats["Ethernet"] += 1
        if packet.haslayer(IP):
            self.protocol_stats["IP"] += 1
            if packet.haslayer(TCP):
                self.protocol_stats["TCP"] += 1
            elif packet.haslayer(UDP):
                self.protocol_stats["UDP"] += 1
            elif packet.haslayer(ICMP):
                self.protocol_stats["ICMP"] += 1
            else:
                self.protocol_stats["Other"] += 1
        elif packet.haslayer(ARP):
            self.protocol_stats["ARP"] += 1
        else:
            if not packet.haslayer(IP) and not packet.haslayer(ARP):
                self.protocol_stats["Other"] += 1

        features = self._extract_dl_features(packet)

        prediction_label = "Normal"
        prediction_confidence = "N/A"

        if self.model and self.scaler:
            try:
                # Scale the features
                features_scaled = self.scaler.transform(features.reshape(1, -1))
                # Get the prediction from the KNN model
                prediction = self.model.predict(features_scaled)
                # The KNN model returns a label directly (0 or 1)
                prediction_label = "Attack" if prediction[0] == 1 else "Normal"
            except Exception as e:
                prediction_label = f"ML Error: {e}"
                print(f"Error during ML prediction: {e}")

        # Prepare packet data for export
        pkt_summary = packet.summary()
        pkt_info = {
            "raw_hex": bytes(packet).hex(),
            "timestamp": time.time(),
            "summary": pkt_summary,
            "features": features.tolist(),
            "ml_prediction": prediction_label,
            "ml_confidence": prediction_confidence
        }

        if packet.haslayer(IP):
            pkt_info["srcIp"] = packet[IP].src
            pkt_info["dstIp"] = packet[IP].dst
            pkt_info["protocol"] = packet[IP].proto
            if packet.haslayer(TCP):
                pkt_info["srcPort"] = packet[TCP].sport
                pkt_info["dstPort"] = packet[TCP].dport
                pkt_info["protocol"] = "TCP"
            elif packet.haslayer(UDP):
                pkt_info["srcPort"] = packet[UDP].sport
                pkt_info["dstPort"] = packet[UDP].dport
                pkt_info["protocol"] = "UDP"
            elif packet.haslayer(ICMP):
                pkt_info["protocol"] = "ICMP"
        elif packet.haslayer(ARP):
            pkt_info["protocol"] = "ARP"
            pkt_info["srcIp"] = packet[ARP].psrc
            pkt_info["dstIp"] = packet[ARP].pdst

        if packet.haslayer(Raw):
            try:
                pkt_info["rawData"] = packet[Raw].load.decode('utf-8', errors='ignore')
            except:
                pkt_info["rawData"] = packet[Raw].load.hex()
        else:
            pkt_info["rawData"] = ""

        self.export_packets_data.append(pkt_info)
        self.master.after(0, self.update_gui_display, pkt_summary, prediction_label)
        self.master.after(0, self.check_for_alerts, packet)

    def update_gui_display(self, pkt_summary, ml_prediction_label):
        self.packet_list_text.configure(state='normal')
        self.packet_list_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] [{ml_prediction_label}] {pkt_summary}\n")
        self.packet_list_text.see(tk.END)
        self.packet_list_text.configure(state='disabled')
        self.update_stats_display()

    def update_stats_display(self):
        self.stats_labels["Total_pkts"].config(text=f"{self.packet_count}")
        self.stats_labels["Total_bytes"].config(text=f"{self.total_bytes / 1024:.2f} KB")

        for proto in ["Ethernet", "IP", "TCP", "UDP", "ICMP", "ARP"]:
            if f"{proto}_pkts" in self.stats_labels:
                self.stats_labels[f"{proto}_pkts"].config(text=f"{self.protocol_stats.get(proto, 0)}")

            if proto == "Ethernet":
                self.stats_labels["Ethernet_bytes"].config(text=f"{self.total_bytes / 1024:.2f} KB")
            elif proto == "IP" and "IP_bytes" in self.stats_labels:
                ip_bytes_estimate = self.protocol_stats['IP'] * 60
                self.stats_labels["IP_bytes"].config(text=f"{ip_bytes_estimate / 1024:.2f} KB")
            elif proto == "TCP" and "TCP_bytes" in self.stats_labels:
                tcp_bytes_estimate = self.protocol_stats['TCP'] * 60
                self.stats_labels["TCP_bytes"].config(text=f"{tcp_bytes_estimate / 1024:.2f} KB")
            elif proto == "UDP" and "UDP_bytes" in self.stats_labels:
                udp_bytes_estimate = self.protocol_stats['UDP'] * 50
                self.stats_labels["UDP_bytes"].config(text=f"{udp_bytes_estimate / 1024:.2f} KB")
            elif proto == "ICMP" and "ICMP_bytes" in self.stats_labels:
                icmp_bytes_estimate = self.protocol_stats['ICMP'] * 40
                self.stats_labels["ICMP_bytes"].config(text=f"{icmp_bytes_estimate / 1024:.2f} KB")
            elif proto == "ARP" and "ARP_bytes" in self.stats_labels:
                arp_bytes_estimate = self.protocol_stats['ARP'] * 42
                self.stats_labels["ARP_bytes"].config(text=f"{arp_bytes_estimate / 1024:.2f} KB")

    def check_for_alerts(self, packet):
        keyword = self.alert_keyword_var.get().strip().lower()
        if not keyword:
            return

        alert_message = None

        if packet.haslayer(Raw):
            payload = packet[Raw].load
            try:
                decoded_payload = payload.decode('utf-8', errors='ignore')
                if keyword in decoded_payload.lower():
                    alert_message = f"Keyword '{keyword}' found in payload from {packet.summary()}"
            except UnicodeDecodeError:
                pass

        if packet.haslayer(TCP) and packet[TCP].flags == 'S':
            if packet[TCP].dport > 1024 and packet[TCP].dport not in [8080, 8443]:
                if alert_message:
                    alert_message += f"\nPotential port scan to non-standard port: {packet[TCP].dport}"
                else:
                    alert_message = f"Potential port scan to non-standard port: {packet[TCP].dport} from {packet[IP].src if packet.haslayer(IP) else 'N/A'}"

        if alert_message:
            self.master.after(0, self._display_alert, message_prefix="Traditional Alert", message=alert_message)

    def _display_alert(self, message_prefix, message):
        self.alerts_text.configure(state='normal')
        self.alerts_text.insert(tk.END, f"{message_prefix}: {message}\n")
        self.alerts_text.see(tk.END)
        self.alerts_text.configure(state='disabled')

    def export_packets(self):
        if not self.export_packets_data:
            messagebox.showinfo("Export", "No packets to export.")
            return

        response = messagebox.askyesno("Export Option",
                                       "Do you want to export as a PCAP file? Click 'No' to export as JSON.")

        if response:
            file_path = filedialog.asksaveasfilename(defaultextension=".pcap",
                                                     filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
            if file_path:
                try:
                    scapy_packets_to_export = []
                    for pkt_info in self.export_packets_data:
                        try:
                            scapy_packets_to_export.append(Ether(bytes.fromhex(pkt_info['raw_hex'])))
                        except Exception as e:
                            print(f"Error reconstructing packet from hex for PCAP export: {e}")
                            continue
                    wrpcap(file_path, scapy_packets_to_export)
                    messagebox.showinfo("Export Success", f"Packets exported to {file_path}")
                except Exception as e:
                    messagebox.showerror("Export Error", f"Failed to export PCAP: {e}")
        else:
            file_path = filedialog.asksaveasfilename(defaultextension=".json",
                                                     filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
            if file_path:
                try:
                    with open(file_path, 'w') as f:
                        json.dump(self.export_packets_data, f, indent=4)
                    messagebox.showinfo("Export Success",
                                         f"Packet data (with features and ML predictions) exported to {file_path}")
                except Exception as e:
                    messagebox.showerror("Export Error", f"Failed to export JSON: {e}")

    def import_pcap(self):
        file_path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
        if file_path:
            try:
                self.status_label.config(text="Status: Importing PCAP...")
                self.export_packets_data = []
                self.packet_list_text.configure(state='normal')
                self.packet_list_text.delete(1.0, tk.END)
                self.packet_list_text.configure(state='disabled')

                self.packet_count = 0
                self.total_bytes = 0
                self.protocol_stats = {k: 0 for k in self.protocol_stats}

                packets = rdpcap(file_path)
                for i, packet in enumerate(packets):
                    features = self._extract_dl_features(packet)
                    pkt_summary = packet.summary()

                    prediction_label = "Normal"
                    prediction_confidence = "N/A"
                    if self.model and self.scaler:
                        try:
                            features_scaled = self.scaler.transform(features.reshape(1, -1))
                            prediction = self.model.predict(features_scaled)
                            prediction_label = "Attack" if prediction[0] == 1 else "Normal"
                        except Exception as e:
                            prediction_label = f"ML Error: {e}"
                            print(f"Error during ML prediction for imported packet: {e}")

                    pkt_info = {
                        "raw_hex": bytes(packet).hex(),
                        "timestamp": time.time(),
                        "summary": pkt_summary,
                        "features": features.tolist(),
                        "ml_prediction": prediction_label,
                        "ml_confidence": prediction_confidence
                    }
                    if packet.haslayer(IP):
                        pkt_info["srcIp"] = packet[IP].src
                        pkt_info["dstIp"] = packet[IP].dst
                        pkt_info["protocol"] = packet[IP].proto
                        if packet.haslayer(TCP):
                            pkt_info["srcPort"] = packet[TCP].sport
                            pkt_info["dstPort"] = packet[TCP].dport
                            pkt_info["protocol"] = "TCP"
                        elif packet.haslayer(UDP):
                            pkt_info["srcPort"] = packet[UDP].sport
                            pkt_info["dstPort"] = packet[UDP].dport
                            pkt_info["protocol"] = "UDP"
                        elif packet.haslayer(ICMP):
                            pkt_info["protocol"] = "ICMP"
                    elif packet.haslayer(ARP):
                        pkt_info["protocol"] = "ARP"
                        pkt_info["srcIp"] = packet[ARP].psrc
                        pkt_info["dstIp"] = packet[ARP].pdst

                    if packet.haslayer(Raw):
                        try:
                            pkt_info["rawData"] = packet[Raw].load.decode('utf-8', errors='ignore')
                        except:
                            pkt_info["rawData"] = packet[Raw].load.hex()
                    else:
                        pkt_info["rawData"] = ""

                    self.export_packets_data.append(pkt_info)
                    self.packet_count += 1
                    self.total_bytes += len(packet)
                    self.protocol_stats["Ethernet"] += 1
                    if packet.haslayer(IP):
                        self.protocol_stats["IP"] += 1
                        if packet.haslayer(TCP):
                            self.protocol_stats["TCP"] += 1
                        elif packet.haslayer(UDP):
                            self.protocol_stats["UDP"] += 1
                        elif packet.haslayer(ICMP):
                            self.protocol_stats["ICMP"] += 1
                        else:
                            self.protocol_stats["Other"] += 1
                    elif packet.haslayer(ARP):
                        self.protocol_stats["ARP"] += 1
                    else:
                        self.protocol_stats["Other"] += 1

                    if i % 50 == 0:
                        self.master.after(0, self.packet_list_text.configure, state='normal')
                        self.master.after(0, self.packet_list_text.insert, tk.END,
                                         f"[{time.strftime('%H:%M:%S')}] [{prediction_label}] {pkt_summary} (Imported)\n")
                        self.master.after(0, self.packet_list_text.see, tk.END)
                        self.master.after(0, self.packet_list_text.configure, state='disabled')
                        self.master.after(0, self.update_stats_display)

                self.master.after(0, self.packet_list_text.configure, state='normal')
                self.master.after(0, self.packet_list_text.insert, tk.END,
                                  f"\n--- Finished importing {len(packets)} packets from {file_path} ---\n")
                self.master.after(0, self.packet_list_text.see, tk.END)
                self.master.after(0, self.packet_list_text.configure, state='disabled')
                self.master.after(0, self.update_stats_display)
                self.status_label.config(text=f"Status: Imported {len(packets)} packets from {file_path}")
                messagebox.showinfo("Import Success", f"Successfully imported {len(packets)} packets from {file_path}")

            except Exception as e:
                messagebox.showerror("Import Error", f"Failed to import PCAP: {e}")
                self.status_label.config(text="Status: Import failed.")

    def _extract_dl_features(self, packet):
        """
        Extracts numerical features from a Scapy packet for deep learning.
        Produces a 69-element numpy array.
        Features:
        1. Packet Length (1 feature)
        2. Protocol Type (5 features: TCP, UDP, ICMP, ARP, Other IP) - One-hot encoded
        3. IP Addresses (2 features: Source IP, Destination IP) - Hashed/Scaled
        4. Port Numbers (2 features: Source Port, Destination Port) - Scaled
        5. TCP Flags (6 features: SYN, ACK, FIN, RST, PSH, URG) - Binary
        6. ICMP Type and Code (2 features)
        7. ARP Opcode (1 feature)
        8. Payload (50 features) - Hashed/Encoded first 50 bytes
        Total features: 1 + 5 + 2 + 2 + 6 + 2 + 1 + 50 = 69
        """
        features = np.zeros(69, dtype=np.float32)

        # 1. Packet Length (Index 0)
        features[0] = len(packet) / 1500.0

        # 2. Protocol Type (Indices 1-5 for one-hot encoding)
        proto_offset = 1
        if packet.haslayer(TCP):
            features[proto_offset] = 1
        elif packet.haslayer(UDP):
            features[proto_offset + 1] = 1
        elif packet.haslayer(ICMP):
            features[proto_offset + 2] = 1
        elif packet.haslayer(ARP):
            features[proto_offset + 3] = 1
        elif packet.haslayer(IP):
            features[proto_offset + 4] = 1

        # 3. IP Addresses (Indices 6-7)
        ip_offset = 6
        if packet.haslayer(IP):
            features[ip_offset] = int(str(packet[IP].src).replace('.', '')) % 100000 / 100000.0
            features[ip_offset + 1] = int(str(packet[IP].dst).replace('.', '')) % 100000 / 100000.0

        # 4. Port Numbers (Indices 8-9)
        port_offset = 8
        if packet.haslayer(TCP):
            features[port_offset] = packet[TCP].sport / 65535.0
            features[port_offset + 1] = packet[TCP].dport / 65535.0
        elif packet.haslayer(UDP):
            features[port_offset] = packet[UDP].sport / 65535.0
            features[port_offset + 1] = packet[UDP].dport / 65535.0

        # 5. TCP Flags (Indices 10-15)
        flags_offset = 10
        if packet.haslayer(TCP):
            flags = packet.getlayer(TCP).flags
            features[flags_offset + 0] = 1 if 'S' in flags else 0  # SYN
            features[flags_offset + 1] = 1 if 'A' in flags else 0  # ACK
            features[flags_offset + 2] = 1 if 'F' in flags else 0  # FIN
            features[flags_offset + 3] = 1 if 'R' in flags else 0  # RST
            features[flags_offset + 4] = 1 if 'P' in flags else 0  # PSH
            features[flags_offset + 5] = 1 if 'U' in flags else 0  # URG

        # 6. ICMP Type and Code (Indices 16-17)
        icmp_offset = 16
        if packet.haslayer(ICMP):
            features[icmp_offset] = packet[ICMP].type / 255.0
            features[icmp_offset + 1] = packet[ICMP].code / 255.0

        # 7. ARP Opcode (Index 18)
        arp_offset = 18
        if packet.haslayer(ARP):
            features[arp_offset] = packet[ARP].op / 10.0

        # 8. Payload (Indices 19-68)
        payload_offset = 19
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            for i in range(min(50, len(payload))):
                features[payload_offset + i] = payload[i] / 255.0

        return features

if __name__ == "__main__":
    # Create the main window
    root = tk.Tk()
    # Create an instance of the app
    app = PacketSnifferApp(root)
    # Start the GUI event loop
    root.mainloop()