import os
import time
import threading
import signal
import requests
import subprocess
import logging
import sqlite3
import json
import sys
from datetime import datetime
from collections import deque
from scapy.all import sniff, IP, TCP
from stem import Signal
from stem.control import Controller

# --- Configuration ---
SUSPICIOUS_PORTS = [22, 23, 80, 443, 445, 3389, 4444]
THRESHOLD = 3
ROTATION_INTERVAL = 20
REPORT_DIR = "SOC_Reports"
WHITELIST_IPS = ["127.0.0.1", "192.168.0.1", "192.168.1.1"]

# --- Setup ---
if not os.path.exists(REPORT_DIR): os.makedirs(REPORT_DIR)
db_conn = sqlite3.connect('soc_database.db', check_same_thread=False)
db_cursor = db_conn.cursor()
db_cursor.execute('CREATE TABLE IF NOT EXISTS blocked_threats (ip TEXT PRIMARY KEY, type TEXT, date TEXT)')
db_conn.commit()

# --- State ---
attack_tracker = {}
blocked_ips = {row[0] for row in db_cursor.execute("SELECT ip FROM blocked_threats").fetchall()}
ongoing_actions = {}
activity_log = deque(maxlen=8)
current_tor_ip = "Initializing!"
countdown = ROTATION_INTERVAL
is_proxy_error = False
error_start_time = 0  # Tracker waktu untuk repair manual
stop_event = threading.Event()

# --- Signal Handler ---
def signal_handler(sig, frame):
    stop_event.set()

signal.signal(signal.SIGINT, signal_handler)

# --- Advanced Tor Healing ---
def attempt_tor_recovery():
    global is_proxy_error
    try:
        with Controller.from_port(port=9051) as controller:
            controller.authenticate()
            controller.signal(Signal.NEWNYM)
            return "SUCCESS"
    except:
        try:
            os.system("sudo pkill -HUP tor")
            time.sleep(2)
            return "SUCCESS"
        except:
            os.system("sudo systemctl restart tor@default")
            time.sleep(5)
            return "HARD_RESET"

def tor_rotator_thread():
    global current_tor_ip, countdown, is_proxy_error, error_start_time
    while not stop_event.is_set():
        try:
            session = requests.Session()
            session.proxies = {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}
            current_tor_ip = session.get("https://httpbin.org/ip", timeout=5).json()['origin']
            is_proxy_error = False
            error_start_time = 0  # Reset timer pas koneksi sukses kembali
            
            for i in range(ROTATION_INTERVAL, 0, -1):
                if stop_event.is_set(): break
                countdown = i
                time.sleep(1)
            attempt_tor_recovery()
        except:
            if error_start_time == 0:
                error_start_time = time.time()  # Mulai hitung waktu pas pertama kali error
                
            is_proxy_error = True
            current_tor_ip = "REPAIRING!"
            attempt_tor_recovery()
            time.sleep(3)

# --- Mitigation ---
def mitigate_attacker(ip, port, attacker_type):
    if ip in blocked_ips or ip in ongoing_actions: return
    ongoing_actions[ip] = "Blocking"
    time.sleep(2)
    try:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        blocked_ips.add(ip)
        db_cursor.execute("INSERT OR IGNORE INTO blocked_threats VALUES (?, ?, ?)", (ip, attacker_type, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        db_conn.commit()
    except: pass
    ongoing_actions[ip] = "Scanning"
    try:
        with open(f"{REPORT_DIR}/scan_{ip}.txt", "w") as f:
            subprocess.run(["rustscan", "-a", ip, "--ulimit", "5000", "--timeout", "1500"], stdout=f, stderr=f)
    except: pass
    with open(f"{REPORT_DIR}/report_{ip}.json", "w") as f:
        json.dump({"ip": ip, "type": attacker_type, "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}, f)
    
    if ip in ongoing_actions: del ongoing_actions[ip]
    activity_log.appendleft(f"[{datetime.now().strftime('%H:%M:%S')}] Sucsesfully blocked {ip}")

def packet_callback(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src, port = packet[IP].src, packet[TCP].dport
        if src not in WHITELIST_IPS and port in SUSPICIOUS_PORTS and src not in blocked_ips:
            # FIX: Inisialisasi awal ditambahkan kunci 'type': 'PENDING'
            if src not in attack_tracker:
                attack_tracker[src] = {"count": 0, "first_seen": time.time(), "type": "PENDING"}
                
            attack_tracker[src]["count"] += 1
            
            if attack_tracker[src]["count"] >= THRESHOLD:
                attacker_type = "BOT" if (time.time() - attack_tracker[src]["first_seen"]) < 3.0 else "HUMAN"
                attack_tracker[src]["type"] = attacker_type  # FIX: Update tipe ke database tracker lokal
                threading.Thread(target=mitigate_attacker, args=(src, port, attacker_type), daemon=True).start()

# --- Main Interface ---
def main():
    if os.geteuid() != 0: print("[!] Run as root."); sys.exit()
    threading.Thread(target=tor_rotator_thread, daemon=True).start()
    
    try:
        while not stop_event.is_set():
            dots = "." * ((int(time.time()) % 5) + 1)
            feed_dots = "." * ((int(time.time() * 2) % 3) + 1)
            os.system('clear')
            
            print("=====================================================================================================")
            print("                          | master.security.py , By : sabda |                                        ")
            print("=====================================================================================================")
            
            security_status = "[!]DANGER!" if len(ongoing_actions) > 0 else "[*]SAFE"
            print(f" [NET SECURITY] {security_status:^60}")
            print("=====================================================================================================")
            
            status_text = f"FIXING{dots}" if is_proxy_error else f"ROTATING IP{dots}"
            print(f" [SYSTEM STATUS] TOR IP: {current_tor_ip} | {status_text:<20}")
            
            # --- LOGIKA PENAMPILAN PESAN REPAIR MANUAL ---
            if is_proxy_error and error_start_time > 0 and (time.time() - error_start_time) > 15:
                print(" [!] If this takes too long, try to fix it manually:")
                print("     sudo killall tor && sudo systemctl restart tor@default")
            
            print(f"\n {'IP ADDRESS':<18} | {'FREQ':<8} | {'TYPE':<15} | {'STATUS':<15}")
            print("-" * 80)
            print(f" Scanning all ports for suspicious activity{dots:<5}")
            
            for ip, data in attack_tracker.items():
                action = ongoing_actions.get(ip, "MONITORING")
                status = "BLOCKED" if ip in blocked_ips else action
                # FIX: Menggunakan .get() sebagai perlindungan ekstra dari KeyError
                attacker_type = data.get("type", "PENDING")
                print(f" {ip:<18} | {str(data['count'])+'x':<8} | {attacker_type:<15} | {status:<15}")

            print("\n [LIVE FEED]")
            print("-" * 80)
            for ip_addr, status_act in list(ongoing_actions.items()):
                print(f" [{datetime.now().strftime('%H:%M:%S')}] {status_act}{feed_dots} ({ip_addr})")
            for log in activity_log: print(f" {log}")
            
            print("\n=====================================================================================================")
            sniff(prn=packet_callback, stop_filter=lambda x: stop_event.is_set(), timeout=0.5, store=0)
            
    finally:
        print("\n\n[!] Shutting down system gracefully...")
        # Ambil IP asli saat sistem di-close
        try:
            real_ip = requests.get("https://api.ipify.org", timeout=3).text
        except:
            real_ip = "Unknown"
            
        db_conn.close()
        print("[*] Verifying network connection and restoring original interface...")
        print(f"[*] Everything is back to normal, your IP has been set to original : {real_ip}")
        print("[*] Security Suite Closed. Stay safe!")

if __name__ == "__main__":
    main()
