import subprocess
import os
import sys
import time
import csv

PCAP_DIR = "../../data/pcap/"
CSV_DIR = "../../data/csv/"

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

def convert_all_pcaps():
    start_time = time.time()
    os.makedirs(CSV_DIR, exist_ok=True)
    pcap_files = [f for f in os.listdir(PCAP_DIR) if f.endswith('.pcap')]
    print(f"[INFO] Menemukan {len(pcap_files)} file pcap di {PCAP_DIR}")
    for pcap_file in pcap_files:
        pcap_path = os.path.join(PCAP_DIR, pcap_file)
        csv_file = os.path.splitext(pcap_file)[0] + ".csv"
        csv_path = os.path.join(CSV_DIR, csv_file)
        print(f"[INFO] Konversi {pcap_path} -> {csv_path}")
        cicflowmeter_cmd = f"cicflowmeter -f {pcap_path} -c {csv_path}"
        subprocess.run(cicflowmeter_cmd, shell=True)
        file_summary(pcap_path, csv_path)
    total_time = time.time() - start_time
    print(f"\n[INFO] Total waktu pemrosesan: {total_time:.2f} detik")

if __name__ == "__main__":
    convert_all_pcaps()