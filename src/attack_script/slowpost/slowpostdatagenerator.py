import subprocess
import os
import time
import csv
import sys

PCAP_DIR = "../../data/pcap/"
CSV_DIR = "../../data/csv/"
PCAP_NAME = "slowpost.pcap"
CSV_NAME = "slowpost.csv"
INTERFACE = "ens18"

def file_summary(pcap_file, csv_file):
    pcap_size = os.path.getsize(pcap_file) / (1024 * 1024) if os.path.exists(pcap_file) else 0
    csv_size = os.path.getsize(csv_file) / (1024 * 1024) if os.path.exists(csv_file) else 0
    csv_rows = 0
    if os.path.exists(csv_file):
        with open(csv_file, 'r') as f:
            reader = csv.reader(f)
            csv_rows = sum(1 for _ in reader) - 1  # minus header
    print(f"[SUMMARY] {os.path.basename(pcap_file)}: {pcap_size:.2f} MB")
    print(f"[SUMMARY] {os.path.basename(csv_file)}: {csv_size:.2f} MB, {csv_rows} baris/entry")

def run_tcpdump_and_convert(duration):
    os.makedirs(CSV_DIR, exist_ok=True)
    os.makedirs(PCAP_DIR, exist_ok=True)
    pcap_path = os.path.join(PCAP_DIR, PCAP_NAME)
    csv_path = os.path.join(CSV_DIR, CSV_NAME)

    print(f"[INFO] Menjalankan tcpdump selama {duration} detik ke {pcap_path}")
    tcpdump_cmd = f"timeout {duration} tcpdump -i {INTERFACE} -w {pcap_path} port 80"
    subprocess.run(tcpdump_cmd, shell=True)
    print(f"[INFO] tcpdump selesai untuk {pcap_path}")

    start_time = time.time()
    print(f"[INFO] Mengonversi {pcap_path} ke {csv_path} menggunakan cicflowmeter")
    if not os.path.exists(pcap_path):
        print(f"[ERROR] File {pcap_path} tidak ditemukan.")
        return

    print(f"[INFO] Konversi {pcap_path} -> {csv_path}")
    cicflowmeter_cmd = f"cicflowmeter -f {pcap_path} -c {csv_path}"
    subprocess.run(cicflowmeter_cmd, shell=True)
    file_summary(pcap_path, csv_path)
    total_time = time.time() - start_time
    print(f"\n[INFO] Total waktu Konversi PCAP ke CSV: {total_time:.2f} detik")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        try:
            duration = int(sys.argv[1])
        except ValueError:
            print("Argumen durasi harus berupa angka (detik).")
            sys.exit(1)
    else:
        duration = 60
    run_tcpdump_and_convert(duration)