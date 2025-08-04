import subprocess
import os
import time
import sys
import csv

PCAP_DIR = "../../data/pcap/"
CSV_DIR = "../../data/csv/"
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

# Runtime per capture (detik)
RUNTIME_PER_CAPTURE = 240

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

def run_capture_and_convert(capture_idx, runtime):
    timestamp = int(time.time())
    pcap_file = os.path.join(PCAP_DIR, f"capture_{capture_idx}_{timestamp}.pcap")
    csv_file = os.path.join(CSV_DIR, f"capture_{capture_idx}_{timestamp}.csv")
    print(f"\n[INFO] Capture ke: {pcap_file} selama {runtime} detik")

    # Start tcpdump
    tcpdump_cmd = f"timeout {runtime} tcpdump -i {INTERFACE} -w {pcap_file} port 80"
    print(f"[INFO] Menjalankan: {tcpdump_cmd}")
    subprocess.run(tcpdump_cmd, shell=True)
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
    capture_idx = 1
    while True:
        elapsed = time.time() - start_time
        if elapsed >= TOTAL_RUNTIME:
            print(f"\n[INFO] Waktu total {TOTAL_RUNTIME} detik sudah tercapai. Selesai.")
            sys.exit(0)
        run_capture_and_convert(capture_idx, RUNTIME_PER_CAPTURE)
        capture_idx += 1