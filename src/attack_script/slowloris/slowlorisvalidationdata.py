import pandas as pd
import subprocess
import os
import time
import csv
import sys

# --- KONFIGURASI ---
PCAP_DIR = "../../data/pcap/"
CSV_DIR = "../../data/csv/"
PCAP_NAME = "slowlorisvalidation.pcap"
RAW_CSV_NAME = "slowlorisvalidation_raw.csv"
BALANCED_CSV_NAME = "slowlorisvalidation_balanced.csv"
INTERFACE = "ens18"

# --- IP GROUND TRUTH ---
ATTACK_IP = "192.168.100.135"
BENIGN_IP = "192.168.100.41"

def file_summary(pcap_file, csv_file):
    pcap_size = os.path.getsize(pcap_file) / (1024 * 1024) if os.path.exists(pcap_file) else 0
    csv_size = os.path.getsize(csv_file) / (1024 * 1024) if os.path.exists(csv_file) else 0
    csv_rows = 0
    if os.path.exists(csv_file):
        try:
            df = pd.read_csv(csv_file)
            csv_rows = len(df)
        except Exception:
            with open(csv_file, 'r') as f:
                f.seek(0)
                reader = csv.reader(f)
                csv_rows = sum(1 for _ in reader) - 1
    print(f"[SUMMARY] {os.path.basename(pcap_file)}: {pcap_size:.2f} MB")
    print(f"[SUMMARY] {os.path.basename(csv_file)}: {csv_size:.2f} MB, {csv_rows} baris/entry")

def run_tcpdump_and_convert(duration):
    os.makedirs(CSV_DIR, exist_ok=True)
    os.makedirs(PCAP_DIR, exist_ok=True)
    pcap_path = os.path.join(PCAP_DIR, PCAP_NAME)
    raw_csv_path = os.path.join(CSV_DIR, RAW_CSV_NAME)

    print(f"[INFO] Menjalankan tcpdump selama {duration} detik ke {pcap_path}")
    tcpdump_cmd = f"timeout {duration} tcpdump -i {INTERFACE} -w {pcap_path} port 80"
    
    try:
        # Kita coba jalankan perintahnya
        subprocess.run(tcpdump_cmd, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        # Jika ada error, kita cek kode statusnya
        if e.returncode == 124:
            # Jika kodenya 124, ini adalah 'sukses' yang diharapkan dari timeout. Kita lanjutkan saja.
            print("[INFO] Timeout tercapai seperti yang diharapkan. Melanjutkan proses...")
            pass
        else:
            # Jika kodenya lain, berarti ini error sungguhan. Kita tampilkan dan hentikan.
            print(f"[ERROR] Perintah tcpdump gagal dengan kode exit {e.returncode}")
            raise e
            
    print(f"[INFO] tcpdump selesai untuk {pcap_path}")

    start_time = time.time()
    print(f"[INFO] Mengonversi {pcap_path} ke {raw_csv_path} menggunakan cicflowmeter")
    if not os.path.exists(pcap_path):
        print(f"[ERROR] File {pcap_path} tidak ditemukan.")
        return None

    cicflowmeter_cmd = f"cicflowmeter -f {pcap_path} -c {raw_csv_path}"
    subprocess.run(cicflowmeter_cmd, shell=True, check=True)
    file_summary(pcap_path, raw_csv_path)
    total_time = time.time() - start_time
    print(f"\n[INFO] Total waktu Konversi PCAP ke CSV: {total_time:.2f} detik")
    return raw_csv_path

def balance_csv_from_ips(input_csv_path, output_csv_path):
    """
    Menyeimbangkan CSV berdasarkan IP sumber menggunakan metode under-sampling.
    Juga menangani kasus jika file CSV input kosong.
    """
    print(f"\n[INFO] Memulai proses penyeimbangan untuk {input_csv_path}")
    if not os.path.exists(input_csv_path):
        print(f"[ERROR] File input {input_csv_path} tidak ditemukan.")
        return

    # --- BLOK PERBAIKAN DIMULAI DI SINI ---
    try:
        # Kita coba membaca file CSV
        df = pd.read_csv(input_csv_path)
        # Jika dataframe kosong setelah dibaca (misalnya hanya berisi header)
        if df.empty:
            print(f"[WARNING] File CSV '{input_csv_path}' hanya berisi header atau kosong. Proses penyeimbangan dilewati.")
            return
            
    except pd.errors.EmptyDataError:
        # Jika pandas gagal membaca karena file benar-benar kosong (0 byte)
        print(f"[WARNING] File CSV '{input_csv_path}' kosong dan tidak bisa diproses. Proses penyeimbangan dilewati.")
        return
    # --- BLOK PERBAIKAN SELESAI ---

    # Memisahkan data berdasarkan IP sumber
    df_attack = df[df['src_ip'] == ATTACK_IP]
    df_benign = df[df['src_ip'] == BENIGN_IP]

    print(f"[INFO] Menyeimbangkan data: {len(df_attack)} baris Attack, {len(df_benign)} baris Benign")
    attack_count = len(df_attack)
    benign_count = len(df_benign)

    min_count = min(attack_count, benign_count)

    if min_count == 0:
        print("[WARNING] Salah satu kelas (Attack/Benign) tidak ditemukan dalam data. Tidak ada file seimbang yang dibuat.")
        return

    df_attack_balanced = df_attack.sample(n=min_count, random_state=42)
    df_benign_balanced = df_benign.sample(n=min_count, random_state=42)
    df_balanced = pd.concat([df_attack_balanced, df_benign_balanced])
    df_balanced = df_balanced.sample(frac=1, random_state=42).reset_index(drop=True)
    df_balanced.to_csv(output_csv_path, index=False)
    
    # --- Blok Ringkasan Akhir ---
    print("\n" + "="*45)
    print("     📊 HASIL AKHIR PROSES PENYEIMBANGAN")
    print("="*45)
    print("SEBELUM diseimbangkan:")
    print(f"  - Baris Attack ({ATTACK_IP}): {attack_count} baris")
    print(f"  - Baris Benign ({BENIGN_IP}) : {benign_count} baris")
    print("\nSETELAH diseimbangkan (metode under-sampling):")
    print(f"  - Baris Attack: {len(df_attack_balanced)} baris")
    print(f"  - Baris Benign: {len(df_benign_balanced)} baris")
    print(f"  --------------------------------- +")
    print(f"  - Total Data   : {len(df_balanced)} baris (rasio 50:50)")
    print("="*45)
    print(f"\n[SUCCESS] File seimbang telah disimpan di: {output_csv_path}")

if __name__ == "__main__":
    duration = 60
    if len(sys.argv) > 1:
        try:
            duration = int(sys.argv[1])
        except ValueError:
            print("Argumen durasi harus berupa angka (detik).")
            sys.exit(1)

    raw_csv_file = run_tcpdump_and_convert(duration)

    if raw_csv_file and os.path.exists(raw_csv_file):
        balanced_csv_file = os.path.join(CSV_DIR, BALANCED_CSV_NAME)
        balance_csv_from_ips(raw_csv_file, balanced_csv_file)