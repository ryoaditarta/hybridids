import subprocess
import time
import os
import json
import csv
import sys
import datetime

# --- Konfigurasi ---
INTERFACE = 'ens18'
PCAP_OUTPUT_DIR = '/home/victim/project/data/pcap/'
CSV_OUTPUT_DIR = '/home/victim/project/data/csv/'
PCAP_OUTPUT_FILE = os.path.join(PCAP_OUTPUT_DIR, 'result.pcap')
SURICATA_CONFIG_PATH = '/etc/suricata/suricata.yaml'
EVE_JSON_PATH = '/home/victim/project/data/log/eve.json'
CICFLOWMETER_CSV_PATH = os.path.join(CSV_OUTPUT_DIR, 'result.csv')
PATH_TO_LOG = '/home/victim/project/data/log/'

# Ambil durasi dari argumen command-line, default 20 detik jika tidak diberikan
if len(sys.argv) > 1:
    try:
        DURATION_SECONDS = int(sys.argv[1])
    except ValueError:
        print("Argumen durasi harus berupa angka (detik). Menggunakan default 20 detik.")
        DURATION_SECONDS = 20
else:
    DURATION_SECONDS = 20

# --- Fungsi untuk menjalankan proses ---
def run_capture():
    """
    Menjalankan tcpdump dan Suricata dengan termination yang lebih andal.
    tcpdump akan berhenti sendiri setelah durasi yang ditentukan.
    """
    print(f"Memulai pengambilan data pada antarmuka '{INTERFACE}' selama {DURATION_SECONDS} detik...")
    os.makedirs(PCAP_OUTPUT_DIR, exist_ok=True)
    open(EVE_JSON_PATH, 'w').close()

    try:
        # Perintah tcpdump yang hanya menangkap trafik port 80 dan berhenti sendiri sesuai durasi
        tcpdump_command = f"timeout {DURATION_SECONDS} tcpdump -i {INTERFACE} -w {PCAP_OUTPUT_FILE} port 80"
        
        # Suricata tetap dihentikan secara manual
        suricata_command = f"timeout {DURATION_SECONDS} suricata -c {SURICATA_CONFIG_PATH} -i {INTERFACE} -l {PATH_TO_LOG} -v"

        tcpdump_process = subprocess.Popen(tcpdump_command, shell=True)
        suricata_process = subprocess.Popen(suricata_command, shell=True, preexec_fn=os.setsid)
        
        print(f"tcpdump berjalan dengan PID: {tcpdump_process.pid}")
        print(f"Suricata berjalan dengan PID: {suricata_process.pid}")
        
        print(f"Menunggu {DURATION_SECONDS} detik...")
        tcpdump_process.wait()
        
        print("\nDurasi selesai. Menghentikan Suricata...")
        os.killpg(os.getpgid(suricata_process.pid), 2)
        suricata_process.wait()
        
        print("\nProses pengambilan data selesai.")
        return True
    except FileNotFoundError as e:
        print(f"Kesalahan: '{e.filename}' tidak ditemukan. Pastikan sudah terinstal.")
        return False

def process_data():
    """Menjalankan cicflowmeter, membaca log, dan mencocokkan tuple."""
    print("\n--- Memulai Analisis Data ---")
    
    print("-> Menjalankan cicflowmeter...")
    try:
        cicflowmeter_command = f"cicflowmeter -f {PCAP_OUTPUT_FILE} -c {CICFLOWMETER_CSV_PATH}"
        subprocess.run(cicflowmeter_command, shell=True, check=True)
        print("cicflowmeter selesai. File CSV telah dibuat.")
    except Exception:
        print("Kesalahan saat menjalankan cicflowmeter.")
        return

    # Mulai pengukuran waktu metric pencocokan dan filtering
    metric_start = time.time()

    alert_tuples = set()
    alert_labels = dict()  # key: tuple, value: label
    # Mapping protocol names to numbers
    proto_map = {
        'TCP': '6', 'tcp': '6',
        'UDP': '17', 'udp': '17',
        'ICMP': '1', 'icmp': '1',
        'IGMP': '2', 'igmp': '2',
        'GRE': '47', 'gre': '47',
        'ESP': '50', 'esp': '50',
        'AH': '51', 'ah': '51',
        'SCTP': '132', 'sctp': '132',
        'EIGRP': '88', 'eigrp': '88',
        'OSPF': '89', 'ospf': '89',
        'IPIP': '4', 'ipip': '4',
        'VRRP': '112', 'vrrp': '112',
        'PIM': '103', 'pim': '103',
        'L2TP': '115', 'l2tp': '115',
    }
    # SID to label mapping
    sid_label_map = {
        '1004': 'slowloris',
        '1005': 'slowread',
        '1006': 'slowpost',
    }
    def tuple_normalize(key):
        # key: (src_ip, src_port, dst_ip, dst_port, proto)
        # Return tuple in sorted order so (A,B,C,D,P) == (C,D,A,B,P)
        ip_port_1 = (key[0], key[1])
        ip_port_2 = (key[2], key[3])
        proto = key[4]
        # Sort by ip/port, but keep proto at the end
        if ip_port_1 <= ip_port_2:
            return (ip_port_1[0], ip_port_1[1], ip_port_2[0], ip_port_2[1], proto)
        else:
            return (ip_port_2[0], ip_port_2[1], ip_port_1[0], ip_port_1[1], proto)

    # Fungsi parse_timestamp untuk Suricata dan CSV
    def parse_timestamp(ts):
        # Suricata: "2025-08-04T20:27:56.057716+0000"
        # CSV: "2025-08-04 20:42:34"
        if not ts:
            return None
        try:
            # Suricata format
            return datetime.datetime.strptime(ts[:26], "%Y-%m-%dT%H:%M:%S.%f")
        except Exception:
            try:
                # CSV format
                return datetime.datetime.strptime(ts[:19], "%Y-%m-%d %H:%M:%S")
            except Exception:
                return None

    # Saat parsing eve.json
    with open(EVE_JSON_PATH, 'r') as f:
        for line in f:
            event = json.loads(line)
            if event.get("event_type") == "alert":
                src_ip = event.get("src_ip")
                src_port = event.get("src_port")
                dest_ip = event.get("dest_ip")
                dest_port = event.get("dest_port")
                proto = event.get("proto")
                sid = str(event.get("alert", {}).get("signature_id", event.get("sid", "")))
                proto_num = proto_map.get(str(proto).upper(), str(proto)) if isinstance(proto, str) else str(proto)
                # Ambil waktu dari kolom "start" di event["flow"], fallback ke event["start"] jika tidak ada
                start = None
                if "flow" in event and "start" in event["flow"]:
                    start = event["flow"]["start"]
                elif "start" in event:
                    start = event["start"]
                ts_parsed = parse_timestamp(start)
                key = tuple_normalize((src_ip, str(src_port), dest_ip, str(dest_port), proto_num))
                print(f"[DEBUG] Tuple dari alert eve.json: {key} SID: {sid} TS: {ts_parsed}")
                if all([src_ip, src_port, dest_ip, dest_port, proto_num]):
                    alert_tuples.add((key, ts_parsed))
                    label = sid_label_map.get(sid, "")
                    if label:
                        alert_labels[(key, ts_parsed)] = label

    flow_tuples = set()
    csv_rows = []
    # Saat parsing cicflowmeter CSV
    with open(CICFLOWMETER_CSV_PATH, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                src_ip = row['src_ip']
                src_port = row['src_port']
                dest_ip = row['dst_ip']
                dest_port = row['dst_port']
                proto = row['protocol']
                proto_num = proto_map.get(str(proto).upper(), str(proto)) if isinstance(proto, str) else str(proto)
                key = tuple_normalize((src_ip, src_port, dest_ip, dest_port, proto_num))
                ts = row.get('timestamp')
                ts_parsed = parse_timestamp(ts) if ts else None
                #print(f"[DEBUG] Tuple dari cicflowmeter CSV: {key} TS: {ts_parsed}")
                if all([src_ip, src_port, dest_ip, dest_port, proto_num]):
                    flow_tuples.add((key, ts_parsed))
                row['proto_num'] = proto_num
                row['norm_key'] = key
                row['norm_ts'] = ts_parsed
                csv_rows.append(row)
            except KeyError:
                continue

    # Fungsi pencocokan dengan toleransi timestamp 1 detik
    def match_tuple_with_time(alert_tuple, flow_tuple):
        key_a, ts_a = alert_tuple
        key_f, ts_f = flow_tuple
        if key_a == key_f and ts_a and ts_f:
            delta = abs((ts_a - ts_f).total_seconds())
            #print(f"[DEBUG] Mencocokkan {key_a} dengan {key_f}, delta: {delta}")
            return delta <= 1
        return False

    # Cari matched_tuples dengan toleransi waktu
    matched_tuples = set()
    for alert_tuple in alert_tuples:
        for flow_tuple in flow_tuples:
            if match_tuple_with_time(alert_tuple, flow_tuple):
                matched_tuples.add(flow_tuple)

    print("\n--- Hasil Analisis ---")
    print(f"Jumlah alert yang terdeteksi di eve.json: {len(alert_tuples)}")
    print(f"Jumlah flow yang dianalisis oleh cicflowmeter: {len(flow_tuples)}")
    print(f"Jumlah flow yang cocok dengan alert: {len(matched_tuples)}")

    # Add label column to original CSV
    labeled_csv_path = CICFLOWMETER_CSV_PATH.replace('.csv', '_labeled.csv')
    print(f"Membuat salinan CSV dengan label: {labeled_csv_path}")
    slowloris_count = 0
    slowread_count = 0
    slowpost_count = 0
    if csv_rows:
        fieldnames = list(csv_rows[0].keys())
        if 'label' not in fieldnames:
            fieldnames.append('label')
        # Saat labeling
        for row in csv_rows:
            key = row['norm_key']
            ts = row['norm_ts']
            label = ''
            for (alert_key, alert_ts), lbl in alert_labels.items():
                if key == alert_key and ts and alert_ts and abs((ts - alert_ts).total_seconds()) <= 1:
                    label = lbl
                    break
            row['label'] = label
            if label == 'slowloris':
                slowloris_count += 1
            elif label == 'slowread':
                slowread_count += 1
            elif label == 'slowpost':
                slowpost_count += 1
        with open(labeled_csv_path, 'w', newline='') as outfile:
            writer = csv.DictWriter(outfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(csv_rows)
        print(f"Jumlah flow yang diklasifikasikan sebagai slowloris: {slowloris_count}")
        print(f"Jumlah flow yang diklasifikasikan sebagai slowread: {slowread_count}")
        print(f"Jumlah flow yang diklasifikasikan sebagai slowpost: {slowpost_count}")
    else:
        open(labeled_csv_path, 'w').close()

    # Copy CSV and remove rows that match any alert flow (filtered)
    import shutil
    filtered_csv_path = CICFLOWMETER_CSV_PATH.replace('.csv', '_filtered.csv')
    shutil.copy2(CICFLOWMETER_CSV_PATH, filtered_csv_path)
    print(f"Membuat salinan CSV: {filtered_csv_path}")

    # Read, filter, and overwrite the filtered CSV
    with open(filtered_csv_path, 'r', newline='') as infile:
        reader = csv.DictReader(infile)
        rows = list(reader)
        fieldnames = reader.fieldnames

    print(f"Jumlah baris di CSV sebelum dihapus: {len(rows)}")

    filtered_rows = []
    # Saat filtering
    for row in rows:
        proto_num = proto_map.get(str(row['protocol']).upper(), str(row['protocol'])) if isinstance(row['protocol'], str) else str(row['protocol'])
        key = tuple_normalize((row['src_ip'], row['src_port'], row['dst_ip'], row['dst_port'], proto_num))
        ts = parse_timestamp(row.get('start_time') or row.get('timestamp')) if row.get('start_time') or row.get('timestamp') else None
        matched = False
        for mt_key, mt_ts in matched_tuples:
            if key == mt_key and ts and mt_ts and abs((ts - mt_ts).total_seconds()) <= 1:
                matched = True
                break
        if not matched:
            filtered_rows.append(row)

    print(f"Jumlah baris di CSV setelah dihapus: {len(filtered_rows)}")

    # Handle case when CSV is empty and fieldnames is None
    if fieldnames is None:
        print(f"CSV kosong, tidak ada header untuk ditulis di {filtered_csv_path}.")
        # Just create an empty file
        open(filtered_csv_path, 'w').close()
    else:
        with open(filtered_csv_path, 'w', newline='') as outfile:
            writer = csv.DictWriter(outfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(filtered_rows)
        print(f"Baris yang terdeteksi oleh Suricata telah dihapus dari {filtered_csv_path}.")

    metric_end = time.time()
    metric_duration = metric_end - metric_start
    print(f"\n[METRIC] Waktu proses pencocokan dan filtering: {metric_duration:.3f} detik")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Skrip ini harus dijalankan dengan hak akses root. Coba gunakan 'sudo'.")
    else:
        if run_capture():
            process_data()
