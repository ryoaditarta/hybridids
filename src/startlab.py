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
    Menjalankan tcpdump dan Suricata
    """
    print(f"Capture data in interface '{INTERFACE}' for {DURATION_SECONDS} seconds...")
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
    
def evaluate(with_autoencoder=False):
    if(not with_autoencoder):
        print("\n--- Evaluasi tanpa Autoencoder ---")
    else:
        # --- Memulai inferensi model autoencoder ---
        print("\n--- Memulai Inferensi Model Autoencoder ---")
        import subprocess
        MLcommand = "python3.12 /home/victim/project/src/autoencoder/theautoencoders.py"

        try:
            result = subprocess.run(MLcommand, shell=True, check=True, text=True, capture_output=True)
            # print("Output dari skrip:")
            print(result.stdout)
        except subprocess.CalledProcessError as e:
            print("Terjadi error saat menjalankan perintah:")
            print(e.stderr)

def process_data():
    """Menjalankan cicflowmeter, membaca log, dan mencocokkan tuple."""
    print("\n--- Memulai Analisis Data ---")
    
    import subprocess
    print("-> Menjalankan cicflowmeter...")
    waktucicflowmeter_start = time.time()
    try:
        cicflowmeter_command = f"cicflowmeter -f {PCAP_OUTPUT_FILE} -c {CICFLOWMETER_CSV_PATH}"
        subprocess.run(cicflowmeter_command, shell=True, check=True)
        print("cicflowmeter selesai. File CSV telah dibuat.")
    except Exception:
        print("Kesalahan saat menjalankan cicflowmeter.")
        return
    waktucicflowmeter_end = time.time()
    print("Waktu konversi pcap ke flow:", waktucicflowmeter_end-waktucicflowmeter_start)


    # MATCHING AND FILTERING
    metric_start = time.time()
    alert_dict = {}  # key: normalized 5-tuple, value: list of (timestamp, label)
    proto_map = {
        'TCP': '6', 'tcp': '6',
        'UDP': '17', 'udp': '17',
        'ICMP': '1', 'icmp': '1',
    }
    sid_label_map = {
        '1004': 'slowloris',
        '1007': 'slowloris',
        '1010': 'slowread',
        '1012': 'slowpost',
    }

    def tuple_normalize(key):
        ip_port_1 = (key[0], key[1])
        ip_port_2 = (key[2], key[3])
        proto = key[4]
        if ip_port_1 <= ip_port_2:
            return (ip_port_1[0], ip_port_1[1], ip_port_2[0], ip_port_2[1], proto)
        else:
            return (ip_port_2[0], ip_port_2[1], ip_port_1[0], ip_port_1[1], proto)

    def parse_timestamp(ts):
        if not ts:
            return None
        try:
            return datetime.datetime.strptime(ts[:26], "%Y-%m-%dT%H:%M:%S.%f")
        except Exception:
            try:
                return datetime.datetime.strptime(ts[:19], "%Y-%m-%d %H:%M:%S")
            except Exception:
                return None

    # Efficiently parse eve.json and build alert_dict
    with open(EVE_JSON_PATH, 'r') as f:
        for line in f:
            try:
                event = json.loads(line)
                if event.get("event_type") != "alert":
                    continue
                src_ip = event.get("src_ip")
                src_port = event.get("src_port")
                dest_ip = event.get("dest_ip")
                dest_port = event.get("dest_port")
                proto = event.get("proto")
                sid = str(event.get("alert", {}).get("signature_id", event.get("sid", "")))
                proto_num = proto_map.get(str(proto).upper(), str(proto)) if isinstance(proto, str) else str(proto)
                start = None
                if "flow" in event and "start" in event["flow"]:
                    start = event["flow"]["start"]
                elif "start" in event:
                    start = event["start"]
                ts_parsed = parse_timestamp(start)
                if not all([src_ip, src_port, dest_ip, dest_port, proto_num]):
                    continue
                key = tuple_normalize((src_ip, str(src_port), dest_ip, str(dest_port), proto_num))
                label = sid_label_map.get(sid, "")
                if key not in alert_dict:
                    alert_dict[key] = []
                alert_dict[key].append((ts_parsed, label))
            except Exception:
                continue


    flow_tuples = set()
    csv_rows = []
    # Parse cicflowmeter CSV and build flow_tuples and csv_rows
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
                if all([src_ip, src_port, dest_ip, dest_port, proto_num]):
                    flow_tuples.add((key, ts_parsed))
                row['proto_num'] = proto_num
                row['norm_key'] = key
                row['norm_ts'] = ts_parsed
                csv_rows.append(row)
            except KeyError:
                continue

    # --- Efficient matching: for each flow, check if any alert exists for the same key and timestamp within 1s ---
    matched_tuples = set()
    for key, ts in flow_tuples:
        if key in alert_dict:
            for alert_ts, _ in alert_dict[key]:
                if ts and alert_ts and abs((ts - alert_ts).total_seconds()) <= 1:
                    matched_tuples.add((key, ts))
                    break

    # For reporting, count total alert events (not unique keys)
    total_alert_events = sum(len(v) for v in alert_dict.values())
    print("\n--- Hasil Analisis ---")
    print(f"Jumlah alert yang terdeteksi di eve.json: {total_alert_events}")
    print(f"Jumlah flow yang dianalisis oleh cicflowmeter: {len(flow_tuples)}")
    print(f"Jumlah flow yang cocok dengan alert: {len(matched_tuples)}")

    # Add label column to original CSV
    labeled_csv_path = CICFLOWMETER_CSV_PATH.replace('.csv', '_labeled.csv')
    print(f"\nMembuat salinan CSV dengan label: {labeled_csv_path}")
    slowloris_count = 0
    slowread_count = 0
    slowpost_count = 0
    if csv_rows:
        fieldnames = list(csv_rows[0].keys())
        if 'label' not in fieldnames:
            fieldnames.append('label')
        # Efficient labeling: for each row, check alert_dict for matching key and timestamp
        for row in csv_rows:
            key = row['norm_key']
            ts = row['norm_ts']
            label = ''
            if key in alert_dict:
                for alert_ts, lbl in alert_dict[key]:
                    if ts and alert_ts and abs((ts - alert_ts).total_seconds()) <= 1:
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

    metric_end = time.time()
    metric_duration = metric_end - metric_start
    print(f"\n[METRIC] Waktu proses pencocokan dan filtering: {metric_duration:.3f} detik")
    print(f"\nJumlah baris di CSV sebelum dihapus: {len(rows)}")

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

def evaluate_labeled_vs_groundtruth(labeled_csv_path):
    # Mapping IP ke label ground truth
    ip_label_map = {
        "192.168.100.135": "slowloris",
        "192.168.100.141": "slowread",
        "192.168.100.148": "slowpost",
        "192.168.100.146": "benign"
    }

    classes = ["slowloris", "slowread", "slowpost", "benign"]
    gt_labels = []
    pred_labels = []
    total = 0
    correct = 0
    confusion = {c1: {c2: 0 for c2 in classes} for c1 in classes}

    with open(labeled_csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            src_ip = row.get('src_ip')
            pred = row.get('label', '').strip() or "benign"
            gt = ip_label_map.get(src_ip, "benign")
            gt_labels.append(gt)
            pred_labels.append(pred)
            total += 1
            if pred == gt:
                correct += 1
            confusion[gt][pred] += 1

    accuracy = correct / total if total else 0

    # Per-class metrics
    metrics = {}
    for cls in classes:
        TP = confusion[cls][cls]
        FP = sum(confusion[other][cls] for other in classes if other != cls)
        FN = sum(confusion[cls][other] for other in classes if other != cls)
        TN = sum(confusion[o1][o2] for o1 in classes for o2 in classes if o1 != cls and o2 != cls)
        precision = TP / (TP + FP) if (TP + FP) else 0
        recall = TP / (TP + FN) if (TP + FN) else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
        tpr = recall
        fpr = FP / (FP + TN) if (FP + TN) else 0
        metrics[cls] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "TPR": tpr,
            "FPR": fpr,
            "support": sum(confusion[cls].values())
        }

    print("\n=== Evaluasi Labeled CSV vs Ground Truth (berdasarkan IP) ===")
    print(f"Total baris: {total}")
    print(f"Benar: {correct}")
    print(f"Akurasi: {accuracy:.4f}")
    print("\nConfusion Matrix (GT, Prediksi):")
    print("GT\\Pred".ljust(12) + "".join([c.ljust(12) for c in classes]))
    for gt in classes:
        print(gt.ljust(12) + "".join([str(confusion[gt][pred]).ljust(12) for pred in classes]))
    print("\nPer-class metrics:")
    for cls in classes:
        m = metrics[cls]
        print(f"{cls}: Precision={m['precision']:.3f} Recall={m['recall']:.3f} F1={m['f1']:.3f} TPR={m['TPR']:.3f} FPR={m['FPR']:.3f} Support={m['support']}")

    # Macro average
    macro_precision = sum(m['precision'] for m in metrics.values()) / len(classes)
    macro_recall = sum(m['recall'] for m in metrics.values()) / len(classes)
    macro_f1 = sum(m['f1'] for m in metrics.values()) / len(classes)
    print(f"\nMacro avg: Precision={macro_precision:.3f} Recall={macro_recall:.3f} F1={macro_f1:.3f}")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Skrip ini harus dijalankan dengan hak akses root. Coba gunakan 'sudo'.")
    else:
        if run_capture():
            process_data()
            labeled_csv_path = CICFLOWMETER_CSV_PATH.replace('.csv', '_labeled.csv')
            print("=======EVALUASI SURICATA=======")
            evaluate_labeled_vs_groundtruth(labeled_csv_path)
            evaluate(True)
            print("=======EVALUASI SURICATA + AUTOENCODER=======")
            evaluate_labeled_vs_groundtruth(labeled_csv_path)
