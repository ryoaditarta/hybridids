# inference_and_merge.py

import pandas as pd
import numpy as np
import time
from tensorflow.keras.models import load_model
import joblib
import sys

# --- Mapping Fitur (Sama seperti saat training) ---
FEATURE_MAP = {
    'Destination Port': 'dst_port', 'Protocol': 'protocol', 'Flow Duration': 'flow_duration',
    'Flow Bytes/s': 'flow_byts_s', 'Flow Packets/s': 'flow_pkts_s', 'Forward Packets/s': 'fwd_pkts_s',
    'Backward Packets/s': 'bwd_pkts_s', 'Total Forward Packets': 'tot_fwd_pkts', 'Total Backward Packets': 'tot_bwd_pkts',
    'Total Length of Forward Packets': 'totlen_fwd_pkts', 'Total Length Backward Packets': 'totlen_bwd_pkts',
    'Forward Packet length Mean': 'fwd_pkt_len_mean', 'Backward Packet Length Mean': 'bwd_pkt_len_mean',
    'Packet Length Mean': 'pkt_len_mean', 'Forward Header Length': 'fwd_header_len', 'Backward Header Length': 'bwd_header_len',
    'Forward Act Data Packets': 'fwd_act_data_pkts', 'Flow IAT Mean': 'flow_iat_mean', 'Forward IAT Total': 'fwd_iat_tot',
    'Backward IAT Total': 'bwd_iat_tot', 'Down Up Ratio': 'down_up_ratio', 'Packet Size Average': 'pkt_size_avg',
    'Active Mean': 'active_mean', 'Idle Mean': 'idle_mean', 'Forward Segment Size Average': 'fwd_seg_size_avg',
    'Backward Segment Size Average': 'bwd_seg_size_avg', 'Subflow Forward Packets': 'subflow_fwd_pkts',
    'Subflow Backward Packets': 'subflow_bwd_pkts', 'Subflow Forward Bytes': 'subflow_fwd_byts',
    'Subflow Backward Bytes': 'subflow_bwd_byts', 'Initial Forward Window Bytes': 'init_fwd_win_byts',
    'Initial Backward Window Bytes': 'init_bwd_win_byts', 'Forward Bytes/Bulk Average': 'fwd_byts_b_avg',
    'Forward Packets/Bulk Average': 'fwd_pkts_b_avg', 'Forward Bulk Rate Average': 'fwd_blk_rate_avg'
}

# --- Path Konfigurasi ---
MODEL_PATH = "./autoencoder/slowlorisautoencoder/slowlorisautoencoder.h5"
SCALER_PATH = "./autoencoder/slowlorisautoencoder/slowlorisscaller.gz"
FILTERED_CSV_PATH = "../data/csv/result_filtered.csv"  # Input untuk ML
LABELED_CSV_PATH = "../data/csv/result_labeled.csv"   # File Master untuk diupdate

# Threshold ini didapat dari analisis ROC curve pada data validasi
THRESHOLD = 0.001750

# --- Load Model dan Scaler ---
try:
    print("[INFO] Memuat model dan scaler...")
    model = load_model(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
except Exception as e:
    print(f"[ERROR] Gagal memuat model atau scaler. Pastikan path sudah benar. Detail: {e}")
    sys.exit(1)

# --- Proses Inferensi pada `result_filtered.csv` ---
try:
    print(f"[INFO] Membaca data dari: {FILTERED_CSV_PATH}")
    df_filtered = pd.read_csv(FILTERED_CSV_PATH)
except FileNotFoundError:
    print(f"[ERROR] File '{FILTERED_CSV_PATH}' tidak ditemukan. Keluar.")
    sys.exit(1)

if df_filtered.empty:
    print("[INFO] File 'result_filtered.csv' kosong. Tidak ada yang perlu diinferensi oleh model.")
else:
    print("[INFO] Preprocessing data yang belum terdeteksi...")
    
    # Simpan 5-tuple untuk identifikasi unik sebelum preprocessing
    five_tuple_cols = ["src_ip", "dst_ip", "src_port", "dst_port", "timestamp"]
    identifier_df = df_filtered[five_tuple_cols].copy()

    # Preprocessing hanya pada kolom fitur
    waktupreprocessing_start = time.time()
    selected_cols = [FEATURE_MAP.get(k) for k in FEATURE_MAP if FEATURE_MAP.get(k) in df_filtered.columns]
    X_eval = df_filtered[selected_cols].copy()
    X_eval.replace([np.inf, -np.inf], np.nan, inplace=True)
    X_eval.dropna(inplace=True)


    if not X_eval.empty:
        X_eval_scaled = scaler.transform(X_eval)
        waktupreprocessing_end = time.time()
        
        # --- Inference ---
        print("[INFO] Melakukan inferensi dengan Autoencoder...")
        waktuinference_start = time.time()
        reconstructions = model.predict(X_eval_scaled)
        errors = np.mean(np.power(X_eval_scaled - reconstructions, 2), axis=1)
        print(errors)
        
        # === KOREKSI LOGIKA PENTING ===
        # MSE RENDAH (< threshold) berarti SERANGAN (1), karena model ahli dalam merekonstruksi serangan.
        predictions = (errors <= THRESHOLD).astype(int)
        print(len(predictions))
        print(predictions)
        label_names = np.where(predictions == 1, 'slowloris', 'benign')
        waktuinference_end = time.time()
        
        print("[INFO] Waktu Total")
        print(f"[INFO] Waktu preprocessing: {waktupreprocessing_end - waktupreprocessing_start:.6f} detik")
        print(f"[INFO] Waktu inferensi: {waktuinference_end - waktuinference_start:.6f} detik")
        total_waktu = (waktupreprocessing_end - waktupreprocessing_start) + (waktuinference_end - waktuinference_start)
        print(f"[INFO] Total waktu preprocessing dan inferensi: {total_waktu:.6f} detik")
        
        # Tambahkan label prediksi ke dataframe yang berisi 5-tuple
        # Ambil index baris-baris yang lolos preprocessing
        valid_indices = X_eval.index

        # Siapkan predicted label dengan index yang sesuai
        df_filtered.loc[valid_indices, 'predicted_label'] = label_names

        # --- Proses Penggabungan (Merge) ---
        print("[INFO] Menggabungkan hasil prediksi ML ke file master 'result_labeled.csv'...")
        # Baca file labeled
        df_labeled = pd.read_csv(LABELED_CSV_PATH)

        # Gunakan 5-tuple sebagai kunci pencocokan
        five_tuple_cols = ["src_ip", "dst_ip", "src_port", "dst_port", "timestamp"]

        # Hanya ambil baris yang ada predicted_label-nya
        df_predicted_only = df_filtered[df_filtered['predicted_label'] == 'slowloris']

        # Merge berdasarkan 5-tuple
        df_labeled.set_index(five_tuple_cols, inplace=True)
        df_predicted_only.set_index(five_tuple_cols, inplace=True)

        # Update label jika saat ini masih 'benign', 'unknown', atau NaN
        mask_update = df_labeled['label'].isin(['benign', 'unknown', np.nan])
        df_labeled.loc[mask_update, 'label'] = df_predicted_only['predicted_label']

        # Kembalikan index ke kolom
        df_labeled.reset_index(inplace=True)

        # Simpan hasilnya
        df_labeled.to_csv(LABELED_CSV_PATH, index=False)
        print(f"[SUCCESS] ✅ File '{LABELED_CSV_PATH}' telah diperbarui dengan hasil prediksi Autoencoder.")


    else:
        print("[INFO] Tidak ada data valid di 'result_filtered.csv' setelah dibersihkan.")