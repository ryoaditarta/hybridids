import pandas as pd
import numpy as np
import time
from tensorflow.keras.models import load_model
import joblib
import sys
import os

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
# Direktori utama untuk semua model
BASE_MODEL_DIR = "./autoencoder/"
FILTERED_CSV_PATH = "../data/csv/result_filtered.csv"  # Input untuk ML
LABELED_CSV_PATH = "../data/csv/result_labeled.csv"   # File Master untuk diupdate

# --- Konfigurasi untuk Setiap Model Autoencoder ---
# Anda bisa mengisi nilai threshold yang tepat untuk setiap model di sini.
MODELS_CONFIG = {
    'slowloris': {
        'model_path': os.path.join(BASE_MODEL_DIR, 'slowlorisautoencoder/model_enc25_code10_batch220/slowlorisautoencoder.h5'),
        'scaler_path': os.path.join(BASE_MODEL_DIR, 'slowlorisautoencoder/model_enc25_code10_batch220/slowlorisscaller.gz'),
        'threshold': 0.000129  # Ganti dengan threshold optimal untuk Slowloris
    },
    'slowread': {
        'model_path': os.path.join(BASE_MODEL_DIR, 'slowreadautoencoder/slowreadautoencoder.h5'),
        'scaler_path': os.path.join(BASE_MODEL_DIR, 'slowreadautoencoder/slowreadscaler.gz'),
        'threshold': 0.000121  # Ganti dengan threshold optimal untuk Slow Read
    },
    'slowpost': {
        'model_path': os.path.join(BASE_MODEL_DIR, 'slowpostautoencoder/slowpostautoencoder.h5'),
        'scaler_path': os.path.join(BASE_MODEL_DIR, 'slowpostautoencoder/slowpostscaler.gz'),
        'threshold': 0.000012  # Ganti dengan threshold optimal untuk Slow Post
    }
}

# --- Load Semua Model dan Scaler ---
models = {}
scalers = {}
try:
    print("[INFO] Memuat semua model dan scaler...")
    for name, config in MODELS_CONFIG.items():
        # print(f"  -> Memuat model '{name}'...")
        models[name] = load_model(config['model_path'])
        scalers[name] = joblib.load(config['scaler_path'])
    print("[INFO] ✅ Semua model berhasil dimuat.")
except Exception as e:
    print(f"[ERROR] Gagal memuat salah satu model atau scaler. Pastikan semua path sudah benar. Detail: {e}")
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
    # Pilih hanya kolom fitur untuk diproses ML
    waktupreprocessing_start = time.time()
    selected_cols = [FEATURE_MAP.get(k) for k in FEATURE_MAP if FEATURE_MAP.get(k) in df_filtered.columns]
    X_eval = df_filtered[selected_cols].copy()
    X_eval.replace([np.inf, -np.inf], np.nan, inplace=True)
    
    # Simpan index dari baris yang valid SEBELUM di-dropna
    valid_indices = X_eval.notna().all(axis=1)
    X_eval.dropna(inplace=True)
    waktupreprocessing_end = time.time()
    print("[INFO] Waktu preprocessing:", waktupreprocessing_end - waktupreprocessing_start)

    if not X_eval.empty:
        # --- Inference untuk Setiap Model ---
        print("[INFO] Melakukan inferensi dengan semua model Autoencoder...")
        waktu_inference_start = time.time()
        
        # Dictionary untuk menyimpan hasil MSE dari setiap model
        errors_dict = {}

        for name, model in models.items():
            # Penting: Gunakan scaler yang sesuai untuk setiap model
            scaler = scalers[name]
            X_eval_scaled = scaler.transform(X_eval)
            
            reconstructions = model.predict(X_eval_scaled)
            errors = np.mean(np.power(X_eval_scaled - reconstructions, 2), axis=1)
            errors_dict[name] = errors
        
        # Buat DataFrame dari hasil error untuk perbandingan yang mudah
        df_errors = pd.DataFrame(errors_dict, index=X_eval.index)
        
        # ==============================================================================
        # --- Logika Prediksi Bertingkat Sesuai Permintaan Anda ---
        # ==============================================================================
        def assign_label_from_rules(row):
            """
            Menerapkan logika decisional bertingkat (nested if/else)
            untuk menentukan label prediksi akhir.
            """
            # Ambil nilai error untuk setiap model dari baris saat ini
            lsl = row['slowloris']
            lsr = row['slowread']
            lsp = row['slowpost']

            # Ambil nilai threshold yang sudah ditentukan
            tsl = MODELS_CONFIG['slowloris']['threshold']
            tsr = MODELS_CONFIG['slowread']['threshold']
            tsp = MODELS_CONFIG['slowpost']['threshold']

            # Periksa model mana saja yang errornya di bawah threshold ("triggered")
            slowloris_triggered = lsl <= tsl
            slowread_triggered = lsr <= tsr
            slowpost_triggered = lsp <= tsp
            
            # --- Implementasi Logika Bertingkat ---
            
            # Kasus 1: Hanya SATU model yang terpicu
            if slowloris_triggered and not slowread_triggered and not slowpost_triggered:
                return 'slowloris'
            elif not slowloris_triggered and slowread_triggered and not slowpost_triggered:
                return 'slowread'
            elif not slowloris_triggered and not slowread_triggered and slowpost_triggered:
                return 'slowpost'
            
            # Kasus 2: DUA model terpicu
            elif slowloris_triggered and slowread_triggered and not slowpost_triggered:
                return 'slowloris' if lsl < lsr else 'slowread'
            elif slowloris_triggered and not slowread_triggered and slowpost_triggered:
                return 'slowloris' if lsl < lsp else 'slowpost'
            elif not slowloris_triggered and slowread_triggered and slowpost_triggered:
                return 'slowread' if lsr < lsp else 'slowpost'
            
            # Kasus 3: SEMUA TIGA model terpicu
            elif slowloris_triggered and slowread_triggered and slowpost_triggered:
                # Cari error terkecil di antara ketiganya
                min_error = min(lsl, lsr, lsp)
                if min_error == lsl:
                    return 'slowloris'
                elif min_error == lsr:
                    return 'slowread'
                else:
                    return 'slowpost'
            
            # Kasus 4: TIDAK ADA model yang terpicu
            else:
                return 'benign'

            # if slowloris_triggered:
            #     return 'slowloris'
            # else:
            #     return 'benign'

        # print(df_errors)
        # for e in df_errors:
        #     print(e)
        final_predictions = df_errors.apply(assign_label_from_rules, axis=1)
        waktu_inference_end = time.time()
        print("Waktu inferensi: ", waktu_inference_end - waktu_inference_start)

        # --- Penggabungan Hasil ---
        print("\n[INFO] Menggabungkan hasil prediksi ML ke file master 'result_labeled.csv'...")
        waktuevaluasi_start = time.time()
        five_tuple_cols = ["src_ip", "dst_ip", "src_port", "dst_port", "timestamp"]
        # Buat DataFrame baru yang berisi kunci (5-tuple) dan hasil prediksi ML
        # Index dari final_predictions sudah sesuai dengan X_eval, yang index-nya
        # sesuai dengan df_filtered setelah baris invalid dihapus.
        df_predictions = df_filtered.loc[valid_indices, five_tuple_cols].copy()
        df_predictions['ml_prediction'] = final_predictions

        # Muat file master yang akan diupdate
        df_labeled = pd.read_csv(LABELED_CSV_PATH)

        # Lakukan LEFT MERGE:
        # Pertahankan semua baris dari df_labeled, dan tambahkan kolom 'ml_prediction'
        # jika 5-tuple-nya cocok dengan yang ada di df_predictions.
        df_merged = pd.merge(df_labeled, df_predictions, on=five_tuple_cols, how='left')

        # --- LOGIKA UPDATE YANG BENAR ---
        # Kondisi untuk update:
        # 1. Label asli adalah 'benign' ATAU kosong (NaN).
        # 2. Ada prediksi baru dari ML untuk baris tersebut (ml_prediction tidak NaN).
        # 3. Prediksi baru dari ML BUKAN 'benign'. Kita hanya ingin menambahkan label serangan.
        condition_to_update = (
            df_merged['label'].isin(['benign', np.nan]) &
            df_merged['ml_prediction'].notna() &
            (df_merged['ml_prediction'] != 'benign')
        )

        # Terapkan update:
        # Jika kondisi terpenuhi, gunakan 'ml_prediction'. Jika tidak, pertahankan 'label' asli.
        df_merged['label'] = np.where(
            condition_to_update,
            df_merged['ml_prediction'],
            df_merged['label']
        )

        # Hapus kolom sementara dan simpan hasilnya
        df_merged.drop(columns=['ml_prediction'], inplace=True)
        df_merged.to_csv(LABELED_CSV_PATH, index=False)

        # Hitung jumlah baris yang berhasil diupdate oleh ML
        updated_count = condition_to_update.sum()

        print(f"[SUCCESS] ✅ File '{LABELED_CSV_PATH}' telah diperbarui. Model ML berhasil menambahkan {updated_count} label serangan baru.")
        waktuevaluasi_end = time.time()
        print("[INFO] Waktu evaluasi: ", waktuevaluasi_end - waktuevaluasi_start)

    else:
        print("[INFO] Tidak ada data valid di 'result_filtered.csv' setelah dibersihkan.")
