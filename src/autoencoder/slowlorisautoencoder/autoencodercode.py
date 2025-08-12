# run_experiment.py
import pandas as pd
import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import confusion_matrix, roc_curve, auc
import matplotlib.pyplot as plt
import seaborn as sns
import os
import joblib

# ==============================================================================
# 🎯 BAGIAN 1: KONFIGURASI EKSPERIMEN (UBAH NILAI DI SINI UNTUK SETIAP MODEL)
# ==============================================================================
# --- Atur Hyperparameter untuk Model Ini ---
ENCODING_DIM = 25
CODE_SIZE = 10
BATCH_SIZE = 220
EPOCHS = 100

# --- Nama File & Direktori ---
# Nama file akan dibuat secara otomatis berdasarkan parameter di atas
MODEL_NAME = f"model_enc{ENCODING_DIM}_code{CODE_SIZE}_batch{BATCH_SIZE}"
MODEL_DIR = f"./saved_models/{MODEL_NAME}" # Direktori unik untuk setiap model
EVAL_FILE_PATH = "./data/csv/slowlorisvalidation_balanced.csv"

# --- Konfigurasi Data ---
TRAIN_FILE_PATH = "../data/csv/slowloris.csv"
ATTACK_IP = "192.168.100.135"

val_mse_slowloris = []
val_mse_slowread = []
val_mse_slowpost = []

# --- Mapping Fitur (Tetap) ---
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
# ==============================================================================
# BAGIAN 2: FUNGSI-FUNGSI (Tidak perlu diubah)
# ==============================================================================

def preprocess_data(filepath):
    try:
        data = pd.read_csv(filepath)
    except FileNotFoundError:
        print(f"  [ERROR] File training '{filepath}' tidak ditemukan.")
        return None

    selected_cols = [FEATURE_MAP[f] for f in FEATURE_MAP.keys() if FEATURE_MAP[f] in data.columns]
    data = data[selected_cols].copy()
    data.replace([np.inf, -np.inf], np.nan, inplace=True)
    data.dropna(inplace=True)
    scaler = MinMaxScaler()
    X_scaled = scaler.fit_transform(data)

    return X_scaled, scaler

def build_autoencoder(input_dim, encoding_dim, code_size):
    return keras.Sequential([
        layers.Input(shape=(input_dim,)),
        layers.Dense(encoding_dim, activation='relu'),
        layers.Dense(code_size, activation='relu'),
        layers.Dense(encoding_dim, activation='relu'),
        layers.Dense(input_dim, activation='sigmoid')
    ])


def train_model(params, preprocessed_data,scaler):
    """Melatih satu model dengan hyperparameter spesifik dan menyimpannya."""
    print("\n" + "="*80)
    print(f" " * 25 + f"MEMULAI TRAINING: {params['name']}")
    print("="*80)

    X_train, X_val = train_test_split(preprocessed_data, test_size=0.2, random_state=42)

    input_dim = X_train.shape[1]
    autoencoder = build_autoencoder(input_dim, params['encoding_dim'], params['code_size'])
    autoencoder.compile(optimizer='adam', loss='mean_squared_error')

    print("\n[INFO] Memulai proses fitting model...")
    autoencoder.fit(
        X_train, X_train, epochs=params['epochs'], batch_size=params['batch_size'], shuffle=True,
        validation_data=(X_val, X_val),
        callbacks=[keras.callbacks.EarlyStopping(monitor='val_loss', patience=10, restore_best_weights=True)],
        verbose=1
    )
    print("\n[INFO] Training selesai.")

    # 🔍 Hitung MSE pada data training dan validation
    print("\n[INFO] Menghitung reconstruction error (MSE)...")
    train_preds = autoencoder.predict(X_train)
    val_preds = autoencoder.predict(X_val)
    train_mse = np.mean(np.power(train_preds - X_train, 2), axis=1)
    val_mse = np.mean(np.power(val_preds - X_val, 2), axis=1)

    print(f"  - Rata-rata MSE Training   : {train_mse.mean():.6f}")
    print(f"  - Rata-rata MSE Validation : {val_mse.mean():.6f}")

    # 📊 Plot histogram MSE pada validation set
    plt.figure(figsize=(10,6))
    sns.histplot(val_mse, bins=50, kde=True)
    plt.title("Distribusi Reconstruction Error (MSE) - Validation Set")
    plt.xlabel("Mean Squared Error (MSE)")
    plt.ylabel("Frekuensi")
    plt.grid(True)
    plt.show()

    os.makedirs(params['dir'], exist_ok=True)
    autoencoder.save(os.path.join(params['dir'], "model.h5"))
    joblib.dump(scaler, os.path.join(params['dir'], "scaler.gz"))
    print(f"\n[SUCCESS] ✅ Model dan scaler untuk '{params['name']}' berhasil disimpan di '{params['dir']}'.")

    # Simpan semua error validation (jika mau digunakan di luar)
    return autoencoder, scaler, val_mse

def define_threshold(val_mse):
    """Menentukan threshold berdasarkan error validation."""
    print("\n" + "="*80)
    print(f" " * 25 + f"MEMULAI DEFINISI THRESHOLD")
    print("="*80)

    print("\n[INFO] Menentukan threshold...")
    return np.quantile(val_mse, 0.90)

# ==============================================================================
# BAGIAN 3: EKSEKUSI UTAMA
# ==============================================================================
if __name__ == "__main__":
    # Kumpulkan parameter dari konfigurasi di atas
    params = {
        'encoding_dim': ENCODING_DIM,
        'code_size': CODE_SIZE,
        'batch_size': BATCH_SIZE,
        'epochs': EPOCHS,
        'name': MODEL_NAME,
        'dir': MODEL_DIR
    }

    # 1. Preprocessing Data sekali saja di awal
    preprocessed_data, scaler = preprocess_data(TRAIN_FILE_PATH)
    if preprocessed_data is None:
        print(f"\n[ERROR] Data training tidak ditemukan atau tidak valid.")
    else:
        thresholds = []
        num_runs = 1  # jumlah iterasi

        for run in range(num_runs):
            print(f"\n{'='*40} [RUN {run+1}/{num_runs}] {'='*40}")

            # 2. Latih model
            trained_model, trained_scaler, val_errors = train_model(params, preprocessed_data, scaler)
            val_mse_slowloris = val_errors

            # 3. Hitung threshold untuk run ini
            th = define_threshold(val_errors)
            thresholds.append(th)
            print(f"[INFO] Threshold run-{run+1}: {th:.6f}")

        # Setelah selesai semua run
        avg_threshold = np.mean(thresholds)
        std_threshold = np.std(thresholds)
        print("\n" + "="*80)
        print(f"[RESULT] Threshold 85th percentile rata-rata dari {num_runs} run : {avg_threshold:.6f}")
        print(f"[RESULT] Std. dev: {std_threshold:.6f}")
        print("="*80)

