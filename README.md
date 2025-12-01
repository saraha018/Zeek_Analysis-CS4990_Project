# Zeek Network Traffic ML Classifier

A machine learning pipeline for classifying network traffic as benign or malware using features extracted from Zeek logs (converted to CSV format).

## Overview

This project implements a complete machine learning pipeline for network traffic classification:

1. **Feature Extraction**: Extracts ML-ready features from Zeek log CSV files
2. **Ground Truth Matching**: Matches samples with attack logs using timestamp/IP-based matching
3. **Model Training**: Trains a Random Forest classifier to distinguish benign from malicious traffic
4. **Visualization**: Generates performance metrics and feature importance plots

## Project Structure

```
zeek-ml-classifier/
├── README.md
├── requirements.txt
├── config.py                       # Configuration settings
├── zeek_log_to_csv.py              # Convert Zeek .log files to CSV format
├── zeek_log_to_csvfeatures.py      # Convert Zeek logs to CSV with filtered important fields
├── extract_features_from_csv.py    # Extract features from CSV logs and match with ground truth
├── train_model.py                  # Train ML classifier
├── predict.py                      # Predict on new PCAP files
├── inspect_csv_structure.py        # Helper: Inspect CSV file structure
├── analyze_data_structure.py       # Helper: Analyze data structure and matching
├── utils/
│   ├── __init__.py
│   └── feature_engineering.py     # Feature engineering utilities
└── data/
    ├── zeek_logs/                   # CSV log files (organized by sample)
    ├── features/                    # Extracted features (CSV)
    └── models/                      # Trained models and visualizations
```

## Requirements

- Python 3.8+
- Required packages (see `requirements.txt`):
  - pandas
  - numpy
  - scikit-learn
  - matplotlib
  - seaborn
  - tqdm
  - joblib

## Installation

```bash
# Install Python dependencies
pip3 install -r requirements.txt
```

## Usage

### 0. Convert Zeek Logs to CSV (Optional)

If you have Zeek `.log` files instead of CSV files, convert them first:

**Option A: Convert all fields (full conversion)**
```bash
python3 zeek_log_to_csv.py path/to/conn.log output/conn.csv
```

**Option B: Convert with filtered important fields (recommended)**
```bash
python3 zeek_log_to_csvfeatures.py path/to/conn.log
# Outputs: conn.csv (in current directory)
```

The filtered version (`zeek_log_to_csvfeatures.py`) keeps only relevant fields for each log type, making the CSV files smaller and more focused.

### 1. Prepare Your Data

Organize your Zeek log CSV files in subdirectories (one folder per PCAP/sample):

```
data/zeek_logs/
├── sample1/
│   ├── conn.csv
│   ├── http.csv
│   ├── dns.csv
│   └── ...
├── sample2/
│   ├── conn.csv
│   ├── http.csv
│   └── ...
└── ...
```

### 2. Extract Features from CSV Files

**Note:** If you're starting with Zeek `.log` files, use the conversion scripts above first to create CSV files.

```bash
python3 extract_features_from_csv.py \
    --csv-dir data/zeek_logs \
    --ground-truth path/to/ground_truth.csv \
    --output data/features/features.csv \
    --match-mode timestamp
```

**Parameters:**

- `--csv-dir`: Directory containing CSV files (organized in subdirectories)
- `--ground-truth`: Path to ground truth CSV file (attack log format)
- `--output`: Output CSV file path (default: `data/features/features.csv`)
- `--match-mode`: Matching mode - `timestamp` (match by time ranges) or `ip` (match by IP addresses)

The script will:

- Process all CSV files in subdirectories
- Extract features from each log type (conn, http, dns, ftp, ssh, smtp, files, weird)
- Combine features from all log types per sample
- Match samples with ground truth (by timestamp or IP)
- Create a combined features CSV with labels

### 3. Train the Model

```bash
python3 train_model.py \
    --features data/features/features.csv \
    --output data/models/
```

This will:

- Train a Random Forest classifier
- Perform train/test split
- Generate performance metrics
- Create visualizations:
  - `model_performance.png` - Confusion matrix and ROC curve
  - `feature_importance.png` - Top 15 most important features
  - `class_distribution.png` - Dataset class balance
  - `roc_curve.png` - Standalone ROC curve
- Save the trained model, scaler, and metadata

### 4. Make Predictions

```bash
python3 predict.py \
    --pcap path/to/new_file.pcap \
    --model data/models/model.pkl \
    --scaler data/models/scaler.pkl \
    --features data/models/feature_names.json
```

## Ground Truth Format

The ground truth file should be a CSV with attack information. Expected columns:

- `Start time` / `Last time` - Timestamp ranges
- `Source IP` / `Destination IP` - IP addresses
- `Source Port` / `Destination Port` - Port numbers
- `Attack category` / `Attack Name` - Attack information

The script automatically detects and matches column names.

## Matching Modes

### Timestamp Matching (`--match-mode timestamp`)

- Matches samples by checking if CSV time ranges overlap with attack time ranges
- Best when you have timestamp information in both CSV files and ground truth

### IP Matching (`--match-mode ip`)

- Matches samples by checking if IP addresses in CSV files match attack IPs
- Best when IP addresses are consistent between logs and ground truth

## Output Files

After training, you'll find in `data/models/`:

- `model.pkl` - Trained Random Forest model
- `scaler.pkl` - Feature scaler
- `feature_names.json` - List of feature names
- `metrics.json` - Performance metrics
- `feature_importance.csv` - Feature importance rankings
- `model_performance.png` - Confusion matrix and ROC curve
- `feature_importance.png` - Top 15 features visualization
- `class_distribution.png` - Dataset balance visualization
- `roc_curve.png` - ROC curve plot

## Features Extracted

The pipeline extracts features from multiple Zeek log types:

**Connection Features (conn.log):**

- Duration, bytes, packets statistics
- Protocol distribution (TCP, UDP, ICMP)
- Connection state distribution
- Service distribution

**HTTP Features (http.log):**

- HTTP method distribution
- Status code statistics
- URI, user agent, referrer statistics

**DNS Features (dns.log):**

- Query type distribution
- Response code distribution
- Query name statistics

**Other Log Types:**

- FTP, SSH, SMTP, Files, Weird logs - Basic event counts and IP statistics

## Model Performance

The Random Forest classifier provides:

- Feature importance rankings
- Cross-validation scores
- ROC-AUC metrics
- Classification reports

## Helper Scripts

### Zeek Log Conversion

**`zeek_log_to_csv.py`** - Convert Zeek `.log` files to CSV format (all fields)
```bash
python3 zeek_log_to_csv.py input.log output.csv
```
- Converts a single Zeek log file to CSV
- Preserves all fields from the original log
- Useful when you need complete data

**`zeek_log_to_csvfeatures.py`** - Convert Zeek logs to CSV with filtered important fields
```bash
python3 zeek_log_to_csvfeatures.py conn.log
# Automatically creates conn.csv in current directory
```
- Converts Zeek logs to CSV but keeps only important fields per log type
- Reduces file size and focuses on relevant features
- Automatically detects log type from filename (conn.log → conn, dns.log → dns, etc.)
- Recommended for most use cases

### Data Inspection

**`inspect_csv_structure.py`** - Inspect CSV file structure and contents
```bash
# Inspect a single CSV file
python3 inspect_csv_structure.py --csv path/to/file.csv

# Inspect multiple files in a directory
python3 inspect_csv_structure.py --csv-dir data/zeek_logs
```
- Shows column names, data types, sample rows
- Useful for understanding CSV format before feature extraction

**`analyze_data_structure.py`** - Analyze data structure and matching compatibility
```bash
python3 analyze_data_structure.py data/zeek_logs path/to/ground_truth.csv
```
- Compares CSV files with ground truth file
- Checks IP address overlap (for IP-based matching)
- Checks timestamp overlap (for timestamp-based matching)
- Provides recommendations on which matching mode to use
- Useful for troubleshooting matching issues

## Notes

- **Class Imbalance**: The model handles imbalanced datasets, but balanced data performs better
- **Feature Engineering**: Features are automatically extracted based on log type detection
