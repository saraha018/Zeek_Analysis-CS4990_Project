"""
Configuration settings for Zeek ML Classifier
"""
import os
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).parent

# Data directories
DATA_DIR = BASE_DIR / "data"
PCAP_DIR = DATA_DIR / "pcap"
ZEEK_LOGS_DIR = DATA_DIR / "zeek_logs"
FEATURES_DIR = DATA_DIR / "features"
MODELS_DIR = DATA_DIR / "models"
BENIGN_DIR = DATA_DIR / "benign"
MALWARE_DIR = DATA_DIR / "malware"

# Create directories if they don't exist
for dir_path in [DATA_DIR, PCAP_DIR, ZEEK_LOGS_DIR, FEATURES_DIR, MODELS_DIR, BENIGN_DIR, MALWARE_DIR]:
    dir_path.mkdir(parents=True, exist_ok=True)

# Zeek configuration
ZEEK_BINARY = "zeek"  # Path to Zeek binary (should be in PATH)
ZEEK_SCRIPT = "local"  # Use local.zeek script

# Feature extraction settings
FEATURE_COLUMNS = [
    # Connection features
    'duration', 'orig_bytes', 'resp_bytes', 'conn_state',
    'missed_bytes', 'orig_pkts', 'resp_pkts',
    
    # Protocol features
    'proto', 'service',
    
    # HTTP features
    'http_method', 'http_status_code', 'http_user_agent_len',
    'http_uri_len', 'http_referrer_len',
    
    # DNS features
    'dns_query', 'dns_qtype', 'dns_rcode',
    
    # SSL/TLS features
    'ssl_version', 'ssl_cipher', 'ssl_server_name',
    
    # Statistical features
    'packet_size_mean', 'packet_size_std', 'packet_size_min', 'packet_size_max',
    'inter_arrival_mean', 'inter_arrival_std',
    
    # Temporal features
    'hour', 'day_of_week',
]

# ML model settings
RANDOM_STATE = 42
TEST_SIZE = 0.2
CV_FOLDS = 5

# Model hyperparameters
RANDOM_FOREST_PARAMS = {
    'n_estimators': 100,
    'max_depth': 20,
    'min_samples_split': 5,
    'min_samples_leaf': 2,
    'random_state': RANDOM_STATE,
    'n_jobs': -1
}

