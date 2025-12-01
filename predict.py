#!/usr/bin/env python3
"""
Predict whether a PCAP file contains benign or malware traffic.
"""
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

import argparse
import subprocess
import tempfile
import shutil
import pandas as pd
import numpy as np
from joblib import load
import json
import config
from utils.feature_engineering import extract_features_from_zeek_logs


def process_pcap_and_extract_features(pcap_file, temp_dir=None):
    """
    Process PCAP file with Zeek and extract features.
    
    Args:
        pcap_file: Path to PCAP file
        temp_dir: Temporary directory for Zeek logs (optional)
        
    Returns:
        Dictionary of features
    """
    pcap_path = Path(pcap_file)
    
    # Create temporary directory for Zeek logs if not provided
    if temp_dir is None:
        temp_dir = tempfile.mkdtemp()
        cleanup_temp = True
    else:
        cleanup_temp = False
    
    temp_path = Path(temp_dir)
    log_dir = temp_path / pcap_path.stem
    log_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        # Run Zeek on PCAP file
        cmd = [
            config.ZEEK_BINARY,
            '-r', str(pcap_path),
            '-C',
            '-b',
            'local',
            'Log::default_logdir=' + str(log_dir)
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.returncode != 0:
            print(f"Error processing PCAP with Zeek: {result.stderr}")
            return None
        
        # Extract features
        features = extract_features_from_zeek_logs(log_dir)
        
        return features
        
    except Exception as e:
        print(f"Error: {str(e)}")
        return None
    finally:
        if cleanup_temp:
            shutil.rmtree(temp_dir, ignore_errors=True)


def predict_single_pcap(pcap_file, model_file, scaler_file, feature_names_file):
    """
    Predict label for a single PCAP file.
    
    Args:
        pcap_file: Path to PCAP file
        model_file: Path to trained model
        scaler_file: Path to scaler
        feature_names_file: Path to feature names JSON
        
    Returns:
        Prediction (0=benign, 1=malware), probability
    """
    # Load model, scaler, and feature names
    model = load(model_file)
    scaler = load(scaler_file)
    
    with open(feature_names_file, 'r') as f:
        feature_names = json.load(f)
    
    # Process PCAP and extract features
    print(f"Processing {pcap_file}...")
    features = process_pcap_and_extract_features(pcap_file)
    
    if features is None:
        return None, None
    
    # Create feature vector matching training features
    feature_vector = []
    for feat_name in feature_names:
        if feat_name in features:
            feature_vector.append(features[feat_name])
        else:
            feature_vector.append(0)  # Missing features set to 0
    
    feature_vector = np.array(feature_vector).reshape(1, -1)
    
    # Scale features
    feature_vector_scaled = scaler.transform(feature_vector)
    
    # Predict
    prediction = model.predict(feature_vector_scaled)[0]
    probability = model.predict_proba(feature_vector_scaled)[0]
    
    return prediction, probability


def main():
    parser = argparse.ArgumentParser(
        description="Predict if PCAP file contains benign or malware traffic"
    )
    parser.add_argument(
        '--pcap',
        type=str,
        required=True,
        help='Path to PCAP file'
    )
    parser.add_argument(
        '--model',
        type=str,
        default=str(config.MODELS_DIR / "model.pkl"),
        help='Path to trained model'
    )
    parser.add_argument(
        '--scaler',
        type=str,
        default=str(config.MODELS_DIR / "scaler.pkl"),
        help='Path to scaler'
    )
    parser.add_argument(
        '--features',
        type=str,
        default=str(config.MODELS_DIR / "feature_names.json"),
        help='Path to feature names JSON'
    )
    parser.add_argument(
        '--output',
        type=str,
        default=None,
        help='Output file for results (optional)'
    )
    
    args = parser.parse_args()
    
    # Check if files exist
    if not Path(args.pcap).exists():
        print(f"Error: PCAP file not found: {args.pcap}")
        return
    
    if not Path(args.model).exists():
        print(f"Error: Model file not found: {args.model}")
        return
    
    if not Path(args.scaler).exists():
        print(f"Error: Scaler file not found: {args.scaler}")
        return
    
    if not Path(args.features).exists():
        print(f"Error: Feature names file not found: {args.features}")
        return
    
    # Predict
    prediction, probability = predict_single_pcap(
        args.pcap,
        args.model,
        args.scaler,
        args.features
    )
    
    if prediction is None:
        print("Failed to make prediction")
        return
    
    # Display results
    label = "MALWARE" if prediction == 1 else "BENIGN"
    malware_prob = probability[1] if len(probability) > 1 else probability[0]
    benign_prob = probability[0]
    
    print(f"\n{'='*50}")
    print(f"Prediction Results")
    print(f"{'='*50}")
    print(f"PCAP File: {args.pcap}")
    print(f"Prediction: {label}")
    print(f"Confidence:")
    print(f"  Benign: {benign_prob:.4f} ({benign_prob*100:.2f}%)")
    print(f"  Malware: {malware_prob:.4f} ({malware_prob*100:.2f}%)")
    print(f"{'='*50}")
    
    # Save to file if requested
    if args.output:
        results = {
            'pcap_file': str(args.pcap),
            'prediction': int(prediction),
            'label': label,
            'probabilities': {
                'benign': float(benign_prob),
                'malware': float(malware_prob)
            }
        }
        
        output_path = Path(args.output)
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\nResults saved to {output_path}")


if __name__ == "__main__":
    main()

