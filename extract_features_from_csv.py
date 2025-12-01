#!/usr/bin/env python3
"""
Extract features from CSV files (converted Zeek logs) and merge with ground truth labels.
Handles matching by IP addresses, ports, and timestamps.
"""
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

import argparse
import pandas as pd
import numpy as np
from pathlib import Path
from tqdm import tqdm
import config
from utils.feature_engineering import (
    extract_connection_features,
    extract_http_features,
    extract_dns_features
)


def extract_features_from_csv(csv_file, log_type=None):
    """
    Extract features from a single CSV file (Zeek log converted to CSV).
    
    Args:
        csv_file: Path to CSV file
        log_type: Type of log (conn, dns, http, etc.) - auto-detected if None
        
    Returns:
        Dictionary of extracted features
    """
    try:
        # Read CSV file
        df = pd.read_csv(csv_file, low_memory=False)
        
        if df.empty:
            return {}
        
        all_features = {}
        
        # Auto-detect log type if not provided
        if log_type is None:
            if 'id.orig_h' in df.columns and 'id.resp_h' in df.columns:
                if 'method' in df.columns or 'host' in df.columns:
                    log_type = 'http'
                elif 'query' in df.columns or 'qtype' in df.columns or 'rcode_name' in df.columns:
                    log_type = 'dns'
                elif 'conn_state' in df.columns or 'proto' in df.columns:
                    log_type = 'conn'
                elif 'user' in df.columns and 'password' in df.columns:
                    log_type = 'ftp'
                elif 'version' in df.columns and 'client' in df.columns:
                    log_type = 'ssh'
                elif 'helo' in df.columns or 'mailfrom' in df.columns:
                    log_type = 'smtp'
                elif 'fuid' in df.columns and 'mime_type' in df.columns:
                    log_type = 'files'
                else:
                    log_type = 'conn'  # Default to conn
            else:
                log_type = 'unknown'
        
        # Extract features based on log type
        if log_type == 'conn':
            conn_features = extract_connection_features(df)
            all_features.update(conn_features)
        
        elif log_type == 'http':
            http_features = extract_http_features(df)
            all_features.update(http_features)
        
        elif log_type == 'dns':
            # Handle DNS log format (may have rcode_name instead of rcode)
            dns_df = df.copy()
            if 'rcode_name' in dns_df.columns and 'rcode' not in dns_df.columns:
                dns_df['rcode'] = dns_df['rcode_name']
            dns_features = extract_dns_features(dns_df)
            all_features.update(dns_features)
        
        # For other log types, extract basic statistics
        elif log_type in ['ftp', 'ssh', 'smtp', 'files', 'weird']:
            features = {}
            features[f'{log_type}_events'] = len(df)
            
            # Extract IP statistics if available
            if 'id.orig_h' in df.columns:
                features[f'{log_type}_unique_orig_ips'] = df['id.orig_h'].nunique()
            if 'id.resp_h' in df.columns:
                features[f'{log_type}_unique_resp_ips'] = df['id.resp_h'].nunique()
            
            all_features.update(features)
        
        return all_features
        
    except Exception as e:
        print(f"Error processing {csv_file}: {str(e)}")
        import traceback
        traceback.print_exc()
        return {}


def load_ground_truth_attacks(ground_truth_file):
    """
    Load ground truth from attack log format.
    
    Expected columns:
    - Start time, Last time (timestamps)
    - Source IP, Source Port
    - Destination IP, Destination Port
    - Attack category (or similar to determine if malicious)
    
    Args:
        ground_truth_file: Path to ground truth CSV file
        
    Returns:
        DataFrame with attack information
    """
    df = pd.read_csv(ground_truth_file, low_memory=False)
    
    # Clean column names (remove extra spaces, dots)
    df.columns = df.columns.str.strip().str.replace('.', '_')
    
    # Print available columns for debugging
    print(f"Ground truth columns: {list(df.columns)}")
    
    # Map common column name variations
    column_mapping = {
        'source_ip': ['Source IP', 'source_ip', 'src_ip', 'Source_IP'],
        'source_port': ['Source Port', 'source_port', 'src_port', 'Source_Port'],
        'dest_ip': ['Destination IP', 'dest_ip', 'dst_ip', 'Destination_IP', 'Destination IP'],
        'dest_port': ['Destination Port', 'dest_port', 'dst_port', 'Destination_Port', 'Destination Port'],
        'start_time': ['Start time', 'start_time', 'Start_time', 'start'],
        'end_time': ['Last time', 'end_time', 'Last_time', 'last_time', 'last'],
        'attack_category': ['Attack category', 'attack_category', 'Attack_category', 'category'],
        'attack_name': ['Attack Name', 'attack_name', 'Attack_name', 'attack']
    }
    
    # Find actual column names
    actual_columns = {}
    for key, possible_names in column_mapping.items():
        for col in df.columns:
            # Check exact match first, then case-insensitive
            if col in possible_names:
                actual_columns[key] = col
                break
            elif col.lower() in [n.lower() for n in possible_names]:
                actual_columns[key] = col
                break
    
    # Rename columns to standard names
    rename_dict = {v: k for k, v in actual_columns.items()}
    df = df.rename(columns=rename_dict)
    
    # Debug: show what columns were found
    if 'start_time' not in df.columns and 'Start time' in df.columns:
        print(f"  Warning: 'Start time' column not renamed. Keeping original name.")
    if 'end_time' not in df.columns and 'Last time' in df.columns:
        print(f"  Warning: 'Last time' column not renamed. Keeping original name.")
    
    # Mark all entries as malicious (since this is an attack log)
    df['is_malicious'] = 1
    
    # Convert timestamps if they're numeric
    if 'start_time' in df.columns:
        df['start_time'] = pd.to_numeric(df['start_time'], errors='coerce')
    if 'end_time' in df.columns:
        df['end_time'] = pd.to_numeric(df['end_time'], errors='coerce')
    
    return df


def match_by_timestamp(csv_file, attack_df):
    """
    Match a CSV file to attack entries by timestamp ranges.
    
    Args:
        csv_file: Path to CSV file
        attack_df: DataFrame with attack information (must have start_time and end_time)
        
    Returns:
        Label (1 if matches any attack time range, 0 otherwise)
    """
    try:
        df = pd.read_csv(csv_file, low_memory=False)
        
        if df.empty:
            return 0  # No data = benign
        
        # Check if CSV has timestamps
        if 'ts' not in df.columns:
            return 0  # No timestamps = can't match
        
        # Get timestamps from CSV - use min/max for range check (more efficient)
        # Sample for detailed checking if needed
        csv_times_all = pd.to_numeric(df['ts'], errors='coerce').dropna()
        
        if len(csv_times_all) == 0:
            return 0  # No valid timestamps
        
        csv_min_time = csv_times_all.min()
        csv_max_time = csv_times_all.max()
        
        print(f"    CSV time range: {csv_min_time:.0f} to {csv_max_time:.0f} ({len(csv_times_all)} timestamps)")
        
        # Check column names - handle both renamed and original column names
        start_col = None
        end_col = None
        
        if 'start_time' in attack_df.columns:
            start_col = 'start_time'
        elif 'Start time' in attack_df.columns:
            start_col = 'Start time'
        elif 'Start_time' in attack_df.columns:
            start_col = 'Start_time'
        
        if 'end_time' in attack_df.columns:
            end_col = 'end_time'
        elif 'Last time' in attack_df.columns:
            end_col = 'Last time'
        elif 'Last_time' in attack_df.columns:
            end_col = 'Last_time'
        
        if not start_col or not end_col:
            print(f"    Warning: Could not find time columns. Available: {list(attack_df.columns)[:10]}")
            return 0
        
        print(f"    Using columns: '{start_col}' and '{end_col}'")
        
        start_times = pd.to_numeric(attack_df[start_col], errors='coerce')
        end_times = pd.to_numeric(attack_df[end_col], errors='coerce')
        
        # Remove NaN values
        valid_mask = start_times.notna() & end_times.notna()
        if not valid_mask.any():
            print(f"    Warning: No valid timestamps in ground truth")
            return 0
        
        start_times = start_times[valid_mask]
        end_times = end_times[valid_mask]
        
        print(f"    Ground truth time range: {start_times.min():.0f} to {end_times.max():.0f} ({len(start_times)} attack entries)")
        
        # Check for overlap: CSV time range overlaps with any attack time range
        # Two time ranges overlap if: csv_min <= attack_end AND csv_max >= attack_start
        overlaps = (csv_min_time <= end_times) & (csv_max_time >= start_times)
        
        if overlaps.any():
            # Found time range overlap - this is enough to label as malicious
            num_overlaps = overlaps.sum()
            print(f"    ✓ Found {num_overlaps} overlapping attack time ranges - labeling as MALICIOUS")
            return 1  # Malicious
        else:
            print(f"    ✗ No time range overlap found")
        
        return 0  # Benign (no time overlap)
        
    except Exception as e:
        print(f"Error matching {csv_file} by timestamp: {str(e)}")
        import traceback
        traceback.print_exc()
        return 0  # Default to benign on error


def match_csv_to_attacks(csv_file, attack_df, match_mode='timestamp'):
    """
    Match a CSV file to attack entries in ground truth.
    
    Args:
        csv_file: Path to CSV file
        attack_df: DataFrame with attack information
        match_mode: 'timestamp' or 'ip'
        
    Returns:
        Label (1 if matches any attack, 0 otherwise)
    """
    if match_mode == 'timestamp':
        return match_by_timestamp(csv_file, attack_df)
    
    # Original IP-based matching (kept as fallback)
    try:
        df = pd.read_csv(csv_file, low_memory=False)
        
        if df.empty:
            return 0
        
        # Get unique IP pairs from CSV
        csv_ips = set()
        if 'id.orig_h' in df.columns:
            csv_ips.update(df['id.orig_h'].dropna().astype(str).unique())
        if 'id.resp_h' in df.columns:
            csv_ips.update(df['id.resp_h'].dropna().astype(str).unique())
        
        # Get IPs from attack log
        attack_ips = set()
        if 'source_ip' in attack_df.columns:
            attack_ips.update(attack_df['source_ip'].dropna().astype(str).str.strip().unique())
        if 'dest_ip' in attack_df.columns:
            attack_ips.update(attack_df['dest_ip'].dropna().astype(str).str.strip().unique())
        
        csv_ips = {ip.strip() for ip in csv_ips}
        
        if csv_ips & attack_ips:
            return 1
        
        return 0
        
    except Exception as e:
        print(f"Error matching {csv_file}: {str(e)}")
        return 0


def process_csv_directory(csv_dir, ground_truth_file, output_file=None, match_mode='timestamp', combine_log_types=True):
    """
    Process all CSV files in a directory, extract features, and merge with ground truth.
    
    Args:
        csv_dir: Directory containing CSV files
        ground_truth_file: Path to ground truth CSV file (attack log format)
        output_file: Output CSV file path (default: data/features/features.csv)
        match_mode: How to match ('ip' for IP-based, 'filename' for filename-based)
    """
    csv_path = Path(csv_dir)
    
    if not csv_path.exists():
        raise ValueError(f"Directory not found: {csv_dir}")
    
    # Load ground truth
    print(f"Loading ground truth from {ground_truth_file}...")
    attack_df = load_ground_truth_attacks(ground_truth_file)
    print(f"Loaded {len(attack_df)} attack entries")
    
    # Show sample of attack IPs for debugging
    if 'source_ip' in attack_df.columns:
        sample_ips = attack_df['source_ip'].dropna().unique()[:5]
        print(f"Sample source IPs from ground truth: {list(sample_ips)}")
    if 'dest_ip' in attack_df.columns:
        sample_ips = attack_df['dest_ip'].dropna().unique()[:5]
        print(f"Sample destination IPs from ground truth: {list(sample_ips)}")
    
    # Check if CSV files are organized in subdirectories (one per PCAP/sample)
    subdirs = [d for d in csv_path.iterdir() if d.is_dir()]
    csv_files_direct = list(csv_path.glob("*.csv"))
    
    if subdirs and not csv_files_direct:
        # CSV files are organized in subdirectories (one folder per PCAP/sample)
        print(f"Found {len(subdirs)} sample directories")
        print("Processing each directory as a separate sample...")
        process_by_subdirectories = True
    elif csv_files_direct and not subdirs:
        # CSV files are directly in the directory (all from one sample)
        print(f"Found {len(csv_files_direct)} CSV files in root directory")
        process_by_subdirectories = False
        csv_files = csv_files_direct
    else:
        # Mixed structure - prefer subdirectories if they exist
        if subdirs:
            print(f"Found {len(subdirs)} sample directories and {len(csv_files_direct)} CSV files in root")
            print("Processing subdirectories as separate samples...")
            process_by_subdirectories = True
        else:
            process_by_subdirectories = False
            csv_files = csv_files_direct
    
    if process_by_subdirectories:
        # Process each subdirectory as a separate sample
        feature_list = []
        matched_count = 0
        
        for subdir in tqdm(subdirs, desc="Processing samples"):
            csv_files = list(subdir.glob("*.csv"))
            
            if not csv_files:
                print(f"  ⚠ No CSV files in {subdir.name}")
                continue
            
            print(f"\n  Processing sample: {subdir.name} ({len(csv_files)} CSV files)")
            
            # Extract and combine features from all CSV files in this subdirectory
            combined_features = {}
            
            for csv_file in csv_files:
                # Determine log type from filename
                log_type = None
                filename_lower = csv_file.stem.lower()
                if 'conn' in filename_lower:
                    log_type = 'conn'
                elif 'http' in filename_lower:
                    log_type = 'http'
                elif 'dns' in filename_lower:
                    log_type = 'dns'
                elif 'ftp' in filename_lower:
                    log_type = 'ftp'
                elif 'ssh' in filename_lower:
                    log_type = 'ssh'
                elif 'smtp' in filename_lower:
                    log_type = 'smtp'
                elif 'files' in filename_lower:
                    log_type = 'files'
                elif 'weird' in filename_lower:
                    log_type = 'weird'
                
                features = extract_features_from_csv(csv_file, log_type)
                if features:
                    combined_features.update(features)
            
            if combined_features:
                # Match with ground truth using conn.csv if available, otherwise first file
                matching_csv = None
                for csv_file in csv_files:
                    if 'conn' in csv_file.stem.lower():
                        matching_csv = csv_file
                        break
                
                if not matching_csv and csv_files:
                    matching_csv = csv_files[0]
                
                if matching_csv:
                    label = match_csv_to_attacks(matching_csv, attack_df, match_mode)
                else:
                    label = 0
                
                combined_features['label'] = label
                combined_features['sample_id'] = subdir.name
                
                if label == 1:
                    matched_count += 1
                    print(f"    ✓ Matched as malicious")
                else:
                    print(f"    - Labeled as benign")
                
                feature_list.append(combined_features)
        
        # Skip the combine_log_types section since we already processed subdirectories
        matched_count_total = matched_count
        # Jump to final processing section
        if not feature_list:
            print("No features extracted!")
            return
    else:
        # Original behavior: process all CSV files in root directory
        if not csv_files:
            raise ValueError(f"No CSV files found in {csv_dir}")
        
        print(f"Found {len(csv_files)} CSV files")
        
        # Process CSV files in root directory
        if combine_log_types:
            print("\nCombining all log types into single feature vectors...")
            # All CSV files are different log types from the same time period
            # Combine them into one feature vector
            
            # Extract features from all CSV files and combine
            combined_features = {}
            sample_times = []
            
            for csv_file in tqdm(csv_files, desc="Extracting features from log types"):
                # Determine log type from filename
                log_type = None
                filename_lower = csv_file.stem.lower()
                if 'conn' in filename_lower:
                    log_type = 'conn'
                elif 'http' in filename_lower:
                    log_type = 'http'
                elif 'dns' in filename_lower:
                    log_type = 'dns'
                elif 'ftp' in filename_lower:
                    log_type = 'ftp'
                elif 'ssh' in filename_lower:
                    log_type = 'ssh'
                elif 'smtp' in filename_lower:
                    log_type = 'smtp'
                elif 'files' in filename_lower:
                    log_type = 'files'
                elif 'weird' in filename_lower:
                    log_type = 'weird'
                
                features = extract_features_from_csv(csv_file, log_type)
                
                if features:
                    # Combine all features
                    combined_features.update(features)
                    
                    # Collect timestamps for matching
                    try:
                        df = pd.read_csv(csv_file, nrows=100)  # Sample for timestamps
                        if 'ts' in df.columns:
                            times = pd.to_numeric(df['ts'], errors='coerce').dropna()
                            if len(times) > 0:
                                sample_times.extend(times.tolist())
                    except:
                        pass
            
            # Create one combined sample
            if combined_features:
                # Try to match using conn.csv first (most comprehensive), then try others
                matching_csv = None
                for csv_file in csv_files:
                    if 'conn' in csv_file.stem.lower():
                        matching_csv = csv_file
                        break
                
                # If no conn.csv, use first file
                if not matching_csv and csv_files:
                    matching_csv = csv_files[0]
                
                if matching_csv:
                    print(f"\n  Matching using: {matching_csv.name}")
                    label = match_csv_to_attacks(matching_csv, attack_df, match_mode)
                    
                    # Debug: show time ranges
                    try:
                        df_sample = pd.read_csv(matching_csv, nrows=100)
                        if 'ts' in df_sample.columns:
                            times = pd.to_numeric(df_sample['ts'], errors='coerce').dropna()
                            if len(times) > 0:
                                print(f"    CSV time range: {times.min():.0f} to {times.max():.0f}")
                    except:
                        pass
                    
                    # Check ground truth time range
                    if 'start_time' in attack_df.columns or 'Start time' in attack_df.columns:
                        start_col = 'start_time' if 'start_time' in attack_df.columns else 'Start time'
                        end_col = 'end_time' if 'end_time' in attack_df.columns else 'Last time'
                        start_times = pd.to_numeric(attack_df[start_col], errors='coerce')
                        end_times = pd.to_numeric(attack_df[end_col], errors='coerce')
                        print(f"    Ground truth time range: {start_times.min():.0f} to {end_times.max():.0f}")
                else:
                    label = 0
                
                combined_features['label'] = label
                combined_features['sample_id'] = 'combined_logs'
                
                feature_list = [combined_features]
                matched_count = 1 if label == 1 else 0
                
                if label == 1:
                    print(f"\n  ✓ Matched combined logs as malicious")
                else:
                    print(f"\n  - Combined logs labeled as benign")
        else:
            # Original behavior: process each CSV file separately
            feature_list = []
            matched_count = 0
            
            for csv_file in tqdm(csv_files, desc="Extracting features"):
                # Determine log type from filename if possible
                log_type = None
                filename_lower = csv_file.stem.lower()
                if 'conn' in filename_lower:
                    log_type = 'conn'
                elif 'http' in filename_lower:
                    log_type = 'http'
                elif 'dns' in filename_lower:
                    log_type = 'dns'
                elif 'ftp' in filename_lower:
                    log_type = 'ftp'
                elif 'ssh' in filename_lower:
                    log_type = 'ssh'
                elif 'smtp' in filename_lower:
                    log_type = 'smtp'
                elif 'files' in filename_lower:
                    log_type = 'files'
                elif 'weird' in filename_lower:
                    log_type = 'weird'
                
                features = extract_features_from_csv(csv_file, log_type)
                
                if features:
                    # Match with ground truth
                    if match_mode == 'timestamp':
                        label = match_csv_to_attacks(csv_file, attack_df, match_mode)
                    elif match_mode == 'ip':
                        label = match_csv_to_attacks(csv_file, attack_df, match_mode)
                    else:
                        # Filename-based matching (fallback)
                        label = 0  # Default to benign
                    
                    features['label'] = label
                    features['sample_id'] = csv_file.stem
                    
                    if label == 1:
                        matched_count += 1
                        print(f"\n  ✓ Matched {csv_file.name} as malicious")
                    
                    feature_list.append(features)
                else:
                    print(f"\n  ⚠ No features extracted from {csv_file.name}")
    
    if not feature_list:
        print("No features extracted!")
        return
    
    # Convert to DataFrame
    df = pd.DataFrame(feature_list)
    
    # Fill NaN values with 0
    df = df.fillna(0)
    
    # Report results
    print(f"\nLabeling Results:")
    if 'matched_count_total' in locals():
        print(f"  Malicious samples: {matched_count_total}/{len(feature_list)}")
    else:
        print(f"  Malicious samples: {matched_count}/{len(feature_list)}")
    print(f"  Benign samples: {(df['label'] == 0).sum()}")
    print(f"  Malware samples: {(df['label'] == 1).sum()}")
    
    # Save features
    if output_file is None:
        output_file = config.FEATURES_DIR / "features.csv"
    else:
        output_file = Path(output_file)
    
    output_file.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_file, index=False)
    print(f"\nSaved features to {output_file}")
    print(f"Total samples: {len(df)}")
    print(f"Total features: {len(df.columns) - 2}")  # Exclude label and sample_id
    
    return df


def main():
    parser = argparse.ArgumentParser(
        description="Extract features from CSV files and merge with ground truth labels"
    )
    parser.add_argument(
        '--csv-dir',
        type=str,
        required=True,
        help='Directory containing CSV files (one per log)'
    )
    parser.add_argument(
        '--ground-truth',
        type=str,
        required=True,
        help='Path to ground truth CSV file (attack log format)'
    )
    parser.add_argument(
        '--output',
        type=str,
        default=None,
        help='Output CSV file path (default: data/features/features.csv)'
    )
    parser.add_argument(
        '--match-mode',
        type=str,
        default='timestamp',
        choices=['ip', 'timestamp', 'filename'],
        help='Matching mode: ip (match by IP), timestamp (match by time ranges), or filename'
    )
    parser.add_argument(
        '--combine-logs',
        action='store_true',
        default=True,
        help='Combine all log types into single feature vectors (default: True)'
    )
    parser.add_argument(
        '--no-combine-logs',
        dest='combine_logs',
        action='store_false',
        help='Process each CSV file separately'
    )
    
    args = parser.parse_args()
    
    try:
        process_csv_directory(
            args.csv_dir,
            args.ground_truth,
            args.output,
            args.match_mode,
            args.combine_logs
        )
    except Exception as e:
        print(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
