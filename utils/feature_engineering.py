"""
Feature engineering utilities for Zeek logs.
"""
import pandas as pd
import numpy as np
from pathlib import Path
import json


def parse_zeek_log(log_file):
    """
    Parse a Zeek log file (TSV format).
    
    Args:
        log_file: Path to Zeek log file
        
    Returns:
        DataFrame with parsed log data
    """
    try:
        # Zeek logs are TSV with #-prefixed header
        df = pd.read_csv(
            log_file,
            sep='\t',
            comment='#',
            low_memory=False
        )
        return df
    except Exception as e:
        print(f"Error parsing {log_file}: {str(e)}")
        return pd.DataFrame()


def extract_connection_features(conn_df):
    """
    Extract features from conn.log.
    
    Args:
        conn_df: DataFrame from conn.log
        
    Returns:
        Dictionary of aggregated features
    """
    if conn_df.empty:
        return {}
    
    features = {}
    
    # Basic connection statistics
    features['total_connections'] = len(conn_df)
    features['unique_orig_ips'] = conn_df['id.orig_h'].nunique() if 'id.orig_h' in conn_df else 0
    features['unique_resp_ips'] = conn_df['id.resp_h'].nunique() if 'id.resp_h' in conn_df else 0
    
    # Duration statistics
    if 'duration' in conn_df:
        duration = pd.to_numeric(conn_df['duration'], errors='coerce')
        features['duration_mean'] = duration.mean() if not duration.isna().all() else 0
        features['duration_std'] = duration.std() if not duration.isna().all() else 0
        features['duration_max'] = duration.max() if not duration.isna().all() else 0
    
    # Byte statistics
    if 'orig_bytes' in conn_df:
        orig_bytes = pd.to_numeric(conn_df['orig_bytes'], errors='coerce')
        features['orig_bytes_total'] = orig_bytes.sum() if not orig_bytes.isna().all() else 0
        features['orig_bytes_mean'] = orig_bytes.mean() if not orig_bytes.isna().all() else 0
    
    if 'resp_bytes' in conn_df:
        resp_bytes = pd.to_numeric(conn_df['resp_bytes'], errors='coerce')
        features['resp_bytes_total'] = resp_bytes.sum() if not resp_bytes.isna().all() else 0
        features['resp_bytes_mean'] = resp_bytes.mean() if not resp_bytes.isna().all() else 0
    
    # Packet statistics
    if 'orig_pkts' in conn_df:
        orig_pkts = pd.to_numeric(conn_df['orig_pkts'], errors='coerce')
        features['orig_pkts_total'] = orig_pkts.sum() if not orig_pkts.isna().all() else 0
        features['orig_pkts_mean'] = orig_pkts.mean() if not orig_pkts.isna().all() else 0
    
    if 'resp_pkts' in conn_df:
        resp_pkts = pd.to_numeric(conn_df['resp_pkts'], errors='coerce')
        features['resp_pkts_total'] = resp_pkts.sum() if not resp_pkts.isna().all() else 0
        features['resp_pkts_mean'] = resp_pkts.mean() if not resp_pkts.isna().all() else 0
    
    # Protocol distribution
    if 'proto' in conn_df:
        proto_counts = conn_df['proto'].value_counts()
        features['proto_tcp'] = proto_counts.get('tcp', 0)
        features['proto_udp'] = proto_counts.get('udp', 0)
        features['proto_icmp'] = proto_counts.get('icmp', 0)
    
    # Connection state distribution
    if 'conn_state' in conn_df:
        state_counts = conn_df['conn_state'].value_counts()
        features['state_S0'] = state_counts.get('S0', 0)
        features['state_S1'] = state_counts.get('S1', 0)
        features['state_SF'] = state_counts.get('SF', 0)
        features['state_REJ'] = state_counts.get('REJ', 0)
    
    # Service distribution
    if 'service' in conn_df:
        service_counts = conn_df['service'].value_counts()
        features['service_http'] = service_counts.get('http', 0)
        features['service_https'] = service_counts.get('https', 0)
        features['service_dns'] = service_counts.get('dns', 0)
        features['service_ssh'] = service_counts.get('ssh', 0)
    
    return features


def extract_http_features(http_df):
    """
    Extract features from http.log.
    
    Args:
        http_df: DataFrame from http.log
        
    Returns:
        Dictionary of aggregated features
    """
    if http_df.empty:
        return {}
    
    features = {}
    
    features['http_requests'] = len(http_df)
    
    # HTTP method distribution
    if 'method' in http_df:
        method_counts = http_df['method'].value_counts()
        features['http_method_get'] = method_counts.get('GET', 0)
        features['http_method_post'] = method_counts.get('POST', 0)
        features['http_method_put'] = method_counts.get('PUT', 0)
        features['http_method_head'] = method_counts.get('HEAD', 0)
    
    # Status code statistics
    if 'status_code' in http_df:
        status = pd.to_numeric(http_df['status_code'], errors='coerce')
        features['http_status_mean'] = status.mean() if not status.isna().all() else 0
        features['http_status_2xx'] = ((status >= 200) & (status < 300)).sum()
        features['http_status_4xx'] = ((status >= 400) & (status < 500)).sum()
        features['http_status_5xx'] = ((status >= 500) & (status < 600)).sum()
    
    # URI length statistics
    if 'uri' in http_df:
        uri_lengths = http_df['uri'].astype(str).str.len()
        features['http_uri_len_mean'] = uri_lengths.mean()
        features['http_uri_len_max'] = uri_lengths.max()
        features['http_uri_len_std'] = uri_lengths.std()
    
    # User agent statistics
    if 'user_agent' in http_df:
        ua_lengths = http_df['user_agent'].astype(str).str.len()
        features['http_ua_len_mean'] = ua_lengths.mean()
        features['http_ua_len_max'] = ua_lengths.max()
        features['http_ua_unique'] = http_df['user_agent'].nunique()
    
    # Referrer statistics
    if 'referrer' in http_df:
        ref_lengths = http_df['referrer'].astype(str).str.len()
        features['http_referrer_len_mean'] = ref_lengths.mean()
        features['http_referrer_present'] = http_df['referrer'].notna().sum()
    
    return features


def extract_dns_features(dns_df):
    """
    Extract features from dns.log.
    
    Args:
        dns_df: DataFrame from dns.log
        
    Returns:
        Dictionary of aggregated features
    """
    if dns_df.empty:
        return {}
    
    features = {}
    
    features['dns_queries'] = len(dns_df)
    
    # Query type distribution
    if 'qtype' in dns_df:
        qtype_counts = dns_df['qtype'].value_counts()
        features['dns_qtype_A'] = qtype_counts.get('A', 0)
        features['dns_qtype_AAAA'] = qtype_counts.get('AAAA', 0)
        features['dns_qtype_MX'] = qtype_counts.get('MX', 0)
        features['dns_qtype_TXT'] = qtype_counts.get('TXT', 0)
    
    # Response code distribution
    # Handle both 'rcode' and 'rcode_name' columns
    rcode_col = None
    if 'rcode' in dns_df:
        rcode_col = dns_df['rcode']
    elif 'rcode_name' in dns_df:
        rcode_col = dns_df['rcode_name']
    
    if rcode_col is not None:
        rcode_counts = rcode_col.value_counts()
        features['dns_rcode_NOERROR'] = rcode_counts.get('NOERROR', 0)
        features['dns_rcode_NXDOMAIN'] = rcode_counts.get('NXDOMAIN', 0)
        features['dns_rcode_SERVFAIL'] = rcode_counts.get('SERVFAIL', 0)
    
    # Query name statistics
    if 'query' in dns_df:
        query_lengths = dns_df['query'].astype(str).str.len()
        features['dns_query_len_mean'] = query_lengths.mean()
        features['dns_query_len_max'] = query_lengths.max()
        features['dns_query_unique'] = dns_df['query'].nunique()
    
    return features


def extract_ssl_features(ssl_df):
    """
    Extract features from ssl.log.
    
    Args:
        ssl_df: DataFrame from ssl.log
        
    Returns:
        Dictionary of aggregated features
    """
    if ssl_df.empty:
        return {}
    
    features = {}
    
    features['ssl_connections'] = len(ssl_df)
    
    # SSL version distribution
    if 'version' in ssl_df:
        version_counts = ssl_df['version'].value_counts()
        features['ssl_version_TLSv12'] = version_counts.get('TLSv12', 0)
        features['ssl_version_TLSv13'] = version_counts.get('TLSv13', 0)
        features['ssl_version_TLSv11'] = version_counts.get('TLSv11', 0)
    
    # Cipher suite statistics
    if 'cipher' in ssl_df:
        features['ssl_cipher_unique'] = ssl_df['cipher'].nunique()
        cipher_counts = ssl_df['cipher'].value_counts()
        features['ssl_cipher_most_common'] = cipher_counts.iloc[0] if len(cipher_counts) > 0 else 0
    
    # Server name statistics
    if 'server_name' in ssl_df:
        features['ssl_server_name_unique'] = ssl_df['server_name'].nunique()
        sn_lengths = ssl_df['server_name'].astype(str).str.len()
        features['ssl_server_name_len_mean'] = sn_lengths.mean()
    
    return features


def extract_features_from_zeek_logs(log_dir):
    """
    Extract all features from a directory of Zeek logs.
    
    Args:
        log_dir: Directory containing Zeek log files
        
    Returns:
        Dictionary of all extracted features
    """
    log_path = Path(log_dir)
    all_features = {}
    
    # Parse different log types
    conn_file = log_path / "conn.log"
    http_file = log_path / "http.log"
    dns_file = log_path / "dns.log"
    ssl_file = log_path / "ssl.log"
    
    # Extract connection features
    if conn_file.exists():
        conn_df = parse_zeek_log(conn_file)
        conn_features = extract_connection_features(conn_df)
        all_features.update(conn_features)
    
    # Extract HTTP features
    if http_file.exists():
        http_df = parse_zeek_log(http_file)
        http_features = extract_http_features(http_df)
        all_features.update(http_features)
    
    # Extract DNS features
    if dns_file.exists():
        dns_df = parse_zeek_log(dns_file)
        dns_features = extract_dns_features(dns_df)
        all_features.update(dns_features)
    
    # Extract SSL features
    if ssl_file.exists():
        ssl_df = parse_zeek_log(ssl_file)
        ssl_features = extract_ssl_features(ssl_df)
        all_features.update(ssl_features)
    
    return all_features

