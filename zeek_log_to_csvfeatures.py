#!/usr/bin/env python3
"""
zeek_log_to_csv.py

Converts a Zeek log to CSV AND keeps only the important fields
based on log type (conn, dns, http, etc.).
"""

import argparse
import csv
import os



# IMPORTANT FIELDS PER LOG TYPE
IMPORTANT_FIELDS = {
    "conn": [
        "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
        "proto", "service", "duration",
        "orig_bytes", "resp_bytes", "conn_state",
        "local_orig", "local_resp",
        "orig_pkts", "orig_ip_bytes",
        "resp_pkts", "resp_ip_bytes",
    ],
    "dns": [
        "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
        "proto", "rcode_name", "AA", "TC", "RD", "RA",
        "answers", "TTLs", "rejected",
    ],
    "http": [
        "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
        "trans_depth", "method", "host", "uri", "version",
        "user_agent", "request_body_len", "response_body_len",
        "status_code", "status_msg", "resp_fuids", "resp_mime_types",
    ],
    "files": [
        "ts", "fuid", "uid", "id.orig_h", "id.orig_p",
        "id.resp_h", "id.resp_p", "source", "depth", "analyzers",
        "mime_type", "filename", "duration",
        "local_orig", "is_orig", "seen_bytes", "total_bytes",
        "missing_bytes", "overflow_bytes", "timeout",
    ],
    "ftp": [
        "ts", "uid", "id.orig_h", "id.orig_p",
        "id.resp_h", "id.resp_p",
        "user", "password", "command",
        "reply_code", "reply_msg",
        "data_channel.passive",
        "data_channel.orig_h", "data_channel.resp_h",
        "data_channel.resp_p",
        "fuid",
    ],
    "ssh": [
        "ts", "uid", "id.orig_h", "id.orig_p",
        "id.resp_h", "id.resp_p",
        "version", "client", "server",
        "cipher_alg", "mac_alg", "compression_alg",
        "kex_alg", "host_key_alg", "host_key",
    ],
    "smtp": [
        "ts", "uid", "id.orig_h", "id.orig_p",
        "id.resp_h", "id.resp_p",
        "trans_depth", "helo", "mailfrom", "rcptto",
        "date", "from", "to", "cc", "msg_id", "subject",
        "first_received", "last_reply", "path",
        "user_agent", "tls", "fuids",
    ],
    "weird": [
        "ts", "uid", "id.orig_h", "id.orig_p",
        "id.resp_h", "id.resp_p",
        "name", "addl", "notice", "peer", "source",
    ],
     "analyzer": [
        "analyzer_name",
        "uid",
        "fuid",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
        "proto",
        "failure_reason",
    ], 
}



# AUTO-NAME HANDLER
def get_unique_path(path):
    if not os.path.exists(path):
        return path
    base, ext = os.path.splitext(path)
    counter = 1
    while True:
        new = f"{base}({counter}){ext}"
        if not os.path.exists(new):
            return new
        counter += 1


# MAIN PARSER
def parse_zeek_log(input_path):
    separator = "\t"
    fields = None
    data_rows = []

    with open(input_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue

            if line.startswith("#"):
                if line.startswith("#separator"):
                    parts = line.split()
                    if len(parts) >= 2:
                        separator = parts[1].encode().decode("unicode_escape")
                elif line.startswith("#fields"):
                    fields = line.split()[1:]
                continue

            row = line.split(separator)
            data_rows.append(row)

    if fields is None:
        raise ValueError(f"No #fields header found in {input_path}")

    # Normalize row lengths
    fixed = []
    for r in data_rows:
        if len(r) < len(fields):
            r += [""] * (len(fields) - len(r))
        fixed.append(r)

    return fields, fixed


# FILTER IMPORTANT FIELDS
def filter_fields(log_type, fields, rows):
    wanted = IMPORTANT_FIELDS.get(log_type)
    if not wanted:
        raise ValueError(f"Unknown log type: {log_type}")

    present = [f for f in wanted if f in fields]
    missing = [f for f in wanted if f not in fields]

    if missing:
        print(f"[WARN] Missing in log: {missing}")

    # Map old index → new index
    index_map = [fields.index(f) for f in present]

    new_rows = []
    for r in rows:
        new_rows.append([r[i] for i in index_map])

    return present, new_rows



# MAIN EXECUTION
def main():
    parser = argparse.ArgumentParser(description="Convert Zeek logs to filtered CSV.")
    parser.add_argument("input_log", help="Path to Zeek .log file (conn.log, dns.log, etc.)")
    args = parser.parse_args()

    input_path = args.input_log
    basename = os.path.basename(input_path)
    log_type = basename.split(".")[0]     # conn.log → conn
    output_csv = f"{log_type}.csv"

    fields, rows = parse_zeek_log(input_path)
    filtered_fields, filtered_rows = filter_fields(log_type, fields, rows)

    output_csv = get_unique_path(output_csv)
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(filtered_fields)
        writer.writerows(filtered_rows)

    print(f"[OK] Converted {input_path} → {output_csv}")
    print(f"     Columns: {len(filtered_fields)}   Rows: {len(filtered_rows)}")


if __name__ == "__main__":
    main()


