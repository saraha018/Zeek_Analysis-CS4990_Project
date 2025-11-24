#!/usr/bin/env python3
"""
zeek_log_to_csv.py

Script to convert a single Zeek log file into a CSV file.
"""

import argparse
import csv
import os


def parse_zeek_log(input_path, output_path):
    """
    Read a Zeek log file and write it out as a CSV.
    Open the Zeek log and read line by line.
    Find the field separator from '#separator' (usually '\x09' = tab).
    Find the column names from '#fields'.
    Skip all other header/comment lines starting with '#'.
    Split each remaining data line using the separator and write to CSV.
    """

    # Default separator is tab, but we will override it if #separator is present.
    separator = "\t"
    fields = None  # Column names will be filled from "#fields"
    data_rows = []

    with open(input_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")

            # Skip completely empty lines
            if not line:
                continue

            # Handle Zeek header lines (they all start with '#')
            if line.startswith("#"):
                # Example: "#separator \x09"
                if line.startswith("#separator"):
                    # Split on whitespace and take the last token (e.g., '\x09')
                    parts = line.split()
                    if len(parts) >= 2:
                        raw_sep = parts[1]
                        # The separator may be in escaped form like '\x09'
                        # Decode escape sequences so '\x09' becomes an actual tab character.
                        separator = raw_sep.encode("utf-8").decode("unicode_escape")

                # Example: "#fields ts uid id.orig_h id.orig_p ..."
                elif line.startswith("#fields"):
                    parts = line.split()
                    # parts[0] is '#fields', the rest are the column names
                    fields = parts[1:]

                # Ignore all other header lines (e.g., #types, #path, #open, #close)
                continue

            # At this point, the line is a data line (does not start with '#')
            # Split it using the detected separator.
            row = line.split(separator)
            data_rows.append(row)

    # Safety check: we must have discovered the columns from '#fields'
    if fields is None:
        raise ValueError(f"No '#fields' header line found in {input_path}")

    # Optional: ensure each row has the same length as fields.
    # If not, we can truncate or pad. Here we truncate extra columns.
    cleaned_rows = []
    num_fields = len(fields)
    for row in data_rows:
        if len(row) > num_fields:
            row = row[:num_fields]
        elif len(row) < num_fields:
            # Pad with empty strings if the row is shorter
            row = row + [""] * (num_fields - len(row))
        cleaned_rows.append(row)

    # Write out to CSV using Python's csv module
    # newline='' is important on Windows to avoid blank lines.
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as out_f:
        writer = csv.writer(out_f)
        # First write the header row
        writer.writerow(fields)
        # Then write all data rows
        writer.writerows(cleaned_rows)

    print(f"Converted {input_path} -> {output_path}")
    print(f"Rows (excluding header): {len(cleaned_rows)}")
    print(f"Columns: {len(fields)}")


def main():
    """
    Parse command-line arguments and run the conversion.
    """
    parser = argparse.ArgumentParser(
        description="Convert a Zeek log file to CSV."
    )
    parser.add_argument(
        "input_log",
        help="Path to the Zeek .log file (e.g., conn.log, dns.log, http.log)",
    )
    parser.add_argument(
        "output_csv",
        help="Path to the output .csv file (will be created or overwritten)",
    )

    args = parser.parse_args()

    parse_zeek_log(args.input_log, args.output_csv)


if __name__ == "__main__":
    main()
