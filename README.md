# Zeek_Analysis-CS4990_Project

This project implements a pipeline for analyzing Network Traffic using Zeek (formerly Bro) and Machine Learning (ML) to extract meaningful features and detect patterns, potentially identifying malicious or anomalous network activity.

### Project Overview

The core goal of this project is to transform raw network capture files (.pcap) into a structured dataset of network flow features suitable for training a Machine Learning model.

## Pipeline Components

The project pipeline consists of the following stages:

- **Network Traffic Acquisition:** Starts with raw network traffic, either live or captured in a .pcap (Packet Capture) file.

- **Protocol Analysis (Zeek):** The .pcap is processed by Zeek, a powerful network security monitor, which generates detailed, rich logs of network activity (e.g., connection logs, DNS queries, HTTP requests).

- **Log Analysis & Feature Selection (Python):**

  - A custom Python script processes the raw Zeek logs.

  - Crucially, this is where we filter and select the specific Zeek logs (e.g., conn.log, http.log, dns.log) that contain the most relevant information for our detection goal.

  - This script then performs feature engineering to derive meaningful metrics (features).

- **Feature Dataset Creation:** The engineered features are output into a .csv (Features CSV) file.

- **Machine Learning (ML):** The final .csv dataset is used to train, test, and validate a Machine Learning model (e.g., a classifier like Random Forest for anomaly detection).

## Prerequisites

- Zeek installed and configured on your system.

- Python 3.x environment.

- Required Python libraries
  - numpy>=1.21.0
  - pandas>=1.3.0
  - scikit-learn>=1.0.0
  - matplotlib>=3.4.0
  - seaborn>=0.11.0
  - tqdm>=4.62.0
  - joblib>=1.0.0

## How to execute

### Python dependencies

pip install pandas scikit-learn numpy matplotlib seaborn tqdm joblib

### Process PCAP with Zeek

// put line to run code here

### Generate Features CSV

// put line to run code here

### Run Machine Learning Model

// put line to run code here
