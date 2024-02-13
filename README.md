# toolbox.CTF

## Introduction
`toolbox.CTF` is a collection of tools designed to assist in Capture The Flag (CTF) competitions and general cybersecurity practices. This toolbox contains various scripts and utilities for tasks like scanning, brute-forcing, and analyzing files for malicious content using VirusTotal's API.

## Tools Included

### VirusTotal_API.py
This script allows users to search for file hashes against VirusTotal's database to identify potentially malicious files. It requires a VirusTotal API key to function.

### bruteforce.py
A utility for attempting brute force attacks on various services. It can be customized to target different ports and services as needed.

### nmap_scanner.py
A Python wrapper for nmap, facilitating automated scanning and reporting. It can be used to perform comprehensive scans on target networks or systems.

### nmap_scan_report.docx
A template report document for presenting findings from `nmap_scanner.py` scans in a more readable format.

## Usage

### Setting Up
1. Clone the repository to your local machine.
2. Ensure you have Python installed.
3. Install any dependencies as required by the individual scripts, typically via `pip install -r requirements.txt`.

```bash
git clone https://github.com/mangeeriiksson/toolbox.CTF
cd toolbox-ctf
pip install -r requirements.txt
```

### Running Scripts
Each script can be run from the command line. For example, to use `VirusTotal_API.py`, you would execute:

```bash
python VirusTotal_API.py <file_hash>
