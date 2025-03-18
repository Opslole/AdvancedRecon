# AdvancedRecon
AdvancedRecon is an advanced web reconnaissance tool for bug bounty hunting.   It integrates multiple recon techniques in one lightweight, Python-based script.

## ✨ Features

- **Custom Wordlist Generation:**  
  Scrapes the target homepage to generate a tailored wordlist (saved to `wordlist.txt`) for further fuzzing.

- **Favicon Hash Analysis:**  
  Downloads the favicon (`/favicon.ico`) and computes its MD5 hash.

- **SSL Certificate Subdomain Enumeration:**  
  Queries [crt.sh](https://crt.sh) for certificates issued to the target domain and extracts subdomains.

- **Virtual Host Enumeration:**  
  Uses the custom wordlist to fuzz potential virtual hosts (e.g. `admin.example.com`) by sending HTTP requests with custom Host headers and flags candidates with a 200 status code.

- **JSON Reporting:**  
  Saves detailed results to `recon_results.json`.

## 🚀 Requirements

- Python 3.x  
- [requests](https://pypi.org/project/requests/)  
- [beautifulsoup4](https://pypi.org/project/beautifulsoup4/)  

## 🛠 Installation

Clone the repository:

```bash
git clone https://github.com/Opslole/AdvancedRecon.git
cd AdvancedRecon
chmod +x AdvancedRecon.py
```

## ⚙️ Usage
Run the tool by specifying a target domain:

```bash
./AdvancedRecon.py example.com --protocol https --timeout 10 --delay 0.1 --min-length 100 --output recon_results.json

Example Output:


[12:00:00] INFO: Initialized AdvancedRecon for target: example.com using HTTPS
[12:00:01] INFO: Fetching content from https://example.com for wordlist generation...
[12:00:02] INFO: Wordlist generated with 235 unique words.
[12:00:02] INFO: Wordlist saved to wordlist.txt
[12:00:03] INFO: Downloading favicon from https://example.com/favicon.ico ...
[12:00:03] INFO: Favicon MD5 Hash: 1a2b3c4d5e6f7890...
[12:00:04] INFO: Querying crt.sh for subdomains of example.com ...
[12:00:06] INFO: crt.sh returned 15 subdomains.
[12:00:06] INFO: Starting virtual host enumeration using custom wordlist...
[12:00:12] INFO: Virtual host enumeration complete. 3 candidates found.
```
