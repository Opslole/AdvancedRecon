#!/usr/bin/env python3
"""
Advanced Reconnaissance Tool for Web Bug Bounty Hunting
--------------------------------------------------------

Features:
1. Custom Wordlist Generation:
   - Scrapes the target homepage, removes non-essential elements,
     and extracts unique words (minimum 3 letters).
   - Saves the resulting wordlist to a file named "wordlist.txt" for fuzzing.

2. Favicon Hash Analysis:
   - Downloads the favicon (assumed at /favicon.ico) and computes its MD5 hash.
   - The hash can later be used (e.g., with Shodan) to find similar assets.

3. SSL Certificate Subdomain Enumeration:
   - Queries crt.sh with a wildcard for the target domain and extracts subdomains
     from certificate records.

4. Virtual Host Enumeration:
   - Uses the custom wordlist to generate candidate subdomains (e.g. blog.example.com).
   - Instead of obtaining a baseline response from an invalid host, it flags any candidate
     that returns a HTTP 200 status code and a response length above a small threshold.
   - This should help focus on hosts that appear to be live without relying on a baseline.

Results are saved to a JSON file ("recon_results.json") and the wordlist to "wordlist.txt".

References:
  :contentReference[oaicite:0]{index=0} (wordlist generation),
  :contentReference[oaicite:1]{index=1} and :contentReference[oaicite:2]{index=2} (favicon analysis),
  :contentReference[oaicite:3]{index=3} (vhost enumeration techniques).

Author: Your Name
Date: 2025-03-18
"""

import argparse
import logging
import requests
import re
import hashlib
import json
import sys
import time
from bs4 import BeautifulSoup

# =============================================================================
# Setup Logging and Global Variables
# =============================================================================
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%H:%M:%S'
)

DEFAULT_USER_AGENT = "AdvancedReconTool/1.0 (Python)"


# =============================================================================
# Define the ReconTool Class
# =============================================================================
class ReconTool:
    def __init__(self, domain, protocol='http', timeout=10, user_agent=DEFAULT_USER_AGENT):
        self.domain = domain.lower().strip()
        self.protocol = protocol.lower().strip()
        self.timeout = timeout
        self.headers = {"User-Agent": user_agent}
        self.base_url = f"{self.protocol}://{self.domain}"
        self.results = {
            "wordlist": [],
            "favicon_hash": None,
            "crt_subdomains": [],
            "vhost_candidates": []
        }
        logging.info(f"Initialized ReconTool for target: {self.domain} using {self.protocol.upper()}")

    # -------------------------------------------------------------------------
    # Module 1: Custom Wordlist Generation
    # -------------------------------------------------------------------------
    def generate_custom_wordlist(self):
        """
        Scrape the target homepage to generate a custom wordlist.
        Extracts text from the page (ignoring scripts, styles, headers, etc.),
        extracts words of at least 3 letters, and deduplicates them.
        """
        logging.info(f"Fetching content from {self.base_url} for wordlist generation...")
        try:
            response = requests.get(self.base_url, headers=self.headers, timeout=self.timeout)
            if response.status_code != 200:
                logging.error(f"Failed to fetch {self.base_url} (HTTP {response.status_code})")
                return []
            soup = BeautifulSoup(response.text, "html.parser")
            # Remove non-content tags
            for tag in soup(["script", "style", "noscript", "header", "footer", "nav"]):
                tag.decompose()
            text = soup.get_text(separator=" ")
            text = re.sub(r'\s+', ' ', text)
            words = re.findall(r'\b[a-zA-Z]{3,}\b', text)
            unique_words = sorted(set(word.lower() for word in words))
            self.results["wordlist"] = unique_words
            logging.info(f"Wordlist generated with {len(unique_words)} unique words.")

            # Save wordlist to file for fuzzing
            try:
                with open("wordlist.txt", "w") as wf:
                    for word in unique_words:
                        wf.write(word + "\n")
                logging.info("Wordlist saved to wordlist.txt")
            except Exception as file_err:
                logging.error(f"Error writing wordlist.txt: {file_err}")

            return unique_words
        except Exception as e:
            logging.error(f"Exception during wordlist generation: {e}")
            return []

    # -------------------------------------------------------------------------
    # Module 2: Favicon Hash Analysis
    # -------------------------------------------------------------------------
    def analyze_favicon_hash(self):
        """
        Downloads the favicon from the target (assumed at /favicon.ico)
        and computes its MD5 hash.
        """
        favicon_url = self.base_url.rstrip('/') + '/favicon.ico'
        logging.info(f"Downloading favicon from {favicon_url} ...")
        try:
            resp = requests.get(favicon_url, headers=self.headers, timeout=self.timeout)
            if resp.status_code != 200:
                logging.warning(f"Favicon not found at {favicon_url} (HTTP {resp.status_code})")
                return None
            favicon_data = resp.content
            fav_hash = hashlib.md5(favicon_data).hexdigest()
            self.results["favicon_hash"] = fav_hash
            logging.info(f"Favicon MD5 Hash: {fav_hash}")
            return fav_hash
        except Exception as e:
            logging.error(f"Error during favicon analysis: {e}")
            return None

    # -------------------------------------------------------------------------
    # Module 3: SSL Certificate Subdomain Enumeration via crt.sh
    # -------------------------------------------------------------------------
    def ssl_cert_subdomain_enumeration(self):
        """
        Queries crt.sh for certificates issued to the target domain.
        Extracts and deduplicates subdomains from the JSON output.
        """
        query_url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        logging.info(f"Querying crt.sh for subdomains of {self.domain} ...")
        try:
            resp = requests.get(query_url, headers=self.headers, timeout=self.timeout)
            if resp.status_code != 200:
                logging.error(f"crt.sh query failed (HTTP {resp.status_code})")
                return []
            try:
                data = resp.json()
            except json.JSONDecodeError:
                logging.error("Failed to decode JSON from crt.sh response.")
                return []
            subdomains_set = set()
            for entry in data:
                names = entry.get("name_value", "")
                for sub in names.splitlines():
                    sub = sub.strip().lower()
                    if self.domain in sub:
                        subdomains_set.add(sub)
            crt_subdomains = sorted(subdomains_set)
            self.results["crt_subdomains"] = crt_subdomains
            logging.info(f"crt.sh returned {len(crt_subdomains)} subdomains.")
            return crt_subdomains
        except Exception as e:
            logging.error(f"Exception during crt.sh subdomain enumeration: {e}")
            return []

    # -------------------------------------------------------------------------
    # Module 4: Virtual Host Enumeration (VHost Fuzzing)
    # -------------------------------------------------------------------------
    def virtual_host_enumeration(self, wordlist, delay=0.1, min_length=100):
        """
        Performs virtual host enumeration by generating candidate hostnames using
        the provided wordlist (e.g. word.domain). Instead of comparing with a baseline
        invalid host, this method flags any candidate that returns an HTTP 200 response
        and whose response length exceeds a minimal threshold (min_length) as a potential
        virtual host.
        """
        valid_hosts = []
        target_url = self.base_url
        logging.info("Starting virtual host enumeration...")
        for word in wordlist:
            candidate = f"{word}.{self.domain}"
            try:
                resp = requests.get(
                    target_url,
                    headers={"Host": candidate, "User-Agent": self.headers["User-Agent"]},
                    timeout=self.timeout
                )
                resp_length = len(resp.content)
                # Candidate qualifies if status is 200 and response length is above threshold.
                if resp.status_code == 200 and resp_length >= min_length:
                    logging.info(f"Candidate: {candidate} (HTTP 200, {resp_length} bytes)")
                    valid_hosts.append(candidate)
                time.sleep(delay)
            except Exception as e:
                logging.debug(f"Request for {candidate} failed: {e}")
                continue

        self.results["vhost_candidates"] = valid_hosts
        logging.info(f"Virtual host enumeration complete. {len(valid_hosts)} candidates identified.")
        return valid_hosts

    # -------------------------------------------------------------------------
    # Save and Report Functions
    # -------------------------------------------------------------------------
    def save_results(self, filename="recon_results.json"):
        """
        Saves the complete results dictionary to a JSON file.
        """
        try:
            with open(filename, "w") as outfile:
                json.dump(self.results, outfile, indent=4)
            logging.info(f"Results saved to {filename}.")
        except Exception as e:
            logging.error(f"Error saving results: {e}")

    def print_summary(self):
        """
        Prints a detailed summary of the reconnaissance results.
        """
        print("\nReconnaissance Summary")
        print("=" * 50)
        print(f"Target Domain      : {self.domain}")
        print(f"Base URL           : {self.base_url}")
        print(f"Favicon MD5 Hash   : {self.results.get('favicon_hash', 'N/A')}")
        print(f"Wordlist Size      : {len(self.results.get('wordlist', []))} words (saved to wordlist.txt)")
        print(f"Subdomains (crt.sh): {len(self.results.get('crt_subdomains', []))} found")
        print(f"Virtual Hosts      : {len(self.results.get('vhost_candidates', []))} candidates")
        print("=" * 50)
        print("\nWordlist:")
        for word in self.results.get("wordlist", []):
            print(f"  - {word}")
        print("\nSubdomains from crt.sh:")
        for sub in self.results.get("crt_subdomains", []):
            print(f"  - {sub}")
        print("\nVirtual Host Candidates:")
        for vh in self.results.get("vhost_candidates", []):
            print(f"  - {vh}")
        print("=" * 50)
        print("End of Summary\n")


# =============================================================================
# Utility Functions
# =============================================================================
def print_banner():
    banner = r"""
     ___            _                        _               
    | _ \___ _ _ __| |___ _ __  ___ _ _  __| |___ _ _  ___  
    |   / -_) '_/ _` / -_) '_ \/ -_) ' \/ _` / -_) ' \/ -_) 
    |_|_\___|_| \__,_\___| .__/\___|_||_\__,_\___|_||_\___| 
                        |_|                               
    Advanced Recon Tool for Bug Bounty Hunting
    -----------------------------------------------------
    """
    print(banner)
    print("Developed for ethical bug bounty research\n")


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Advanced Recon Tool for Web Bug Bounty Hunting"
    )
    parser.add_argument("domain", help="Target domain (e.g., example.com)")
    parser.add_argument("--protocol", default="http", choices=["http", "https"],
                        help="Protocol to use (default: http)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Timeout for HTTP requests (default: 10 seconds)")
    parser.add_argument("--delay", type=float, default=0.1,
                        help="Delay between requests during vhost fuzzing (default: 0.1 sec)")
    parser.add_argument("--min-length", type=int, default=100,
                        help="Minimum response length to consider a vhost candidate (default: 100 bytes)")
    parser.add_argument("--output", default="recon_results.json",
                        help="Output JSON filename (default: recon_results.json)")
    return parser.parse_args()


# =============================================================================
# Main Function
# =============================================================================
def main():
    print_banner()
    args = parse_arguments()

    # Instantiate the recon tool with given parameters
    recon = ReconTool(domain=args.domain, protocol=args.protocol, timeout=args.timeout)

    # Module 1: Generate and save custom wordlist
    words = recon.generate_custom_wordlist()
    if not words:
        logging.warning("No words extracted; using a fallback wordlist.")
        words = ["admin", "blog", "test", "dev", "staging", "api"]
        recon.results["wordlist"] = words

    # Module 2: Favicon hash analysis
    recon.analyze_favicon_hash()

    # Module 3: SSL Certificate Subdomain Enumeration via crt.sh
    recon.ssl_cert_subdomain_enumeration()

    # Module 4: Virtual Host Enumeration using the custom wordlist.
    recon.virtual_host_enumeration(words, delay=args.delay, min_length=args.min_length)

    # Save all results to JSON file.
    recon.save_results(filename=args.output)

    # Print the detailed summary.
    recon.print_summary()


# =============================================================================
# Entry Point
# =============================================================================
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.error("Execution interrupted by user.")
        sys.exit(1)
    except Exception as ex:
        logging.error(f"An unexpected error occurred: {ex}")
        sys.exit(1)
