import subprocess
import sys
import os
import re

def run_command(cmd):
    print(f"[+] Running: {cmd}")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"[-] Command failed: {e}")
        return ""

def filter_subdomains(file_path, domain):
    """
    Filter lines in file_path to keep only subdomains of 'domain',
    exclude any URLs (lines starting with http:// or https://),
    overwrite the file with filtered results.
    """
    if not os.path.exists(file_path):
        return
    with open(file_path, 'r') as f:
        lines = f.readlines()

    filtered = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        # Exclude URLs
        if line.startswith("http://") or line.startswith("https://"):
            continue
        # Only keep lines ending with the domain (case-insensitive)
        if line.lower().endswith(domain.lower()):
            filtered.append(line)

    # Remove duplicates and sort
    filtered = sorted(set(filtered))

    with open(file_path, 'w') as f:
        for line in filtered:
            f.write(line + "\n")

def append_unique(master_file, new_file):
    if not os.path.exists(master_file):
        open(master_file, 'w').close()
    with open(master_file, 'r') as f:
        existing = set(line.strip() for line in f if line.strip())
    with open(new_file, 'r') as f:
        new_lines = set(line.strip() for line in f if line.strip())
    combined = existing.union(new_lines)
    with open(master_file, 'w') as f:
        for line in sorted(combined):
            f.write(line + "\n")

def main(domain):
    master_file = f"{domain}_all_subdomains.txt"

    # List of tuples: (command, output file)
    tools = [
        (f"subfinder -d {domain} -all -recursive -o subfinder-subs.txt", "subfinder-subs.txt"),
        (f"assetfinder --subs-only {domain} > assetfinder-subs.txt", "assetfinder-subs.txt"),
        (f"chaos -d {domain} > chaos-subs.txt", "chaos-subs.txt"),
        (f"virusubs {domain} | sed -E 's|https?://||; s|/$||' > virusubs.txt", "virusubs.txt"),
        (f"curl -s \"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names\" | jq -r '.[] | .dns_names[]' | sort -u > certspotter-subs.txt", "certspotter-subs.txt"),
        (f"curl -s \"https://anubisdb.com/anubis/subdomains/{domain}\" | jq -r '.[]' > anubis-subs.txt", "anubis-subs.txt"),
        (f"curl -s \"https://api.hackertarget.com/hostsearch/?q={domain}\" | cut -d ',' -f 1 > hackertarget-subs.txt", "hackertarget-subs.txt"),
        (f"curl -s \"https://crt.sh/?q=%25.{domain}&output=json\" | jq -r '.[].name_value' | sort -u > crtsh-subs.txt", "crtsh-subs.txt"),
        (f"~/SubCerts/subcerts.sh -u {domain} > subcerts-subs.txt", "subcerts-subs.txt"),
        # (f"/home/kali/subenum/SubEnum/subenum.sh -d {domain} -u wayback,crt,abuseipdb,bufferover,Findomain,Subfinder,Assetfinder -o subenum-subs.txt", "subenum-subs.txt"),
    ]

    for cmd, outfile in tools:
        run_command(cmd)
        filter_subdomains(outfile, domain)
        append_unique(master_file, outfile)
        # Remove intermediate file
        try:
            os.remove(outfile)
            print(f"[+] Removed intermediate file: {outfile}")
        except Exception as e:
            print(f"[-] Could not remove {outfile}: {e}")

    print(f"[+] All subdomains saved in {master_file}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <domain>")
        sys.exit(1)
    target_domain = sys.argv[1]
    main(target_domain)
