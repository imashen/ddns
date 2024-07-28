import os
import requests
import json
import time
import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

# Get environment variables
provider = os.getenv('PROVIDER', 'dnspod').lower()
api_id = os.getenv('API_ID')
api_token = os.getenv('API_TOKEN')
domain = os.getenv('DOMAIN')
sub_domain = os.getenv('SUB_DOMAIN')
update_interval = int(os.getenv('UPDATE_INTERVAL', 600))  # default to 600 seconds if not set

# DNS API endpoints and parameters
if provider == 'dnspod':
    base_url = "https://dnsapi.cn"
    headers = {}
    common_payload = {
        "login_token": f"{api_id},{api_token}",
        "format": "json",
        "domain": domain,
        "sub_domain": sub_domain,
        "record_line": "默认"
    }
elif provider == 'alidns':
    base_url = "https://alidns.aliyuncs.com/"
    headers = {"Authorization": f"Bearer {api_token}"}
    common_payload = {
        "Action": "UpdateDomainRecord",
        "DomainName": domain,
        "RR": sub_domain
    }
else:
    raise ValueError("Unsupported provider. Use 'dnspod' or 'alidns'.")

# Function to get public IP addresses
def get_public_ips():
    ipv4, ipv6 = None, None
    try:
        ipv4 = requests.get("https://api-ipv4.ip.sb/ip", headers={"User-Agent": "Mozilla"}).text.strip()
    except requests.RequestException as e:
        print(f"Failed to get IPv4 address")

    try:
        ipv6 = requests.get("https://api-ipv6.ip.sb/ip", headers={"User-Agent": "Mozilla"}).text.strip()
    except requests.RequestException as e:
        print(f"Failed to get IPv6 address")

    return ipv4, ipv6

# Function to get DNS record ID
def get_record_id(record_type):
    if provider == 'dnspod':
        payload = common_payload.copy()
        payload.update({"record_type": record_type})
        try:
            response = requests.post(f"{base_url}/Record.List", headers=headers, data=payload)
            response.raise_for_status()
            result = response.json()
            if result.get("status", {}).get("code") == "1":
                for record in result.get("records", []):
                    if record.get("type") == record_type:
                        return record.get("id")
        except requests.RequestException as e:
            print(f"Failed to get {record_type} record ID: {e}")
    # Add Alidns provider handling if needed
    return None

# Function to create DNS record
def create_dns_record(record_type, ip_address):
    payload = common_payload.copy()
    payload.update({"record_type": record_type, "value": ip_address, "record_line": "默认"})
    try:
        response = requests.post(f"{base_url}/Record.Create", headers=headers, data=payload)
        response.raise_for_status()
        result = response.json()
        if result.get("status", {}).get("code") == "1":
            print(f"{record_type} record created successfully: {ip_address}")
        else:
            print(f"Failed to create {record_type} record: {result.get('status', {}).get('message')}")
    except requests.RequestException as e:
        print(f"Failed to create {record_type} record: {e}")

# Function to update DNS records
def update_dns_record(record_type, ip_address):
    if ip_address is None:
        print(f"Skipping {record_type} record update as no IP address was obtained.")
        return

    record_id = get_record_id(record_type)
    if not record_id:
        print(f"No existing {record_type} record found, creating new one.")
        create_dns_record(record_type, ip_address)
        return

    payload = common_payload.copy()
    if provider == 'dnspod':
        payload.update({"record_id": record_id, "record_type": record_type, "value": ip_address})

    # Add Alidns provider handling soon~~~~

    try:
        response = requests.post(f"{base_url}/Record.Modify", headers=headers, data=payload)
        response.raise_for_status()
        result = response.json()
    except requests.RequestException as e:
        print(f"Failed to update {record_type} record: {e}")
        return

    if provider == 'dnspod' and result.get("status", {}).get("code") == "1":
        print(f"{record_type} record updated successfully: {ip_address}")
    else:
        print(f"Failed to update {record_type} record: {result.get('status', {}).get('message')}")

def main():
    while True:
        ipv4, ipv6 = get_public_ips()
        if ipv4:
            print(f"Current IPv4: {ipv4}")
            update_dns_record("A", ipv4)
        else:
            print("No IPv4 address obtained, skipping A record update.")

        if ipv6:
            print(f"Current IPv6: {ipv6}")
            update_dns_record("AAAA", ipv6)
        else:
            print("No IPv6 address obtained, skipping AAAA record update.")
        
        time.sleep(update_interval)

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/myip':
            ipv4, ipv6 = get_public_ips()
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(f"IPv4: {ipv4}\nIPv6: {ipv6}\n".encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

def start_server():
    server_address = ('0.0.0.0', 8044)  # Listen on all interfaces
    httpd = HTTPServer(server_address, RequestHandler)
    httpd.serve_forever()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('action', nargs='?', default='update', help="Specify 'update' to update DNS records or 'myip' to get current IP addresses")
    args = parser.parse_args()

    if args.action == 'myip':
        ipv4, ipv6 = get_public_ips()
        print(f"IPv4: {ipv4}\nIPv6: {ipv6}")
    else:
        # Start the server in a separate thread
        server_thread = Thread(target=start_server)
        server_thread.daemon = True
        server_thread.start()

        main()