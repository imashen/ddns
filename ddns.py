import os
import requests
import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread


provider = os.getenv('PROVIDER').lower()
api_id = os.getenv('API_ID')
api_token = os.getenv('API_TOKEN')
domain = os.getenv('DOMAIN')
sub_domain = os.getenv('SUB_DOMAIN')
update_interval = int(os.getenv('UPDATE_INTERVAL', 600)) 


if provider == 'dnspod':
    api_url = "https://dnsapi.cn/Record.Modify"
    headers = {}
    payload_template = {
        "login_token": f"{api_id},{api_token}",
        "format": "json",
        "domain": domain,
        "sub_domain": sub_domain,
        "record_line": "默认"
    }
elif provider == 'alidns':
    api_url = "https://alidns.aliyuncs.com/"
    headers = {"Authorization": f"Bearer {api_token}"}
    payload_template = {
        "Action": "UpdateDomainRecord",
        "DomainName": domain,
        "RR": sub_domain
    }
else:
    raise ValueError("Unsupported provider. Use 'dnspod' or 'alidns'.")


def get_public_ips():
    ipv4 = requests.get("https://api-ipv4.ip.sb/ip", headers={"User-Agent": "Mozilla"}).text.strip()
    ipv6 = requests.get("https://api-ipv6.ip.sb/ip", headers={"User-Agent": "Mozilla"}).text.strip()
    return ipv4, ipv6

def update_dns_record(record_type, ip_address):
    payload = payload_template.copy()
    if provider == 'dnspod':
        payload.update({"record_type": record_type, "value": ip_address})
    elif provider == 'alidns':
        payload.update({"Type": record_type, "Value": ip_address})
    
    response = requests.post(api_url, headers=headers, data=payload)
    result = response.json()

    if provider == 'dnspod' and result["status"]["code"] == "1":
        print(f"{record_type} record updated successfully: {ip_address}")
    elif provider == 'alidns' and result.get("Code") == "DomainRecordDuplicate":
        print(f"{record_type} record updated successfully: {ip_address}")
    else:
        print(f"Failed to update {record_type} record: {result.get('Message', result)}")

def main():
    while True:
        ipv4, ipv6 = get_public_ips()
        print(f"Current IPv4: {ipv4}, Current IPv6: {ipv6}")
        update_dns_record("A", ipv4)
        update_dns_record("AAAA", ipv6)
        time.sleep(update_interval)


class HealthCheckHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')

def run_health_check_server():
    server_address = ('', 80)
    httpd = HTTPServer(server_address, HealthCheckHandler)
    httpd.serve_forever()

if __name__ == "__main__":
    Thread(target=run_health_check_server).start()
    main()
