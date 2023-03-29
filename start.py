import os
import sys
import requests
import json
import ipaddress
import re
import random
import time

def countCIDR(cidr):
    mask = int(cidr.split('/')[1])
    count = 2 ** (32 - mask)
    return count

def processCIDR(cidr):
    ip, mask = cidr.split('/')
    ip_obj = ipaddress.IPv4Address(ip)
    start = int(ip_obj)
    end = start | (0xffffffff >> int(mask))
    ips = []
    for i in range(start, end+1):
        ip = ipaddress.IPv4Address(i)
        ips.append(str(ip))
    return ips

import requests
import time

def getDownloadSpeed(ip, size):
    download_size = size * 1024
    url = f"https://speed.cloudflare.com/__down?bytes={download_size}"
    headers = {'Host': 'speed.cloudflare.com'}
    params = {'resolve': f"speed.cloudflare.com:443:{ip}"}
    start_time = time.time()
    response = requests.get(url, headers=headers, params=params)
    download_time = time.time() - start_time
    download_speed = int(download_size / download_time * 9 / 10000) / 100

    return download_speed

def getUploadSpeed(ip, size):
    upload_size = int(size * 1024 / 10) # To save bandwith, i set upload size 1/10 of downlaod size
    url = 'https://speed.cloudflare.com/__up'
    headers = {'Content-Type': 'multipart/form-data', 'Host': 'speed.cloudflare.com'}
    params = {'resolve': f"speed.cloudflare.com:443:{ip}"}
    files = {'file': ('sample.bin', b"\x00" * upload_size)}
    start_time = time.time()
    response = requests.post(url, headers=headers, params=params, files=files)
    upload_time = time.time() - start_time
    upload_speed = int(upload_size / upload_time * 9 / 10000) / 100
    return upload_speed

def getExistingRecords(email, api_key, zone_id, subdomain):
    headers = {
        "X-Auth-Email": email,
        "X-Auth-Key": api_key,
        "Content-Type": "application/json"
    }
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=A&name={subdomain}"
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return json.loads(response.text)["result"]

def deleteRecord(email, api_key, zone_id, record_id):
    headers = {
        "X-Auth-Email": email,
        "X-Auth-Key": api_key,
        "Content-Type": "application/json"
    }
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
    response = requests.delete(url, headers=headers)
    response.raise_for_status()

def addRecord(email, api_key, zone_id, subdomain, ip):
    headers = {
        "X-Auth-Email": email,
        "X-Auth-Key": api_key,
        "Content-Type": "application/json"
    }
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
    data = {
        "type": "A",
        "name": subdomain,
        "content": ip,
        "ttl": 1,
        "proxied": False
    }
    response = requests.post(url, headers=headers, json=data)
    response.raise_for_status()


import configparser

# Set default values for configuration variables
DEFAULT_MAX_IP = 50
DEFAULT_MAX_LATENCY = 500
DEFAULT_IP_REGEX = ""
DEFAULT_IP_INCLUDE = ""
DEFAULT_IP_EXCLUDE = ""
DEFAULT_DOWNLOAD_SIZE_KB = 1024
DEFAULT_MIN_DOWNLOAD_SPEED = 3
DEFAULT_MIN_UPLOAD_SPEED = 0.3

# Create a new configparser instance and load the configuration file
config = configparser.ConfigParser()
config.read('config.ini')

# Get the values of the configuration variables, using default values if not available
max_ip = int(config.get('DEFAULT', 'max_ip', fallback=DEFAULT_MAX_IP))
max_latency = int(config.get('DEFAULT', 'max_latency', fallback=DEFAULT_MAX_LATENCY))
ip_include = config.get('DEFAULT', 'ip_include', fallback=DEFAULT_IP_INCLUDE)
ip_exclude = config.get('DEFAULT', 'ip_exclude', fallback=DEFAULT_IP_EXCLUDE)
test_size = config.get('DEFAULT', 'test_size', fallback=DEFAULT_DOWNLOAD_SIZE_KB)
min_download_speed = config.get('DEFAULT', 'min_download_speed', fallback=DEFAULT_MIN_DOWNLOAD_SPEED)
min_upload_speed = config.get('DEFAULT', 'min_upload_speed', fallback=DEFAULT_MIN_UPLOAD_SPEED)
default_email = config.get('DEFAULT', 'email', fallback='')
default_zone_id = config.get('DEFAULT', 'zone_id', fallback='')
default_api_key = config.get('DEFAULT', 'api_key', fallback='')
default_subdomain = config.get('DEFAULT', 'subdomain', fallback='')

cidr_list = []
ip_list = []
selectd_ip_list = []
include_regex = ''
exclude_regex = ''

print("Press CTRL+C to exit...\n")
try:
    # Prompt user for input with default values from configuration file
    max_ip = input(f"Enter max IP [{max_ip}]: ") or max_ip
    max_latency = input(f"Enter max latency [{max_latency}]: ") or max_latency
    ip_include = input(f"Enter IPs to include (comma seperated, '-' to ignore) [{ip_include}]: ") or ip_include
    ip_exclude = input(f"Enter IPs to exclude (comma seperated, '-' to ignore) [{ip_exclude}]: ") or ip_exclude
    test_size = input(f"Enter test data size in KB [{test_size}]: ") or test_size
    min_download_speed = input(f"Enter minimum download speed (Mbps) [{min_download_speed}]: ") or min_download_speed
    min_upload_speed = input(f"Enter minimum upload speed (Mbps) [{min_upload_speed}]: ") or min_upload_speed

    if ip_include == '-':
        ip_include = ''
    if ip_exclude == '-':
        ip_exclude = ''

    # Convert the input to the appropriate types
    try:
        max_ip = int(max_ip)
        max_latency = int(max_latency)
        test_size = int(test_size)
        min_download_speed = float(min_download_speed)
        min_upload_speed = float(min_upload_speed)
    except ValueError:
        sys.exit("Invalid Input :(")

    email = default_email
    zone_id = default_zone_id
    api_key = default_api_key
    subdomain = default_subdomain

    replace_cf = input("Do you want to upload the result to your Cloudflare subdomain [y/N]? ")
    if replace_cf.lower() in ["y", "yes"]:
        # Prompt user for Cloudflare credentials
        email = input(f"Cloudflare email [{default_email}]: ") or default_email
        zone_id = input(f"Cloudflare zone ID [{default_zone_id}]: ") or default_zone_id
        api_key = input(f"Cloudflare API key [{default_api_key}]: ") or default_api_key
        subdomain = input(f"Subdomain to modify [{default_subdomain}]: ") or default_subdomain

    config['DEFAULT'] = {
        'max_ip': str(max_ip),
        'max_latency': str(max_latency),
        'ip_include': ip_include,
        'ip_exclude': ip_exclude,
        'test_size': test_size,
        'min_download_speed': min_download_speed,
        'min_upload_speed': min_upload_speed,
        'email': email,
        'zone_id': zone_id,
        'api_key': api_key,
        'subdomain': subdomain
    }

    with open('config.ini', 'w') as configfile:
        config.write(configfile)

    if ip_include:
        include_regex = re.compile('|'.join(['^' + re.escape(c).replace('.', '\\.') + '\\.' for c in ip_include.split(',')]))
    if ip_exclude:
        exclude_regex = re.compile('|'.join(['^' + re.escape(c).replace('.', '\\.') + '\\.' for c in ip_exclude.split(',')]))

    with open('cf-ipv4.txt', 'r') as f:
        for line in f:
            cidr = line.strip()
            if cidr:
                print(f"Processing {cidr}...      \r", end='')
                if include_regex and not include_regex.match(cidr):
                    continue
                if exclude_regex and exclude_regex.match(cidr):
                    continue
                ip_list = ip_list + processCIDR(cidr)

    print("")
    print(f"{len(ip_list)} IPs found. Shuffling the IPs...", end='')
    random.shuffle(ip_list)
    print("Done.")
except KeyboardInterrupt:
    print("\n\nRequest cancelled by user!")
    sys.exit(0)
except requests.exceptions.RequestException as e:
    print("Error:", e)
    sys.exit(1)


timeout = max_latency / 1000
test_no = 0
successful_no = 0

for ip in ip_list:
    test_no = test_no + 1
    print(f"\rTest #{test_no:4d}: {ip:16s}", end='')
    try:
        response = requests.get(f"http://{ip}/cdn-cgi/trace", timeout=timeout)
        successful_no = successful_no + 1
        download_speed = getDownloadSpeed(ip, test_size)
        upload_speed = getUploadSpeed(ip, test_size)

        if download_speed < min_download_speed or upload_speed < min_upload_speed:
            continue

        if successful_no == 1:
            print("\r", end='')
            print("|-----|------------------|----------------|----------------|")
            print("|  #  |                  | Downlaod(Mbps) |  Upload(Mbps)  |")
            print("|-----|------------------|----------------|----------------|")

        print(f"\r| {successful_no:3d} | {ip:16s} |     {download_speed:10.2f} |     {upload_speed:10.2f} |")
        selectd_ip_list.append(ip)
    except KeyboardInterrupt:
        print("\n\nRequest cancelled by user!")
        sys.exit(0)
    except requests.exceptions.RequestException as e:
        print("\r", end='') # Nothing to do

    if len(selectd_ip_list) >= max_ip:
        break

print("|-----|------------------|----------------|----------------|")

if replace_cf.lower() in ["y", "yes"]:
    existing_records = getExistingRecords(email, api_key, zone_id, subdomain)
    print("\nDeleting existing records...", end='')
    for record in existing_records:
        deleteRecord(email, api_key, zone_id, record["id"])
    print(" Done.")

    print("\nAdding new A Records for selected IPs:")
    for ip in selectd_ip_list:
        print(ip, end='')
        addRecord(email, api_key, zone_id, subdomain, ip)
        print(" Done.")
    print("\nAll records have been added to your subdomain.")


print("\nWriting result to `selected-ips.csv` file....", end='')

with open('selected-ips.csv', 'w') as f:
    for ip in selectd_ip_list:
        f.write(ip + '\n')

print(" Done.\n\nFinished.")


