import os
import sys
import requests
import json
import ipaddress
import re
import random
import time
import configparser
import ping3
from functools import partial
from multiprocessing import Pool
import itertools
from typing import Pattern, AnyStr, List

# Function to get a list of IP addresses in a CIDR block
def processCIDR(cidr):
    """
    Args:
    cidr (str): A CIDR block of Cloudflare Network to be converted to IP addresses.

    Returns:
    array: The list of IP addresses in the CIDR block
    """

    # Split CIDR into IP and mask
    ip, mask = cidr.split('/')
    # Create an IPv4 address object from the IP
    ip_obj = ipaddress.IPv4Address(ip)
    # Calculate the start IP address of the CIDR block
    start = int(ip_obj)
    # Calculate the end IP address of the CIDR block
    end = start | (0xffffffff >> int(mask))
    # Create a list to store the IP addresses in the CIDR block
    ips = []
    # Iterate over each IP address in the range and add it to the list
    for i in range(start, end+1):
        ip = ipaddress.IPv4Address(i)
        ips.append(str(ip))
    # Return the list of IP addresses in the CIDR block
    return ips


# Function to get the ping and jitter of an IP address
def getPingAndJitter(ip, acceptable_ping):
    """
    Args:
    ip (str): IP of Cloudflare Network to test its upload speed.
    acceptable_ping (float): The minimum acceptable download speed.

    Returns:
    int: The latency in milliseconds.
    int: The jitter in milliseconds.
    """

    # Calculate the timeout for requested minimum ping time
    timeout = acceptable_ping / 1000 * 2
    ping = 0
    jitter = 0
    last_ping = 0
    try:
        for i in range(5):
            # Start the timer for the download request
            start_time = time.time()
            # Get response time of the ping request
            response_time = ping3.ping(ip, timeout=timeout)
            # Calculate spent time for fallback
            duration = int((time.time() - start_time) * 1000)
            # Calculate the ping in milliseconds
            current_ping = int(response_time * 1000) if response_time is not None and response_time > 0 else duration

            if i > 0:
                jitter = jitter + abs(current_ping - last_ping)

            last_ping = current_ping
            ping = ping + current_ping
            timeout = acceptable_ping / 1000 * 1.2

        ping = int(ping / 5)
        jitter = int(jitter / 4)
    except Exception as e:
        ping = -1
        jitter = -1

    # Return ping and jitter in milliseconds
    return ping , jitter


# Function to get the latency of an IP address
def getLatency(ip, acceptable_latency):
    """
    Args:
    ip (str): IP of Cloudflare Network to test its upload speed.
    acceptable_latency (float): The minimum acceptable download speed.

    Returns:
    int: The latency in milliseconds.
    """

    # An small data to download to calculate latency
    download_size = 1000
    # Calculate the timeout for requested minimum latency
    timeout = acceptable_latency / 1000 * 1.5
    # Set the URL for the download request
    url = f"https://speed.cloudflare.com/__down?bytes={download_size}"
    # Set the headers for the download request
    headers = {'Host': 'speed.cloudflare.com'}
    # Set the parameters for the download request
    params = {'resolve': f"speed.cloudflare.com:443:{ip}"}

    latency = 0
    try:
        for i in range(2):
            # Start the timer for the download request
            start_time = time.time()
            # Send the download request and get the response
            response = requests.get(url, headers=headers, params=params, timeout=timeout)
            # Calculate the latency in milliseconds
            latency = latency + int((time.time() - start_time) * 1000)
            timeout = acceptable_latency / 1000

        latency = int(latency / 2)
    except requests.exceptions.RequestException as e:
        # If there was an exception, set latency to 99999
        latency = 99999

    # Return latency in milliseconds
    return latency


# Function to get the download speed of an IP address
def getDownloadSpeed(ip, size, min_speed):
    """
    Args:
    ip (str): IP of Cloudflare Network to test its upload speed.
    size (int): Size of sample data to download for speed test.
    min_speed (float): The minimum acceptable download speed.

    Returns:
    float: The download speed in Mbps.
    """

    # Convert size from KB to bytes
    download_size = size * 1024
    # Convert minimum speed from Mbps to bytes/s
    min_speed_bytes = min_speed * 125000  # 1 Mbps = 125000 bytes/s
    # Calculate the timeout for the download request
    timeout = download_size / min_speed_bytes
    # Set the URL for the download request
    url = f"https://speed.cloudflare.com/__down?bytes={download_size}"
    # Set the headers for the download request
    headers = {'Host': 'speed.cloudflare.com'}
    # Set the parameters for the download request
    params = {'resolve': f"speed.cloudflare.com:443:{ip}"}

    try:
        # Start the timer for the download request
        start_time = time.time()
        # Send the download request and get the response
        response = requests.get(url, headers=headers, params=params, timeout=timeout)
        # Calculate the download time
        download_time = time.time() - start_time
        # Calculate the download speed in Mbps
        download_speed = round(download_size / download_time * 8 / 1000000, 2)
    except requests.exceptions.RequestException as e:
        # If there was an exception, set download speed to 0
        download_speed = 0

    # Return the download speed in Mbps
    return download_speed


# Function to get the upload speed of an IP address
def getUploadSpeed(ip, size, min_speed):
    """
    Args:
    ip (str): IP of Cloudflare Network to test its upload speed.
    size (int): Size of sample data to upload for speed test.
    min_speed (float): The minimum acceptable upload speed.

    Returns:
    float: The upload speed in Mbps.
    """

    # Calculate the upload size, which is 1/4 of the download size to save bandwidth
    upload_size = int(size * 1024 / 4)
    # Calculate the minimum speed in bytes per second
    min_speed_bytes = min_speed * 125000  # 1 Mbps = 125000 bytes/s
    # Calculate the timeout for the request based on the upload size and minimum speed
    timeout = upload_size / min_speed_bytes
    # Set the URL, headers, and parameters for the request
    url = 'https://speed.cloudflare.com/__up'
    headers = {'Content-Type': 'multipart/form-data', 'Host': 'speed.cloudflare.com'}
    params = {'resolve': f"speed.cloudflare.com:443:{ip}"}
    # Create a sample file with null bytes of the specified size
    files = {'file': ('sample.bin', b"\x00" * upload_size)}

    try:
        # Send the request and measure the upload time
        start_time = time.time()
        response = requests.post(url, headers=headers, params=params, files=files, timeout=timeout)
        upload_time = time.time() - start_time
        # Calculate the upload speed in Mbps
        upload_speed = round(upload_size / upload_time * 8 / 1000000, 2)
    except requests.exceptions.RequestException as e:
        # If an error occurs, set the upload speed to 0
        upload_speed = 0

    # Return the upload speed in Mbps
    return upload_speed


# Function to validate Cloudflare API credentials by making a GET request to the Cloudflare API with the provided credentials.
def validateCloudflareCredentials(email, api_key, zone_id):
    """
    Args:
    email (str): The email address associated with the Cloudflare account.
    api_key (str): The API key associated with the Cloudflare account.
    zone_id (str): The ID of the DNS zone for which to validate the credentials.

    Returns:
    bool: True if the credentials are valid, False otherwise.
    """

    headers = {
        "X-Auth-Email": email,
        "X-Auth-Key": api_key,
        "Content-Type": "application/json"
    }
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
    response = requests.get(url, headers=headers)
    return response.status_code == 200


# Function to get list of existing DNS records for the specified subdomain in the specified Cloudflare DNS zone.
def getCloudflareExistingRecords(email, api_key, zone_id, subdomain):
    """
    Args:
    email (str): The email address associated with the Cloudflare account.
    api_key (str): The API key associated with the Cloudflare account.
    zone_id (str): The ID of the DNS zone for which to get the existing records.
    subdomain (str): The subdomain for which to get the existing records.

    Returns:
    list: A list of existing DNS records for the specified subdomain in the specified Cloudflare DNS zone.
    """

    headers = {
        "X-Auth-Email": email,
        "X-Auth-Key": api_key,
        "Content-Type": "application/json"
    }
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=A&name={subdomain}"
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return json.loads(response.text)["result"]


# Function to delete an existing DNS record in Cloudflare.
def deleteCloudflareExistingRecord(email: str, api_key: str, zone_id: str, record_id: str) -> None:
    """
    Args:
        email (str): Cloudflare account email address.
        api_key (str): Cloudflare API key.
        zone_id (str): ID of the DNS zone where the record belongs.
        record_id (str): ID of the DNS record to be deleted.

    Returns:
        None
    """

    headers = {
        "X-Auth-Email": email,
        "X-Auth-Key": api_key,
        "Content-Type": "application/json"
    }
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
    response = requests.delete(url, headers=headers)
    response.raise_for_status()


# Function to add a new DNS record in Cloudflare.
def addNewCloudflareRecord(email: str, api_key: str, zone_id: str, subdomain: str, ip: str) -> None:
    """
    Args:
        email (str): Cloudflare account email address.
        api_key (str): Cloudflare API key.
        zone_id (str): ID of the DNS zone where the record should be added.
        subdomain (str): Name of the subdomain to be added.
        ip (str): IP address to be associated with the subdomain.

    Returns:
        None
    """

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


# Function to filter CIDR based on user provided regex and return the processed CIDR block
def processRegex(cidr: str, include_reg: Pattern[AnyStr], exclude_reg: Pattern[AnyStr]) -> List[AnyStr]:
    """
    Args:
        cidr (str): A CIDR block of Cloudflare Network to be converted to IP addresses.
        include_reg (Pattern[AnyStr]): A Regex Pattern to include IPs
        exclude_reg (Pattern[AnyStr]): A Regex Pattern to exclude IPs

    Returns:
        List[AnyStr]: A list of IPs converted from cidr
    """
    cidr = cidr.strip()
    if cidr:
        print(f"Processing {cidr}...      \r", end='')
        if include_reg and not include_reg.match(cidr):
            return []
        if exclude_reg and exclude_reg.match(cidr):
            return []
        return processCIDR(cidr)


if __name__ == "__main__":
    DEFAULT_MAX_IP = 50
    DEFAULT_MAX_PING = 500
    DEFAULT_MAX_JITTER = 100
    DEFAULT_MAX_LATENCY = 1000
    DEFAULT_IP_REGEX = ""
    DEFAULT_IP_INCLUDE = ""
    DEFAULT_IP_EXCLUDE = ""
    DEFAULT_DOWNLOAD_SIZE_KB = 1024
    DEFAULT_MIN_DOWNLOAD_SPEED = 3
    DEFAULT_MIN_UPLOAD_SPEED = 0.2

    # Create a new configparser instance and load the configuration file
    config = configparser.ConfigParser()
    config.read('config.ini')

    # Get the values of the configuration variables, using default values if not available
    max_ip = int(config.get('DEFAULT', 'max_ip', fallback=DEFAULT_MAX_IP))
    max_ping = int(config.get('DEFAULT', 'max_ping', fallback=DEFAULT_MAX_PING))
    max_jitter = int(config.get('DEFAULT', 'max_jitter', fallback=DEFAULT_MAX_JITTER))
    max_latency = int(config.get('DEFAULT', 'max_latency', fallback=DEFAULT_MAX_LATENCY))
    ip_include = config.get('DEFAULT', 'ip_include', fallback=DEFAULT_IP_INCLUDE)
    ip_exclude = config.get('DEFAULT', 'ip_exclude', fallback=DEFAULT_IP_EXCLUDE)
    test_size = config.get('DEFAULT', 'test_size', fallback=DEFAULT_DOWNLOAD_SIZE_KB)
    min_download_speed = config.get('DEFAULT', 'min_download_speed', fallback=DEFAULT_MIN_DOWNLOAD_SPEED)
    min_upload_speed = config.get('DEFAULT', 'min_upload_speed', fallback=DEFAULT_MIN_UPLOAD_SPEED)
    default_upload_results = config.get('DEFAULT', 'upload_results', fallback='no')
    default_delete_existing = config.get('DEFAULT', 'delete_existing', fallback='yes')
    default_email = config.get('DEFAULT', 'email', fallback='')
    default_zone_id = config.get('DEFAULT', 'zone_id', fallback='')
    default_api_key = config.get('DEFAULT', 'api_key', fallback='')
    default_subdomain = config.get('DEFAULT', 'subdomain', fallback='')

    # Initialise the required variables
    delete_existing = 'yes'
    cidr_list = []
    ip_list = []
    selectd_ip_list = []
    include_regex = ''
    exclude_regex = ''

    print("Press CTRL+C to exit...\n")

    try:
        # Prompt user for input with default values from configuration file
        max_ip = input(f"Enter max IP [{max_ip}]: ") or max_ip
        max_ping = input(f"Enter max ping [{max_ping}]: ") or max_ping
        max_jitter = input(f"Enter max jitter [{max_jitter}]: ") or max_jitter
        max_latency = input(f"Enter max latency [{max_latency}]: ") or max_latency
        ip_include = input(f"Enter IPs to include (comma seperated, '-' to ignore) [{ip_include}]: ") or ip_include
        ip_exclude = input(f"Enter IPs to exclude (comma seperated, '-' to ignore) [{ip_exclude}]: ") or ip_exclude
        test_size = input(f"Enter test data size in KB [{test_size}]: ") or test_size
        min_download_speed = input(f"Enter minimum download speed (Mbps) [{min_download_speed}]: ") or min_download_speed
        min_upload_speed = input(f"Enter minimum upload speed (Mbps) [{min_upload_speed}]: ") or min_upload_speed

        # Clear the include regex in case "-" provided by the user
        if ip_include == '-':
            ip_include = ''

        # Clear the exclude regex in case "-" provided by the user
        if ip_exclude == '-':
            ip_exclude = ''

        # Convert the inputs to the appropriate types in related variables
        max_ip = int(max_ip)
        max_ping = int(max_ping)
        max_jitter = int(max_jitter)
        max_latency = int(max_latency)
        test_size = int(test_size)
        min_download_speed = float(min_download_speed)
        min_upload_speed = float(min_upload_speed)
        email = default_email
        zone_id = default_zone_id
        api_key = default_api_key
        subdomain = default_subdomain


        # Prompt the user for whether they want to upload the result to their Cloudflare subdomain
        upload_results = input(f"Do you want to upload the result to your Cloudflare subdomain (yes/no) [{default_upload_results}]? ") or default_upload_results

        # Code block to execute if upload_results is 'y' or 'yes'
        if upload_results.lower() in ["y", "yes"]:
            delete_existing = input(f"Do you want to delete extisting records of given subdomain before uploading the result to your Cloudflare (yes/no) [{default_delete_existing}]? ") or default_delete_existing
            email = input(f"Cloudflare email [{default_email}]: ") or default_email
            zone_id = input(f"Cloudflare zone ID [{default_zone_id}]: ") or default_zone_id
            api_key = input(f"Cloudflare API key [{default_api_key}]: ") or default_api_key

            # Prompt user to enter subdomain to modify
            subdomain = input(f"Subdomain to modify (i.e ip.my-domain.com) [{default_subdomain}]: ") or default_subdomain

            # Check if provided credentials are correct and retry if they are not
            while not validateCloudflareCredentials(email, api_key, zone_id):
                print("Invalid cloudflare credentials, please try again.")
                email = input(f"Cloudflare email [{default_email}]: ") or default_email
                zone_id = input(f"Cloudflare zone ID [{default_zone_id}]: ") or default_zone_id
                api_key = input(f"Cloudflare API key [{default_api_key}]: ") or default_api_key


            # Use regular expression to validate subdomain format
            while not re.match(r"^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$", subdomain):
                # If subdomain is invalid, prompt user to try again
                print("Invalid subdomain, please try again.")
                subdomain = input(f"Subdomain to modify (i.e ip.my-domain.com) [{default_subdomain}]: ") or default_subdomain

        # Update config variable with given data from user
        config['DEFAULT'] = {
            'max_ip': str(max_ip),
            'max_ping': str(max_ping),
            'max_jitter': str(max_jitter),
            'max_latency': str(max_latency),
            'ip_include': ip_include,
            'ip_exclude': ip_exclude,
            'test_size': test_size,
            'min_download_speed': min_download_speed,
            'min_upload_speed': min_upload_speed,
            'upload_results': upload_results,
            'delete_existing': delete_existing,
            'email': email,
            'zone_id': zone_id,
            'api_key': api_key,
            'subdomain': subdomain
        }

        # Saving the configuration info to config file for further use
        with open('config.ini', 'w') as configfile:
            config.write(configfile)

        # Convert IP ranges to include (provided by user in a comma-seperated string) to Regular Expression
        if ip_include:
            include_regex = re.compile('|'.join(['^' + re.escape(c).replace('.', '\\.') + '\\.' for c in ip_include.split(',')]))

        # Convert IP ranges to exclude (provided by user in a comma-seperated string) to Regular Expression
        if ip_exclude:
            exclude_regex = re.compile('|'.join(['^' + re.escape(c).replace('.', '\\.') + '\\.' for c in ip_exclude.split(',')]))

        print("")
        # Read IPv4 CIDR blocks of Cloudflare Network from related file
        with open('cf-ipv4.txt', 'r') as f:
            lines = f.readlines()
            with Pool(5) as p:
                result = p.map(
                    partial(processRegex, include_reg=include_regex, exclude_reg=exclude_regex), lines)

        ip_list = list(itertools.chain(*result))

        # Shuffling the IP list in order to test different ip in different ranges by random
        print(f"\n{len(ip_list)} IPs found. Shuffling the IPs...", end='')
        random.shuffle(ip_list)

        # Preparation is done
        print("Done.")
    except KeyboardInterrupt:
        # Print proper message and exit the script in case user pressed CTRL+C
        print("\n\nRequest cancelled by user!")
        sys.exit(0)
    except requests.exceptions.RequestException as e:
        print("Error: Something went wrong, Please try again!")
        sys.exit(1)


    # Initiate variables
    test_no = 0
    successful_no = 0

    # Loop through IP adresses to check their ping, latency and download/upload speed
    for ip in ip_list:
        # Increase the test number
        test_no = test_no + 1
        print(f"\r\033[KTest #{test_no}: {ip}", end='', flush=True)

        try:
            # Calculate ping of selected ip using related function
            ping, jitter = getPingAndJitter(ip, max_ping)
            # Ignore the IP if ping dosn't match the maximum required ping
            if ping > max_ping:
                continue
            # Ignore the IP if jitter dosn't match the maximum required ping
            if jitter > max_jitter:
                continue

            print(f"\nPing: {ping}ms, Jitter: {jitter}ms", end='', flush=True)

            # Calculate latency of selected ip using related function
            latency = getLatency(ip, max_latency)
            # Ignore the IP if latency dosn't match the maximum required latency
            if latency > max_latency:
                print(f"\r\033[K\033[F\r\033[K", end='', flush=True)
                continue

            print(f", Latency: {latency}ms", end='', flush=True)

            # Calculate upload speed of selected ip using related function
            upload_speed = getUploadSpeed(ip, test_size, min_upload_speed)
            # Ignore the IP if upload speed dosn't match the minimum required speed
            if upload_speed < min_upload_speed:
                print(f"\r\033[K\033[F\r\033[K", end='', flush=True)
                continue

            print(f", Upload: {upload_speed}Mbps", end='', flush=True)

            # Calculate download speed of selected ip using related function
            download_speed = getDownloadSpeed(ip, test_size, min_download_speed)
            # Ignore the IP if download speed dosn't match the minimum required speed

            print(f"\r\033[K\033[F\r\033[K", end='', flush=True)

            if download_speed < min_download_speed:
                continue

            # Increase number of successful test
            successful_no = successful_no + 1

            # Print out table header if it was the first record
            if successful_no == 1:
                print("\r", end='')
                print("|---|---------------|--------|-------|-------|--------|----------|")
                print("| # |       IP      |Ping(ms)|Jit(ms)|Lat(ms)|Up(Mbps)|Down(Mbps)|")
                print("|---|---------------|--------|-------|-------|--------|----------|")

            # Print out the IP and related info as well as ping, latency and download/upload speed
            print(f"\r|{successful_no:3d}|{ip:15s}|{ping:7d} |{jitter:6d} |{latency:6d} |{upload_speed:7.2f} |{download_speed:9.2f} |")
            selectd_ip_list.append(ip)
        except KeyboardInterrupt:
            print("\n\nRequest cancelled by user!")
            sys.exit(0)
        except requests.exceptions.RequestException as e:
            print("\r", end='', flush=True) # Nothing to do

        # Exit the loop if we found required number of clean IP addresses
        if len(selectd_ip_list) >= max_ip:
            break

    print("|---|---------------|--------|-------|-------|--------|----------|")

    # Updating relevant subdomain with clean IP adresses
    if upload_results.lower() in ["y", "yes"]:
        try:
            # Check if user wanted to delete existing records of given subdomain
            if delete_existing.lower() in ["y", "yes"]:
                # Get existing records of the given subdomain
                existing_records = getCloudflareExistingRecords(email, api_key, zone_id, subdomain)
                print("\nDeleting existing records...", end='', flush=True)
                #Delete all existing records of the given subdomain
                for record in existing_records:
                    deleteCloudflareExistingRecord(email, api_key, zone_id, record["id"])
                print(" Done.")

            print("\nAdding new A Records for selected IPs:")
            for ip in selectd_ip_list:
                print(ip, end='', flush=True)
                addNewCloudflareRecord(email, api_key, zone_id, subdomain, ip)
                print(" Done.")
            print("\nAll records have been added to your subdomain.")
        except:
            print("\nFailed to update Cloudflare subdomain! Invalid credentials provided.")



    print("\nWriting result to `selected-ips.csv` file....", end='', flush=True)

    with open('selected-ips.csv', 'w') as f:
        for ip in selectd_ip_list:
            f.write(ip + '\n')

    print(" Done.\n\nFinished.")
