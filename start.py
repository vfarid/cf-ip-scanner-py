#!/usr/bin/env python3

import os
import sys
import requests
import json
import ipaddress
import re
import random
import time
import configparser
from functools import partial
from multiprocessing import Pool
import itertools
from typing import Pattern, AnyStr, List
import curses
import subprocess

print_ping_error_message = False   # initialize flag variable
openssl_is_active = False

try:
    import ping3
except ImportError:
    print_ping_error_message = True


# Main function
def main():
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
    config.read(sys.argv[1] if len(sys.argv) > 1 else 'config.ini')

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

    # Define global variable
    global print_ping_error_message
    global openssl_is_active

    # Initialise the required variables
    delete_existing = 'yes'
    cidr_list = []
    ip_list = []
    include_regex = ''
    exclude_regex = ''

    print("Press CTRL+C to exit...\n")

    try:

        # If no config file was specified...
        if len(sys.argv) <= 1:

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

            # Saving the configuration info to default config file for further use
            with open('config.ini', 'w') as configfile:
                config.write(configfile)

        # Convert IP ranges to include (provided by user in a comma-seperated string) to Regular Expression
        if ip_include:
            include_regex = re.compile('|'.join(['^' + re.escape(c).replace('.', '\\.') + '\\.' for c in ip_include.split(',')]))

        # Convert IP ranges to exclude (provided by user in a comma-seperated string) to Regular Expression
        if ip_exclude:
            exclude_regex = re.compile('|'.join(['^' + re.escape(c).replace('.', '\\.') + '\\.' for c in ip_exclude.split(',')]))

        # Get IPv4 CIDR blocks of Cloudflare Network from related function
        cidr_list = getCIDRv4Ranges()

        # Process CIDR list
        try:
            with Pool(5) as p:
                result = p.map(
                    partial(processRegex, include_reg=include_regex, exclude_reg=exclude_regex), cidr_list)

            ip_list = list(itertools.chain(*result))
        except:
            for cidr in cidr_list:
                print(f"Processing {cidr}...      \r", end='')

                # Ignore CIDR block if not matches with include regex
                if include_regex and not include_regex.match(cidr):
                    continue

                # Ignore CIDR block if matches with exclude regex
                if exclude_regex and exclude_regex.match(cidr):
                    continue

                # Convert CIDR block to IP addresses and add them to IP List
                ip_list = ip_list + processCIDR(cidr)


        # Shuffling the IP list in order to test different ip in different ranges by random
        print(f"\nShuffling the IPs...", end='')
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

    if print_ping_error_message:
        print("Couldn't find \"ping3\" module. You may add it to your installation using following command: \n>> python -m pip install ping3\n")
        print("The ping functionality will be ignored...")
        print_ping_error_message = False
        time.sleep(2)

    if has_openssl():
        openssl_is_active = True
    else:
        print("OpenSSL is not installed! You man install it to your system and try again.")
        openssl_is_active = False

    # Start testing clean IPs
    selectd_ip_list, total_test = curses.wrapper(startTest, ip_list=ip_list, config=config)

    print(f"\n{total_test} of {len(ip_list)} matched IPs have peen tested.")
    print(f"{len(selectd_ip_list)} IP(s) found:")
    print("|---|---------------|--------|-------|-------|--------|----------|")
    print("| # |       IP      |Ping(ms)|Jit(ms)|Lat(ms)|Up(Mbps)|Down(Mbps)|")
    print("|---|---------------|--------|-------|-------|--------|----------|")

    successful_no = 0
    for el in selectd_ip_list:
        successful_no = successful_no + 1
        # Print out the IP and related info as well as ping, latency and download/upload speed
        print(f"\r|{successful_no:3d}|{el.ip:15s}|{el.ping:7d} |{el.jitter:6d} |{el.latency:6d} |{el.upload:7.2f} |{el.download:9.2f} |")

    print("|---|---------------|--------|-------|-------|--------|----------|\n")

    print("IP list successfuly exported to `selected-ips.csv` file.\n")

    # Updating relevant subdomain with clean IP adresses
    if upload_results.lower() in ["y", "yes"]:
        try:
            # Check if user wanted to delete existing records of given subdomain
            if delete_existing.lower() in ["y", "yes"]:
                # Get existing records of the given subdomain
                existing_records = getCloudflareExistingRecords(email, api_key, zone_id, subdomain)
                print("Deleting existing records...", end='', flush=True)
                #Delete all existing records of the given subdomain
                for record in existing_records:
                    deleteCloudflareExistingRecord(email, api_key, zone_id, record["id"])
                print("Done.")

            print("Adding new A Record(s) for selected IP(s):")
            for el in selectd_ip_list:
                print(el.ip, end='', flush=True)
                addNewCloudflareRecord(email, api_key, zone_id, subdomain, el.ip)
                print(" Done.")
            print("All records have been added to your subdomain.")
        except Exception as e:
            print("Failed to update Cloudflare subdomain!")
            print(e)

    print("Done.\n")


def startTest(stdscr: curses.window, ip_list: Pattern[AnyStr], config: configparser.ConfigParser):
    # Clear the screen
    stdscr.clear()
    stdscr.refresh()

    # Initiate variables
    selectd_ip_list = []
    test_no = 0
    successful_no = 0
    max_ip = int(config.get('DEFAULT', 'max_ip'))
    max_ping = int(config.get('DEFAULT', 'max_ping'))
    max_jitter = int(config.get('DEFAULT', 'max_jitter'))
    max_latency = int(config.get('DEFAULT', 'max_latency'))
    test_size = int(config.get('DEFAULT', 'test_size'))
    min_download_speed = float(config.get('DEFAULT', 'min_download_speed'))
    min_upload_speed = float(config.get('DEFAULT', 'min_upload_speed'))

    # Creating `selected-ips.csv` file to output results
    with open('selected-ips.csv', 'w') as csv_file:
        csv_file.write("#,IP,Ping (ms),Jitter (ms),Latency (ms),Upload (Mbps),Download (Mbps)\n")

    # Creating `selected-ips.csv` file to output results
    with open('selected-ips.txt', 'w') as txt_file:
        txt_file.write("")

    # Print out table header if it was the first record
    stdscr.addstr(3, 0, "|---|---------------|--------|-------|-------|--------|----------|")
    stdscr.addstr(4, 0, "| # |       IP      |Ping(ms)|Jit(ms)|Lat(ms)|Up(Mbps)|Down(Mbps)|")
    stdscr.addstr(5, 0, "|---|---------------|--------|-------|-------|--------|----------|")
    stdscr.addstr(6, 0, "|---|---------------|--------|-------|-------|--------|----------|")

    # Loop through IP adresses to check their ping, latency and download/upload speed
    for ip in ip_list:
        col = 0
        # Increase the test number
        test_no = test_no + 1

        stdscr.move(0, 0)
        stdscr.clrtoeol()    # Clear the entire line
        stdscr.addstr(0, 0, f"Test #{test_no}: {ip}")
        stdscr.refresh()

        try:
            # Calculate ping of selected ip using related function
            ping = getPing(ip, max_ping)
            # Ignore the IP if ping dosn't match the maximum required ping
            if ping > max_ping:
                continue

            str = f"Ping: {ping}ms"
            stdscr.addstr(1, 0, str)
            stdscr.refresh()
            col = col + len(str)

            # Calculate latency of selected ip using related function
            latency, jitter = getLatencyAndJitter(ip, max_latency)

            # Ignore the IP if jitter dosn't match the maximum required ping
            if jitter > max_jitter:
                continue
            # Ignore the IP if latency dosn't match the maximum required latency
            if latency > max_latency:
                stdscr.move(1, 0)
                stdscr.clrtoeol()    # Clear the entire line
                continue

            str = f", Jitter: {jitter}ms, Latency: {latency}ms"
            stdscr.addstr(1, col, str)
            stdscr.refresh()
            col = col + len(str)

            # Calculate upload speed of selected ip using related function
            upload_speed = getUploadSpeed(ip, test_size, min_upload_speed)
            # Ignore the IP if upload speed dosn't match the minimum required speed
            if upload_speed < min_upload_speed:
                stdscr.move(1, 0)
                stdscr.clrtoeol()    # Clear the entire line
                continue

            str = f", Upload: {upload_speed}Mbps"
            stdscr.addstr(1, col, str)
            stdscr.refresh()

            # Calculate download speed of selected ip using related function
            download_speed = getDownloadSpeed(ip, test_size, min_download_speed)
            # Ignore the IP if download speed dosn't match the minimum required speed

            stdscr.move(1, 0)
            stdscr.clrtoeol()    # Clear the entire line
            stdscr.refresh()

            if download_speed < min_download_speed:
                continue

            # Increase number of successful test
            successful_no = successful_no + 1

            # Move cursor to the right position
            stdscr.move(6, 0)
            # Insert a new line at the cursor position, shifting the existing lines down
            stdscr.insertln()
            # Print out the IP and related info as well as ping, latency and download/upload speed
            stdscr.addstr(f"|{successful_no:3d}|{ip:15s}|{ping:7d} |{jitter:6d} |{latency:6d} |{upload_speed:7.2f} |{download_speed:9.2f} |")
            stdscr.refresh()

            selectd_ip_list.append(IPInfo(ip, ping, jitter, latency, upload_speed, download_speed))

            with open('selected-ips.csv', 'a') as csv_file:
                csv_file.write(f"{successful_no},{ip},{ping},{jitter},{latency},{upload_speed},{download_speed}\n")
            with open('selected-ips.txt', 'a') as txt_file:
                txt_file.write(f"{ip}\n")

        except KeyboardInterrupt:
            print("\n\nRequest cancelled by user!")
            sys.exit(0)
        except requests.exceptions.RequestException as e:
            print("\r", end='', flush=True) # Nothing to do

        # Exit the loop if we found required number of clean IP addresses
        if len(selectd_ip_list) >= max_ip:
            break

    stdscr.move(0, 0)
    stdscr.clrtoeol()    # Clear the entire line
    stdscr.move(1, 0)
    stdscr.clrtoeol()    # Clear the entire line
    stdscr.addstr(0, 0, "Done.")
    stdscr.refresh()
    time.sleep(3)

    return selectd_ip_list, test_no


class IPInfo:
    def __init__(self, ip, ping, jitter, latency, upload, download):
        self.ip = ip
        self.ping = ping
        self.jitter = jitter
        self.latency = latency
        self.upload = upload
        self.download = download


# Function to get a list of IP addresses in a CIDR block
def processCIDR(cidr):
    """
    Args:
    cidr (str): A CIDR block of Cloudflare Network to be converted to IP addresses.

    Returns:
    array: The list of IP addresses in the CIDR block
    """

    ips = []
    network = ipaddress.ip_network(cidr, strict=False)
    for ip in network:
        ips.append(str(ip))

    return ips


# Function to get the ping and jitter of an IP address
def getPing(ip, acceptable_ping):
    """
    Args:
    ip (str): IP of Cloudflare Network to test its upload speed.
    acceptable_ping (float): The minimum acceptable download speed.

    Returns:
    int: The latency in milliseconds.
    int: The jitter in milliseconds.
    """

    # Calculate the timeout for requested minimum ping time
    timeout = acceptable_ping / 1000
    try:
        # Start the timer for the download request
        start_time = time.time()
        # Get response time of the ping request
        response_time = ping3.ping(ip, timeout=timeout)
        # Calculate spent time for fallback
        duration = int((time.time() - start_time) * 1000)
        # Calculate the ping in milliseconds
        ping = int(response_time * 1000) if response_time is not None and response_time > 0 else duration
    except Exception as e:
        ping = -1

    # Return ping and jitter in milliseconds
    return ping


# Function to get the latency of an IP address
def getLatencyAndJitter(ip, acceptable_latency):
    """
    Args:
    ip (str): IP of Cloudflare Network to test its upload speed.
    acceptable_latency (float): The minimum acceptable download speed.

    Returns:
    int: The latency in milliseconds.
    """

    global openssl_is_active

    # An small data to download to calculate latency
    download_size = 1000
    # Calculate the timeout for requested minimum latency
    timeout = acceptable_latency / 1000 * 1.5
    # Set the URL for the download request
    url = f"https://speed.cloudflare.com/__down?bytes={download_size}"
    # Set the headers for the download request
    headers = {'Host': 'speed.cloudflare.com'}
    # Set the parameters for the download request
    if openssl_is_active:
        params = {'resolve': f"speed.cloudflare.com:443:{ip}", 'alpn': 'h2,http/1.1', 'utls': 'random'}
    else:
        params = {'resolve': f"speed.cloudflare.com:443:{ip}"}

    latency = 0
    jitter = 0
    last_latency = 0
    try:
        for i in range(4):
            # Start the timer for the download request
            start_time = time.time()
            # Send the download request and get the response
            response = requests.get(url, headers=headers, params=params, timeout=timeout)
            # Calculate the latency in milliseconds
            current_latency = int((time.time() - start_time) * 1000)
            latency = latency + current_latency
            timeout = acceptable_latency / 1000

            if i > 0:
                jitter = jitter + abs(current_latency - last_latency)

            last_latency = current_latency

        latency = int(latency / 4)
        jitter = int(jitter / 3)
    except requests.exceptions.RequestException as e:
        # If there was an exception, set latency to 99999 and jitter to -1
        latency = 99999
        jitter = -1


    # Return latency in milliseconds
    return latency, jitter


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

    global openssl_is_active

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
    if openssl_is_active:
        params = {'resolve': f"speed.cloudflare.com:443:{ip}", 'alpn': 'h2,http/1.1', 'utls': 'random'}
    else:
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

    global openssl_is_active

    # Calculate the upload size, which is 1/4 of the download size to save bandwidth
    upload_size = int(size * 1024 / 4)
    # Calculate the minimum speed in bytes per second
    min_speed_bytes = min_speed * 125000  # 1 Mbps = 125000 bytes/s
    # Calculate the timeout for the request based on the upload size and minimum speed
    timeout = upload_size / min_speed_bytes
    # Set the URL, headers, and parameters for the request
    url = 'https://speed.cloudflare.com/__up'
    headers = {'Content-Type': 'multipart/form-data', 'Host': 'speed.cloudflare.com'}
    if openssl_is_active:
        params = {'resolve': f"speed.cloudflare.com:443:{ip}", 'alpn': 'h2,http/1.1', 'utls': 'random'}
    else:
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
        "ttl": 3600,
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


# Check if openssl is installed or not
def has_openssl():
    try:
        openssl = subprocess.check_call(["openssl", "version"], stdout=subprocess.PIPE)
        return True
    except:
        return False


# Define CIDR ranges of Cloudflare Network
def getCIDRv4Ranges():
    return [
        '5.226.179.0/24',
        '5.226.181.0/24',
        '8.10.148.0/24',
        '8.14.199.0/24',
        '8.14.201.0/24',
        '8.14.202.0/24',
        '8.14.203.0/24',
        '8.14.204.0/24',
        '8.17.205.0/24',
        '8.17.206.0/24',
        '8.17.207.0/24',
        '8.18.113.0/24',
        '8.18.194.0/24',
        '8.18.195.0/24',
        '8.18.196.0/24',
        '8.18.50.0/24',
        '8.19.8.0/24',
        '8.20.100.0/24',
        '8.20.101.0/24',
        '8.20.103.0/24',
        '8.20.122.0/24',
        '8.20.123.0/24',
        '8.20.124.0/24',
        '8.20.125.0/24',
        '8.20.126.0/24',
        '8.20.253.0/24',
        '8.21.10.0/24',
        '8.21.110.0/24',
        '8.21.111.0/24',
        '8.21.13.0/24',
        '8.21.239.0/24',
        '8.21.8.0/24',
        '8.21.9.0/24',
        '8.23.139.0/24',
        '8.23.240.0/24',
        '8.24.242.0/24',
        '8.24.243.0/24',
        '8.24.244.0/24',
        '8.24.87.0/24',
        '8.25.249.0/24',
        '8.25.96.0/24',
        '8.25.97.0/24',
        '8.26.180.0/24',
        '8.26.182.0/24',
        '8.27.64.0/24',
        '8.27.66.0/24',
        '8.27.67.0/24',
        '8.27.68.0/24',
        '8.27.69.0/24',
        '8.27.79.0/24',
        '8.28.126.0/24',
        '8.28.20.0/24',
        '8.28.213.0/24',
        '8.28.82.0/24',
        '8.29.105.0/24',
        '8.29.109.0/24',
        '8.29.228.0/24',
        '8.29.230.0/24',
        '8.29.231.0/24',
        '8.30.234.0/24',
        '8.31.160.0/24',
        '8.31.161.0/24',
        '8.31.2.0/24',
        '8.34.200.0/24',
        '8.34.201.0/24',
        '8.34.202.0/24',
        '8.34.69.0/24',
        '8.34.70.0/24',
        '8.34.71.0/24',
        '8.35.149.0/24',
        '8.35.211.0/24',
        '8.35.57.0/24',
        '8.35.58.0/24',
        '8.35.59.0/24',
        '8.36.216.0/24',
        '8.36.217.0/24',
        '8.36.218.0/24',
        '8.36.219.0/24',
        '8.37.41.0/24',
        '8.37.43.0/24',
        '8.38.147.0/24',
        '8.38.148.0/24',
        '8.38.149.0/24',
        '8.38.172.0/24',
        '8.39.125.0/24',
        '8.39.126.0/24',
        '8.39.18.0/24',
        '8.39.201.0/24',
        '8.39.202.0/24',
        '8.39.203.0/24',
        '8.39.204.0/24',
        '8.39.205.0/24',
        '8.39.206.0/24',
        '8.39.207.0/24',
        '8.39.212.0/24',
        '8.39.213.0/24',
        '8.39.214.0/24',
        '8.39.215.0/24',
        '8.39.6.0/24',
        '8.40.107.0/24',
        '8.40.111.0/24',
        '8.40.140.0/24',
        '8.40.26.0/24',
        '8.40.27.0/24',
        '8.40.28.0/24',
        '8.40.29.0/24',
        '8.40.30.0/24',
        '8.40.31.0/24',
        '8.41.36.0/24',
        '8.41.37.0/24',
        '8.41.5.0/24',
        '8.41.6.0/24',
        '8.41.7.0/24',
        '8.42.161.0/24',
        '8.42.164.0/24',
        '8.42.172.0/24',
        '8.42.245.0/24',
        '8.42.51.0/24',
        '8.42.52.0/24',
        '8.42.54.0/24',
        '8.42.55.0/24',
        '8.43.121.0/24',
        '8.43.122.0/24',
        '8.43.123.0/24',
        '8.43.224.0/24',
        '8.43.225.0/24',
        '8.43.226.0/24',
        '8.44.0.0/24',
        '8.44.1.0/24',
        '8.44.2.0/24',
        '8.44.3.0/24',
        '8.44.58.0/24',
        '8.44.6.0/24',
        '8.44.60.0/24',
        '8.44.61.0/24',
        '8.44.62.0/24',
        '8.44.63.0/24',
        '8.45.101.0/24',
        '8.45.102.0/24',
        '8.45.108.0/24',
        '8.45.111.0/24',
        '8.45.144.0/24',
        '8.45.145.0/24',
        '8.45.146.0/24',
        '8.45.147.0/24',
        '8.45.41.0/24',
        '8.45.43.0/24',
        '8.45.44.0/24',
        '8.45.45.0/24',
        '8.45.46.0/24',
        '8.45.47.0/24',
        '8.45.97.0/24',
        '8.46.113.0/24',
        '8.46.114.0/24',
        '8.46.115.0/24',
        '8.46.117.0/24',
        '8.46.118.0/24',
        '8.46.119.0/24',
        '8.47.12.0/24',
        '8.47.13.0/24',
        '8.47.14.0/24',
        '8.47.15.0/24',
        '8.47.69.0/24',
        '8.47.71.0/24',
        '8.47.9.0/24',
        '8.48.130.0/24',
        '8.48.131.0/24',
        '8.48.132.0/24',
        '8.48.133.0/24',
        '8.48.134.0/24',
        '8.6.144.0/24',
        '8.6.145.0/24',
        '8.6.146.0/24',
        '8.9.231.0/24',
        '23.247.163.0/24',
        '31.22.116.0/24',
        '31.43.179.0/24',
        '38.67.242.0/24',
        '45.12.30.0/23',
        '45.131.208.0/22',
        '45.131.4.0/22',
        '45.133.247.0/24',
        '45.14.174.0/24',
        '45.142.120.0/24',
        '45.159.216.0/22',
        '45.8.104.0/22',
        '45.8.211.0/24',
        '45.80.111.0/24',
        '45.85.118.0/23',
        '45.87.175.0/24',
        '45.94.169.0/24',
        '45.95.241.0/24',
        '64.68.192.0/24',
        '66.235.200.0/24',
        '66.81.247.0/24',
        '66.81.255.0/24',
        '80.94.83.0/24',
        '89.116.250.0/24',
        '89.207.18.0/24',
        '89.47.56.0/23',
        '91.195.110.0/24',
        '93.114.64.0/23',
        '94.140.0.0/24',
        '103.11.212.0/24',
        '103.11.214.0/24',
        '103.160.204.0/24',
        '103.169.142.0/24',
        '103.172.110.0/23',
        '103.21.244.0/24',
        '103.21.246.0/24',
        '103.21.247.0/24',
        '103.22.200.0/24',
        '103.22.201.0/24',
        '103.22.202.0/24',
        '103.22.203.0/24',
        '103.31.4.0/22',
        '104.16.0.0/12',
        '104.16.0.0/20',
        '104.16.112.0/20',
        '104.16.128.0/20',
        '104.16.144.0/20',
        '104.16.16.0/20',
        '104.16.160.0/20',
        '104.16.176.0/20',
        '104.16.192.0/20',
        '104.16.208.0/20',
        '104.16.224.0/20',
        '104.16.240.0/20',
        '104.16.32.0/20',
        '104.16.48.0/20',
        '104.16.64.0/20',
        '104.16.80.0/20',
        '104.16.96.0/20',
        '104.17.0.0/20',
        '104.17.112.0/20',
        '104.17.128.0/20',
        '104.17.144.0/20',
        '104.17.16.0/20',
        '104.17.160.0/20',
        '104.17.176.0/20',
        '104.17.192.0/20',
        '104.17.208.0/20',
        '104.17.224.0/20',
        '104.17.240.0/20',
        '104.17.32.0/20',
        '104.17.48.0/20',
        '104.17.64.0/20',
        '104.17.80.0/20',
        '104.17.96.0/20',
        '104.18.0.0/20',
        '104.18.112.0/20',
        '104.18.128.0/20',
        '104.18.144.0/20',
        '104.18.16.0/20',
        '104.18.160.0/20',
        '104.18.176.0/20',
        '104.18.192.0/20',
        '104.18.208.0/20',
        '104.18.224.0/20',
        '104.18.240.0/20',
        '104.18.32.0/19',
        '104.18.32.0/20',
        '104.18.32.0/24',
        '104.18.33.0/24',
        '104.18.34.0/24',
        '104.18.35.0/24',
        '104.18.36.0/24',
        '104.18.37.0/24',
        '104.18.38.0/24',
        '104.18.39.0/24',
        '104.18.40.0/24',
        '104.18.41.0/24',
        '104.18.42.0/24',
        '104.18.43.0/24',
        '104.18.44.0/24',
        '104.18.45.0/24',
        '104.18.46.0/24',
        '104.18.47.0/24',
        '104.18.48.0/24',
        '104.18.49.0/24',
        '104.18.50.0/24',
        '104.18.51.0/24',
        '104.18.52.0/24',
        '104.18.53.0/24',
        '104.18.54.0/24',
        '104.18.55.0/24',
        '104.18.56.0/24',
        '104.18.57.0/24',
        '104.18.58.0/24',
        '104.18.59.0/24',
        '104.18.60.0/24',
        '104.18.61.0/24',
        '104.18.62.0/24',
        '104.18.63.0/24',
        '104.18.64.0/20',
        '104.18.80.0/20',
        '104.18.96.0/20',
        '104.19.0.0/20',
        '104.19.112.0/20',
        '104.19.128.0/20',
        '104.19.144.0/20',
        '104.19.16.0/20',
        '104.19.160.0/20',
        '104.19.176.0/20',
        '104.19.192.0/20',
        '104.19.208.0/20',
        '104.19.224.0/20',
        '104.19.240.0/20',
        '104.19.32.0/20',
        '104.19.48.0/20',
        '104.19.64.0/20',
        '104.19.80.0/20',
        '104.19.96.0/20',
        '104.20.0.0/20',
        '104.20.112.0/20',
        '104.20.128.0/20',
        '104.20.144.0/20',
        '104.20.16.0/20',
        '104.20.160.0/20',
        '104.20.176.0/20',
        '104.20.192.0/20',
        '104.20.208.0/20',
        '104.20.224.0/20',
        '104.20.240.0/20',
        '104.20.32.0/20',
        '104.20.48.0/20',
        '104.20.64.0/20',
        '104.20.80.0/20',
        '104.20.96.0/20',
        '104.21.0.0/19',
        '104.21.0.0/20',
        '104.21.112.0/20',
        '104.21.16.0/20',
        '104.21.192.0/19',
        '104.21.192.0/20',
        '104.21.208.0/20',
        '104.21.224.0/20',
        '104.21.32.0/19',
        '104.21.32.0/20',
        '104.21.48.0/20',
        '104.21.64.0/19',
        '104.21.64.0/20',
        '104.21.80.0/20',
        '104.21.96.0/19',
        '104.21.96.0/20',
        '104.22.0.0/20',
        '104.22.16.0/20',
        '104.22.32.0/20',
        '104.22.48.0/20',
        '104.22.64.0/20',
        '104.23.112.0/20',
        '104.23.128.0/20',
        '104.23.96.0/20',
        '104.234.158.0/24',
        '104.24.0.0/20',
        '104.24.128.0/20',
        '104.24.144.0/20',
        '104.24.16.0/20',
        '104.24.160.0/20',
        '104.24.176.0/20',
        '104.24.192.0/20',
        '104.24.208.0/20',
        '104.24.224.0/20',
        '104.24.240.0/20',
        '104.24.32.0/20',
        '104.24.48.0/20',
        '104.24.64.0/20',
        '104.24.80.0/20',
        '104.25.0.0/20',
        '104.25.112.0/20',
        '104.25.128.0/20',
        '104.25.144.0/20',
        '104.25.16.0/20',
        '104.25.160.0/20',
        '104.25.176.0/20',
        '104.25.192.0/20',
        '104.25.208.0/20',
        '104.25.224.0/20',
        '104.25.240.0/20',
        '104.25.32.0/20',
        '104.25.48.0/20',
        '104.25.64.0/20',
        '104.25.80.0/20',
        '104.25.96.0/20',
        '104.254.140.0/24',
        '104.26.0.0/20',
        '104.27.0.0/20',
        '104.27.112.0/20',
        '104.27.16.0/20',
        '104.27.192.0/20',
        '104.27.32.0/20',
        '104.27.48.0/20',
        '104.27.64.0/20',
        '104.27.80.0/20',
        '104.27.96.0/20',
        '104.28.0.0/24',
        '104.28.1.0/24',
        '104.28.10.0/24',
        '104.28.100.0/24',
        '104.28.101.0/24',
        '104.28.102.0/24',
        '104.28.103.0/24',
        '104.28.104.0/24',
        '104.28.105.0/24',
        '104.28.106.0/24',
        '104.28.107.0/24',
        '104.28.108.0/24',
        '104.28.109.0/24',
        '104.28.11.0/24',
        '104.28.110.0/24',
        '104.28.111.0/24',
        '104.28.112.0/24',
        '104.28.113.0/24',
        '104.28.114.0/24',
        '104.28.115.0/24',
        '104.28.116.0/24',
        '104.28.117.0/24',
        '104.28.118.0/24',
        '104.28.119.0/24',
        '104.28.12.0/24',
        '104.28.120.0/24',
        '104.28.121.0/24',
        '104.28.122.0/24',
        '104.28.123.0/24',
        '104.28.124.0/24',
        '104.28.125.0/24',
        '104.28.126.0/24',
        '104.28.127.0/24',
        '104.28.128.0/24',
        '104.28.129.0/24',
        '104.28.13.0/24',
        '104.28.130.0/24',
        '104.28.131.0/24',
        '104.28.132.0/24',
        '104.28.133.0/24',
        '104.28.134.0/24',
        '104.28.135.0/24',
        '104.28.14.0/24',
        '104.28.144.0/24',
        '104.28.145.0/24',
        '104.28.146.0/24',
        '104.28.147.0/24',
        '104.28.148.0/24',
        '104.28.149.0/24',
        '104.28.15.0/24',
        '104.28.150.0/24',
        '104.28.151.0/24',
        '104.28.152.0/24',
        '104.28.153.0/24',
        '104.28.154.0/24',
        '104.28.155.0/24',
        '104.28.156.0/24',
        '104.28.157.0/24',
        '104.28.158.0/24',
        '104.28.159.0/24',
        '104.28.16.0/24',
        '104.28.17.0/24',
        '104.28.18.0/24',
        '104.28.19.0/24',
        '104.28.192.0/24',
        '104.28.193.0/24',
        '104.28.194.0/24',
        '104.28.195.0/24',
        '104.28.196.0/24',
        '104.28.197.0/24',
        '104.28.198.0/24',
        '104.28.199.0/24',
        '104.28.2.0/24',
        '104.28.20.0/24',
        '104.28.200.0/24',
        '104.28.201.0/24',
        '104.28.202.0/24',
        '104.28.203.0/24',
        '104.28.204.0/24',
        '104.28.205.0/24',
        '104.28.206.0/24',
        '104.28.207.0/24',
        '104.28.208.0/24',
        '104.28.209.0/24',
        '104.28.21.0/24',
        '104.28.210.0/24',
        '104.28.211.0/24',
        '104.28.212.0/24',
        '104.28.213.0/24',
        '104.28.214.0/24',
        '104.28.215.0/24',
        '104.28.216.0/24',
        '104.28.217.0/24',
        '104.28.218.0/24',
        '104.28.219.0/24',
        '104.28.22.0/24',
        '104.28.220.0/24',
        '104.28.221.0/24',
        '104.28.222.0/24',
        '104.28.223.0/24',
        '104.28.224.0/24',
        '104.28.225.0/24',
        '104.28.226.0/24',
        '104.28.227.0/24',
        '104.28.228.0/24',
        '104.28.229.0/24',
        '104.28.23.0/24',
        '104.28.230.0/24',
        '104.28.231.0/24',
        '104.28.232.0/24',
        '104.28.233.0/24',
        '104.28.234.0/24',
        '104.28.235.0/24',
        '104.28.236.0/24',
        '104.28.237.0/24',
        '104.28.238.0/24',
        '104.28.239.0/24',
        '104.28.24.0/24',
        '104.28.240.0/24',
        '104.28.241.0/24',
        '104.28.242.0/24',
        '104.28.243.0/24',
        '104.28.244.0/24',
        '104.28.245.0/24',
        '104.28.246.0/24',
        '104.28.247.0/24',
        '104.28.248.0/24',
        '104.28.249.0/24',
        '104.28.25.0/24',
        '104.28.250.0/24',
        '104.28.251.0/24',
        '104.28.252.0/24',
        '104.28.253.0/24',
        '104.28.254.0/24',
        '104.28.255.0/24',
        '104.28.26.0/24',
        '104.28.27.0/24',
        '104.28.28.0/24',
        '104.28.29.0/24',
        '104.28.3.0/24',
        '104.28.30.0/24',
        '104.28.31.0/24',
        '104.28.32.0/24',
        '104.28.33.0/24',
        '104.28.34.0/24',
        '104.28.35.0/24',
        '104.28.36.0/24',
        '104.28.37.0/24',
        '104.28.38.0/24',
        '104.28.39.0/24',
        '104.28.4.0/24',
        '104.28.40.0/24',
        '104.28.41.0/24',
        '104.28.42.0/24',
        '104.28.43.0/24',
        '104.28.44.0/24',
        '104.28.45.0/24',
        '104.28.46.0/24',
        '104.28.47.0/24',
        '104.28.48.0/24',
        '104.28.49.0/24',
        '104.28.50.0/24',
        '104.28.51.0/24',
        '104.28.52.0/24',
        '104.28.53.0/24',
        '104.28.54.0/24',
        '104.28.55.0/24',
        '104.28.56.0/24',
        '104.28.57.0/24',
        '104.28.58.0/24',
        '104.28.59.0/24',
        '104.28.6.0/24',
        '104.28.60.0/24',
        '104.28.61.0/24',
        '104.28.62.0/24',
        '104.28.63.0/24',
        '104.28.64.0/24',
        '104.28.65.0/24',
        '104.28.66.0/24',
        '104.28.67.0/24',
        '104.28.68.0/24',
        '104.28.69.0/24',
        '104.28.7.0/24',
        '104.28.70.0/24',
        '104.28.71.0/24',
        '104.28.72.0/24',
        '104.28.73.0/24',
        '104.28.74.0/24',
        '104.28.75.0/24',
        '104.28.76.0/24',
        '104.28.77.0/24',
        '104.28.78.0/24',
        '104.28.79.0/24',
        '104.28.8.0/24',
        '104.28.80.0/24',
        '104.28.81.0/24',
        '104.28.82.0/24',
        '104.28.83.0/24',
        '104.28.84.0/24',
        '104.28.85.0/24',
        '104.28.86.0/24',
        '104.28.87.0/24',
        '104.28.88.0/24',
        '104.28.89.0/24',
        '104.28.9.0/24',
        '104.28.90.0/24',
        '104.28.91.0/24',
        '104.28.92.0/24',
        '104.28.93.0/24',
        '104.28.94.0/24',
        '104.28.95.0/24',
        '104.28.96.0/24',
        '104.28.97.0/24',
        '104.28.98.0/24',
        '104.28.99.0/24',
        '104.29.0.0/24',
        '104.29.1.0/24',
        '104.29.10.0/24',
        '104.29.100.0/24',
        '104.29.101.0/24',
        '104.29.102.0/24',
        '104.29.103.0/24',
        '104.29.104.0/24',
        '104.29.105.0/24',
        '104.29.106.0/24',
        '104.29.107.0/24',
        '104.29.11.0/24',
        '104.29.12.0/24',
        '104.29.13.0/24',
        '104.29.14.0/24',
        '104.29.15.0/24',
        '104.29.16.0/24',
        '104.29.17.0/24',
        '104.29.18.0/24',
        '104.29.19.0/24',
        '104.29.2.0/24',
        '104.29.20.0/24',
        '104.29.21.0/24',
        '104.29.22.0/24',
        '104.29.23.0/24',
        '104.29.24.0/24',
        '104.29.25.0/24',
        '104.29.26.0/24',
        '104.29.27.0/24',
        '104.29.28.0/24',
        '104.29.29.0/24',
        '104.29.3.0/24',
        '104.29.30.0/24',
        '104.29.31.0/24',
        '104.29.32.0/24',
        '104.29.33.0/24',
        '104.29.34.0/24',
        '104.29.35.0/24',
        '104.29.36.0/24',
        '104.29.37.0/24',
        '104.29.38.0/24',
        '104.29.39.0/24',
        '104.29.4.0/24',
        '104.29.40.0/24',
        '104.29.41.0/24',
        '104.29.42.0/24',
        '104.29.43.0/24',
        '104.29.44.0/24',
        '104.29.45.0/24',
        '104.29.46.0/24',
        '104.29.47.0/24',
        '104.29.48.0/24',
        '104.29.49.0/24',
        '104.29.5.0/24',
        '104.29.50.0/24',
        '104.29.53.0/24',
        '104.29.54.0/24',
        '104.29.55.0/24',
        '104.29.56.0/24',
        '104.29.57.0/24',
        '104.29.58.0/24',
        '104.29.59.0/24',
        '104.29.6.0/24',
        '104.29.60.0/24',
        '104.29.61.0/24',
        '104.29.62.0/24',
        '104.29.63.0/24',
        '104.29.65.0/24',
        '104.29.66.0/24',
        '104.29.67.0/24',
        '104.29.68.0/24',
        '104.29.69.0/24',
        '104.29.7.0/24',
        '104.29.70.0/24',
        '104.29.71.0/24',
        '104.29.72.0/24',
        '104.29.73.0/24',
        '104.29.76.0/24',
        '104.29.77.0/24',
        '104.29.78.0/24',
        '104.29.79.0/24',
        '104.29.8.0/24',
        '104.29.80.0/24',
        '104.29.81.0/24',
        '104.29.82.0/24',
        '104.29.83.0/24',
        '104.29.84.0/24',
        '104.29.85.0/24',
        '104.29.86.0/24',
        '104.29.87.0/24',
        '104.29.88.0/24',
        '104.29.89.0/24',
        '104.29.9.0/24',
        '104.29.90.0/24',
        '104.29.91.0/24',
        '104.29.92.0/24',
        '104.29.93.0/24',
        '104.29.94.0/24',
        '104.29.95.0/24',
        '104.29.96.0/24',
        '104.29.97.0/24',
        '104.29.98.0/24',
        '104.29.99.0/24',
        '104.30.0.0/24',
        '104.30.1.0/24',
        '104.30.128.0/23',
        '104.30.2.0/24',
        '104.30.3.0/24',
        '104.30.4.0/24',
        '104.30.5.0/24',
        '104.31.16.0/23',
        '108.162.192.0/20',
        '108.162.192.0/24',
        '108.162.193.0/24',
        '108.162.194.0/24',
        '108.162.195.0/24',
        '108.162.196.0/24',
        '108.162.198.0/24',
        '108.162.210.0/24',
        '108.162.211.0/24',
        '108.162.212.0/24',
        '108.162.213.0/24',
        '108.162.216.0/24',
        '108.162.217.0/24',
        '108.162.218.0/24',
        '108.162.226.0/24',
        '108.162.227.0/24',
        '108.162.235.0/24',
        '108.162.236.0/24',
        '108.162.237.0/24',
        '108.162.238.0/24',
        '108.162.239.0/24',
        '108.162.240.0/24',
        '108.162.241.0/24',
        '108.162.242.0/24',
        '108.162.243.0/24',
        '108.162.244.0/24',
        '108.162.245.0/24',
        '108.162.246.0/24',
        '108.162.247.0/24',
        '108.162.248.0/24',
        '108.162.249.0/24',
        '108.162.250.0/24',
        '108.162.255.0/24',
        '108.165.216.0/24',
        '123.253.174.0/24',
        '141.101.100.0/24',
        '141.101.108.0/24',
        '141.101.109.0/24',
        '141.101.110.0/24',
        '141.101.112.0/20',
        '141.101.112.0/23',
        '141.101.114.0/23',
        '141.101.120.0/22',
        '141.101.64.0/24',
        '141.101.65.0/24',
        '141.101.66.0/24',
        '141.101.67.0/24',
        '141.101.68.0/24',
        '141.101.69.0/24',
        '141.101.70.0/24',
        '141.101.71.0/24',
        '141.101.72.0/24',
        '141.101.73.0/24',
        '141.101.74.0/24',
        '141.101.75.0/24',
        '141.101.76.0/23',
        '141.101.82.0/24',
        '141.101.83.0/24',
        '141.101.84.0/24',
        '141.101.85.0/24',
        '141.101.86.0/24',
        '141.101.87.0/24',
        '141.101.88.0/24',
        '141.101.89.0/24',
        '141.101.90.0/24',
        '141.101.91.0/24',
        '141.101.92.0/24',
        '141.101.93.0/24',
        '141.101.94.0/24',
        '141.101.95.0/24',
        '141.101.96.0/24',
        '141.101.97.0/24',
        '141.101.98.0/24',
        '141.101.99.0/24',
        '141.11.194.0/23',
        '141.193.213.0/24',
        '146.19.22.0/24',
        '147.185.161.0/24',
        '147.78.121.0/24',
        '147.78.140.0/24',
        '154.219.2.0/23',
        '154.51.129.0/24',
        '154.51.160.0/24',
        '154.83.2.0/24',
        '154.83.22.0/23',
        '154.83.30.0/23',
        '154.84.14.0/23',
        '154.84.16.0/21',
        '154.84.175.0/24',
        '154.84.24.0/22',
        '154.85.8.0/22',
        '154.85.99.0/24',
        '154.94.8.0/23',
        '156.237.4.0/23',
        '156.238.14.0/23',
        '156.238.18.0/23',
        '156.239.152.0/22',
        '159.112.235.0/24',
        '159.246.55.0/24',
        '160.153.0.0/24',
        '162.158.0.0/22',
        '162.158.10.0/24',
        '162.158.100.0/24',
        '162.158.101.0/24',
        '162.158.102.0/24',
        '162.158.103.0/24',
        '162.158.104.0/24',
        '162.158.105.0/24',
        '162.158.106.0/24',
        '162.158.107.0/24',
        '162.158.108.0/24',
        '162.158.109.0/24',
        '162.158.11.0/24',
        '162.158.110.0/24',
        '162.158.111.0/24',
        '162.158.112.0/24',
        '162.158.113.0/24',
        '162.158.114.0/24',
        '162.158.116.0/24',
        '162.158.117.0/24',
        '162.158.118.0/24',
        '162.158.119.0/24',
        '162.158.12.0/24',
        '162.158.124.0/22',
        '162.158.128.0/22',
        '162.158.132.0/24',
        '162.158.133.0/24',
        '162.158.134.0/24',
        '162.158.135.0/24',
        '162.158.136.0/22',
        '162.158.136.0/24',
        '162.158.140.0/24',
        '162.158.141.0/24',
        '162.158.142.0/24',
        '162.158.143.0/24',
        '162.158.144.0/24',
        '162.158.145.0/24',
        '162.158.146.0/24',
        '162.158.147.0/24',
        '162.158.148.0/24',
        '162.158.149.0/24',
        '162.158.150.0/24',
        '162.158.151.0/24',
        '162.158.152.0/24',
        '162.158.153.0/24',
        '162.158.154.0/24',
        '162.158.155.0/24',
        '162.158.156.0/24',
        '162.158.157.0/24',
        '162.158.158.0/24',
        '162.158.159.0/24',
        '162.158.16.0/22',
        '162.158.160.0/24',
        '162.158.161.0/24',
        '162.158.162.0/24',
        '162.158.163.0/24',
        '162.158.164.0/24',
        '162.158.165.0/24',
        '162.158.166.0/24',
        '162.158.167.0/24',
        '162.158.168.0/24',
        '162.158.169.0/24',
        '162.158.170.0/24',
        '162.158.171.0/24',
        '162.158.172.0/24',
        '162.158.173.0/24',
        '162.158.174.0/24',
        '162.158.175.0/24',
        '162.158.176.0/24',
        '162.158.178.0/24',
        '162.158.179.0/24',
        '162.158.180.0/22',
        '162.158.184.0/24',
        '162.158.185.0/24',
        '162.158.186.0/24',
        '162.158.187.0/24',
        '162.158.188.0/24',
        '162.158.189.0/24',
        '162.158.190.0/24',
        '162.158.191.0/24',
        '162.158.192.0/24',
        '162.158.193.0/24',
        '162.158.194.0/24',
        '162.158.195.0/24',
        '162.158.196.0/24',
        '162.158.198.0/24',
        '162.158.199.0/24',
        '162.158.20.0/22',
        '162.158.20.0/24',
        '162.158.200.0/22',
        '162.158.204.0/23',
        '162.158.206.0/24',
        '162.158.207.0/24',
        '162.158.208.0/22',
        '162.158.21.0/24',
        '162.158.212.0/24',
        '162.158.214.0/24',
        '162.158.215.0/24',
        '162.158.216.0/23',
        '162.158.218.0/23',
        '162.158.22.0/24',
        '162.158.220.0/22',
        '162.158.224.0/24',
        '162.158.225.0/24',
        '162.158.226.0/23',
        '162.158.228.0/24',
        '162.158.23.0/24',
        '162.158.232.0/23',
        '162.158.234.0/23',
        '162.158.236.0/22',
        '162.158.24.0/23',
        '162.158.240.0/22',
        '162.158.244.0/23',
        '162.158.248.0/23',
        '162.158.25.0/24',
        '162.158.250.0/23',
        '162.158.253.0/24',
        '162.158.254.0/24',
        '162.158.255.0/24',
        '162.158.26.0/24',
        '162.158.27.0/24',
        '162.158.28.0/24',
        '162.158.29.0/24',
        '162.158.30.0/24',
        '162.158.31.0/24',
        '162.158.32.0/22',
        '162.158.36.0/24',
        '162.158.37.0/24',
        '162.158.38.0/24',
        '162.158.39.0/24',
        '162.158.4.0/24',
        '162.158.40.0/24',
        '162.158.41.0/24',
        '162.158.42.0/24',
        '162.158.43.0/24',
        '162.158.44.0/24',
        '162.158.48.0/24',
        '162.158.5.0/24',
        '162.158.51.0/24',
        '162.158.52.0/22',
        '162.158.56.0/24',
        '162.158.57.0/24',
        '162.158.58.0/24',
        '162.158.59.0/24',
        '162.158.60.0/24',
        '162.158.61.0/24',
        '162.158.62.0/24',
        '162.158.63.0/24',
        '162.158.64.0/21',
        '162.158.72.0/24',
        '162.158.73.0/24',
        '162.158.74.0/24',
        '162.158.75.0/24',
        '162.158.76.0/22',
        '162.158.8.0/24',
        '162.158.80.0/24',
        '162.158.81.0/24',
        '162.158.82.0/24',
        '162.158.84.0/22',
        '162.158.88.0/24',
        '162.158.89.0/24',
        '162.158.9.0/24',
        '162.158.90.0/24',
        '162.158.91.0/24',
        '162.158.92.0/24',
        '162.158.93.0/24',
        '162.158.94.0/24',
        '162.158.95.0/24',
        '162.158.96.0/24',
        '162.158.97.0/24',
        '162.158.98.0/24',
        '162.158.99.0/24',
        '162.159.0.0/20',
        '162.159.0.0/24',
        '162.159.1.0/24',
        '162.159.10.0/24',
        '162.159.11.0/24',
        '162.159.12.0/24',
        '162.159.128.0/17',
        '162.159.128.0/19',
        '162.159.13.0/24',
        '162.159.14.0/24',
        '162.159.15.0/24',
        '162.159.16.0/20',
        '162.159.16.0/24',
        '162.159.160.0/24',
        '162.159.17.0/24',
        '162.159.18.0/24',
        '162.159.19.0/24',
        '162.159.192.0/22',
        '162.159.192.0/24',
        '162.159.193.0/24',
        '162.159.194.0/24',
        '162.159.195.0/24',
        '162.159.196.0/24',
        '162.159.2.0/24',
        '162.159.20.0/24',
        '162.159.200.0/24',
        '162.159.201.0/24',
        '162.159.202.0/24',
        '162.159.204.0/24',
        '162.159.205.0/24',
        '162.159.21.0/24',
        '162.159.22.0/24',
        '162.159.23.0/24',
        '162.159.24.0/24',
        '162.159.240.0/20',
        '162.159.25.0/24',
        '162.159.26.0/24',
        '162.159.27.0/24',
        '162.159.28.0/24',
        '162.159.29.0/24',
        '162.159.3.0/24',
        '162.159.30.0/24',
        '162.159.31.0/24',
        '162.159.32.0/20',
        '162.159.32.0/23',
        '162.159.34.0/23',
        '162.159.36.0/24',
        '162.159.4.0/24',
        '162.159.40.0/23',
        '162.159.42.0/23',
        '162.159.46.0/24',
        '162.159.48.0/20',
        '162.159.5.0/24',
        '162.159.58.0/24',
        '162.159.6.0/24',
        '162.159.60.0/24',
        '162.159.64.0/20',
        '162.159.7.0/24',
        '162.159.79.0/24',
        '162.159.8.0/24',
        '162.159.9.0/24',
        '162.251.82.0/24',
        '162.44.104.0/22',
        '164.38.155.0/24',
        '167.1.148.0/24',
        '167.1.150.0/24',
        '168.100.6.0/24',
        '170.114.45.0/24',
        '170.114.46.0/24',
        '170.114.52.0/24',
        '172.64.0.0/16',
        '172.64.128.0/20',
        '172.64.144.0/24',
        '172.64.145.0/24',
        '172.64.146.0/24',
        '172.64.147.0/24',
        '172.64.148.0/24',
        '172.64.149.0/24',
        '172.64.150.0/24',
        '172.64.151.0/24',
        '172.64.152.0/24',
        '172.64.153.0/24',
        '172.64.154.0/24',
        '172.64.155.0/24',
        '172.64.156.0/24',
        '172.64.157.0/24',
        '172.64.158.0/24',
        '172.64.159.0/24',
        '172.64.160.0/20',
        '172.64.192.0/20',
        '172.64.228.0/24',
        '172.64.229.0/24',
        '172.64.236.0/24',
        '172.64.237.0/24',
        '172.64.238.0/24',
        '172.64.239.0/24',
        '172.64.240.0/20',
        '172.64.32.0/20',
        '172.64.32.0/24',
        '172.64.33.0/24',
        '172.64.34.0/24',
        '172.64.35.0/24',
        '172.64.36.0/23',
        '172.64.38.0/24',
        '172.64.40.0/24',
        '172.64.48.0/20',
        '172.64.52.0/24',
        '172.64.53.0/24',
        '172.64.68.0/24',
        '172.64.69.0/24',
        '172.64.80.0/20',
        '172.64.96.0/20',
        '172.65.0.0/19',
        '172.65.0.0/20',
        '172.65.112.0/20',
        '172.65.128.0/20',
        '172.65.144.0/20',
        '172.65.16.0/20',
        '172.65.160.0/20',
        '172.65.176.0/20',
        '172.65.192.0/20',
        '172.65.208.0/20',
        '172.65.224.0/20',
        '172.65.240.0/20',
        '172.65.32.0/19',
        '172.65.32.0/20',
        '172.65.48.0/20',
        '172.65.64.0/20',
        '172.65.80.0/20',
        '172.65.96.0/20',
        '172.66.0.0/22',
        '172.66.40.0/21',
        '172.67.0.0/20',
        '172.67.112.0/20',
        '172.67.128.0/20',
        '172.67.144.0/20',
        '172.67.16.0/20',
        '172.67.160.0/20',
        '172.67.176.0/20',
        '172.67.192.0/20',
        '172.67.208.0/20',
        '172.67.224.0/20',
        '172.67.240.0/20',
        '172.67.32.0/20',
        '172.67.48.0/20',
        '172.67.64.0/20',
        '172.67.80.0/20',
        '172.67.96.0/20',
        '172.68.0.0/22',
        '172.68.100.0/22',
        '172.68.104.0/22',
        '172.68.104.0/24',
        '172.68.108.0/22',
        '172.68.112.0/24',
        '172.68.113.0/24',
        '172.68.114.0/24',
        '172.68.115.0/24',
        '172.68.116.0/24',
        '172.68.117.0/24',
        '172.68.118.0/24',
        '172.68.119.0/24',
        '172.68.12.0/22',
        '172.68.120.0/23',
        '172.68.123.0/24',
        '172.68.124.0/23',
        '172.68.126.0/24',
        '172.68.127.0/24',
        '172.68.128.0/24',
        '172.68.129.0/24',
        '172.68.130.0/24',
        '172.68.131.0/24',
        '172.68.132.0/24',
        '172.68.133.0/24',
        '172.68.134.0/24',
        '172.68.135.0/24',
        '172.68.136.0/22',
        '172.68.140.0/24',
        '172.68.141.0/24',
        '172.68.142.0/24',
        '172.68.143.0/24',
        '172.68.144.0/24',
        '172.68.145.0/24',
        '172.68.146.0/24',
        '172.68.147.0/24',
        '172.68.148.0/22',
        '172.68.152.0/24',
        '172.68.153.0/24',
        '172.68.154.0/24',
        '172.68.155.0/24',
        '172.68.16.0/21',
        '172.68.160.0/24',
        '172.68.161.0/24',
        '172.68.162.0/24',
        '172.68.163.0/24',
        '172.68.164.0/23',
        '172.68.166.0/23',
        '172.68.168.0/24',
        '172.68.169.0/24',
        '172.68.170.0/24',
        '172.68.171.0/24',
        '172.68.172.0/22',
        '172.68.176.0/24',
        '172.68.177.0/24',
        '172.68.179.0/24',
        '172.68.180.0/22',
        '172.68.184.0/22',
        '172.68.188.0/24',
        '172.68.189.0/24',
        '172.68.190.0/24',
        '172.68.191.0/24',
        '172.68.196.0/22',
        '172.68.200.0/24',
        '172.68.201.0/24',
        '172.68.202.0/24',
        '172.68.203.0/24',
        '172.68.204.0/23',
        '172.68.206.0/24',
        '172.68.207.0/24',
        '172.68.208.0/24',
        '172.68.209.0/24',
        '172.68.210.0/24',
        '172.68.211.0/24',
        '172.68.212.0/22',
        '172.68.216.0/24',
        '172.68.217.0/24',
        '172.68.218.0/24',
        '172.68.219.0/24',
        '172.68.220.0/23',
        '172.68.222.0/24',
        '172.68.223.0/24',
        '172.68.224.0/22',
        '172.68.228.0/23',
        '172.68.230.0/24',
        '172.68.231.0/24',
        '172.68.232.0/22',
        '172.68.236.0/22',
        '172.68.24.0/22',
        '172.68.240.0/22',
        '172.68.244.0/22',
        '172.68.248.0/24',
        '172.68.249.0/24',
        '172.68.250.0/24',
        '172.68.251.0/24',
        '172.68.252.0/24',
        '172.68.253.0/24',
        '172.68.255.0/24',
        '172.68.28.0/24',
        '172.68.29.0/24',
        '172.68.30.0/24',
        '172.68.31.0/24',
        '172.68.32.0/22',
        '172.68.36.0/23',
        '172.68.38.0/24',
        '172.68.39.0/24',
        '172.68.4.0/24',
        '172.68.40.0/22',
        '172.68.45.0/24',
        '172.68.46.0/24',
        '172.68.47.0/24',
        '172.68.48.0/22',
        '172.68.5.0/24',
        '172.68.52.0/22',
        '172.68.56.0/24',
        '172.68.57.0/24',
        '172.68.58.0/24',
        '172.68.59.0/24',
        '172.68.60.0/22',
        '172.68.64.0/24',
        '172.68.65.0/24',
        '172.68.66.0/24',
        '172.68.67.0/24',
        '172.68.68.0/22',
        '172.68.72.0/23',
        '172.68.74.0/24',
        '172.68.75.0/24',
        '172.68.76.0/23',
        '172.68.78.0/24',
        '172.68.79.0/24',
        '172.68.8.0/22',
        '172.68.80.0/24',
        '172.68.81.0/24',
        '172.68.83.0/24',
        '172.68.84.0/22',
        '172.68.88.0/24',
        '172.68.89.0/24',
        '172.68.90.0/24',
        '172.68.91.0/24',
        '172.68.92.0/24',
        '172.68.93.0/24',
        '172.68.94.0/24',
        '172.68.95.0/24',
        '172.68.96.0/24',
        '172.68.97.0/24',
        '172.68.98.0/24',
        '172.68.99.0/24',
        '172.69.0.0/23',
        '172.69.100.0/24',
        '172.69.101.0/24',
        '172.69.102.0/24',
        '172.69.103.0/24',
        '172.69.105.0/24',
        '172.69.106.0/24',
        '172.69.107.0/24',
        '172.69.108.0/23',
        '172.69.110.0/24',
        '172.69.111.0/24',
        '172.69.112.0/22',
        '172.69.116.0/22',
        '172.69.12.0/24',
        '172.69.124.0/22',
        '172.69.128.0/22',
        '172.69.13.0/24',
        '172.69.132.0/24',
        '172.69.133.0/24',
        '172.69.134.0/24',
        '172.69.135.0/24',
        '172.69.136.0/22',
        '172.69.14.0/24',
        '172.69.140.0/22',
        '172.69.144.0/22',
        '172.69.15.0/24',
        '172.69.156.0/24',
        '172.69.157.0/24',
        '172.69.158.0/24',
        '172.69.159.0/24',
        '172.69.16.0/24',
        '172.69.160.0/24',
        '172.69.161.0/24',
        '172.69.162.0/24',
        '172.69.163.0/24',
        '172.69.164.0/22',
        '172.69.168.0/22',
        '172.69.172.0/24',
        '172.69.18.0/24',
        '172.69.180.0/24',
        '172.69.181.0/24',
        '172.69.182.0/24',
        '172.69.183.0/24',
        '172.69.184.0/22',
        '172.69.188.0/22',
        '172.69.19.0/24',
        '172.69.192.0/22',
        '172.69.196.0/24',
        '172.69.197.0/24',
        '172.69.198.0/24',
        '172.69.199.0/24',
        '172.69.2.0/24',
        '172.69.20.0/24',
        '172.69.200.0/22',
        '172.69.204.0/24',
        '172.69.205.0/24',
        '172.69.208.0/24',
        '172.69.209.0/24',
        '172.69.21.0/24',
        '172.69.210.0/24',
        '172.69.211.0/24',
        '172.69.212.0/24',
        '172.69.213.0/24',
        '172.69.216.0/24',
        '172.69.217.0/24',
        '172.69.218.0/24',
        '172.69.219.0/24',
        '172.69.22.0/24',
        '172.69.220.0/24',
        '172.69.221.0/24',
        '172.69.224.0/23',
        '172.69.226.0/24',
        '172.69.227.0/24',
        '172.69.228.0/24',
        '172.69.23.0/24',
        '172.69.232.0/24',
        '172.69.233.0/24',
        '172.69.234.0/24',
        '172.69.235.0/24',
        '172.69.236.0/24',
        '172.69.237.0/24',
        '172.69.238.0/24',
        '172.69.239.0/24',
        '172.69.24.0/21',
        '172.69.241.0/24',
        '172.69.242.0/24',
        '172.69.244.0/23',
        '172.69.246.0/23',
        '172.69.248.0/24',
        '172.69.250.0/24',
        '172.69.251.0/24',
        '172.69.252.0/24',
        '172.69.253.0/24',
        '172.69.254.0/24',
        '172.69.255.0/24',
        '172.69.3.0/24',
        '172.69.32.0/24',
        '172.69.33.0/24',
        '172.69.34.0/24',
        '172.69.35.0/24',
        '172.69.36.0/23',
        '172.69.38.0/23',
        '172.69.4.0/22',
        '172.69.40.0/22',
        '172.69.44.0/24',
        '172.69.45.0/24',
        '172.69.46.0/24',
        '172.69.47.0/24',
        '172.69.48.0/24',
        '172.69.52.0/24',
        '172.69.53.0/24',
        '172.69.54.0/24',
        '172.69.55.0/24',
        '172.69.56.0/24',
        '172.69.57.0/24',
        '172.69.58.0/24',
        '172.69.59.0/24',
        '172.69.60.0/24',
        '172.69.61.0/24',
        '172.69.62.0/24',
        '172.69.63.0/24',
        '172.69.64.0/24',
        '172.69.65.0/24',
        '172.69.66.0/24',
        '172.69.67.0/24',
        '172.69.68.0/24',
        '172.69.69.0/24',
        '172.69.70.0/24',
        '172.69.71.0/24',
        '172.69.72.0/22',
        '172.69.76.0/23',
        '172.69.78.0/24',
        '172.69.79.0/24',
        '172.69.8.0/22',
        '172.69.80.0/22',
        '172.69.84.0/24',
        '172.69.88.0/22',
        '172.69.92.0/24',
        '172.69.96.0/24',
        '172.69.97.0/24',
        '172.70.0.0/19',
        '172.70.100.0/24',
        '172.70.101.0/24',
        '172.70.102.0/24',
        '172.70.103.0/24',
        '172.70.104.0/24',
        '172.70.105.0/24',
        '172.70.106.0/24',
        '172.70.107.0/24',
        '172.70.108.0/24',
        '172.70.109.0/24',
        '172.70.110.0/24',
        '172.70.111.0/24',
        '172.70.112.0/24',
        '172.70.113.0/24',
        '172.70.114.0/24',
        '172.70.115.0/24',
        '172.70.116.0/24',
        '172.70.117.0/24',
        '172.70.120.0/24',
        '172.70.121.0/24',
        '172.70.122.0/24',
        '172.70.123.0/24',
        '172.70.124.0/24',
        '172.70.125.0/24',
        '172.70.126.0/24',
        '172.70.127.0/24',
        '172.70.128.0/24',
        '172.70.129.0/24',
        '172.70.130.0/24',
        '172.70.131.0/24',
        '172.70.132.0/24',
        '172.70.133.0/24',
        '172.70.134.0/24',
        '172.70.135.0/24',
        '172.70.136.0/24',
        '172.70.138.0/24',
        '172.70.139.0/24',
        '172.70.140.0/24',
        '172.70.141.0/24',
        '172.70.142.0/24',
        '172.70.143.0/24',
        '172.70.144.0/24',
        '172.70.145.0/24',
        '172.70.146.0/24',
        '172.70.147.0/24',
        '172.70.148.0/24',
        '172.70.149.0/24',
        '172.70.150.0/24',
        '172.70.152.0/24',
        '172.70.153.0/24',
        '172.70.154.0/24',
        '172.70.155.0/24',
        '172.70.156.0/24',
        '172.70.157.0/24',
        '172.70.158.0/24',
        '172.70.160.0/24',
        '172.70.161.0/24',
        '172.70.162.0/24',
        '172.70.163.0/24',
        '172.70.172.0/24',
        '172.70.173.0/24',
        '172.70.174.0/24',
        '172.70.175.0/24',
        '172.70.176.0/24',
        '172.70.177.0/24',
        '172.70.178.0/24',
        '172.70.179.0/24',
        '172.70.180.0/24',
        '172.70.181.0/24',
        '172.70.182.0/24',
        '172.70.183.0/24',
        '172.70.184.0/24',
        '172.70.185.0/24',
        '172.70.186.0/24',
        '172.70.187.0/24',
        '172.70.188.0/24',
        '172.70.189.0/24',
        '172.70.190.0/24',
        '172.70.191.0/24',
        '172.70.192.0/24',
        '172.70.193.0/24',
        '172.70.194.0/24',
        '172.70.195.0/24',
        '172.70.196.0/24',
        '172.70.197.0/24',
        '172.70.198.0/24',
        '172.70.199.0/24',
        '172.70.200.0/24',
        '172.70.202.0/24',
        '172.70.203.0/24',
        '172.70.204.0/24',
        '172.70.205.0/24',
        '172.70.206.0/24',
        '172.70.207.0/24',
        '172.70.208.0/24',
        '172.70.209.0/24',
        '172.70.210.0/24',
        '172.70.211.0/24',
        '172.70.212.0/24',
        '172.70.213.0/24',
        '172.70.214.0/24',
        '172.70.215.0/24',
        '172.70.216.0/24',
        '172.70.217.0/24',
        '172.70.218.0/24',
        '172.70.219.0/24',
        '172.70.220.0/24',
        '172.70.221.0/24',
        '172.70.222.0/24',
        '172.70.223.0/24',
        '172.70.224.0/24',
        '172.70.225.0/24',
        '172.70.226.0/24',
        '172.70.227.0/24',
        '172.70.228.0/24',
        '172.70.229.0/24',
        '172.70.230.0/24',
        '172.70.231.0/24',
        '172.70.232.0/24',
        '172.70.233.0/24',
        '172.70.234.0/24',
        '172.70.235.0/24',
        '172.70.236.0/24',
        '172.70.237.0/24',
        '172.70.238.0/24',
        '172.70.239.0/24',
        '172.70.240.0/24',
        '172.70.241.0/24',
        '172.70.242.0/24',
        '172.70.243.0/24',
        '172.70.244.0/24',
        '172.70.245.0/24',
        '172.70.246.0/24',
        '172.70.247.0/24',
        '172.70.248.0/24',
        '172.70.249.0/24',
        '172.70.250.0/24',
        '172.70.251.0/24',
        '172.70.252.0/24',
        '172.70.253.0/24',
        '172.70.254.0/24',
        '172.70.255.0/24',
        '172.70.32.0/24',
        '172.70.33.0/24',
        '172.70.34.0/24',
        '172.70.35.0/24',
        '172.70.36.0/24',
        '172.70.37.0/24',
        '172.70.38.0/24',
        '172.70.39.0/24',
        '172.70.40.0/24',
        '172.70.41.0/24',
        '172.70.42.0/24',
        '172.70.43.0/24',
        '172.70.44.0/24',
        '172.70.45.0/24',
        '172.70.46.0/24',
        '172.70.47.0/24',
        '172.70.48.0/24',
        '172.70.49.0/24',
        '172.70.51.0/24',
        '172.70.52.0/24',
        '172.70.53.0/24',
        '172.70.54.0/24',
        '172.70.55.0/24',
        '172.70.56.0/24',
        '172.70.57.0/24',
        '172.70.58.0/24',
        '172.70.59.0/24',
        '172.70.60.0/24',
        '172.70.61.0/24',
        '172.70.62.0/24',
        '172.70.63.0/24',
        '172.70.64.0/21',
        '172.70.72.0/21',
        '172.70.80.0/24',
        '172.70.81.0/24',
        '172.70.82.0/24',
        '172.70.83.0/24',
        '172.70.84.0/24',
        '172.70.85.0/24',
        '172.70.86.0/24',
        '172.70.87.0/24',
        '172.70.88.0/24',
        '172.70.89.0/24',
        '172.70.90.0/24',
        '172.70.91.0/24',
        '172.70.92.0/24',
        '172.70.93.0/24',
        '172.70.94.0/24',
        '172.70.95.0/24',
        '172.70.96.0/24',
        '172.70.97.0/24',
        '172.70.98.0/24',
        '172.70.99.0/24',
        '172.71.0.0/24',
        '172.71.10.0/24',
        '172.71.100.0/24',
        '172.71.101.0/24',
        '172.71.102.0/24',
        '172.71.103.0/24',
        '172.71.108.0/24',
        '172.71.109.0/24',
        '172.71.11.0/24',
        '172.71.110.0/24',
        '172.71.111.0/24',
        '172.71.112.0/24',
        '172.71.113.0/24',
        '172.71.114.0/24',
        '172.71.115.0/24',
        '172.71.116.0/24',
        '172.71.117.0/24',
        '172.71.118.0/24',
        '172.71.119.0/24',
        '172.71.12.0/24',
        '172.71.120.0/24',
        '172.71.121.0/24',
        '172.71.122.0/24',
        '172.71.123.0/24',
        '172.71.124.0/24',
        '172.71.125.0/24',
        '172.71.126.0/24',
        '172.71.127.0/24',
        '172.71.128.0/24',
        '172.71.129.0/24',
        '172.71.13.0/24',
        '172.71.130.0/24',
        '172.71.131.0/24',
        '172.71.132.0/24',
        '172.71.133.0/24',
        '172.71.134.0/24',
        '172.71.135.0/24',
        '172.71.136.0/24',
        '172.71.137.0/24',
        '172.71.138.0/24',
        '172.71.139.0/24',
        '172.71.14.0/24',
        '172.71.140.0/24',
        '172.71.141.0/24',
        '172.71.142.0/24',
        '172.71.143.0/24',
        '172.71.144.0/24',
        '172.71.145.0/24',
        '172.71.146.0/24',
        '172.71.147.0/24',
        '172.71.148.0/24',
        '172.71.149.0/24',
        '172.71.15.0/24',
        '172.71.150.0/24',
        '172.71.151.0/24',
        '172.71.152.0/24',
        '172.71.153.0/24',
        '172.71.154.0/24',
        '172.71.155.0/24',
        '172.71.156.0/24',
        '172.71.157.0/24',
        '172.71.158.0/24',
        '172.71.159.0/24',
        '172.71.16.0/24',
        '172.71.160.0/24',
        '172.71.161.0/24',
        '172.71.162.0/24',
        '172.71.163.0/24',
        '172.71.164.0/24',
        '172.71.165.0/24',
        '172.71.166.0/24',
        '172.71.167.0/24',
        '172.71.168.0/24',
        '172.71.169.0/24',
        '172.71.17.0/24',
        '172.71.170.0/24',
        '172.71.171.0/24',
        '172.71.172.0/24',
        '172.71.173.0/24',
        '172.71.174.0/24',
        '172.71.175.0/24',
        '172.71.176.0/24',
        '172.71.177.0/24',
        '172.71.178.0/24',
        '172.71.179.0/24',
        '172.71.18.0/24',
        '172.71.180.0/24',
        '172.71.181.0/24',
        '172.71.182.0/24',
        '172.71.183.0/24',
        '172.71.184.0/24',
        '172.71.185.0/24',
        '172.71.186.0/24',
        '172.71.187.0/24',
        '172.71.188.0/24',
        '172.71.189.0/24',
        '172.71.190.0/24',
        '172.71.191.0/24',
        '172.71.192.0/24',
        '172.71.193.0/24',
        '172.71.194.0/24',
        '172.71.195.0/24',
        '172.71.196.0/24',
        '172.71.197.0/24',
        '172.71.198.0/24',
        '172.71.199.0/24',
        '172.71.2.0/24',
        '172.71.20.0/24',
        '172.71.200.0/24',
        '172.71.201.0/24',
        '172.71.202.0/24',
        '172.71.203.0/24',
        '172.71.204.0/24',
        '172.71.205.0/24',
        '172.71.206.0/24',
        '172.71.207.0/24',
        '172.71.208.0/24',
        '172.71.209.0/24',
        '172.71.21.0/24',
        '172.71.210.0/24',
        '172.71.211.0/24',
        '172.71.212.0/24',
        '172.71.213.0/24',
        '172.71.214.0/24',
        '172.71.215.0/24',
        '172.71.216.0/24',
        '172.71.217.0/24',
        '172.71.218.0/24',
        '172.71.219.0/24',
        '172.71.22.0/24',
        '172.71.220.0/24',
        '172.71.221.0/24',
        '172.71.222.0/24',
        '172.71.223.0/24',
        '172.71.224.0/24',
        '172.71.225.0/24',
        '172.71.226.0/24',
        '172.71.227.0/24',
        '172.71.228.0/24',
        '172.71.229.0/24',
        '172.71.23.0/24',
        '172.71.230.0/24',
        '172.71.231.0/24',
        '172.71.232.0/24',
        '172.71.233.0/24',
        '172.71.234.0/24',
        '172.71.235.0/24',
        '172.71.236.0/24',
        '172.71.237.0/24',
        '172.71.238.0/24',
        '172.71.239.0/24',
        '172.71.24.0/24',
        '172.71.240.0/24',
        '172.71.241.0/24',
        '172.71.242.0/24',
        '172.71.243.0/24',
        '172.71.244.0/24',
        '172.71.245.0/24',
        '172.71.246.0/24',
        '172.71.247.0/24',
        '172.71.248.0/24',
        '172.71.249.0/24',
        '172.71.25.0/24',
        '172.71.250.0/24',
        '172.71.251.0/24',
        '172.71.252.0/24',
        '172.71.253.0/24',
        '172.71.254.0/24',
        '172.71.255.0/24',
        '172.71.26.0/24',
        '172.71.27.0/24',
        '172.71.28.0/24',
        '172.71.29.0/24',
        '172.71.3.0/24',
        '172.71.30.0/24',
        '172.71.31.0/24',
        '172.71.32.0/19',
        '172.71.4.0/24',
        '172.71.5.0/24',
        '172.71.6.0/24',
        '172.71.7.0/24',
        '172.71.8.0/24',
        '172.71.80.0/24',
        '172.71.81.0/24',
        '172.71.82.0/24',
        '172.71.83.0/24',
        '172.71.84.0/24',
        '172.71.85.0/24',
        '172.71.86.0/24',
        '172.71.87.0/24',
        '172.71.88.0/24',
        '172.71.89.0/24',
        '172.71.9.0/24',
        '172.71.90.0/24',
        '172.71.91.0/24',
        '172.71.92.0/24',
        '172.71.93.0/24',
        '172.71.94.0/24',
        '172.71.95.0/24',
        '172.71.96.0/24',
        '172.71.97.0/24',
        '172.71.98.0/24',
        '172.71.99.0/24',
        '172.83.72.0/24',
        '172.83.73.0/24',
        '172.83.76.0/24',
        '173.245.49.0/24',
        '173.245.54.0/24',
        '173.245.58.0/24',
        '173.245.59.0/24',
        '173.245.60.0/23',
        '173.245.63.0/24',
        '174.136.134.0/24',
        '176.126.206.0/23',
        '185.109.21.0/24',
        '185.122.0.0/24',
        '185.135.9.0/24',
        '185.148.104.0/24',
        '185.148.105.0/24',
        '185.148.106.0/24',
        '185.148.107.0/24',
        '185.162.228.0/23',
        '185.162.230.0/23',
        '185.170.166.0/24',
        '185.173.35.0/24',
        '185.174.138.0/24',
        '185.176.24.0/24',
        '185.176.26.0/24',
        '185.18.250.0/24',
        '185.193.28.0/23',
        '185.193.30.0/23',
        '185.201.139.0/24',
        '185.207.92.0/24',
        '185.209.154.0/24',
        '185.212.144.0/24',
        '185.213.240.0/24',
        '185.213.243.0/24',
        '185.221.160.0/24',
        '185.234.22.0/24',
        '185.238.228.0/24',
        '185.244.106.0/24',
        '185.38.135.0/24',
        '185.59.218.0/24',
        '185.67.124.0/24',
        '185.7.190.0/23',
        '185.72.49.0/24',
        '188.114.100.0/24',
        '188.114.102.0/24',
        '188.114.103.0/24',
        '188.114.106.0/23',
        '188.114.108.0/24',
        '188.114.111.0/24',
        '188.114.96.0/24',
        '188.114.97.0/24',
        '188.114.98.0/24',
        '188.114.99.0/24',
        '188.244.122.0/24',
        '188.42.88.0/24',
        '188.42.89.0/24',
        '190.93.240.0/20',
        '190.93.244.0/22',
        '191.101.251.0/24',
        '192.133.11.0/24',
        '192.65.217.0/24',
        '193.16.63.0/24',
        '193.17.206.0/24',
        '193.188.14.0/24',
        '193.227.99.0/24',
        '193.67.144.0/24',
        '193.9.49.0/24',
        '194.1.194.0/24',
        '194.152.44.0/24',
        '194.169.194.0/24',
        '194.36.216.0/24',
        '194.36.217.0/24',
        '194.36.218.0/24',
        '194.36.219.0/24',
        '194.36.49.0/24',
        '194.36.55.0/24',
        '194.40.240.0/24',
        '194.40.241.0/24',
        '194.53.53.0/24',
        '194.87.58.0/23',
        '195.137.167.0/24',
        '195.242.122.0/23',
        '195.245.221.0/24',
        '195.85.23.0/24',
        '195.85.59.0/24',
        '196.13.241.0/24',
        '196.207.45.0/24',
        '197.234.240.0/22',
        '197.234.240.0/24',
        '197.234.241.0/24',
        '197.234.242.0/24',
        '198.217.251.0/24',
        '198.41.128.0/24',
        '198.41.129.0/24',
        '198.41.130.0/24',
        '198.41.132.0/22',
        '198.41.136.0/22',
        '198.41.144.0/22',
        '198.41.148.0/22',
        '198.41.148.0/24',
        '198.41.152.0/22',
        '198.41.192.0/21',
        '198.41.200.0/21',
        '198.41.208.0/23',
        '198.41.211.0/24',
        '198.41.212.0/24',
        '198.41.214.0/23',
        '198.41.216.0/24',
        '198.41.217.0/24',
        '198.41.218.0/24',
        '198.41.219.0/24',
        '198.41.220.0/23',
        '198.41.222.0/24',
        '198.41.223.0/24',
        '198.41.228.0/22',
        '198.41.232.0/23',
        '198.41.234.0/24',
        '198.41.236.0/22',
        '198.41.240.0/24',
        '198.41.241.0/24',
        '198.41.242.0/24',
        '198.41.243.0/24',
        '198.41.245.0/24',
        '198.41.245.0/24',
        '198.41.246.0/23',
        '198.41.248.0/23',
        '198.41.250.0/24',
        '198.41.251.0/24',
        '198.41.252.0/24',
        '198.41.253.0/24',
        '198.41.254.0/24',
        '198.41.255.0/24',
        '198.41.255.0/24',
        '198.96.214.0/24',
        '199.181.197.0/24',
        '199.212.90.0/24',
        '199.27.128.0/22',
        '199.27.132.0/24',
        '199.27.134.0/23',
        '199.60.103.0/24',
        '202.82.250.0/24',
        '203.107.173.0/24',
        '203.13.32.0/24',
        '203.17.126.0/24',
        '203.19.222.0/24',
        '203.193.21.0/24',
        '203.22.223.0/24',
        '203.23.103.0/24',
        '203.23.104.0/24',
        '203.23.106.0/24',
        '203.24.102.0/24',
        '203.24.103.0/24',
        '203.24.108.0/24',
        '203.24.109.0/24',
        '203.28.8.0/24',
        '203.28.9.0/24',
        '203.29.52.0/24',
        '203.29.53.0/24',
        '203.29.54.0/23',
        '203.30.188.0/22',
        '203.32.120.0/23',
        '203.34.28.0/24',
        '203.34.80.0/24',
        '203.55.107.0/24',
        '203.89.5.0/24',
        '204.209.72.0/24',
        '204.209.73.0/24',
        '204.62.141.0/24',
        '204.68.111.0/24',
        '205.233.181.0/24',
        '206.196.23.0/24',
        '207.189.149.0/24',
        '208.100.60.0/24',
        '212.110.134.0/23',
        '212.239.86.0/24',
        '212.24.127.0/24',
        '216.116.134.0/24',
        '216.120.180.0/23'
    ]



# Call the main function
if __name__ == '__main__':
    main()
