import sys
import os.path
import requests
import base64
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
    config.read('config.ini')

    # Get the values of the configuration variables, using default values if not available
    max_ip = int(config.get('DEFAULT', 'max_ip', fallback=DEFAULT_MAX_IP))
    max_ping = int(config.get('DEFAULT', 'max_ping',
                   fallback=DEFAULT_MAX_PING))
    max_jitter = int(config.get('DEFAULT', 'max_jitter',
                     fallback=DEFAULT_MAX_JITTER))
    max_latency = int(config.get('DEFAULT', 'max_latency',
                      fallback=DEFAULT_MAX_LATENCY))
    ip_include = config.get('DEFAULT', 'ip_include',
                            fallback=DEFAULT_IP_INCLUDE)
    ip_exclude = config.get('DEFAULT', 'ip_exclude',
                            fallback=DEFAULT_IP_EXCLUDE)
    test_size = config.get('DEFAULT', 'test_size',
                           fallback=DEFAULT_DOWNLOAD_SIZE_KB)
    min_download_speed = config.get(
        'DEFAULT', 'min_download_speed', fallback=DEFAULT_MIN_DOWNLOAD_SPEED)
    min_upload_speed = config.get(
        'DEFAULT', 'min_upload_speed', fallback=DEFAULT_MIN_UPLOAD_SPEED)
    default_upload_results = config.get(
        'DEFAULT', 'upload_results', fallback='no')
    default_delete_existing = config.get(
        'DEFAULT', 'delete_existing', fallback='yes')
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
        # Prompt user for input with default values from configuration file
        max_ip = input(f"Enter max IP [{max_ip}]: ") or max_ip
        max_ping = input(f"Enter max ping [{max_ping}]: ") or max_ping
        max_jitter = input(f"Enter max jitter [{max_jitter}]: ") or max_jitter
        max_latency = input(
            f"Enter max latency [{max_latency}]: ") or max_latency
        ip_include = input(
            f"Enter IPs to include (comma seperated, '-' to ignore) [{ip_include}]: ") or ip_include
        ip_exclude = input(
            f"Enter IPs to exclude (comma seperated, '-' to ignore) [{ip_exclude}]: ") or ip_exclude
        test_size = input(
            f"Enter test data size in KB [{test_size}]: ") or test_size
        min_download_speed = input(
            f"Enter minimum download speed (Mbps) [{min_download_speed}]: ") or min_download_speed
        min_upload_speed = input(
            f"Enter minimum upload speed (Mbps) [{min_upload_speed}]: ") or min_upload_speed

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
        upload_results = input(
            f"Do you want to upload the result to your Cloudflare subdomain (yes/no) [{default_upload_results}]? ") or default_upload_results

        # Code block to execute if upload_results is 'y' or 'yes'
        if upload_results.lower() in ["y", "yes"]:
            delete_existing = input(
                f"Do you want to delete extisting records of given subdomain before uploading the result to your Cloudflare (yes/no) [{default_delete_existing}]? ") or default_delete_existing
            email = input(
                f"Cloudflare email [{default_email}]: ") or default_email
            zone_id = input(
                f"Cloudflare zone ID [{default_zone_id}]: ") or default_zone_id
            api_key = input(
                f"Cloudflare API key [{default_api_key}]: ") or default_api_key

            # Prompt user to enter subdomain to modify
            subdomain = input(
                f"Subdomain to modify (i.e ip.my-domain.com) [{default_subdomain}]: ") or default_subdomain

            # Check if provided credentials are correct and retry if they are not
            while not validateCloudflareCredentials(email, api_key, zone_id):
                print("Invalid cloudflare credentials, please try again.")
                email = input(
                    f"Cloudflare email [{default_email}]: ") or default_email
                zone_id = input(
                    f"Cloudflare zone ID [{default_zone_id}]: ") or default_zone_id
                api_key = input(
                    f"Cloudflare API key [{default_api_key}]: ") or default_api_key

            # Use regular expression to validate subdomain format
            while not re.match(r"^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$", subdomain):
                # If subdomain is invalid, prompt user to try again
                print("Invalid subdomain, please try again.")
                subdomain = input(
                    f"Subdomain to modify (i.e ip.my-domain.com) [{default_subdomain}]: ") or default_subdomain

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
            include_regex = re.compile('|'.join(
                ['^' + re.escape(c).replace('.', '\\.') + '\\.' for c in ip_include.split(',')]))

        # Convert IP ranges to exclude (provided by user in a comma-seperated string) to Regular Expression
        if ip_exclude:
            exclude_regex = re.compile('|'.join(
                ['^' + re.escape(c).replace('.', '\\.') + '\\.' for c in ip_exclude.split(',')]))

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
    selectd_ip_list, total_test = curses.wrapper(
        startTest, ip_list=ip_list, config=config)

    print(f"\n{total_test} of {len(ip_list)} matched IPs have peen tested.")
    print(f"{len(selectd_ip_list)} IP(s) found:")
    print("|---|---------------|----------|---------|---------|----------|------------|")
    print("| # |       IP      | Ping(ms) | Jit(ms) | Lat(ms) | Up(Mbps) | Down(Mbps) |")
    print("|---|---------------|----------|---------|---------|----------|------------|")

    successful_no = 0
    for el in selectd_ip_list:
        successful_no = successful_no + 1
        # Print out the IP and related info as well as ping, latency and download/upload speed
        print(f"\r|{successful_no:3d}|{el.ip:15s}|{el.ping:7d} |{el.jitter:6d} |{el.latency:6d} |{el.upload:7.2f} |{el.download:9.2f} |")

    print("|---|---------------|----------|---------|---------|----------|------------|\n")

    print("IP list successfuly exported to `selected-ips.csv` file.\n")

    # Updating relevant subdomain with clean IP adresses
    if upload_results.lower() in ["y", "yes"]:
        try:
            # Check if user wanted to delete existing records of given subdomain
            if delete_existing.lower() in ["y", "yes"]:
                # Get existing records of the given subdomain
                existing_records = getCloudflareExistingRecords(
                    email, api_key, zone_id, subdomain)
                print("Deleting existing records...", end='', flush=True)
                # Delete all existing records of the given subdomain
                for record in existing_records:
                    deleteCloudflareExistingRecord(
                        email, api_key, zone_id, record["id"])
                print("Done.")

            print("Adding new A Record(s) for selected IP(s):")
            for el in selectd_ip_list:
                print(el.ip, end='', flush=True)
                addNewCloudflareRecord(
                    email, api_key, zone_id, subdomain, el.ip)
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
        csv_file.write(
            "#,IP,Ping (ms),Jitter (ms),Latency (ms),Upload (Mbps),Download (Mbps)\n")

    # Creating `selected-ips.csv` file to output results
    with open('selected-ips.txt', 'w') as txt_file:
        txt_file.write("")

    # Print out table header if it was the first record
    stdscr.addstr(
        3, 0, "|---|---------------|----------|---------|---------|----------|------------|")
    stdscr.addstr(
        4, 0, "| # |       IP      | Ping(ms) | Jit(ms) | Lat(ms) | Up(Mbps) | Down(Mbps) |")
    stdscr.addstr(
        5, 0, "|---|---------------|----------|---------|---------|----------|------------|")
    stdscr.addstr(
        6, 0, "|---|---------------|----------|---------|---------|----------|------------|")

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
            download_speed = getDownloadSpeed(
                ip, test_size, min_download_speed)
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
            stdscr.addstr(
                f"|{successful_no:3d}|{ip:15s}|{ping:7d} |{jitter:6d} |{latency:6d} |{upload_speed:7.2f} |{download_speed:9.2f} |")
            stdscr.refresh()

            selectd_ip_list.append(
                IPInfo(ip, ping, jitter, latency, upload_speed, download_speed))

            with open('selected-ips.csv', 'a') as csv_file:
                csv_file.write(
                    f"{successful_no},{ip},{ping},{jitter},{latency},{upload_speed},{download_speed}\n")
            with open('selected-ips.txt', 'a') as txt_file:
                txt_file.write(f"{ip}\n")

        except KeyboardInterrupt:
            print("\n\nRequest cancelled by user!")
            sys.exit(0)
        except requests.exceptions.RequestException as e:
            print("\r", end='', flush=True)  # Nothing to do

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
        ping = int(
            response_time * 1000) if response_time is not None and response_time > 0 else duration
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
        params = {'resolve': f"speed.cloudflare.com:443:{ip}",
                  'alpn': 'h2,http/1.1', 'utls': 'random'}
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
            response = requests.get(
                url, headers=headers, params=params, timeout=timeout)
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
        params = {'resolve': f"speed.cloudflare.com:443:{ip}",
                  'alpn': 'h2,http/1.1', 'utls': 'random'}
    else:
        params = {'resolve': f"speed.cloudflare.com:443:{ip}"}

    try:
        # Start the timer for the download request
        start_time = time.time()
        # Send the download request and get the response
        response = requests.get(url, headers=headers,
                                params=params, timeout=timeout)
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
    headers = {'Content-Type': 'multipart/form-data',
               'Host': 'speed.cloudflare.com'}
    if openssl_is_active:
        params = {'resolve': f"speed.cloudflare.com:443:{ip}",
                  'alpn': 'h2,http/1.1', 'utls': 'random'}
    else:
        params = {'resolve': f"speed.cloudflare.com:443:{ip}"}

    # Create a sample file with null bytes of the specified size
    files = {'file': ('sample.bin', b"\x00" * upload_size)}

    try:
        # Send the request and measure the upload time
        start_time = time.time()
        response = requests.post(url, headers=headers,
                                 params=params, files=files, timeout=timeout)
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
        openssl = subprocess.check_call(
            ["openssl", "version"], stdout=subprocess.PIPE)
        return True
    except:
        return False


# Define CIDR ranges of Cloudflare Network
def getCIDRv4Ranges():
    ipv4_file = './ipv4.txt'
    if(os.path.isfile(ipv4_file)):
        # ipv4.txt is exist and get contents
        with open(ipv4_file) as f:
            contents = f.readlines()

        # replace \n and return list
        return [item.replace('\n', '') if '\n' in item else item for item in contents]

    else:
        # download and save ipv4.txt and get contents
        response = requests.get(
            'https://api.github.com/repos/mzarchi/cf-ip-scanner-py/contents/ipv4.txt?ref=main')
        result = json.loads(response.text)
        with open(ipv4_file, "+a") as f:
            f.write(base64.b64decode(result['content']).decode('utf-8'))
        return getCIDRv4Ranges()


# Call the main function
if __name__ == '__main__':
    main()
