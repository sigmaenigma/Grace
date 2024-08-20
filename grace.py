#!/usr/bin/env python3
import os
import time
import json
from datetime import datetime
import paramiko
import csv
import logging
from logging.handlers import RotatingFileHandler
import requests
import math

__author__ = "Adrian Sanabria-Diaz"
__license__ = "MIT"

# Create a logger
logger = logging.getLogger('grace_logger')
logger.setLevel(logging.DEBUG)

# Create a rotating file handler
handler = RotatingFileHandler('grace.log', maxBytes=10*1024*1024, backupCount=5)
handler.setLevel(logging.DEBUG)

# Create a formatter and set it for the handler
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

# Add the handler to the logger
logger.addHandler(handler)

def initialize():
    """ Returns the configuration file to be used by different functions """
    try:
        global c
        filename = 'config.json'
        os.path.exists(filename)
        with open(filename, 'r') as f:
            c = json.load(f)
        return c
    except Exception as e:
        exc_msg = f'Issue running get_config(): {e}'
        logger.error(exc_msg)
        print(exc_msg)

def run_get_request(ip):
    """ Runs a GET request against a known IP and returns a True if the HTTP Status Code is 200 """
    try:
        http_url = "https://" + ip.replace("'",'')
        r = requests.get(http_url)
        print(f'-- GET request result for {ip}: {r.status_code}')
        time.sleep(1)
        if r.status_code == 200:
            return True
        else:
            return False
    except Exception as e:
        exc_msg = f'Issue running run_get_request(): {e}'
        logger.error(exc_msg)
        print(exc_msg)
        return False

def save_network_device_history_to_disk():
    """ Store the number of IP addresses discovered on the LAN using the nmap script in the bash file """
    try:
        test_mode = c["run_mode"]["test"]
        if test_mode == True:
            return True
        else:
            ip_count=len(import_list_of_ips_from_scan())
            filename = 'network_device_history.txt'
            # Read the existing lines from the file
            with open(filename, 'r') as f:
                lines = f.readlines()
            # Add the new line
            row_to_write = f'{datetime.now()}, {ip_count}\n'
            lines.append(row_to_write)
            # Keep only the last 100 lines
            if len(lines) > 100:
                lines = lines[-100:]
            # Write the lines back to the file
            with open(filename, 'w') as f:
                f.writelines(lines)
            logger.info(f'Storing {ip_count} IP addresses to disk')
            return True
    except Exception as e:
        exc_msg = f'Issue running save_network_device_history_to_disk(): {e}'
        logger.error(exc_msg)
        print(exc_msg)

def ssh_and_shutdown(host, username, sudo_password, rsa_path):
    """ Log into a server via SSH and shut it down """
    try:
        logger.critical(f"Shutting down server {host}")
        print(f'SSHing into {host} with username {username}')
        username = c["linux_servers"]["heartbeat_server"]["username"]
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        private_key = paramiko.RSAKey(filename=rsa_path)
        ssh.connect(host, username=username, pkey=private_key)

        # Use sudo with -S to read password from stdin
        command = f'echo {sudo_password} | sudo -S shutdown'
        stdin, stdout, stderr = ssh.exec_command(command)
        # print(stdin.read().decode('utf-8'))
        print(stdout.read().decode('utf-8'))
        print(stderr.read().decode('utf-8'))
        return True
    except Exception as e:
        exc_msg = f'Issue running ssh_and_shutdown(): {e}'
        logger.error(exc_msg)
        print(exc_msg)
        return False
    finally:
        ssh.close()
        logger.info(f'Logging out host {host} was successful')

def synology_login_payload(nas_ip, username, password):
    """ Returns the Synology Session ID using the username & password for a specific Synology server """
    try:
        # Login to get a session ID
        login_url = f'https://{nas_ip}:5000/webapi/auth.cgi'
        login_payload = {
            'api': 'SYNO.API.Auth',
            'version': '1',
            'method': 'login',
            'account': username,
            'passwd': password,
            'session': 'Core',
            'format': 'sid'
        }
        response = requests.get(login_url, params=login_payload, verify=False)
        print(response.text)
        print(response.json())
        sid = response.json()['data']['sid']
        return sid
    except Exception as e:
        print(f'An issue occured with synology_login_payload(): {e}')

def shutdown_synology_server(nas_ip, username, password):
    """ Shuts down the Synology Server using the Synology API """
    try:
        sid = synology_login_payload(nas_ip, username, password)
        # Shutdown command
        shutdown_url = f'http://{nas_ip}:5001/webapi/entry.cgi'
        shutdown_payload = {
            'api': 'SYNO.Core.System',
            'version': '1',
            'method': 'shutdown',
            '_sid': sid
        }
        requests.get(shutdown_url, params=shutdown_payload)
    except Exception as e:
        print(f'An issue occured attempting to shutdown the synology server: {e}')

def ssh_login(host, username, rsa_path):
    """ Atttempts to log in via SSH to a known host. If the connection is successful, a True is returned """
    try:
        ips = ips = list([host]*10)
        if check_if_ips_reachable(ips, threshold=.1, mode='ICMP'):
            try:
                print(f'SSHing into {host} with username {username}')
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                private_key = paramiko.RSAKey(filename=rsa_path)
                ssh.connect(host, username=username, pkey=private_key)
            finally:
                msg = f'Logging out of host {host} was successful'
                logger.info(msg)
                ssh.close()
                print(msg)
                time.sleep(1)
                return True
        else:
            print(f'SSH device is not pingable.')
            return False
    except Exception as e:
        exc_msg = f'Issue running ssh_login(): {e}'
        logger.error(exc_msg)
        print(exc_msg)
        return False

def check_of_ssh_device_available():
    """ Performs an SSH test connection and runs a command """
    try:
        print(f'Starting SSH Test... ')
        host = c["linux_servers"]["heartbeat_server"]["server_ip"]    # IP of the device to SSH into
        username = c["linux_servers"]["heartbeat_server"]["username"]
        rsa_path = c["linux_servers"]["heartbeat_server"]["rsa_path"]
        ssh_heartbeat_server = ssh_login(host, username, rsa_path)
        if ssh_heartbeat_server == True:
            return 'Available'
        else:
            return 'Not Available'
    except Exception as e:
        exc_msg = f'Issue running check_of_ssh_device_available(): {e}'
        logger.error(exc_msg)
        print(exc_msg)
        return False

def import_list_of_ips_from_scan():
    """ Imports list of IPs from a Network Scan """
    ip_list = []
    try:
        file_with_list_of_ips = "ip_addresses.txt"
        with open(file_with_list_of_ips, 'r') as f:
            lines = f.readlines()
            ip_list = [line.strip().strip('"') for line in lines]
    except Exception as e:
        exc_msg = f'Issue running import_list_of_ips_from_scan(): {e}'
        logger.error(exc_msg)
        print(exc_msg)
    return ip_list

def ping_device(ip, count=1):
    """ Pings an IP address. If pingable, a True is returned. Otherwise a False is returned """
    try:
        logger.info(f'Pinging device {ip}')
        response = os.system(f"ping -c {count} {ip}")
        if response == 0:
            return True
        else:
            return False
    except Exception as e:
        exc_msg = f'Issue running ping_device(): {e}'
        logger.error(exc_msg)
        print(exc_msg)
        return None

def check_if_ips_reachable(ips, threshold, mode='ICMP'):
    """ Runs a series of tests, either via ICMP or REST API calls to see if an endpoint is available """
    try:
        ip_length = len(ips)
        if mode == 'ICMP':
            print(f'Number of LAN IP addresses detected: {ip_length}')
            results = [ping_device(ip) for ip in ips]
            true_results = [result for result in results if result]
            false_results = [result for result in results if not result]
            true_count,false_count = len(true_results),len(false_results)
            print(f"True Count: {true_count}, False Count: {false_count}")
            if true_count >= threshold:
                return True
            else:
                return False
        elif mode == 'REST':
            print(f'Number of WAN IP addresses detected: {ip_length}')
            results = [run_get_request(ip) for ip in ips]
            true_results = [result for result in results if result]
            false_results = [result for result in results if not result]
            true_count,false_count = len(true_results),len(false_results)
            print(f"True Count: {true_count}, False Count: {false_count}")
            if true_count >= threshold:
                return True
            else:
                return False
        else:
            print(f'Mode {mode} is not valid')
            return None
    except Exception as e:
        exc_msg = f'Issue running check_if_ips_reachable(): {e}'
        logger.error(exc_msg)
        print(exc_msg)

def shut_down_servers(test_mode=True):
    """ Shut down Linux and Synology server(s) """
    try:
        if test_mode == False:
            print(f'Actually shutting down servers!! Waiting 5 seconds....')
            host = c["linux_servers"]["heartbeat_server"]["server_ip"]    # IP of the device to SSH into
            username = c["linux_servers"]["heartbeat_server"]["username"]
            rsa_path = c["linux_servers"]["heartbeat_server"]["rsa_path"]
            sudo_password = c["linux_servers"]["heartbeat_server"]["sudo_password"]
            time.sleep(5)
            ssh_and_shutdown(host, username, sudo_password, rsa_path)
        else:
            print(f'Pretending to shut down servers!!!')
            logger.info("Running shut_down_servers() in Test mode")
        return True
    except Exception as e:
        exc_msg = f'Issue running shut_down_servers(): {e}'
        logger.error(exc_msg)
        print(exc_msg)
        return False

def remove_file(file):
    """ Remove a given file """
    try:
        print(f'Removing file {file}...')
        if os.path.exists(file):
            os.remove(file)
            if not os.path.exists(file):
                return True
            else:
                return False
        else:
            print(f'File {file} did not exist')
            return False
    except Exception as e:
        exc_msg = f'Issue running remove_file(): {e}'
        logger.error(exc_msg)
        print(exc_msg)
        return False

def scan_network():
    """ 
    Run the scan_network.sh bash script to generate a list of IP Addresses using the NMAP package
    If successful, this will generate a file and return True after checking if the file exists
    """
    try:
        test_mode = c["run_mode"]["test"]
        if test_mode == True:
            return True
        else:
            file_with_list_of_ips = "ip_addresses.txt"
            if os.path.exists(file_with_list_of_ips):
                remove_file(file_with_list_of_ips)
            os.system('./scan_network.sh')
            return os.path.exists(file_with_list_of_ips)
    except Exception as e:
        exc_msg = f'Issue running scan_network(): {e}'
        logger.error(exc_msg)
        print(exc_msg)

def get_public_addresses_from_config_file():
    """ Pull in Public IP addresses (e.g. Google, CloudFlare) from the configuration file and return them as a list """
    try:
        public_addresses = c["public_addresses"]
        public_ip_list = [public_addresses[key] for key in public_addresses]
        return public_ip_list
    except Exception as e:
        exc_msg = f'Issue running get_public_addresses_from_config_file(): {e}'
        logger.error(exc_msg)
        print(exc_msg)

def is_internet_up(threshold):
    """ Tests if the WAN is accessible """
    try:
        ips = get_public_addresses_from_config_file()
        result = check_if_ips_reachable(ips, threshold, mode='REST')
        return result
    except Exception as e:
        exc_msg = f'Issue running is_internet_up(): {e}'
        logger.error(exc_msg)
        print(exc_msg)

def analyze_historical_network_detection(records_to_look_back, threshold, test_mode):
    """ 
    Using a threshold and counting how many devices were found over time, decide if 
    one should be suspicious should a dip be detected in the number of devices
    on the LAN
    """
    try:
        # Read the data from the file
        with open('network_device_history.txt', 'r') as file:
            reader = csv.reader(file)
            data = [int(row[1]) for row in reader]
        # Calculate the average of the last n values in the second column
        average_n_values = float(sum(data[-records_to_look_back:]) / records_to_look_back)
        if test_mode == True:
            latest_discovered_devices = c["run_mode"]["test_mode_discovered_devices"]
        elif test_mode == False:
            latest_discovered_devices = data[-1]

        # If the latest number of discovered devices is less than a certain percentantage of the historical average,
        # be suspicious

        threshold_trigger = float(average_n_values * threshold)
        print(f'-- Average number of devices detected in the last {records_to_look_back} runs: {average_n_values}')
        print(f'-- Last record: {latest_discovered_devices}')
        print(f'-- Threshold Trigger {threshold_trigger} with a threshold multiplier of {threshold*100}%')

        if latest_discovered_devices < threshold_trigger:
            print(f"-- Issue Detected. Latest value of {latest_discovered_devices} is less than {threshold_trigger}")
            return False
        else:
            print(f"-- No Issue Detected. Latest value of {latest_discovered_devices} is not less than {threshold_trigger}")
            return True
    except Exception as e:
        exc_msg = f'Issue running analyze_historical_network_detection(): {e}'
        logger.error(exc_msg)
        print(exc_msg)

def decide_if_shutdown_should_occur():
    """ 
    This function decides if the shutdown sequence should occur based on if 
    the WAN is accessible and/or if LAN devices are accessible. We don't want
    to shut things down if an access point is down.
    """
    try:
        test_mode = c["run_mode"]["test"]
        # How many records to look back
        records_to_look_back = c["analysis_variables"]["records_to_look_back"]
        
        # Percentage of devices that are allowed to be 'offline' before hitting a threshold
        threshold =  float(c["analysis_variables"]["threshold_percent"])

        network_analysis_result = analyze_historical_network_detection(records_to_look_back, threshold, test_mode)
        public_ip_threshold = c["analysis_variables"]["public_internet_threshold"]
        is_internet_up_result = is_internet_up(threshold=public_ip_threshold)

        if is_internet_up_result == True and network_analysis_result == True:
            print(f'All Tests passed.')
        elif is_internet_up_result == True and network_analysis_result == False:
            print(f'Internet is up, but an Access Point might be down')
        elif is_internet_up_result == False and network_analysis_result == True:
            print(f'Internet is down, but power is up')
        elif is_internet_up_result == False and network_analysis_result == False:
            print(f'Internet is down and Network Devices are down. Being suspicious')
            ssh_test_result = check_of_ssh_device_available()
            if ssh_test_result == True:
                print(f'Not shutting things down. The internet is down but SSH test passed')
            elif ssh_test_result == False:
                print(f'Unable to SSH into the heartbeat device. Initiating Shutdown sequence')
                shut_down_servers(test_mode=True)
    except Exception as e:
        exc_msg = f'Issue running decide_if_shutdown_should_occur(): {e}'
        logger.error(exc_msg)
        print(exc_msg)

def monitor_power_outage_device():
    """ This device is monitored and if no longer reachable, it should be assumed that the device is off due to a power failure """
    try:
        ip = str(c["analysis_variables"]["always_on_device_to_monitor"])
        ips = list([ip]*10)
        device_to_monitor_threshold = c["analysis_variables"]["always_on_device_to_monitor_threshold"]
        threshold = math.floor(float(device_to_monitor_threshold) * float(len(ips)))
        print(f'Monitor Power Outage Threshold: {threshold}')
        if check_if_ips_reachable(ips, threshold, mode='ICMP') == False:
            return 'Offline'
        else:
            return 'Online'
    except Exception as e:
        exc_msg = f'Issue running monitor_power_outage_device(): {e}'
        logger.error(exc_msg)
        print(exc_msg)
        return False

def main():
    start_msg = '---------- Starting ----------'
    logger.info(start_msg)
    print(start_msg)
    initialize()
    if monitor_power_outage_device() == 'Offline':
        if check_of_ssh_device_available() == 'Not Available':
            scan_network()
            save_network_device_history_to_disk()
            decide_if_shutdown_should_occur()
    end_msg = '---------- Completed ----------'
    logger.info(end_msg)
    print(end_msg)

if __name__ == "__main__":
    x = 1
    while True:
        main()
        logger.info(f"----- Run {x} -----")
        time.sleep(5)
        x += 1
