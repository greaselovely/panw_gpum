#!/usr/bin/env python3
r"""
GlobalProtect Authentication Failure Log Downloader v1.0

This script downloads GlobalProtect authentication failure logs from PAN-OS firewalls,
processes them to extract failed authentication attempts, manages IP whitelisting,
and optionally updates External Dynamic Lists (EDLs) via the KineticLull API.

Key Features:
- Direct API integration with PAN-OS firewalls
- Incremental log queries using timestamps
- Automatic IP whitelisting for current GlobalProtect users
- Whitelist management with CIDR support
- EDL integration for automatic IP blocking
- Comprehensive logging and audit trails
- Retry logic for reliable operation

Author: Zero One Six Security
Version: 1.0
 _____   __________  ____ ________
/__  /  / ____/ __ \/ __ <  / ___/
  / /  / __/ / /_/ / / / / / __ \
 / /__/ /___/ _, _/ /_/ / / /_/ /
/____/_____/_/ |_|\____/_/\____/

This script is designed to be run as a cron job or manually, and it will automatically
handle the necessary authentication, log retrieval, and IP management tasks.
It is intended for use in environments where GlobalProtect authentication failures
need to be monitored and managed, such as in security operations centers or network
administration teams.
It is recommended to run this script with Python 3.12 or higher.

Example usage:

python3 main.py -f <FIREWALL_IP> -l -e
    or
python3 main.py --frwl <FIREWALL_IP> --log --edl

"""

import json
import os
import sys
import time
import argparse
import xmltodict
import requests
import urllib3
import ipaddress
import logging
from datetime import datetime
from getpass import getpass
from panos.firewall import Firewall
from panos.errors import PanDeviceError

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
SEARCH_TEXT = 'Authentication failed: Invalid username or password'
CONFIG_FILE = 'config.json'
JOB_TIMEOUT = 90  # seconds
MAX_LOGS = 5000  # Maximum logs to retrieve per query
MAX_RETRIES = 3  # Maximum retry attempts
RETRY_DELAY = 5  # Seconds to wait between retries
XML_RETENTION_HOURS = 24  # Keep XML files for 24 hours
XML_DIR = 'xml_logs'  # Directory for XML files
IP_LIST_FILE = 'blocked_ips.txt'  # Single IP list file
LOG_FILE = 'gp_downloader.log'  # Log file for cron jobs
WHITELIST_LOG_FILE = 'whitelist_failures.log'  # Log file for whitelisted IP failures
WHITELIST_UPDATE_LOG = 'whitelist_updates.log'  # Log file for whitelist changes

class GlobalProtectLogDownloader:
    """
    Main class for downloading and processing GlobalProtect authentication failure logs.
    
    This class handles the complete workflow of:
    1. Authenticating to PAN-OS firewalls
    2. Querying GlobalProtect authentication failure logs
    3. Managing IP whitelists and blocklists
    4. Updating External Dynamic Lists (EDLs)
    5. Maintaining audit trails and logging
    
    Attributes:
        logger: Logging instance for output management
        config: Configuration dictionary loaded from config.json
        firewall: PAN-OS firewall connection object
        update_edl_flag: Boolean flag to control EDL updates
    """
    
    def __init__(self, enable_logging=False):
        """
        Initialize the GlobalProtect log downloader.
        
        Args:
            enable_logging (bool): Enable file logging for cron jobs (default: False)
        """
        self.logger = self.setup_logging(enable_logging)
        self.config = self.load_config()
        self.firewall = None
        self.ensure_xml_directory()
        self.cleanup_old_files()
    
    def setup_logging(self, enable_logging):
        """
        Setup logging configuration for console and file output.
        
        Args:
            enable_logging (bool): Whether to enable file logging
            
        Returns:
            logging.Logger: Configured logger instance
        """
        logger = logging.getLogger('gp_downloader')
        logger.setLevel(logging.INFO)
        
        # Remove existing handlers to avoid duplicates
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
        
        # Console handler (always enabled)
        console_handler = logging.StreamHandler(sys.stdout)
        console_format = logging.Formatter('%(asctime)s - %(message)s', '%Y-%m-%d %H:%M:%S')
        console_handler.setFormatter(console_format)
        logger.addHandler(console_handler)
        
        # File handler (enabled for cron jobs)
        if enable_logging:
            file_handler = logging.FileHandler(LOG_FILE)
            file_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', '%Y-%m-%d %H:%M:%S')
            file_handler.setFormatter(file_format)
            logger.addHandler(file_handler)
        
        return logger
    
    def log(self, message):
        """
        Log a message using the configured logger.
        
        Args:
            message (str): Message to log
        """
        self.logger.info(message)
        
    def ensure_xml_directory(self):
        """
        Create XML logs directory if it doesn't exist.
        
        Creates the directory specified by XML_DIR constant for storing
        downloaded XML log files.
        """
        if not os.path.exists(XML_DIR):
            os.makedirs(XML_DIR)
            self.log(f"Created directory: {XML_DIR}")
    
    def cleanup_old_files(self):
        """
        Remove XML log files older than the retention period.
        
        Automatically removes XML files older than XML_RETENTION_HOURS
        to prevent disk space issues from accumulating log files.
        """
        if not os.path.exists(XML_DIR):
            return
        
        cutoff_time = time.time() - (XML_RETENTION_HOURS * 3600)
        removed_count = 0
        
        for filename in os.listdir(XML_DIR):
            if filename.endswith('.xml'):
                filepath = os.path.join(XML_DIR, filename)
                if os.path.getmtime(filepath) < cutoff_time:
                    os.remove(filepath)
                    removed_count += 1
        
        if removed_count > 0:
            self.log(f"Cleaned up {removed_count} old XML files")
    
    def load_config(self):
        """
        Load configuration from JSON file and ensure required sections exist.
        
        Loads the main configuration file and automatically creates missing
        sections for KineticLull EDL integration, whitelist management, and
        GlobalProtect settings.
        
        Returns:
            dict: Complete configuration dictionary
        """
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
        else:
            config = {"firewalls": {}}
        
    def load_config(self):
        """
        Load configuration from JSON file and ensure required sections exist.
        
        Loads the main configuration file and automatically creates missing
        sections for KineticLull EDL integration, whitelist management, and
        GlobalProtect settings.
        
        Returns:
            dict: Complete configuration dictionary
        """
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
        else:
            config = {"firewalls": {}}
            
        # Ensure KineticLull section exists
        if "KineticLull" not in config:
            config["KineticLull"] = {
                "api_key": "",
                "edls": {
                    "1": {
                        "name": "GlobalProtect Failed Auth",
                        "url": ""
                    }
                }
            }
            self.save_config(config)
            self.log("Added KineticLull EDL framework to config.json")
            
        # Ensure whitelist section exists
        if "whitelist" not in config:
            config["whitelist"] = {
                "description": "IPs to exclude from blocking - internal networks, trusted sources, etc.",
                "ips": []
            }
            self.save_config(config)
            self.log("Added whitelist framework to config.json")
            
        # Ensure GlobalProtect section exists
        if "globalprotect" not in config:
            config["globalprotect"] = {
                "gateway_name": "CHANGE_ME",
                "auto_whitelist": True,
                "description": "Set gateway_name to your GP gateway name for auto-whitelist functionality"
            }
            self.save_config(config)
            self.log("Added GlobalProtect framework to config.json")
            
        return config
    
    def save_config(self, config=None):
        """
        Save configuration dictionary to JSON file.
        
        Args:
            config (dict, optional): Configuration to save. If None, uses self.config
        """
        if config is None:
            config = self.config
            
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
    
    def get_firewall_list(self):
        """
        Get list of configured firewall IP addresses.
        
        Returns:
            list: List of firewall IP addresses from configuration
        """
        return list(self.config["firewalls"].keys())
    
    def select_firewall(self, target_ip=None):
        """
        Select firewall for log query via menu or direct IP specification.
        
        Args:
            target_ip (str, optional): Specific firewall IP to use
            
        Returns:
            str: Selected firewall IP address
        """
        if target_ip:
            return target_ip
        
        firewalls = self.get_firewall_list()
        
        if not firewalls:
            return input("Enter firewall IP address: ").strip()
        
        print("\nAvailable firewalls:")
        for i, fw in enumerate(firewalls, 1):
            print(f"{i}. {fw}")
        print(f"{len(firewalls) + 1}. Add new firewall")
        
        while True:
            try:
                choice = int(input("\nSelect firewall: "))
                if 1 <= choice <= len(firewalls):
                    return firewalls[choice - 1]
                elif choice == len(firewalls) + 1:
                    return input("Enter new firewall IP address: ").strip()
                else:
                    print("Invalid selection")
            except ValueError:
                print("Please enter a number")
    
    def discover_globalprotect_gateways(self):
        """
        Discover available GlobalProtect gateways and let user select the external one.
        
        Returns:
            str or None: Selected gateway name, or None if discovery fails/cancelled
        """
        try:
            url = f"https://{self.firewall.hostname}/api/"
            cmd = '<show><global-protect-gateway><summary><all></all></summary></global-protect-gateway></show>'
            params = {
                'type': 'op',
                'cmd': cmd,
                'key': self.firewall.api_key
            }
            
            response = requests.get(url, params=params, verify=False)
            response.raise_for_status()
            
            # Save the raw XML response for debugging
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            debug_filename = f"gateway_discovery_{self.firewall.hostname}_{timestamp}.xml"
            debug_filepath = os.path.join(XML_DIR, debug_filename)
            
            with open(debug_filepath, 'w') as f:
                f.write(response.text)
            self.log(f"Saved gateway discovery XML to: {debug_filepath}")
            
            # Parse XML response
            xml_dict = xmltodict.parse(response.text)
            
            # Check for success
            if xml_dict.get('response', {}).get('@status') != 'success':
                error_msg = xml_dict.get('response', {}).get('msg', 'Unknown error')
                self.log(f"Warning: Failed to discover gateways: {error_msg}")
                return None
            
            # Extract gateway information from result text
            result_text = xml_dict.get('response', {}).get('result', '')
            if not result_text:
                self.log("Warning: No gateway information found")
                return None
            
            self.log(f"Gateway discovery result text: {result_text}")
            
            # Parse gateway names from the result text
            gateways = []
            lines = result_text.strip().split('\n')
            
            for line in lines:
                line = line.strip()
                # Look for lines that contain a gateway name followed by connection count
                # Format: "GP-GW-01 : 30590"
                if ':' in line and not 'gateway name' in line.lower() and not 'successful connections' in line.lower():
                    # This should be a gateway line like "GP-GW-01 : 30590"
                    parts = line.split(':')
                    if len(parts) >= 2:
                        gateway_name = parts[0].strip()
                        # Validate that this looks like a gateway name (not empty, not just numbers)
                        if gateway_name and not gateway_name.isdigit():
                            gateways.append(gateway_name)
                            self.log(f"Found gateway: {gateway_name}")
            
            if not gateways:
                self.log("Warning: No GlobalProtect gateways found in result text")
                return None
            
            if len(gateways) == 1:
                selected_gateway = gateways[0]
                self.log(f"Auto-selected single gateway: {selected_gateway}")
                return selected_gateway
            
            # Multiple gateways found - let user choose
            print(f"\nFound {len(gateways)} GlobalProtect gateways:")
            for i, gateway in enumerate(gateways, 1):
                print(f"{i}. {gateway}")
            print("Note: Select the EXTERNAL gateway (not internal/site-to-site gateways)")
            
            while True:
                try:
                    choice = input(f"\nSelect external gateway (1-{len(gateways)}): ").strip()
                    choice_num = int(choice)
                    
                    if 1 <= choice_num <= len(gateways):
                        selected_gateway = gateways[choice_num - 1]
                        self.log(f"Selected gateway: {selected_gateway}")
                        return selected_gateway
                    else:
                        print(f"Invalid choice. Please enter 1-{len(gateways)}")
                        
                except ValueError:
                    print("Please enter a valid number")
                except KeyboardInterrupt:
                    print("\nGateway selection cancelled")
                    return None
            
        except Exception as e:
            self.log(f"Warning: Gateway discovery failed: {e}")
            return None
    
    def authenticate_firewall(self, fw_ip):
        """
        Authenticate to firewall and store API key for future use.
        
        Attempts to use stored API key first, falling back to interactive
        username/password authentication if needed.
        
        Args:
            fw_ip (str): Firewall IP address
            
        Returns:
            bool: True if authentication successful, False otherwise
        """
        fw_config = self.config["firewalls"].get(fw_ip, {})
        api_key = fw_config.get("api_key")
        
        # Try existing API key first
        if api_key:
            try:
                fw = Firewall(fw_ip, api_key=api_key)
                fw.refresh_system_info()
                self.firewall = fw
                return True
            except PanDeviceError:
                print("Stored API key invalid, re-authenticating...")
        
        # Get credentials and authenticate
        username = input(f"Username for {fw_ip}: ")
        password = getpass("Password: ")
        
        try:
            fw = Firewall(fw_ip, username, password)
            fw.refresh_system_info()
            
            # Store the API key
            if fw_ip not in self.config["firewalls"]:
                self.config["firewalls"][fw_ip] = {}
            
            self.config["firewalls"][fw_ip]["api_key"] = fw.api_key
            self.save_config()
            
            self.firewall = fw
            
            # Discover and configure GlobalProtect gateway after successful authentication
            current_gateway = self.config.get("globalprotect", {}).get("gateway_name")
            if current_gateway == "CHANGE_ME":
                self.log("Discovering GlobalProtect gateways...")
                discovered_gateway = self.discover_globalprotect_gateways()
                
                if discovered_gateway:
                    self.config["globalprotect"]["gateway_name"] = discovered_gateway
                    self.save_config()
                    self.log(f"Updated gateway_name in config: {discovered_gateway}")
                else:
                    self.log("Gateway discovery failed - gateway_name remains as CHANGE_ME")
            
            return True
            
        except PanDeviceError as e:
            print(f"Authentication failed: {e}")
            return False
    
    def get_last_timestamp(self, fw_ip):
        """
        Get the last query timestamp for a specific firewall.
        
        Args:
            fw_ip (str): Firewall IP address
            
        Returns:
            str or None: Last query timestamp in YYYY/MM/DD HH:MM:SS format
        """
        return self.config["firewalls"].get(fw_ip, {}).get("last_timestamp")
    
    def update_last_timestamp(self, fw_ip, timestamp):
        """
        Update the last query timestamp for a firewall.
        
        Args:
            fw_ip (str): Firewall IP address
            timestamp (str): Timestamp in YYYY/MM/DD HH:MM:SS format
        """
        if fw_ip not in self.config["firewalls"]:
            self.config["firewalls"][fw_ip] = {}
        
        self.config["firewalls"][fw_ip]["last_timestamp"] = timestamp
        self.save_config()
    
    def build_query(self, fw_ip):
        """
        Build GlobalProtect log query with optional timestamp filtering.
        
        Creates a log query that searches for authentication failures. If a last
        query timestamp exists, adds incremental filtering to only get new logs.
        
        Args:
            fw_ip (str): Firewall IP address for timestamp lookup
            
        Returns:
            str: Formatted log query string for PAN-OS API
        """
        base_query = f"(error contains '{SEARCH_TEXT}')"
        
        last_timestamp = self.get_last_timestamp(fw_ip)
        if last_timestamp:
            # Use the working timestamp syntax: geq with YYYY/MM/DD HH:MM:SS format
            query = f"{base_query} and (time_generated geq '{last_timestamp}')"
            self.log(f"Using incremental query from: {last_timestamp}")
        else:
            query = base_query
            self.log("First run - querying all available logs")
        
        return query
    
    def submit_log_query(self, fw_ip):
        """
        Submit GlobalProtect log query to firewall and return job ID.
        
        Args:
            fw_ip (str): Firewall IP address
            
        Returns:
            str: Job ID for tracking query progress
            
        Raises:
            Exception: If query submission fails or no job ID returned
        """
        query = self.build_query(fw_ip)
        
        try:
            # Use direct API call format
            url = f"https://{fw_ip}/api/"
            params = {
                'type': 'log',
                'log-type': 'globalprotect',
                'query': query,
                'nlogs': MAX_LOGS,
                'key': self.firewall.api_key
            }
            
            response = requests.get(url, params=params, verify=False)
            response.raise_for_status()
            
            # Parse XML response with xmltodict
            xml_dict = xmltodict.parse(response.text)
            
            # Check for success
            if xml_dict.get('response', {}).get('@status') != 'success':
                error_msg = xml_dict.get('response', {}).get('msg', 'Unknown error')
                raise Exception(f"API error: {error_msg}")
            
            # Extract job ID
            job_id = xml_dict.get('response', {}).get('result', {}).get('job')
            if job_id:
                return job_id
            else:
                raise Exception("No job ID found in response")
                
        except Exception as e:
            raise Exception(f"Failed to submit log query: {e}")
    
    def check_job_status(self, job_id):
        """
        Check the status and progress of a log query job.
        
        Args:
            job_id (str): Job ID from submit_log_query
            
        Returns:
            tuple: (status, progress) where status is job state and progress is completion percentage
            
        Raises:
            Exception: If status check fails
        """
        try:
            url = f"https://{self.firewall.hostname}/api/"
            params = {
                'type': 'op',
                'cmd': f'<show><jobs><id>{job_id}</id></jobs></show>',
                'key': self.firewall.api_key
            }
            
            response = requests.get(url, params=params, verify=False)
            response.raise_for_status()
            
            # Parse XML response with xmltodict
            xml_dict = xmltodict.parse(response.text)
            
            # Check for success
            if xml_dict.get('response', {}).get('@status') != 'success':
                return "error", "0"
            
            # Extract job status and progress
            job_info = xml_dict.get('response', {}).get('result', {}).get('job', {})
            status = job_info.get('status', 'unknown')
            progress = job_info.get('progress', '0')
            
            return status, progress
                
        except Exception as e:
            raise Exception(f"Failed to check job status: {e}")
    
    def wait_for_job(self, job_id):
        """
        Wait for a log query job to complete with progress monitoring.
        
        Args:
            job_id (str): Job ID to monitor
            
        Returns:
            bool: True if job completed successfully
            
        Raises:
            Exception: If job fails or times out
        """
        self.log(f"Waiting for job {job_id} to complete...")
        start_time = time.time()
        
        while time.time() - start_time < JOB_TIMEOUT:
            status, progress = self.check_job_status(job_id)
            
            # Clean up the progress display - remove % if it looks like a timestamp
            progress_display = progress
            if '/' in progress and ':' in progress:
                # This looks like a timestamp, don't show % 
                self.log(f"Job status: {status}, Progress: {progress}")
            else:
                # This looks like an actual percentage
                self.log(f"Job status: {status}, Progress: {progress}%")
            
            if status.lower() == 'fin':
                self.log("Job completed successfully")
                return True
            elif status.lower() in ['error', 'failed']:
                raise Exception(f"Job failed with status: {status}")
            
            time.sleep(2)
        
        raise Exception(f"Job timed out after {JOB_TIMEOUT} seconds")
    
    def download_job_results(self, job_id):
        """
        Download the results of a completed log query job.
        
        Args:
            job_id (str): Completed job ID
            
        Returns:
            str: Raw XML log data from firewall
            
        Raises:
            Exception: If download fails
        """
        try:
            url = f"https://{self.firewall.hostname}/api/"
            params = {
                'type': 'log',
                'action': 'get',
                'job-id': job_id,
                'key': self.firewall.api_key
            }
            
            response = requests.get(url, params=params, verify=False)
            response.raise_for_status()
            
            return response.text
            
        except Exception as e:
            raise Exception(f"Failed to download job results: {e}")
    
    def save_results(self, fw_ip, xml_data):
        """
        Save raw XML log data to archive file.
        
        Args:
            fw_ip (str): Firewall IP address for filename
            xml_data (str): Raw XML log data
            
        Returns:
            str: Path to saved XML file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save XML to xml_logs directory
        xml_filename = f"gp_logs_{fw_ip}_{timestamp}.xml"
        xml_filepath = os.path.join(XML_DIR, xml_filename)
        
        with open(xml_filepath, 'w') as f:
            f.write(xml_data)
        
        return xml_filepath
    
    def is_ip_whitelisted(self, ip_address):
        """
        Check if an IP address is in the whitelist.
        
        Supports both individual IP addresses and CIDR network blocks.
        
        Args:
            ip_address (str): IP address to check
            
        Returns:
            bool: True if IP is whitelisted, False otherwise
        """
        whitelist_config = self.config.get("whitelist", {})
        whitelist_ips = whitelist_config.get("ips", [])
        
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            
            for whitelist_entry in whitelist_ips:
                try:
                    # Handle both single IPs and CIDR blocks
                    if '/' in whitelist_entry:
                        network = ipaddress.ip_network(whitelist_entry, strict=False)
                        if ip_obj in network:
                            return True
                    else:
                        whitelist_ip = ipaddress.ip_address(whitelist_entry)
                        if ip_obj == whitelist_ip:
                            return True
                except ValueError:
                    # Skip invalid whitelist entries
                    continue
            
            return False
            
        except ValueError:
            # Invalid IP address
            return False
    
    def log_whitelisted_failure(self, ip_address, username, timestamp):
        """
        Log authentication failure from a whitelisted IP address.
        
        Creates audit trail for security monitoring of trusted sources.
        
        Args:
            ip_address (str): Source IP address
            username (str): Username that failed authentication
            timestamp (str): Timestamp of the failure
        """
        try:
            with open(WHITELIST_LOG_FILE, 'a') as f:
                f.write(f"{timestamp} - Whitelisted IP: {ip_address} - User: {username} - Failed authentication\n")
        except Exception as e:
            self.log(f"Warning: Failed to log whitelisted failure: {e}")
    
    def log_whitelist_update(self, action, ip_address, source="auto"):
        """
        Log whitelist additions and removals for audit purposes.
        
        Args:
            action (str): Action performed (ADDED, REMOVED, etc.)
            ip_address (str): IP address affected
            source (str): Source of the change (auto, manual, etc.)
        """
        try:
            timestamp = datetime.now().strftime('%Y/%m/%d %H:%M:%S')
            with open(WHITELIST_UPDATE_LOG, 'a') as f:
                f.write(f"{timestamp} - {action.upper()}: {ip_address} - Source: {source}\n")
        except Exception as e:
            self.log(f"Warning: Failed to log whitelist update: {e}")
    
    def get_current_globalprotect_users(self):
        """
        Get current GlobalProtect users and their public IP addresses.
        
        Queries the firewall for active VPN connections to identify legitimate users
        whose IP addresses should be whitelisted.
        
        Returns:
            list: List of dictionaries containing username and public_ip keys
        """
        gp_config = self.config.get("globalprotect", {})
        gateway_name = gp_config.get("gateway_name", "")
        auto_whitelist = gp_config.get("auto_whitelist", True)
        
        if not auto_whitelist:
            return []
        
        if not gateway_name or gateway_name == "CHANGE_ME":
            self.log("Error: GlobalProtect gateway_name not configured in config.json")
            return []
        
        try:
            url = f"https://{self.firewall.hostname}/api/"
            cmd = f'<show><global-protect-gateway><current-user><gateway>{gateway_name}</gateway></current-user></global-protect-gateway></show>'
            params = {
                'type': 'op',
                'cmd': cmd,
                'key': self.firewall.api_key
            }
            
            response = requests.get(url, params=params, verify=False)
            response.raise_for_status()
            
            # Parse XML response
            xml_dict = xmltodict.parse(response.text)
            
            # Check for success
            if xml_dict.get('response', {}).get('@status') != 'success':
                error_msg = xml_dict.get('response', {}).get('msg', 'Unknown error')
                self.log(f"Warning: Failed to get current users: {error_msg}")
                return []
            
            # Extract current users
            current_users = []
            result = xml_dict.get('response', {}).get('result', {})
            entries = result.get('entry', [])
            
            if isinstance(entries, dict):
                entries = [entries]
            elif not isinstance(entries, list):
                entries = []
            
            for entry in entries:
                username = entry.get('username', '')
                public_ip = entry.get('public-ip', '') or entry.get('client-ip', '')
                
                if username and public_ip and public_ip not in ['0.0.0.0', '::', 'unknown']:
                    current_users.append({
                        'username': username,
                        'public_ip': public_ip
                    })
            
            self.log(f"Found {len(current_users)} current GlobalProtect users")
            return current_users
            
        except Exception as e:
            self.log(f"Warning: Failed to get current GlobalProtect users: {e}")
            return []
    
    def update_whitelist_with_current_users(self):
        """Add current user IPs to whitelist if not already present"""
        current_users = self.get_current_globalprotect_users()
        if not current_users:
            return
        
        # Get current whitelist
        whitelist_ips = self.config.get("whitelist", {}).get("ips", [])
        original_count = len(whitelist_ips)
        
        # Check each current user's IP
        new_ips_added = []
        for user in current_users:
            public_ip = user['public_ip']
            username = user['username']
            
            # Check if IP is already in whitelist (including CIDR ranges)
            if not self.is_ip_whitelisted(public_ip):
                # Add the IP to whitelist
                whitelist_ips.append(public_ip)
                new_ips_added.append((public_ip, username))
                self.log_whitelist_update("ADDED", f"{public_ip} (user: {username})", "auto")
        
        # Save updated whitelist if changes were made
        if new_ips_added:
            self.config["whitelist"]["ips"] = whitelist_ips
            self.save_config()
            
            self.log(f"Auto-whitelist: Added {len(new_ips_added)} new IPs from current users")
            for ip, username in new_ips_added:
                self.log(f"  Added: {ip} (user: {username})")
        else:
            self.log("Auto-whitelist: No new IPs to add - all current users already whitelisted")
    
    def clean_blocked_ips_against_whitelist(self):
        """Remove any whitelisted IPs from the existing blocked IP list"""
        if not os.path.exists(IP_LIST_FILE):
            return
        
        # Load existing blocked IPs
        existing_ips = self.load_existing_ip_list()
        original_count = len(existing_ips)
        
        # Check each blocked IP against whitelist
        cleaned_ips = {}
        removed_ips = []
        
        for ip, count in existing_ips.items():
            if self.is_ip_whitelisted(ip):
                removed_ips.append((ip, count))
                self.log_whitelist_update("REMOVED FROM BLOCKLIST", f"{ip} ({count} failures)", "whitelist-cleanup")
            else:
                cleaned_ips[ip] = count
        
        # Save cleaned list if any IPs were removed
        if removed_ips:
            # Sort by IP address
            sorted_items = []
            for ip, count in cleaned_ips.items():
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    sorted_items.append((ip_obj, ip, count))
                except ValueError:
                    continue
            
            sorted_items.sort(key=lambda x: x[0])
            cleaned_data = [(item[1], item[2]) for item in sorted_items]
            
            # Write cleaned list
            try:
                with open(IP_LIST_FILE, 'w') as f:
                    f.write(f"# GlobalProtect Authentication Failures - Updated: {datetime.now().strftime('%Y/%m/%d %H:%M:%S')}\n")
                    f.write(f"# Total unique IPs: {len(cleaned_data)}\n\n")
                    
                    for ip, count in cleaned_data:
                        f.write(f"{ip} # {count} failure{'s' if count != 1 else ''}\n")
                
                self.log(f"Removed {len(removed_ips)} whitelisted IPs from block list:")
                for ip, count in removed_ips:
                    self.log(f"  Removed: {ip} ({count} failures)")
                    
            except Exception as e:
                self.log(f"Failed to clean blocked IP list: {e}")
        else:
            self.log("Block list cleanup: No whitelisted IPs found in block list")
        """Add current user IPs to whitelist if not already present"""
        current_users = self.get_current_globalprotect_users()
        if not current_users:
            return
        
        # Get current whitelist
        whitelist_ips = self.config.get("whitelist", {}).get("ips", [])
        original_count = len(whitelist_ips)
        
        # Check each current user's IP
        new_ips_added = []
        for user in current_users:
            public_ip = user['public_ip']
            username = user['username']
            
            # Check if IP is already in whitelist (including CIDR ranges)
            if not self.is_ip_whitelisted(public_ip):
                # Add the IP to whitelist
                whitelist_ips.append(public_ip)
                new_ips_added.append((public_ip, username))
                self.log_whitelist_update("ADDED", f"{public_ip} (user: {username})", "auto")
        
        # Save updated whitelist if changes were made
        if new_ips_added:
            self.config["whitelist"]["ips"] = whitelist_ips
            self.save_config()
            
            self.log(f"Auto-whitelist: Added {len(new_ips_added)} new IPs from current users")
            for ip, username in new_ips_added:
                self.log(f"  Added: {ip} (user: {username})")
        else:
            self.log("Auto-whitelist: No new IPs to add - all current users already whitelisted")
    
    def extract_unique_ips(self, xml_data):
        """Extract unique source IPs from log data with failure counts, excluding whitelisted IPs"""
        ip_counts = {}
        whitelisted_failures = []
        
        try:
            xml_dict = xmltodict.parse(xml_data)
            
            # Navigate to log entries
            entries = []
            response = xml_dict.get('response', {})
            result = response.get('result', {})
            log = result.get('log', {})
            logs = log.get('logs', {})
            
            if isinstance(logs.get('entry'), list):
                entries = logs['entry']
            elif logs.get('entry'):
                entries = [logs['entry']]
            
            # Process each entry
            for entry in entries:
                # Extract IP and username
                ip = None
                username = entry.get('srcuser', '') or entry.get('user', '') or entry.get('username', '')
                timestamp = entry.get('time_generated', '') or entry.get('receive_time', '')
                
                # Try different IP fields that might exist
                ip_fields = ['public_ip', 'private_ip', 'src', 'source_ip', 'client_ip']
                
                for field in ip_fields:
                    ip_candidate = entry.get(field, '').strip()
                    if ip_candidate and ip_candidate != '0.0.0.0' and ip_candidate != '::' and ip_candidate != 'unknown':
                        ip = ip_candidate
                        break
                
                if ip:
                    # Check if IP is whitelisted
                    if self.is_ip_whitelisted(ip):
                        # Log the whitelisted failure
                        self.log_whitelisted_failure(ip, username, timestamp)
                        whitelisted_failures.append((ip, username, timestamp))
                    else:
                        # Add to block list
                        if ip in ip_counts:
                            ip_counts[ip] += 1
                        else:
                            ip_counts[ip] = 1
            
            # Log summary of whitelisted failures
            if whitelisted_failures:
                self.log(f"Found {len(whitelisted_failures)} authentication failures from whitelisted IPs")
                
                # Group by IP for summary
                whitelist_summary = {}
                for ip, username, timestamp in whitelisted_failures:
                    if ip not in whitelist_summary:
                        whitelist_summary[ip] = []
                    whitelist_summary[ip].append(username)
                
                for ip, usernames in whitelist_summary.items():
                    unique_users = list(set(usernames))
                    self.log(f"  {ip}: {len(usernames)} attempts from {len(unique_users)} users: {', '.join(unique_users[:5])}")
            
            # Sort by IP address value, not alphabetically
            sorted_ips = []
            for ip in ip_counts.keys():
                try:
                    # Validate and convert to IP object for proper sorting
                    ip_obj = ipaddress.ip_address(ip)
                    sorted_ips.append((ip_obj, ip, ip_counts[ip]))
                except ValueError:
                    # Skip invalid IPs
                    self.log(f"Warning: Invalid IP address found: {ip}")
                    continue
            
            # Sort by IP address and return tuples of (ip_string, count)
            sorted_ips.sort(key=lambda x: x[0])
            return [(str(ip_tuple[1]), ip_tuple[2]) for ip_tuple in sorted_ips]
            
        except Exception as e:
            self.log(f"Warning: Failed to extract IPs: {e}")
            return []
    
    def load_existing_ip_list(self):
        """Load existing IP list and return as dict {ip: count}"""
        ip_counts = {}
        
        if os.path.exists(IP_LIST_FILE):
            try:
                with open(IP_LIST_FILE, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Parse format: "1.2.3.4 # 5 failures"
                            parts = line.split(' # ')
                            if len(parts) == 2:
                                ip = parts[0].strip()
                                count_part = parts[1].strip()
                                # Extract number from "5 failures" or "1 failure"
                                count_str = count_part.split()[0]
                                try:
                                    ip_counts[ip] = int(count_str)
                                except ValueError:
                                    continue
            except Exception as e:
                self.log(f"Warning: Failed to load existing IP list: {e}")
        
        return ip_counts
    
    def get_ip_list_for_edl(self):
        """Extract just the IP addresses from the IP list file for EDL, sorted and unique"""
        ip_set = set()  # Use set to ensure uniqueness
        
        if os.path.exists(IP_LIST_FILE):
            try:
                with open(IP_LIST_FILE, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Extract just the IP (first part before #)
                            ip = line.split(' # ')[0].strip()
                            if ip:
                                ip_set.add(ip)
            except Exception as e:
                self.log(f"Warning: Failed to read IP list for EDL: {e}")
                return []
        
        # Convert set to list and sort by IP address value
        sorted_ips = []
        for ip in ip_set:
            try:
                # Validate and convert to IP object for proper sorting
                ip_obj = ipaddress.ip_address(ip)
                sorted_ips.append((ip_obj, ip))
            except ValueError:
                # Skip invalid IPs but log warning
                self.log(f"Warning: Skipping invalid IP for EDL: {ip}")
                continue
        
        # Sort by IP address and return just the string IPs
        sorted_ips.sort(key=lambda x: x[0])
        final_list = [ip_tuple[1] for ip_tuple in sorted_ips]
        
        # Debug: Log first few IPs to verify sorting
        if final_list:
            sample_ips = final_list[:5]
            self.log(f"EDL IP sample (first 5): {sample_ips}")
        
        self.log(f"Prepared {len(final_list)} unique, sorted IPs for EDL")
        return final_list
    
    def merge_ip_lists(self, new_ip_data):
        """Merge new IPs with existing IP list"""
        # Load existing IPs
        existing_ips = self.load_existing_ip_list()
        
        # Merge with new IPs
        for ip, count in new_ip_data:
            if ip in existing_ips:
                existing_ips[ip] += count
            else:
                existing_ips[ip] = count
        
        # Sort by IP address
        sorted_items = []
        for ip, count in existing_ips.items():
            try:
                ip_obj = ipaddress.ip_address(ip)
                sorted_items.append((ip_obj, ip, count))
            except ValueError:
                continue
        
        sorted_items.sort(key=lambda x: x[0])
        return [(item[1], item[2]) for item in sorted_items]
    
    def save_ip_list(self, ip_data):
        """Save merged IP list with failure counts to single text file"""
        if not ip_data:
            self.log("No IPs to save")
            return None
        
        # Merge with existing IPs
        merged_ips = self.merge_ip_lists(ip_data)
        
        try:
            with open(IP_LIST_FILE, 'w') as f:
                f.write(f"# GlobalProtect Authentication Failures - Updated: {datetime.now().strftime('%Y/%m/%d %H:%M:%S')}\n")
                f.write(f"# Total unique IPs: {len(merged_ips)}\n\n")
                
                for ip, count in merged_ips:
                    f.write(f"{ip} # {count} failure{'s' if count != 1 else ''}\n")
            
            self.log(f"Updated {IP_LIST_FILE} with {len(merged_ips)} total unique IPs")
            return IP_LIST_FILE
            
        except Exception as e:
            self.log(f"Failed to save IP list: {e}")
            return None
    
    def extract_latest_timestamp(self, xml_data):
        """Extract the latest timestamp from log results for next query"""
        try:
            xml_dict = xmltodict.parse(xml_data)
            
            # Navigate to log entries
            entries = []
            response = xml_dict.get('response', {})
            result = response.get('result', {})
            log = result.get('log', {})
            logs = log.get('logs', {})
            
            if isinstance(logs.get('entry'), list):
                entries = logs['entry']
            elif logs.get('entry'):
                entries = [logs['entry']]
            
            # Find the latest time_generated
            latest_time = None
            for entry in entries:
                time_gen = entry.get('time_generated')
                if time_gen and (not latest_time or time_gen > latest_time):
                    latest_time = time_gen
            
            return latest_time
            
        except Exception as e:
            self.log(f"Warning: Failed to extract timestamp: {e}")
            return None
    
    def update_edl(self, edl_key="1"):
        """Update EDL via KineticLull API"""
        try:
            # Get KineticLull configuration
            kl_config = self.config.get("KineticLull", {})
            api_key = kl_config.get("api_key")
            edl_config = kl_config.get("edls", {}).get(edl_key, {})
            edl_url = edl_config.get("url")
            edl_name = edl_config.get("name", f"EDL {edl_key}")
            
            if not api_key:
                self.log("Warning: KineticLull API key not configured")
                return False
            
            if not edl_url:
                self.log(f"Warning: EDL '{edl_name}' (key: {edl_key}) URL not configured")
                return False
            
            # Strip trailing slash from URL if present
            edl_url = edl_url.rstrip('/')
            
            # Get IP list
            ip_list = self.get_ip_list_for_edl()
            if not ip_list:
                self.log("No IPs to send to EDL")
                return False
            
            # Prepare API request
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}"
            }
            
            payload = {
                "auto_url": edl_url,
                "command": "overwrite", 
                "fqdn_list": ip_list  # Note: API uses fqdn_list for both IPs and FQDNs
            }
            
            # Make API call
            api_url = "https://edl.zero16sec.com/api/update_edl/"
            response = requests.post(api_url, headers=headers, json=payload, verify=False)
            response.raise_for_status()
            
            self.log(f"Successfully updated EDL '{edl_name}' with {len(ip_list)} IPs")
            return True
            
        except requests.exceptions.RequestException as e:
            self.log(f"Failed to update EDL: {e}")
            return False
        except Exception as e:
            self.log(f"Error updating EDL: {e}")
            return False
    
    def run(self, fw_ip=None, update_edl=False):
        """
        Main execution workflow with comprehensive error handling and retry logic.
        
        Orchestrates the complete process of log collection, analysis, and EDL updates
        with automatic retry capabilities for production reliability.
        
        Args:
            fw_ip (str, optional): Specific firewall IP address to target
            update_edl (bool): Whether to update EDLs after processing logs
            
        Returns:
            bool: True if execution completed successfully, False otherwise
        """
        self.update_edl_flag = update_edl
        
        # Select firewall
        selected_fw = self.select_firewall(fw_ip)
        
        # Authenticate
        if not self.authenticate_firewall(selected_fw):
            return False
        
        # Retry logic for the entire query process
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                self.log(f"Attempt {attempt}/{MAX_RETRIES}")
                
                # Submit query
                job_id = self.submit_log_query(selected_fw)
                
                # Wait for completion
                if not self.wait_for_job(job_id):
                    raise Exception("Job did not complete successfully")
                
                # Update whitelist with current users before processing failures
                self.update_whitelist_with_current_users()
                
                # Clean existing blocked IPs against updated whitelist
                self.clean_blocked_ips_against_whitelist()
                
                # Download results
                xml_data = self.download_job_results(job_id)
                
                # Save XML file
                xml_file = self.save_results(selected_fw, xml_data)
                
                # Extract and merge IP lists
                new_ip_data = self.extract_unique_ips(xml_data)
                ip_file = self.save_ip_list(new_ip_data)
                
                # Update EDL if configured and requested
                if self.update_edl_flag:
                    self.update_edl()
                else:
                    self.log("EDL update skipped (use --edl to enable)")
                
                # Update timestamp for next query
                latest_timestamp = self.extract_latest_timestamp(xml_data)
                if latest_timestamp:
                    self.update_last_timestamp(selected_fw, latest_timestamp)
                
                self.log(f"Saved: {xml_file}")
                if ip_file:
                    self.log(f"Updated: {ip_file}")
                
                return True
                
            except Exception as e:
                self.log(f"Attempt {attempt} failed: {e}")
                
                if attempt < MAX_RETRIES:
                    self.log(f"Waiting {RETRY_DELAY} seconds before retry...")
                    time.sleep(RETRY_DELAY)
                else:
                    self.log("All retry attempts failed")
                    return False
        
        return False

def main():
    """
    Main entry point for command-line execution.
    
    Parses command-line arguments and initializes the GlobalProtect log downloader
    with appropriate configuration for interactive or automated execution.
    """
    parser = argparse.ArgumentParser(
        description='Download GlobalProtect authentication failure logs',
        epilog='Example: python %(prog)s -f 192.168.1.1 --edl --log'
    )
    parser.add_argument('-f', '--frwl', 
                       help='Firewall IP address')
    parser.add_argument('--log', 
                       action='store_true', 
                       help='Enable file logging for cron jobs')
    parser.add_argument('-e', '--edl', 
                       action='store_true', 
                       help='Update EDL after processing logs (default: False)')
    args = parser.parse_args()
    
    downloader = GlobalProtectLogDownloader(enable_logging=args.log)
    success = downloader.run(args.frwl, update_edl=args.edl)
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()