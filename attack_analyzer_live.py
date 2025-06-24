#!/usr/bin/env python3
r"""
GlobalProtect Attack Trend Analyzer v1.0

This script downloads all GlobalProtect authentication failure logs from PAN-OS firewalls
and generates time-based visualizations showing attack patterns over hourly and daily periods.

Key Features:
- Downloads comprehensive historical logs (not incremental)
- Generates hourly attack trend graphs
- Generates daily attack trend graphs
- Integrates with existing config.json structure
- Automatic whitelist filtering
- Comprehensive logging and error handling

Author: Based on Zero One Six Security GlobalProtect downloader
Version: 1.0

 _____   __________  ____ ________
/__  /  / ____/ __ \/ __ <  / ___/
  / /  / __/ / /_/ / / / / / __ \
 / /__/ /___/ _, _/ /_/ / / /_/ /
/____/_____/_/ |_|\____/_/\____/

Example usage:
python3 attack_analyzer.py -f <FIREWALL_IP>
    or
python3 attack_analyzer.py --frwl <FIREWALL_IP> --log
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
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import pandas as pd
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from getpass import getpass
from panos.firewall import Firewall
from panos.errors import PanDeviceError

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
SEARCH_TEXT = 'Authentication failed: Invalid username or password'
CONFIG_FILE = 'config.json'
JOB_TIMEOUT = 120  # Extended timeout for larger queries
MAX_LOGS = 5000  # Increased for comprehensive analysis
MAX_RETRIES = 3
RETRY_DELAY = 5
XML_DIR = 'xml_logs'
OUTPUT_DIR = 'attack_graphs'
LOG_FILE = 'attack_analyzer.log'

class AttackTrendAnalyzer:
    """
    Analyzes GlobalProtect authentication failure trends over time.
    
    This class downloads historical logs and creates time-based visualizations
    to identify attack patterns and trends.
    """
    
    def __init__(self, enable_logging=False):
        """Initialize the attack trend analyzer."""
        self.logger = self.setup_logging(enable_logging)
        self.config = self.load_config()
        self.firewall = None
        self.ensure_directories()
    
    def setup_logging(self, enable_logging):
        """Setup logging configuration."""
        logger = logging.getLogger('attack_analyzer')
        logger.setLevel(logging.INFO)
        
        # Remove existing handlers
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_format = logging.Formatter('%(asctime)s - %(message)s', '%Y-%m-%d %H:%M:%S')
        console_handler.setFormatter(console_format)
        logger.addHandler(console_handler)
        
        # File handler for logging
        if enable_logging:
            file_handler = logging.FileHandler(LOG_FILE)
            file_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', '%Y-%m-%d %H:%M:%S')
            file_handler.setFormatter(file_format)
            logger.addHandler(file_handler)
        
        return logger
    
    def log(self, message):
        """Log a message."""
        self.logger.info(message)
    
    def ensure_directories(self):
        """Create necessary directories."""
        for directory in [XML_DIR, OUTPUT_DIR]:
            if not os.path.exists(directory):
                os.makedirs(directory)
                self.log(f"Created directory: {directory}")
    
    def load_config(self):
        """Load configuration from JSON file."""
        if not os.path.exists(CONFIG_FILE):
            self.log(f"Error: {CONFIG_FILE} not found. Please run the main script first to create configuration.")
            sys.exit(1)
        
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
        
        return config
    
    def get_firewall_list(self):
        """Get list of configured firewall IP addresses."""
        return list(self.config["firewalls"].keys())
    
    def select_firewall(self, target_ip=None):
        """Select firewall for analysis."""
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
    
    def authenticate_firewall(self, fw_ip):
        """Authenticate to firewall using stored or new credentials."""
        fw_config = self.config["firewalls"].get(fw_ip, {})
        api_key = fw_config.get("api_key")
        
        # Try existing API key first
        if api_key:
            try:
                fw = Firewall(fw_ip, api_key=api_key)
                fw.refresh_system_info()
                self.firewall = fw
                self.log(f"Successfully authenticated to {fw_ip} using stored credentials")
                return True
            except PanDeviceError:
                print("Stored API key invalid, re-authenticating...")
        
        # Get credentials and authenticate
        username = input(f"Username for {fw_ip}: ")
        password = getpass("Password: ")
        
        try:
            fw = Firewall(fw_ip, username, password)
            fw.refresh_system_info()
            
            # Store the API key for future use
            if fw_ip not in self.config["firewalls"]:
                self.config["firewalls"][fw_ip] = {}
            
            self.config["firewalls"][fw_ip]["api_key"] = fw.api_key
            self.save_config()
            
            self.firewall = fw
            self.log(f"Successfully authenticated to {fw_ip}")
            return True
            
        except PanDeviceError as e:
            print(f"Authentication failed: {e}")
            return False
    
    def save_config(self):
        """Save configuration to JSON file."""
        with open(CONFIG_FILE, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    def build_comprehensive_query(self):
        """Build query to get ALL authentication failure logs (no timestamp filtering)."""
        query = f"(error contains '{SEARCH_TEXT}')"
        self.log("Building comprehensive query for all historical logs")
        return query
    
    def submit_log_query(self, fw_ip):
        """Submit comprehensive log query to firewall."""
        query = self.build_comprehensive_query()
        
        try:
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
            
            xml_dict = xmltodict.parse(response.text)
            
            if xml_dict.get('response', {}).get('@status') != 'success':
                error_msg = xml_dict.get('response', {}).get('msg', 'Unknown error')
                raise Exception(f"API error: {error_msg}")
            
            job_id = xml_dict.get('response', {}).get('result', {}).get('job')
            if job_id:
                self.log(f"Submitted comprehensive log query, job ID: {job_id}")
                return job_id
            else:
                raise Exception("No job ID found in response")
                
        except Exception as e:
            raise Exception(f"Failed to submit log query: {e}")
    
    def check_job_status(self, job_id):
        """Check job status and progress."""
        try:
            url = f"https://{self.firewall.hostname}/api/"
            params = {
                'type': 'op',
                'cmd': f'<show><jobs><id>{job_id}</id></jobs></show>',
                'key': self.firewall.api_key
            }
            
            response = requests.get(url, params=params, verify=False)
            response.raise_for_status()
            
            xml_dict = xmltodict.parse(response.text)
            
            if xml_dict.get('response', {}).get('@status') != 'success':
                return "error", "0"
            
            job_info = xml_dict.get('response', {}).get('result', {}).get('job', {})
            status = job_info.get('status', 'unknown')
            progress = job_info.get('progress', '0')
            
            return status, progress
                
        except Exception as e:
            raise Exception(f"Failed to check job status: {e}")
    
    def wait_for_job(self, job_id):
        """Wait for job completion with progress monitoring."""
        self.log(f"Waiting for job {job_id} to complete...")
        start_time = time.time()
        
        while time.time() - start_time < JOB_TIMEOUT:
            status, progress = self.check_job_status(job_id)
            
            if '/' in progress and ':' in progress:
                self.log(f"Job status: {status}, Progress: {progress}")
            else:
                self.log(f"Job status: {status}, Progress: {progress}%")
            
            if status.lower() == 'fin':
                self.log("Job completed successfully")
                return True
            elif status.lower() in ['error', 'failed']:
                raise Exception(f"Job failed with status: {status}")
            
            time.sleep(3)
        
        raise Exception(f"Job timed out after {JOB_TIMEOUT} seconds")
    
    def download_job_results(self, job_id):
        """Download completed job results."""
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
    
    def is_ip_whitelisted(self, ip_address):
        """Check if IP is whitelisted (same logic as main script)."""
        whitelist_config = self.config.get("whitelist", {})
        whitelist_ips = whitelist_config.get("ips", [])
        
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            
            for whitelist_entry in whitelist_ips:
                try:
                    if '/' in whitelist_entry:
                        network = ipaddress.ip_network(whitelist_entry, strict=False)
                        if ip_obj in network:
                            return True
                    else:
                        whitelist_ip = ipaddress.ip_address(whitelist_entry)
                        if ip_obj == whitelist_ip:
                            return True
                except ValueError:
                    continue
            
            return False
            
        except ValueError:
            return False
    
    def parse_log_entries(self, xml_data):
        """Parse XML data and extract attack events with timestamps."""
        attack_events = []
        
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
            
            self.log(f"Processing {len(entries)} log entries...")
            
            # Process each entry
            for entry in entries:
                # Extract timestamp
                timestamp_str = entry.get('time_generated', '') or entry.get('receive_time', '')
                if not timestamp_str:
                    continue
                
                # Extract IP
                ip = None
                ip_fields = ['public_ip', 'private_ip', 'src', 'source_ip', 'client_ip']
                
                for field in ip_fields:
                    ip_candidate = entry.get(field, '').strip()
                    if ip_candidate and ip_candidate not in ['0.0.0.0', '::', 'unknown']:
                        ip = ip_candidate
                        break
                
                if not ip:
                    continue
                
                # Skip whitelisted IPs
                if self.is_ip_whitelisted(ip):
                    continue
                
                # Extract username
                username = entry.get('srcuser', '') or entry.get('user', '') or entry.get('username', '')
                
                # Parse timestamp
                try:
                    # Handle different timestamp formats
                    if 'T' in timestamp_str:
                        # ISO format: 2024-01-15T10:30:45
                        dt = datetime.fromisoformat(timestamp_str.replace('Z', ''))
                    else:
                        # Standard format: 2024/01/15 10:30:45
                        dt = datetime.strptime(timestamp_str, '%Y/%m/%d %H:%M:%S')
                    
                    attack_events.append({
                        'timestamp': dt,
                        'ip': ip,
                        'username': username
                    })
                    
                except ValueError as e:
                    self.log(f"Warning: Could not parse timestamp '{timestamp_str}': {e}")
                    continue
            
            self.log(f"Successfully parsed {len(attack_events)} attack events")
            return attack_events
            
        except Exception as e:
            self.log(f"Error parsing log entries: {e}")
            return []
    
    def save_xml_data(self, fw_ip, xml_data):
        """Save raw XML data for analysis."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        xml_filename = f"comprehensive_gp_logs_{fw_ip}_{timestamp}.xml"
        xml_filepath = os.path.join(XML_DIR, xml_filename)
        
        with open(xml_filepath, 'w') as f:
            f.write(xml_data)
        
        self.log(f"Saved comprehensive XML data: {xml_filepath}")
        return xml_filepath
    
    def generate_hourly_graph(self, attack_events, fw_ip):
        """Generate hourly attack trend graph."""
        if not attack_events:
            self.log("No attack events to graph")
            return None
        
        # Group attacks by hour
        hourly_counts = defaultdict(int)
        
        for event in attack_events:
            # Round to nearest hour
            hour_key = event['timestamp'].replace(minute=0, second=0, microsecond=0)
            hourly_counts[hour_key] += 1
        
        # Convert to sorted lists
        hours = sorted(hourly_counts.keys())
        counts = [hourly_counts[hour] for hour in hours]
        
        # Create the plot
        plt.figure(figsize=(15, 8))
        plt.plot(hours, counts, marker='o', linewidth=2, markersize=4)
        plt.title(f'GlobalProtect Authentication Failures - Hourly Trends\nFirewall: {fw_ip}', fontsize=16, fontweight='bold')
        plt.xlabel('Time (Hours)', fontsize=12)
        plt.ylabel('Number of Failed Attempts', fontsize=12)
        plt.grid(True, alpha=0.3)
        
        # Format x-axis
        plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%m/%d %H:%M'))
        plt.gca().xaxis.set_major_locator(mdates.HourLocator(interval=max(1, len(hours)//20)))
        plt.xticks(rotation=45)
        
        # Add statistics
        total_attempts = sum(counts)
        max_attempts = max(counts) if counts else 0
        peak_hour = hours[counts.index(max_attempts)] if counts else None
        
        stats_text = f'Total Attempts: {total_attempts:,}\nPeak Hour: {max_attempts:,} attempts'
        if peak_hour:
            stats_text += f'\nPeak Time: {peak_hour.strftime("%m/%d %H:%M")}'
        
        plt.text(0.02, 0.98, stats_text, transform=plt.gca().transAxes, 
                verticalalignment='top', bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))
        
        plt.tight_layout()
        
        # Save the plot
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"gp_attacks_hourly_{fw_ip}_{timestamp}.png"
        filepath = os.path.join(OUTPUT_DIR, filename)
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        
        self.log(f"Generated hourly trend graph: {filepath}")
        plt.show()
        
        return filepath
    
    def generate_daily_graph(self, attack_events, fw_ip):
        """Generate daily attack trend graph."""
        if not attack_events:
            self.log("No attack events to graph")
            return None
        
        # Group attacks by day
        daily_counts = defaultdict(int)
        
        for event in attack_events:
            # Round to day
            day_key = event['timestamp'].date()
            daily_counts[day_key] += 1
        
        # Convert to sorted lists
        days = sorted(daily_counts.keys())
        counts = [daily_counts[day] for day in days]
        
        # Create the plot
        plt.figure(figsize=(15, 8))
        plt.bar(days, counts, width=0.8, alpha=0.7, color='crimson')
        plt.title(f'GlobalProtect Authentication Failures - Daily Trends\nFirewall: {fw_ip}', fontsize=16, fontweight='bold')
        plt.xlabel('Date', fontsize=12)
        plt.ylabel('Number of Failed Attempts', fontsize=12)
        plt.grid(True, alpha=0.3, axis='y')
        
        # Format x-axis
        plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%m/%d'))
        plt.gca().xaxis.set_major_locator(mdates.DayLocator(interval=max(1, len(days)//15)))
        plt.xticks(rotation=45)
        
        # Add statistics
        total_attempts = sum(counts)
        max_attempts = max(counts) if counts else 0
        avg_daily = total_attempts / len(days) if days else 0
        peak_day = days[counts.index(max_attempts)] if counts else None
        
        stats_text = f'Total Attempts: {total_attempts:,}\nDaily Average: {avg_daily:.1f}\nPeak Day: {max_attempts:,} attempts'
        if peak_day:
            stats_text += f'\nPeak Date: {peak_day.strftime("%m/%d/%Y")}'
        
        plt.text(0.02, 0.98, stats_text, transform=plt.gca().transAxes, 
                verticalalignment='top', bbox=dict(boxstyle='round', facecolor='lightblue', alpha=0.8))
        
        plt.tight_layout()
        
        # Save the plot
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"gp_attacks_daily_{fw_ip}_{timestamp}.png"
        filepath = os.path.join(OUTPUT_DIR, filename)
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        
        self.log(f"Generated daily trend graph: {filepath}")
        plt.show()
        
        return filepath
    
    def generate_summary_stats(self, attack_events):
        """Generate comprehensive attack statistics."""
        if not attack_events:
            return
        
        self.log("\n" + "="*60)
        self.log("ATTACK SUMMARY STATISTICS")
        self.log("="*60)
        
        # Overall stats
        total_attacks = len(attack_events)
        unique_ips = len(set(event['ip'] for event in attack_events))
        date_range = (min(event['timestamp'] for event in attack_events),
                     max(event['timestamp'] for event in attack_events))
        
        self.log(f"Total Failed Attempts: {total_attacks:,}")
        self.log(f"Unique Attacking IPs: {unique_ips:,}")
        self.log(f"Date Range: {date_range[0].strftime('%Y-%m-%d %H:%M')} to {date_range[1].strftime('%Y-%m-%d %H:%M')}")
        
        # Top attacking IPs
        ip_counts = Counter(event['ip'] for event in attack_events)
        self.log(f"\nTop 10 Attacking IPs:")
        for ip, count in ip_counts.most_common(10):
            self.log(f"  {ip}: {count:,} attempts")
        
        # Top usernames targeted
        username_counts = Counter(event['username'] for event in attack_events if event['username'])
        if username_counts:
            self.log(f"\nTop 10 Targeted Usernames:")
            for username, count in username_counts.most_common(10):
                self.log(f"  {username}: {count:,} attempts")
        
        # Daily statistics
        daily_counts = defaultdict(int)
        for event in attack_events:
            day_key = event['timestamp'].date()
            daily_counts[day_key] += 1
        
        if daily_counts:
            avg_daily = sum(daily_counts.values()) / len(daily_counts)
            max_daily = max(daily_counts.values())
            self.log(f"\nDaily Attack Statistics:")
            self.log(f"  Average attacks per day: {avg_daily:.1f}")
            self.log(f"  Maximum attacks in a day: {max_daily:,}")
        
        self.log("="*60)
    
    def run(self, fw_ip=None):
        """Main execution workflow."""
        # Select and authenticate to firewall
        selected_fw = self.select_firewall(fw_ip)
        
        if not self.authenticate_firewall(selected_fw):
            return False
        
        # Execute with retry logic
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                self.log(f"Analysis attempt {attempt}/{MAX_RETRIES}")
                
                # Submit comprehensive query
                job_id = self.submit_log_query(selected_fw)
                
                # Wait for completion
                if not self.wait_for_job(job_id):
                    raise Exception("Job did not complete successfully")
                
                # Download and save results
                xml_data = self.download_job_results(job_id)
                xml_file = self.save_xml_data(selected_fw, xml_data)
                
                # Parse attack events
                attack_events = self.parse_log_entries(xml_data)
                
                if not attack_events:
                    self.log("No attack events found in logs")
                    return True
                
                # Generate comprehensive statistics
                self.generate_summary_stats(attack_events)
                
                # Generate visualizations
                hourly_graph = self.generate_hourly_graph(attack_events, selected_fw)
                daily_graph = self.generate_daily_graph(attack_events, selected_fw)
                
                self.log(f"\nAnalysis complete! Generated files:")
                self.log(f"  Raw data: {xml_file}")
                if hourly_graph:
                    self.log(f"  Hourly trends: {hourly_graph}")
                if daily_graph:
                    self.log(f"  Daily trends: {daily_graph}")
                
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
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Analyze GlobalProtect authentication failure trends over time',
        epilog='Example: python %(prog)s -f 192.168.1.1 --log'
    )
    parser.add_argument('-f', '--frwl', 
                       help='Firewall IP address')
    parser.add_argument('--log', 
                       action='store_true', 
                       help='Enable file logging')
    args = parser.parse_args()
    
    # Check for required dependencies
    try:
        import matplotlib.pyplot as plt
        import pandas as pd
    except ImportError as e:
        print(f"Error: Missing required dependency: {e}")
        print("Please install required packages: pip install matplotlib pandas")
        sys.exit(1)
    
    analyzer = AttackTrendAnalyzer(enable_logging=args.log)
    success = analyzer.run(args.frwl)
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()