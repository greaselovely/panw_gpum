#!/usr/bin/env python3
r"""
CSV-Based GlobalProtect Attack Trend Analyzer v1.0

This script reads stored GlobalProtect authentication failure data from CSV files
and generates time-based visualizations showing attack patterns over hourly and daily periods.
This version works with data collected by the main.py script and stored via data_storage.py.

Key Features:
- Reads from local CSV files (no firewall queries needed)
- Fast execution using pre-aggregated data
- Generates hourly and daily attack trend graphs
- Automatic cleanup of old data based on retention settings
- Comprehensive statistics and analysis
- Multiple firewall support

Author: Zero One Six Security
Version: 1.0
 _____   __________  ____ ________
/__  /  / ____/ __ \/ __ <  / ___/
  / /  / __/ / /_/ / / / / / __ \
 / /__/ /___/ _, _/ /_/ / / /_/ /
/____/_____/_/ |_|\____/_/\____/

Example usage:
python3 attack_analyzer_csv.py -f <FIREWALL_IP>
    or
python3 attack_analyzer_csv.py --frwl <FIREWALL_IP> --days 30
    or
python3 attack_analyzer_csv.py --all-firewalls
"""

import json
import os
import sys
import argparse
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import logging
from datetime import datetime, timedelta
from collections import defaultdict, Counter

# Import CSV data storage for cleanup functionality
try:
    from data_storage import cleanup_old_gp_data
except ImportError:
    print("Warning: data_storage module not found. Data cleanup will be disabled.")
    cleanup_old_gp_data = None

# Configuration
CONFIG_FILE = 'config.json'
OUTPUT_DIR = 'attack_graphs'
APP_LOGS_DIR = 'app_logs'
LOG_FILE = os.path.join(APP_LOGS_DIR, 'csv_attack_analyzer.log')

class CSVAttackAnalyzer:
    """
    Analyzes GlobalProtect authentication failure trends from CSV data.
    
    This class reads historical data from CSV files and creates time-based
    visualizations without needing to query firewalls.
    """
    
    def __init__(self, enable_logging=False):
        """Initialize the CSV attack analyzer."""
        self.logger = self.setup_logging(enable_logging)
        self.config = self.load_config()
        self.ensure_output_directory()
        self.ensure_app_logs_directory()
    
    def setup_logging(self, enable_logging):
        """Setup logging configuration."""
        logger = logging.getLogger('csv_attack_analyzer')
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
    
    def ensure_output_directory(self):
        """Create output directory if it doesn't exist."""
        if not os.path.exists(OUTPUT_DIR):
            os.makedirs(OUTPUT_DIR)
            self.log(f"Created directory: {OUTPUT_DIR}")
    
    def ensure_app_logs_directory(self):
        """Create app logs directory if it doesn't exist."""
        if not os.path.exists(APP_LOGS_DIR):
            os.makedirs(APP_LOGS_DIR)
            self.log(f"Created directory: {APP_LOGS_DIR}")
    
    def load_config(self):
        """Load configuration from JSON file."""
        if not os.path.exists(CONFIG_FILE):
            self.log(f"Error: {CONFIG_FILE} not found. Please run main.py first to create configuration.")
            sys.exit(1)
        
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
        
        return config
    
    def get_csv_filenames(self, firewall_ip):
        """Generate CSV filenames for a firewall."""
        data_dir = 'data'
        individual_file = os.path.join(data_dir, f"gp_attacks_{firewall_ip}.csv")
        aggregated_file = os.path.join(data_dir, f"gp_attacks_aggregated_{firewall_ip}.csv")
        return individual_file, aggregated_file
    
    def get_available_firewalls(self):
        """Get list of firewalls with available CSV data."""
        available_firewalls = []
        
        # Check configured firewalls
        for fw_ip in self.config.get("firewalls", {}).keys():
            individual_file, aggregated_file = self.get_csv_filenames(fw_ip)
            if os.path.exists(individual_file) or os.path.exists(aggregated_file):
                available_firewalls.append(fw_ip)
        
        # Also check for any CSV files in current directory that match pattern
        for filename in os.listdir('.'):
            if filename.startswith('gp_attacks_') and filename.endswith('.csv') and not 'aggregated' in filename:
                # Extract IP from filename: gp_attacks_192.168.1.1.csv
                ip_part = filename[11:-4]  # Remove 'gp_attacks_' and '.csv'
                if ip_part not in available_firewalls:
                    available_firewalls.append(ip_part)
        
        # Also check in data directory for CSV files
        data_dir = 'data'
        if os.path.exists(data_dir):
            for filename in os.listdir(data_dir):
                if filename.startswith('gp_attacks_') and filename.endswith('.csv') and not 'aggregated' in filename:
                    # Extract IP from filename: gp_attacks_192.168.1.1.csv
                    ip_part = filename[11:-4]  # Remove 'gp_attacks_' and '.csv'
                    if ip_part not in available_firewalls:
                        available_firewalls.append(ip_part)
        
        return sorted(available_firewalls)
    
    def select_firewall(self, target_ip=None):
        """Select firewall for analysis."""
        if target_ip:
            return target_ip
        
        available_firewalls = self.get_available_firewalls()
        
        if not available_firewalls:
            self.log("No CSV data files found. Please run main.py first to collect data.")
            sys.exit(1)
        
        print("\nAvailable firewalls with CSV data:")
        for i, fw in enumerate(available_firewalls, 1):
            individual_file, aggregated_file = self.get_csv_filenames(fw)
            status = []
            if os.path.exists(individual_file):
                status.append("individual")
            if os.path.exists(aggregated_file):
                status.append("aggregated")
            print(f"{i}. {fw} ({', '.join(status)} data)")
        
        while True:
            try:
                choice = int(input(f"\nSelect firewall (1-{len(available_firewalls)}): "))
                if 1 <= choice <= len(available_firewalls):
                    return available_firewalls[choice - 1]
                else:
                    print("Invalid selection")
            except ValueError:
                print("Please enter a number")
            except KeyboardInterrupt:
                print("\nAnalysis cancelled")
                sys.exit(0)
    
    def cleanup_old_data(self, firewall_ip):
        """Clean up old data based on retention settings."""
        if cleanup_old_gp_data is None:
            self.log("Data cleanup skipped (data_storage module not available)")
            return
        
        # Get retention settings from config
        data_storage_config = self.config.get("data_storage", {})
        retention_days = data_storage_config.get("retention_days", 90)
        
        if not data_storage_config.get("enabled", True):
            self.log("Data cleanup skipped (data storage disabled)")
            return
        
        try:
            self.log(f"Cleaning up data older than {retention_days} days...")
            cleanup_old_gp_data(firewall_ip, retention_days, self.logger)
        except Exception as e:
            self.log(f"Warning: Data cleanup failed: {e}")
    
    def load_individual_data(self, firewall_ip, days_back=None):
        """Load individual attack events from CSV file."""
        individual_file, _ = self.get_csv_filenames(firewall_ip)
        
        if not os.path.exists(individual_file):
            self.log(f"Individual data file not found: {individual_file}")
            return []
        
        try:
            # Read CSV file
            df = pd.read_csv(individual_file)
            
            if df.empty:
                self.log("Individual data file is empty")
                return []
            
            # Convert timestamp column to datetime
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            # Filter by date range if specified
            if days_back:
                cutoff_date = datetime.now() - timedelta(days=days_back)
                df = df[df['timestamp'] >= cutoff_date]
            
            # Convert to list of dictionaries
            events = []
            for _, row in df.iterrows():
                events.append({
                    'timestamp': row['timestamp'],
                    'ip': row['source_ip'],
                    'username': row['username'] if pd.notna(row['username']) else '',
                    'event_type': row.get('event_type', 'auth_failure')
                })
            
            self.log(f"Loaded {len(events)} individual attack events from {individual_file}")
            return events
            
        except Exception as e:
            self.log(f"Error loading individual data: {e}")
            return []
    
    def load_aggregated_data(self, firewall_ip, days_back=None):
        """Load aggregated attack data from CSV file."""
        _, aggregated_file = self.get_csv_filenames(firewall_ip)
        
        if not os.path.exists(aggregated_file):
            self.log(f"Aggregated data file not found: {aggregated_file}")
            return []
        
        try:
            # Read CSV file
            df = pd.read_csv(aggregated_file)
            
            if df.empty:
                self.log("Aggregated data file is empty")
                return []
            
            # Convert date column to datetime
            df['datetime'] = pd.to_datetime(df['date'] + ' ' + df['hour'].astype(str) + ':00:00')
            
            # Filter by date range if specified
            if days_back:
                cutoff_date = datetime.now() - timedelta(days=days_back)
                df = df[df['datetime'] >= cutoff_date]
            
            # Convert to list of dictionaries
            aggregated_data = []
            for _, row in df.iterrows():
                aggregated_data.append({
                    'datetime': row['datetime'],
                    'date': row['date'],
                    'hour': row['hour'],
                    'count': row['count'],
                    'unique_ips': row['unique_ips'],
                    'unique_usernames': row['unique_usernames']
                })
            
            self.log(f"Loaded {len(aggregated_data)} aggregated data points from {aggregated_file}")
            return aggregated_data
            
        except Exception as e:
            self.log(f"Error loading aggregated data: {e}")
            return []
    
    def generate_hourly_graph_from_aggregated(self, aggregated_data, firewall_ip, days_back=None):
        """Generate hourly attack trend graph from aggregated data."""
        if not aggregated_data:
            self.log("No aggregated data available for hourly graph")
            return None
        
        # Extract data for plotting
        timestamps = [entry['datetime'] for entry in aggregated_data]
        counts = [entry['count'] for entry in aggregated_data]
        
        # Create the plot
        plt.figure(figsize=(15, 8))
        plt.plot(timestamps, counts, marker='o', linewidth=2, markersize=4, color='crimson')
        
        # Title with date range info
        title = f'GlobalProtect Authentication Failures - Hourly Trends\nFirewall: {firewall_ip}'
        if days_back:
            title += f' (Last {days_back} days)'
        plt.title(title, fontsize=16, fontweight='bold')
        
        plt.xlabel('Time (Hours)', fontsize=12)
        plt.ylabel('Number of Failed Attempts', fontsize=12)
        plt.grid(True, alpha=0.3)
        
        # Format x-axis
        plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%m/%d %H:%M'))
        plt.gca().xaxis.set_major_locator(mdates.HourLocator(interval=max(1, len(timestamps)//20)))
        plt.xticks(rotation=45)
        
        # Add statistics
        total_attempts = sum(counts)
        max_attempts = max(counts) if counts else 0
        peak_time = timestamps[counts.index(max_attempts)] if counts else None
        avg_hourly = total_attempts / len(counts) if counts else 0
        
        stats_text = f'Total Attempts: {total_attempts:,}\nAverage per Hour: {avg_hourly:.1f}\nPeak Hour: {max_attempts:,} attempts'
        if peak_time:
            stats_text += f'\nPeak Time: {peak_time.strftime("%m/%d %H:%M")}'
        
        plt.text(0.02, 0.98, stats_text, transform=plt.gca().transAxes, 
                verticalalignment='top', bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))
        
        plt.tight_layout()
        
        # Save the plot
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        suffix = f"_{days_back}days" if days_back else ""
        filename = f"gp_attacks_hourly_{firewall_ip}_{timestamp}{suffix}.png"
        filepath = os.path.join(OUTPUT_DIR, filename)
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        
        self.log(f"Generated hourly trend graph: {filepath}")
        plt.show()
        
        return filepath
    
    def generate_daily_graph_from_aggregated(self, aggregated_data, firewall_ip, days_back=None):
        """Generate daily attack trend graph from aggregated data."""
        if not aggregated_data:
            self.log("No aggregated data available for daily graph")
            return None
        
        # Group by date and sum counts
        daily_totals = defaultdict(lambda: {'count': 0, 'unique_ips': set(), 'unique_usernames': set()})
        
        for entry in aggregated_data:
            date = entry['date']
            daily_totals[date]['count'] += entry['count']
            # For unique counts, we'll use the maximum seen in any hour (approximation)
            daily_totals[date]['unique_ips'].add(entry['unique_ips'])
            daily_totals[date]['unique_usernames'].add(entry['unique_usernames'])
        
        # Convert to sorted lists
        dates = sorted(daily_totals.keys())
        date_objects = [datetime.strptime(date, '%Y-%m-%d').date() for date in dates]
        counts = [daily_totals[date]['count'] for date in dates]
        
        # Create the plot
        plt.figure(figsize=(15, 8))
        plt.bar(date_objects, counts, width=0.8, alpha=0.7, color='darkblue')
        
        # Title with date range info
        title = f'GlobalProtect Authentication Failures - Daily Trends\nFirewall: {firewall_ip}'
        if days_back:
            title += f' (Last {days_back} days)'
        plt.title(title, fontsize=16, fontweight='bold')
        
        plt.xlabel('Date', fontsize=12)
        plt.ylabel('Number of Failed Attempts', fontsize=12)
        plt.grid(True, alpha=0.3, axis='y')
        
        # Format x-axis
        plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%m/%d'))
        plt.gca().xaxis.set_major_locator(mdates.DayLocator(interval=max(1, len(dates)//15)))
        plt.xticks(rotation=45)
        
        # Add statistics
        total_attempts = sum(counts)
        max_attempts = max(counts) if counts else 0
        avg_daily = total_attempts / len(counts) if counts else 0
        peak_day = date_objects[counts.index(max_attempts)] if counts else None
        
        stats_text = f'Total Attempts: {total_attempts:,}\nDaily Average: {avg_daily:.1f}\nPeak Day: {max_attempts:,} attempts'
        if peak_day:
            stats_text += f'\nPeak Date: {peak_day.strftime("%m/%d/%Y")}'
        
        plt.text(0.02, 0.98, stats_text, transform=plt.gca().transAxes, 
                verticalalignment='top', bbox=dict(boxstyle='round', facecolor='lightblue', alpha=0.8))
        
        plt.tight_layout()
        
        # Save the plot
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        suffix = f"_{days_back}days" if days_back else ""
        filename = f"gp_attacks_daily_{firewall_ip}_{timestamp}{suffix}.png"
        filepath = os.path.join(OUTPUT_DIR, filename)
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        
        self.log(f"Generated daily trend graph: {filepath}")
        plt.show()
        
        return filepath
    
    def generate_summary_stats(self, individual_events, aggregated_data, firewall_ip):
        """Generate comprehensive attack statistics."""
        self.log("\n" + "="*60)
        self.log("ATTACK SUMMARY STATISTICS")
        self.log("="*60)
        
        if individual_events:
            # Stats from individual events
            total_attacks = len(individual_events)
            unique_ips = len(set(event['ip'] for event in individual_events))
            date_range = (min(event['timestamp'] for event in individual_events),
                         max(event['timestamp'] for event in individual_events))
            
            self.log(f"Firewall: {firewall_ip}")
            self.log(f"Total Failed Attempts: {total_attacks:,}")
            self.log(f"Unique Attacking IPs: {unique_ips:,}")
            self.log(f"Date Range: {date_range[0].strftime('%Y-%m-%d %H:%M')} to {date_range[1].strftime('%Y-%m-%d %H:%M')}")
            
            # Top attacking IPs
            ip_counts = Counter(event['ip'] for event in individual_events)
            self.log(f"\nTop 10 Attacking IPs:")
            for ip, count in ip_counts.most_common(10):
                self.log(f"  {ip}: {count:,} attempts")
            
            # Top usernames targeted
            username_counts = Counter(event['username'] for event in individual_events if event['username'])
            if username_counts:
                self.log(f"\nTop 10 Targeted Usernames:")
                for username, count in username_counts.most_common(10):
                    self.log(f"  {username}: {count:,} attempts")
        
        elif aggregated_data:
            # Stats from aggregated data only
            total_attacks = sum(entry['count'] for entry in aggregated_data)
            max_unique_ips = max(entry['unique_ips'] for entry in aggregated_data) if aggregated_data else 0
            date_range = (min(entry['datetime'] for entry in aggregated_data),
                         max(entry['datetime'] for entry in aggregated_data))
            
            self.log(f"Firewall: {firewall_ip}")
            self.log(f"Total Failed Attempts: {total_attacks:,}")
            self.log(f"Max Unique IPs (in any hour): {max_unique_ips:,}")
            self.log(f"Date Range: {date_range[0].strftime('%Y-%m-%d %H:%M')} to {date_range[1].strftime('%Y-%m-%d %H:%M')}")
        
        # Daily statistics from aggregated data
        if aggregated_data:
            daily_counts = defaultdict(int)
            for entry in aggregated_data:
                daily_counts[entry['date']] += entry['count']
            
            if daily_counts:
                avg_daily = sum(daily_counts.values()) / len(daily_counts)
                max_daily = max(daily_counts.values())
                self.log(f"\nDaily Attack Statistics:")
                self.log(f"  Average attacks per day: {avg_daily:.1f}")
                self.log(f"  Maximum attacks in a day: {max_daily:,}")
        
        self.log("="*60)
    
    def analyze_firewall(self, firewall_ip, days_back=None):
        """Analyze attack data for a specific firewall."""
        self.log(f"\nAnalyzing attack data for firewall: {firewall_ip}")
        
        # Clean up old data first
        self.cleanup_old_data(firewall_ip)
        
        # Load data
        individual_events = self.load_individual_data(firewall_ip, days_back)
        aggregated_data = self.load_aggregated_data(firewall_ip, days_back)
        
        if not individual_events and not aggregated_data:
            self.log(f"No data found for firewall {firewall_ip}")
            return False
        
        # Generate statistics
        self.generate_summary_stats(individual_events, aggregated_data, firewall_ip)
        
        # Generate graphs (prefer aggregated data for performance)
        hourly_graph = None
        daily_graph = None
        
        if aggregated_data:
            hourly_graph = self.generate_hourly_graph_from_aggregated(aggregated_data, firewall_ip, days_back)
            daily_graph = self.generate_daily_graph_from_aggregated(aggregated_data, firewall_ip, days_back)
        else:
            self.log("Warning: No aggregated data available. Graphs require aggregated data for optimal performance.")
        
        # Report results
        self.log(f"\nAnalysis complete for {firewall_ip}!")
        if hourly_graph:
            self.log(f"  Hourly trends: {hourly_graph}")
        if daily_graph:
            self.log(f"  Daily trends: {daily_graph}")
        
        return True
    
    def analyze_all_firewalls(self, days_back=None):
        """Analyze attack data for all available firewalls."""
        available_firewalls = self.get_available_firewalls()
        
        if not available_firewalls:
            self.log("No firewalls with CSV data found")
            return False
        
        self.log(f"Analyzing data for {len(available_firewalls)} firewalls...")
        
        success_count = 0
        for firewall_ip in available_firewalls:
            try:
                if self.analyze_firewall(firewall_ip, days_back):
                    success_count += 1
            except Exception as e:
                self.log(f"Error analyzing {firewall_ip}: {e}")
        
        self.log(f"\nCompleted analysis for {success_count}/{len(available_firewalls)} firewalls")
        return success_count > 0
    
    def run(self, firewall_ip=None, days_back=None, all_firewalls=False):
        """Main execution workflow."""
        try:
            if all_firewalls:
                return self.analyze_all_firewalls(days_back)
            else:
                selected_fw = self.select_firewall(firewall_ip)
                return self.analyze_firewall(selected_fw, days_back)
                
        except KeyboardInterrupt:
            self.log("\nAnalysis cancelled by user")
            return False
        except Exception as e:
            self.log(f"Analysis failed: {e}")
            return False

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Analyze GlobalProtect authentication failure trends from CSV data',
        epilog='Example: python %(prog)s -f 192.168.1.1 --days 30'
    )
    parser.add_argument('-f', '--frwl', 
                       help='Firewall IP address')
    parser.add_argument('-d', '--days', 
                       type=int,
                       help='Number of days back to analyze (default: all available data)')
    parser.add_argument('-a', '--all-firewalls',
                       action='store_true',
                       help='Analyze all firewalls with available data')
    parser.add_argument('-l', '--log', 
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
    
    analyzer = CSVAttackAnalyzer(enable_logging=args.log)
    success = analyzer.run(args.frwl, args.days, args.all_firewalls)
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()