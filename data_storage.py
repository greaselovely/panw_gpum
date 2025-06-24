#!/usr/bin/env python3
"""
CSV Data Storage Module for GlobalProtect Attack History

This module handles storing GlobalProtect authentication failure data
in CSV files for historical analysis and trend visualization.

Creates two CSV files per firewall:
1. Individual events file: gp_attacks_[firewall_ip].csv
2. Aggregated data file: gp_attacks_aggregated_[firewall_ip].csv

Author: Zero One Six Security
Version: 1.0
 _____   __________  ____ ________
/__  /  / ____/ __ \/ __ <  / ___/
  / /  / __/ / /_/ / / / / / __ \
 / /__/ /___/ _, _/ /_/ / / /_/ /
/____/_____/_/ |_|\____/_/\____/

"""

import os
import csv
import logging
from datetime import datetime, timedelta
from collections import defaultdict

class CSVDataStorage:
    """
    Handles CSV storage for GlobalProtect attack data.
    
    Manages both individual event storage for pattern analysis
    and aggregated data for graph generation.
    """
    
    def __init__(self, logger=None, data_dir='data'):
        """
        Initialize CSV data storage.
        
        Args:
            logger: Logger instance (optional)
            data_dir: Directory to store CSV files (default: 'data')
        """
        self.logger = logger or logging.getLogger(__name__)
        self.data_dir = data_dir
        self.ensure_data_directory()
    
    def ensure_data_directory(self):
        """Create data directory if it doesn't exist."""
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
            self.logger.info(f"Created data directory: {self.data_dir}")
    
    def get_csv_filenames(self, firewall_ip):
        """
        Generate CSV filenames for a firewall.
        
        Args:
            firewall_ip (str): Firewall IP address
            
        Returns:
            tuple: (individual_events_file, aggregated_data_file)
        """
        individual_file = os.path.join(self.data_dir, f"gp_attacks_{firewall_ip}.csv")
        aggregated_file = os.path.join(self.data_dir, f"gp_attacks_aggregated_{firewall_ip}.csv")
        
        return individual_file, aggregated_file
    
    def ensure_csv_headers(self, firewall_ip):
        """
        Ensure CSV files exist with proper headers.
        
        Args:
            firewall_ip (str): Firewall IP address
        """
        individual_file, aggregated_file = self.get_csv_filenames(firewall_ip)
        
        # Individual events file headers
        individual_headers = ['timestamp', 'source_ip', 'username', 'event_type']
        if not os.path.exists(individual_file):
            with open(individual_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(individual_headers)
            self.logger.info(f"Created individual events file: {individual_file}")
        
        # Aggregated data file headers
        aggregated_headers = ['date', 'hour', 'count', 'unique_ips', 'unique_usernames']
        if not os.path.exists(aggregated_file):
            with open(aggregated_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(aggregated_headers)
            self.logger.info(f"Created aggregated data file: {aggregated_file}")
    
    def store_individual_events(self, firewall_ip, attack_events):
        """
        Store individual attack events to CSV file.
        
        Args:
            firewall_ip (str): Firewall IP address
            attack_events (list): List of attack event dictionaries
                Each event should have: timestamp, ip, username
        """
        if not attack_events:
            return
        
        individual_file, _ = self.get_csv_filenames(firewall_ip)
        self.ensure_csv_headers(firewall_ip)
        
        # Append new events to individual file
        with open(individual_file, 'a', newline='') as f:
            writer = csv.writer(f)
            
            for event in attack_events:
                # Format timestamp as string
                timestamp_str = event['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
                
                # Write individual event
                writer.writerow([
                    timestamp_str,
                    event['ip'],
                    event.get('username', ''),
                    'auth_failure'
                ])
        
        self.logger.info(f"Stored {len(attack_events)} individual events to {individual_file}")
    
    def aggregate_events_by_hour(self, attack_events):
        """
        Aggregate attack events by hour for graphing.
        
        Args:
            attack_events (list): List of attack event dictionaries
            
        Returns:
            list: List of hourly aggregation dictionaries
        """
        hourly_data = defaultdict(lambda: {
            'count': 0,
            'unique_ips': set(),
            'unique_usernames': set()
        })
        
        for event in attack_events:
            # Round timestamp to hour
            hour_key = event['timestamp'].replace(minute=0, second=0, microsecond=0)
            
            # Aggregate data
            hourly_data[hour_key]['count'] += 1
            hourly_data[hour_key]['unique_ips'].add(event['ip'])
            
            username = event.get('username', '')
            if username:
                hourly_data[hour_key]['unique_usernames'].add(username)
        
        # Convert to list of dictionaries
        aggregated = []
        for hour, data in sorted(hourly_data.items()):
            aggregated.append({
                'datetime': hour,
                'date': hour.strftime('%Y-%m-%d'),
                'hour': hour.hour,
                'count': data['count'],
                'unique_ips': len(data['unique_ips']),
                'unique_usernames': len(data['unique_usernames'])
            })
        
        return aggregated
    
    def store_aggregated_data(self, firewall_ip, attack_events):
        """
        Store aggregated attack data to CSV file.
        
        Args:
            firewall_ip (str): Firewall IP address
            attack_events (list): List of attack event dictionaries
        """
        if not attack_events:
            return
        
        _, aggregated_file = self.get_csv_filenames(firewall_ip)
        self.ensure_csv_headers(firewall_ip)
        
        # Aggregate events by hour
        hourly_aggregates = self.aggregate_events_by_hour(attack_events)
        
        if not hourly_aggregates:
            return
        
        # Load existing aggregated data to avoid duplicates
        existing_data = self.load_existing_aggregated_data(firewall_ip)
        
        # Merge new data with existing (update existing hours, add new ones)
        merged_data = self.merge_aggregated_data(existing_data, hourly_aggregates)
        
        # Write all aggregated data back to file
        with open(aggregated_file, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow(['date', 'hour', 'count', 'unique_ips', 'unique_usernames'])
            
            # Write aggregated data
            for entry in sorted(merged_data, key=lambda x: (x['date'], x['hour'])):
                writer.writerow([
                    entry['date'],
                    entry['hour'],
                    entry['count'],
                    entry['unique_ips'],
                    entry['unique_usernames']
                ])
        
        self.logger.info(f"Updated aggregated data with {len(hourly_aggregates)} hourly entries in {aggregated_file}")
    
    def load_existing_aggregated_data(self, firewall_ip):
        """
        Load existing aggregated data from CSV file.
        
        Args:
            firewall_ip (str): Firewall IP address
            
        Returns:
            list: List of existing aggregated data dictionaries
        """
        _, aggregated_file = self.get_csv_filenames(firewall_ip)
        existing_data = []
        
        if os.path.exists(aggregated_file):
            try:
                with open(aggregated_file, 'r', newline='') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        existing_data.append({
                            'date': row['date'],
                            'hour': int(row['hour']),
                            'count': int(row['count']),
                            'unique_ips': int(row['unique_ips']),
                            'unique_usernames': int(row['unique_usernames'])
                        })
            except Exception as e:
                self.logger.warning(f"Error loading existing aggregated data: {e}")
        
        return existing_data
    
    def merge_aggregated_data(self, existing_data, new_data):
        """
        Merge new aggregated data with existing data.
        
        Args:
            existing_data (list): Existing aggregated data
            new_data (list): New aggregated data
            
        Returns:
            list: Merged aggregated data
        """
        # Create lookup for existing data
        existing_lookup = {}
        for entry in existing_data:
            key = (entry['date'], entry['hour'])
            existing_lookup[key] = entry
        
        # Merge new data
        for entry in new_data:
            key = (entry['date'], entry['hour'])
            
            if key in existing_lookup:
                # Update existing entry (add to counts)
                existing_lookup[key]['count'] += entry['count']
                existing_lookup[key]['unique_ips'] = max(
                    existing_lookup[key]['unique_ips'], 
                    entry['unique_ips']
                )
                existing_lookup[key]['unique_usernames'] = max(
                    existing_lookup[key]['unique_usernames'], 
                    entry['unique_usernames']
                )
            else:
                # Add new entry
                existing_lookup[key] = entry
        
        return list(existing_lookup.values())
    
    def store_attack_data(self, firewall_ip, attack_events):
        """
        Main method to store both individual and aggregated attack data.
        
        Args:
            firewall_ip (str): Firewall IP address
            attack_events (list): List of attack event dictionaries
                Each event should have: timestamp, ip, username
        """
        if not attack_events:
            self.logger.info("No attack events to store")
            return
        
        try:
            # Store individual events for pattern analysis
            self.store_individual_events(firewall_ip, attack_events)
            
            # Store aggregated data for graph generation
            self.store_aggregated_data(firewall_ip, attack_events)
            
            self.logger.info(f"Successfully stored attack data for firewall {firewall_ip}")
            
        except Exception as e:
            self.logger.error(f"Error storing attack data: {e}")
            raise
    
    def cleanup_old_data(self, firewall_ip, retention_days=90):
        """
        Remove old data beyond retention period.
        
        Args:
            firewall_ip (str): Firewall IP address
            retention_days (int): Number of days to retain data
        """
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        cutoff_date_str = cutoff_date.strftime('%Y-%m-%d')
        
        individual_file, aggregated_file = self.get_csv_filenames(firewall_ip)
        
        # Clean individual events file
        if os.path.exists(individual_file):
            self._cleanup_csv_file(individual_file, 'timestamp', cutoff_date_str, retention_days)
        
        # Clean aggregated data file
        if os.path.exists(aggregated_file):
            self._cleanup_csv_file(aggregated_file, 'date', cutoff_date_str, retention_days)
    
    def _cleanup_csv_file(self, filename, date_column, cutoff_date_str, retention_days):
        """
        Clean up a CSV file by removing old entries.
        
        Args:
            filename (str): CSV filename
            date_column (str): Column name containing date/timestamp
            cutoff_date_str (str): Cutoff date string
            retention_days (int): Retention period in days
        """
        try:
            temp_filename = f"{filename}.tmp"
            rows_kept = 0
            rows_removed = 0
            
            with open(filename, 'r', newline='') as infile, \
                 open(temp_filename, 'w', newline='') as outfile:
                
                reader = csv.DictReader(infile)
                writer = csv.DictWriter(outfile, fieldnames=reader.fieldnames)
                writer.writeheader()
                
                for row in reader:
                    row_date = row[date_column][:10]  # Get just YYYY-MM-DD part
                    
                    if row_date >= cutoff_date_str:
                        writer.writerow(row)
                        rows_kept += 1
                    else:
                        rows_removed += 1
            
            # Replace original file with cleaned version
            os.replace(temp_filename, filename)
            
            if rows_removed > 0:
                self.logger.info(f"Cleaned {filename}: kept {rows_kept} rows, removed {rows_removed} rows older than {retention_days} days")
            else:
                self.logger.info(f"No cleanup needed for {filename} (all data within {retention_days} days)")
                
        except Exception as e:
            self.logger.error(f"Error cleaning up {filename}: {e}")
            # Remove temp file if it exists
            if os.path.exists(temp_filename):
                os.remove(temp_filename)

# Helper function for easy integration
def store_gp_attack_data(firewall_ip, attack_events, logger=None, data_dir='data'):
    """
    Convenience function to store GlobalProtect attack data.
    
    Args:
        firewall_ip (str): Firewall IP address
        attack_events (list): List of attack event dictionaries
        logger: Logger instance (optional)
        data_dir (str): Directory to store CSV files (default: 'data')
    """
    storage = CSVDataStorage(logger, data_dir)
    storage.store_attack_data(firewall_ip, attack_events)

def cleanup_old_gp_data(firewall_ip, retention_days=90, logger=None, data_dir='data'):
    """
    Convenience function to cleanup old GlobalProtect attack data.
    
    Args:
        firewall_ip (str): Firewall IP address
        retention_days (int): Number of days to retain data
        logger: Logger instance (optional)
        data_dir (str): Directory containing CSV files (default: 'data')
    """
    storage = CSVDataStorage(logger, data_dir)
    storage.cleanup_old_data(firewall_ip, retention_days)