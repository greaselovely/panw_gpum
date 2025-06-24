____   __________  ____ ________
/__  /  / ____/ __ \/ __ <  / ___/
  / /  / __/ / /_/ / / / / / __ \
 / /__/ /___/ _, _/ /_/ / / /_/ /
/____/_____/_/ |_|\____/_/\____/

# GlobalProtect Authentication User Enumeration Mitigation (GPUM)

A Python-based security tool for monitoring GlobalProtect authentication failures, automatically managing IP block lists through External Dynamic Lists (EDLs), and providing comprehensive attack trend analysis through historical data visualization.

## Overview

This tool addresses the common security challenge of monitoring and responding to authentication attacks against GlobalProtect VPN services. It automates the process of collecting authentication failure logs, intelligently managing whitelists to avoid blocking legitimate users, updating firewall block lists through EDL integration, and maintaining historical attack data for trend analysis and reporting.

## Key Features

### Core Security Features
- Direct API integration with PAN-OS firewalls for real-time log access
- Incremental log processing using timestamps to avoid duplicate data
- Automatic whitelisting of current GlobalProtect users to prevent service disruption
- Support for CIDR notation and individual IP addresses in whitelist management
- Integration with KineticLull EDL service for automated block list updates
- Comprehensive audit logging for security compliance and troubleshooting
- Built-in retry mechanisms for reliable operation in production environments

### Historical Analysis and Reporting
- **Automatic CSV data storage** for building historical attack databases
- **Fast trend analysis** without requiring firewall queries
- **Hourly and daily attack pattern visualization** with professional graphs
- **Comprehensive attack statistics** including top attacking IPs and targeted usernames
- **Multi-firewall support** for enterprise environments
- **Configurable data retention** with automatic cleanup of old records
- **On-demand reporting** for security briefings and executive summaries

### Operational Excellence
- Designed for unattended operation via cron scheduling
- Separation of data collection (fast) and analysis (on-demand) for optimal performance
- Automatic data cleanup based on configurable retention policies
- Professional graph generation with publication-ready formatting

## Requirements

### Software Dependencies
```bash
pip install -r requirements.txt
```

**Required packages:**
- `matplotlib` - For generating attack trend graphs
- `pandas` - For efficient CSV data processing
- `requests` - For API communication
- `urllib3` - For HTTP handling
- `xmltodict` - For parsing firewall XML responses
- `pan-os-python` - For PAN-OS firewall integration

### Infrastructure Requirements
- PAN-OS firewall with API access enabled
- User account with API permissions for log queries and operational commands
- GlobalProtect gateway properly configured and operational
- Network connectivity between the script host and firewall management interface
- **Python 3.11 or earlier** (Python 3.12+ has compatibility issues with pan-os-python)

### Optional Components
- KineticLull EDL service account for automated block list management
- Configured EDL URLs in your firewall policy

## Installation and Setup

1. Download the script files to your preferred directory:
   - `main.py` - Primary data collection script
   - `data_storage.py` - CSV storage module
   - `attack_analyzer_csv.py` - Historical analysis and graphing tool

2. Install required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the initial setup to create configuration files:
   ```bash
   python main.py -f YOUR_FIREWALL_IP
   ```

4. Edit the generated config.json file with your specific settings

## Configuration

The script creates a config.json file on first run with several sections that require customization:

### Firewall Settings
The firewall section stores connection details and API keys:
```json
{
  "firewalls": {
    "192.168.1.1": {
      "api_key": "automatically-generated-and-stored",
      "last_timestamp": "2025/06/18 14:30:00"
    }
  }
}
```

### Whitelist Configuration
Define IP addresses and networks that should never be blocked:
```json
{
  "whitelist": {
    "description": "IPs to exclude from blocking - internal networks, trusted sources, etc.",
    "ips": [
      "10.0.0.0/8",
      "172.16.0.0/12",
      "192.168.0.0/16",
      "203.0.113.10"
    ]
  }
}
```

### GlobalProtect Auto-Whitelist
Capture the name of your GlobalProtect Gateway and update it. Configure automatic whitelisting of current VPN users:
```json
{
  "globalprotect": {
    "gateway_name": "YOUR-GATEWAY-NAME",
    "auto_whitelist": true,
    "description": "Set gateway_name to your actual GP gateway name"
  }
}
```

**Critical**: You must change the gateway_name from "CHANGE_ME" to your actual GlobalProtect gateway name. The script will fail to run until this is configured.

### Data Storage Configuration
Configure historical data storage and retention:
```json
{
  "data_storage": {
    "enabled": true,
    "retention_days": 90,
    "description": "Historical data storage in CSV format for trend analysis"
  }
}
```

### EDL Integration
Configure KineticLull EDL service integration:
```json
{
  "KineticLull": {
    "api_key": "your-kineticlull-api-key",
    "edls": {
      "1": {
        "name": "GlobalProtect Failed Auth",
        "url": "https://edl.domain.com/your-edl-id.kl"
      }
    }
  }
}
```

## Usage

### Primary Data Collection (main.py)

This is your primary operational script that should be run regularly:

```bash
# Basic operation with interactive firewall selection
python main.py

# Specify target firewall directly
python main.py -f 192.168.1.1

# Enable EDL updates (disabled by default)
python main.py -f 192.168.1.1 --edl

# Enable file logging for automated execution
python main.py -f 192.168.1.1 --log --edl
```

**Available Arguments:**
- `-f, --frwl IP`: Target firewall IP address
- `-e, --edl`: Enable EDL updates after processing logs
- `-l, --log`: Enable file logging suitable for cron execution

### Historical Analysis and Graphing (attack_analyzer_csv.py)

Run this script on-demand when you need trend analysis and graphs:

```bash
# Analyze specific firewall (interactive selection if no IP specified)
python attack_analyzer_csv.py -f 192.168.1.1

# Analyze last 30 days only
python attack_analyzer_csv.py -f 192.168.1.1 --days 30

# Analyze all firewalls with available data
python attack_analyzer_csv.py --all-firewalls

# Generate weekly security report
python attack_analyzer_csv.py --all-firewalls --days 7 --log
```

**Available Arguments:**
- `-f, --frwl IP`: Target firewall IP address
- `--days N`: Limit analysis to last N days
- `--all-firewalls`: Analyze all firewalls with available data
- `--log`: Enable file logging

### Automated Execution

**Recommended cron setup for production:**

```bash
# Primary data collection every 6 hours
0 */6 * * * /usr/bin/python3 /path/to/main.py -f 192.168.1.1 --log --edl

# Weekly automated security report generation
0 8 * * 1 /usr/bin/python3 /path/to/attack_analyzer_csv.py --all-firewalls --days 7 --log
```

**For high-security environments:**
```bash
# Hourly data collection
0 * * * * /usr/bin/python3 /path/to/main.py -f 192.168.1.1 --log --edl
```

## Operation Workflow

### Data Collection Workflow (main.py)
The primary script follows this sequence:

1. **Authentication Phase**: Establishes connection to the firewall using stored API keys or interactive credentials
2. **Configuration Validation**: Verifies that required settings (particularly GlobalProtect gateway name) are properly configured
3. **Current User Discovery**: Queries the firewall for currently connected GlobalProtect users and adds their public IP addresses to the whitelist
4. **Block List Cleanup**: Reviews existing block list entries and removes any IP addresses that are now whitelisted
5. **Log Query Execution**: Retrieves authentication failure logs since the last execution using incremental timestamp queries
6. **Data Processing**: Filters out whitelisted IP addresses, counts failures per IP, and merges with existing data
7. **Historical Data Storage**: **NEW** - Automatically stores attack events in CSV files for trend analysis
8. **EDL Update**: Optionally sends the processed block list to the KineticLull EDL service for firewall policy updates

### Analysis Workflow (attack_analyzer_csv.py)
The analysis script provides fast, offline reporting:

1. **Data Cleanup**: Automatically removes old data based on retention settings
2. **Data Loading**: Reads historical data from CSV files (no firewall queries needed)
3. **Statistical Analysis**: Generates comprehensive attack statistics and trends
4. **Graph Generation**: Creates professional hourly and daily trend visualizations
5. **Report Output**: Saves graphs and displays summary statistics

## Generated Files and Logs

### Primary Output Files
- `blocked_ips.txt`: Main IP block list with failure counts and timestamps
- `config.json`: Configuration file containing firewall settings and API keys

### Historical Data Files (NEW)
- `gp_attacks_[firewall_ip].csv`: Individual attack events for pattern analysis
- `gp_attacks_aggregated_[firewall_ip].csv`: Pre-aggregated hourly data for fast graphing

### Generated Reports and Graphs
- `attack_graphs/gp_attacks_hourly_[firewall_ip]_[timestamp].png`: Hourly trend graphs
- `attack_graphs/gp_attacks_daily_[firewall_ip]_[timestamp].png`: Daily trend graphs

### Audit and Debug Logs
- `whitelist_failures.log`: Authentication failures from whitelisted IP addresses
- `whitelist_updates.log`: Complete audit trail of whitelist additions and removals
- `gp_downloader.log`: Main application log (created when using --log option)
- `csv_attack_analyzer.log`: Analysis script log (created when using --log option)

### Archive Storage
- `xml_logs/`: Directory containing raw XML log files from firewall queries
- Files are automatically removed after 24 hours to manage disk space

### Sample Block List Format
```
# GlobalProtect Authentication Failures - Updated: 2025/06/18 14:30:15
# Total unique IPs: 143

1.2.3.4 # 14 failures
5.6.7.8 # 7 failures
23.234.70.60 # 3 failures
```

### Sample CSV Data Structure

**Individual Events (gp_attacks_[ip].csv):**
```csv
timestamp,source_ip,username,event_type
2025-06-18 14:30:15,1.2.3.4,admin,auth_failure
2025-06-18 14:31:02,5.6.7.8,administrator,auth_failure
```

**Aggregated Data (gp_attacks_aggregated_[ip].csv):**
```csv
date,hour,count,unique_ips,unique_usernames
2025-06-18,14,25,12,8
2025-06-18,15,18,9,6
```

## Security Considerations

### Whitelist Management
The tool implements several layers of protection to prevent blocking legitimate traffic:
- Support for both CIDR blocks (10.0.0.0/8) and individual IP addresses
- Automatic discovery and whitelisting of current GlobalProtect users
- Comprehensive audit logging of all whitelist changes
- Separate logging of authentication failures from whitelisted sources for security monitoring

### Historical Data Security
- CSV files contain attack data and should be treated as security-sensitive
- Implement appropriate file permissions and access controls
- Consider encryption for CSV files in high-security environments
- Regular data retention policies automatically remove old attack data

### Data Validation
All IP addresses undergo validation before processing:
- Invalid IP addresses are automatically filtered out
- Duplicate entries are removed
- IP addresses are sorted numerically for consistency
- Malformed data is logged but does not interrupt processing

### Authentication Failure Analysis
The tool maintains separate logs for whitelisted IP authentication failures, allowing security teams to:
- Monitor for potential insider threats or compromised accounts
- Track authentication patterns from trusted networks
- Identify configuration issues that might cause legitimate users to appear as attackers

## Performance Optimization

### Separation of Concerns
- **main.py**: Optimized for speed and reliability in automated environments
- **attack_analyzer_csv.py**: Optimized for comprehensive analysis without impacting operational performance

### Data Storage Efficiency
- Pre-aggregated data reduces analysis time from minutes to seconds
- CSV format provides excellent performance for time-series data
- Automatic data cleanup prevents unlimited disk space growth

### Scalability Features
- Multi-firewall support with separate data streams
- Configurable retention policies for different security requirements
- Efficient memory usage even with large historical datasets

## Troubleshooting

### Configuration Issues
**Gateway Name Error**: If you see "gateway_name not configured", edit config.json and replace "CHANGE_ME" with your actual GlobalProtect gateway name.

**API Authentication Failures**: Verify that API access is enabled on your firewall and that the user account has appropriate permissions. Check network connectivity to the firewall management interface.

**Python Version Compatibility**: Use Python 3.11 or earlier. Python 3.12+ has compatibility issues with the pan-os-python library.

### Operational Issues
**No Authentication Failures Found**: This may indicate that no actual attacks are occurring, or that the log query parameters need adjustment for your specific PAN-OS version.

**EDL Update Failures**: Verify your KineticLull API key and EDL URL configuration. Ensure that trailing slashes are removed from EDL URLs as the service does not accept them.

**CSV Data Issues**: Check file permissions and disk space. The tool requires write access to create CSV files in the working directory.

### Analysis Issues
**No Graphs Generated**: Ensure matplotlib and pandas are properly installed. Check that CSV data files exist and contain valid data.

**Missing Data in Analysis**: Verify that main.py has been running and collecting data. The analysis tool requires existing CSV files to generate reports.

### Performance Considerations
**Large Log Volumes**: The tool limits queries to 5000 log entries by default. For environments with high attack volumes, consider running the tool more frequently rather than increasing the log limit.

**Network Impact**: API queries are designed to be lightweight, but frequent execution against busy firewalls should be monitored for performance impact.

**Graph Generation Speed**: The analysis tool uses pre-aggregated data for optimal performance. Generating graphs for 90 days of data typically takes less than 30 seconds.

## Best Practices

### Security Operations
- Regularly review whitelist changes in the audit logs
- Monitor authentication failures from whitelisted IP addresses for security incidents
- Implement proper access controls for configuration files containing API keys
- Consider implementing API key rotation on a regular schedule
- **Generate weekly or monthly attack trend reports** for security briefings
- **Use daily graphs to identify attack patterns** and adjust security policies accordingly

### System Administration
- Test the tool manually before implementing automated execution
- Monitor log files for errors and unusual patterns
- Implement proper backup procedures for configuration files and historical data
- Use network segmentation to run the tool from a secure management network
- **Set up automated report generation** for regular security assessments
- **Monitor CSV file growth** and adjust retention policies as needed

### Deployment Strategy
- Begin with EDL updates disabled to verify operation
- Implement in a test environment before production deployment
- Start with longer execution intervals and decrease as confidence builds
- Monitor firewall performance after implementing automated block list updates
- **Start collecting historical data immediately** to build trend analysis capability
- **Establish baseline attack patterns** during the first month of operation

### Reporting and Analysis
- **Generate hourly graphs during active incidents** for real-time threat assessment
- **Use daily/weekly graphs for executive reporting** and security briefings
- **Analyze username patterns** to identify targeted accounts or credential stuffing attempts
- **Compare attack patterns across multiple firewalls** to identify coordinated attacks
- **Set up automated monthly reports** for compliance and security posture assessment

## Use Cases and Examples

### Daily Security Operations
```bash
# Check current attack trends
python attack_analyzer_csv.py -f 192.168.1.1 --days 1

# Weekly security team review
python attack_analyzer_csv.py --all-firewalls --days 7
```

### Incident Response
```bash
# Analyze attack patterns during an incident
python attack_analyzer_csv.py -f 192.168.1.1 --days 3

# Generate detailed statistics for incident reports
python attack_analyzer_csv.py -f 192.168.1.1 --days 7 --log
```

### Executive Reporting
```bash
# Monthly security posture report
python attack_analyzer_csv.py --all-firewalls --days 30

# Quarterly trend analysis
python attack_analyzer_csv.py --all-firewalls --days 90
```

## Version Information

### Current Version: 1.0
This release includes comprehensive functionality:
- Complete PAN-OS API integration
- Automatic whitelist management
- KineticLull EDL service integration
- **Historical data storage and analysis capabilities**
- **Professional graph generation and reporting**
- **Multi-firewall support for enterprise environments**
- Comprehensive logging and audit capabilities
- Production-ready error handling and retry logic

## Support and Maintenance

For technical issues:
1. Review the troubleshooting section above
2. Examine log files for specific error messages
3. Verify configuration file syntax and content
4. Test network connectivity and firewall API access
5. **Check CSV file integrity and data availability for analysis issues**
6. **Verify matplotlib and pandas installation for graphing problems**

The tool is designed to be self-maintaining with automatic cleanup of temporary files, robust error handling for network and API issues, and intelligent data retention management for long-term operation.