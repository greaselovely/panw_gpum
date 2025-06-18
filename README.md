# GlobalProtect Authentication Failure Log Downloader

A Python-based security tool for monitoring GlobalProtect authentication failures and automatically managing IP block lists through External Dynamic Lists (EDLs).

## Overview

This tool addresses the common security challenge of monitoring and responding to authentication attacks against GlobalProtect VPN services. It automates the process of collecting authentication failure logs, intelligently managing whitelists to avoid blocking legitimate users, and updating firewall block lists through EDL integration.

## Key Features

- Direct API integration with PAN-OS firewalls for real-time log access
- Incremental log processing using timestamps to avoid duplicate data
- Automatic whitelisting of current GlobalProtect users to prevent service disruption
- Support for CIDR notation and individual IP addresses in whitelist management
- Integration with KineticLull EDL service for automated block list updates
- Comprehensive audit logging for security compliance and troubleshooting
- Built-in retry mechanisms for reliable operation in production environments
- Designed for unattended operation via cron scheduling

## Requirements

### Software Dependencies
```bash
pip install -r requirements.txt
```

### Infrastructure Requirements
- PAN-OS firewall with API access enabled
- User account with API permissions for log queries and operational commands
- GlobalProtect gateway properly configured and operational
- Network connectivity between the script host and firewall management interface

### Optional Components
- KineticLull EDL service account for automated block list management
- Configured EDL URLs in your firewall policy

## Installation and Setup

1. Download the script files to your preferred directory
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
Capture the name of your GlobalProtect Gateway and update it.  Configure automatic whitelisting of current VPN users:
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

### Command Line Options
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

### Available Arguments
- `-f, --frwl IP`: Target firewall IP address
- `-e, --edl`: Enable EDL updates after processing logs
- `-l, --log`: Enable file logging suitable for cron execution

### Automated Execution
The tool is designed for unattended operation. Example cron configurations:

```bash
# Execute every 6 hours with full logging
0 */6 * * * /usr/bin/python3 /path/to/main.py -f 192.168.1.1 --log --edl

# Hourly execution for high-security environments
0 * * * * /usr/bin/python3 /path/to/main.py -f 192.168.1.1 --log --edl
```

## Operation Workflow

The script follows a specific sequence designed to maximize security while minimizing false positives:

1. **Authentication Phase**: Establishes connection to the firewall using stored API keys or interactive credentials
2. **Configuration Validation**: Verifies that required settings (particularly GlobalProtect gateway name) are properly configured
3. **Current User Discovery**: Queries the firewall for currently connected GlobalProtect users and adds their public IP addresses to the whitelist
4. **Block List Cleanup**: Reviews existing block list entries and removes any IP addresses that are now whitelisted
5. **Log Query Execution**: Retrieves authentication failure logs since the last execution using incremental timestamp queries
6. **Data Processing**: Filters out whitelisted IP addresses, counts failures per IP, and merges with existing data
7. **EDL Update**: Optionally sends the processed block list to the KineticLull EDL service for firewall policy updates

## Generated Files and Logs

### Primary Output Files
- `blocked_ips.txt`: Main IP block list with failure counts and timestamps
- `config.json`: Configuration file containing firewall settings and API keys

### Audit and Debug Logs
- `whitelist_failures.log`: Authentication failures from whitelisted IP addresses
- `whitelist_updates.log`: Complete audit trail of whitelist additions and removals
- `gp_downloader.log`: Main application log (created when using --log option)

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

## Security Considerations

### Whitelist Management
The tool implements several layers of protection to prevent blocking legitimate traffic:
- Support for both CIDR blocks (10.0.0.0/8) and individual IP addresses
- Automatic discovery and whitelisting of current GlobalProtect users
- Comprehensive audit logging of all whitelist changes
- Separate logging of authentication failures from whitelisted sources for security monitoring

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

## Troubleshooting

### Configuration Issues
**Gateway Name Error**: If you see "gateway_name not configured", edit config.json and replace "CHANGE_ME" with your actual GlobalProtect gateway name.

**API Authentication Failures**: Verify that API access is enabled on your firewall and that the user account has appropriate permissions. Check network connectivity to the firewall management interface.

### Operational Issues
**No Authentication Failures Found**: This may indicate that no actual attacks are occurring, or that the log query parameters need adjustment for your specific PAN-OS version.

**EDL Update Failures**: Verify your KineticLull API key and EDL URL configuration. Ensure that trailing slashes are removed from EDL URLs as the service does not accept them.

### Performance Considerations
**Large Log Volumes**: The tool limits queries to 5000 log entries by default. For environments with high attack volumes, consider running the tool more frequently rather than increasing the log limit.

**Network Impact**: API queries are designed to be lightweight, but frequent execution against busy firewalls should be monitored for performance impact.

## Best Practices

### Security Operations
- Regularly review whitelist changes in the audit logs
- Monitor authentication failures from whitelisted IP addresses for security incidents
- Implement proper access controls for the config.json file containing API keys
- Consider implementing API key rotation on a regular schedule

### System Administration
- Test the tool manually before implementing automated execution
- Monitor log files for errors and unusual patterns
- Implement proper backup procedures for configuration files
- Use network segmentation to run the tool from a secure management network

### Deployment Strategy
- Begin with EDL updates disabled to verify operation
- Implement in a test environment before production deployment
- Start with longer execution intervals and decrease as confidence builds
- Monitor firewall performance after implementing automated block list updates

## Version Information

### Current Version: 1.0
This initial release includes all core functionality:
- Complete PAN-OS API integration
- Automatic whitelist management
- KineticLull EDL service integration
- Comprehensive logging and audit capabilities
- Production-ready error handling and retry logic

## Support and Maintenance

For technical issues:
1. Review the troubleshooting section above
2. Examine log files for specific error messages
3. Verify configuration file syntax and content
4. Test network connectivity and firewall API access

The tool is designed to be self-maintaining with automatic cleanup of temporary files and robust error handling for network and API issues.