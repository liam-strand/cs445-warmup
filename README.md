# RIPE Atlas Measurement Scheduler

This project provides a Python framework for scheduling network measurements using RIPE Atlas probes. It includes helper functions for filtering and selecting probes from the RIPE Atlas probe database, and a measurement scheduling system that enforces safety limits.

## Overview
- Load and filter RIPE Atlas probes from a CSV database
- Select probes based on various criteria (country, ASN, status, geographic location, etc.)
- Schedule network measurements (traceroute, ping) through the RIPE Atlas API

## Requirements

### Dependencies

Install the required Python packages:

```bash
pip install requests pandas pydantic
```

### Python Version

Python 3.8 or higher is required.

## Project Structure

```
.
├── starter.py          # Main script with helper functions and measurement scheduling
├── ripe_probes.csv     # RIPE Atlas probe database (CSV format)
└── README.md           # This file
```

## Data Format

The `ripe_probes.csv` file contains the following columns:

- `id`: Unique probe ID
- `address_v4`: IPv4 address of the probe
- `address_v6`: IPv6 address of the probe
- `asn_v4`: Autonomous System Number for IPv4
- `asn_v6`: Autonomous System Number for IPv6
- `country_code`: Two-letter country code (e.g., 'US', 'CZ', 'DE')
- `description`: Probe description
- `first_connected`: Timestamp of first connection
- `lon`: Longitude
- `lat`: Latitude
- `is_anchor`: Whether the probe is an anchor probe ('t' or 'f')
- `is_public`: Whether the probe is public ('t' or 'f')
- `last_connected`: Timestamp of last connection
- `prefix_v4`: IPv4 prefix
- `prefix_v6`: IPv6 prefix
- `status`: Status code (0-4)
- `status_name`: Status name ('Connected', 'Abandoned', 'Written Off', 'Never Connected')
- `status_since`: Timestamp when status changed
- `total_uptime`: Total uptime in seconds
- `last_updated`: Last update timestamp

## Helper Functions

The project includes a comprehensive set of helper functions for working with probe data:

### Data Loading

- **`load_probes(csv_path='ripe_probes.csv')`**: Load the probe CSV file into a pandas DataFrame

### Filtering Functions

- **`filter_by_status(probes, status_name)`**: Filter by status name ('Connected', 'Abandoned', 'Written Off', 'Never Connected')
- **`filter_connected_probes(probes)`**: Get only currently connected probes
- **`filter_by_country(probes, country_code)`**: Filter by two-letter country code
- **`filter_by_asn(probes, asn, ip_version='v4')`**: Filter by Autonomous System Number
- **`filter_has_ipv4(probes)`**: Get probes with IPv4 addresses
- **`filter_has_ipv6(probes)`**: Get probes with IPv6 addresses
- **`filter_public_probes(probes)`**: Get only public probes
- **`filter_anchor_probes(probes)`**: Get only anchor probes
- **`filter_by_geographic_bounds(probes, min_lon, max_lon, min_lat, max_lat)`**: Filter by geographic coordinates
- **`get_probes_by_prefix(probes, prefix, ip_version='v4')`**: Filter by IP prefix

### Data Extraction

- **`get_probe_ids(probes)`**: Extract probe IDs as a list of integers
- **`get_probe_addresses(probes, ip_version='v4')`**: Extract addresses as a list (filters out empty values)

### Statistics

- **`get_probe_stats(probes)`**: Get comprehensive statistics about the probe dataset

## Usage

### Basic Workflow

1. **Configure your settings** in `starter.py`:
   ```python
   USERID = "your_username"
   MEASUREMENT_TYPE = MeasurementType.TRACEROUTE  # or MeasurementType.PING
   ```

2. **Implement `get_addresses_and_probes()`**:
   - Use the helper functions to filter and select probes
   - Return a list of `AddressProbeMapping` objects
   - Each mapping contains an IP address and a list of probe IDs to test from

3. **Run the script**:
   ```bash
   python starter.py
   ```

### Example: Selecting Probes

```python
def get_addresses_and_probes() -> List[AddressProbeMapping]:
    # Load the probes
    probes = load_probes('ripe_probes.csv')
    
    # Get connected probes in the US with IPv4 addresses
    us_connected = filter_has_ipv4(
        filter_connected_probes(
            filter_by_country(probes, 'US')
        )
    )
    
    # Get probe IDs
    probe_ids = get_probe_ids(us_connected)
    
    # Return mapping
    return [
        AddressProbeMapping(
            address="8.8.8.8",
            probes=probe_ids[:1000]  # Limit to 1000 probes
        )
    ]
```

### Example: Multiple Target Addresses

```python
def get_addresses_and_probes() -> List[AddressProbeMapping]:
    probes = load_probes('ripe_probes.csv')
    
    # Get connected probes
    connected = filter_connected_probes(probes)
    probe_ids = get_probe_ids(connected)
    
    # Split probes across multiple addresses
    return [
        AddressProbeMapping(
            address="8.8.8.8",
            probes=probe_ids[:5000]
        ),
        AddressProbeMapping(
            address="1.1.1.1",
            probes=probe_ids[5000:10000]
        )
    ]
```

### Chaining Filters

Helper functions can be chained together for complex filtering:

```python
# Get public, connected probes in Europe with IPv4
europe_probes = filter_has_ipv4(
    filter_public_probes(
        filter_connected_probes(
            filter_by_geographic_bounds(
                probes,
                min_lon=-10, max_lon=40,
                min_lat=35, max_lat=70
            )
        )
    )
)
```

## Measurement Types

Currently supported:
- **`MeasurementType.TRACEROUTE`**: Traceroute measurements
- **`MeasurementType.PING`**: Ping measurements

Future support (not yet implemented):
- HTTP measurements
- DNS measurements
- SSL certificate measurements

## API Endpoint

The script sends measurement requests to:
```
http://caitlyn.cs.northwestern.edu/ripeline/schedule
```

## Error Handling

The `MeasurementRequest` class automatically validates that the total number of probes across all addresses does not exceed 150,000. If the limit is exceeded, a `ValueError` will be raised with a descriptive message.

## Examples in Code

The `get_addresses_and_probes()` function includes comprehensive examples demonstrating:
- Loading and filtering probes
- Getting statistics
- Filtering by various criteria
- Extracting probe IDs and addresses
- Geographic filtering

Run the script to see these examples in action (they will be printed before the input prompt).

## Notes

- The probe database (`ripe_probes.csv`) contains over 56,000 probes
- Not all probes are active - use `filter_connected_probes()` to get only active probes
- Some probes may not have IPv4 or IPv6 addresses - use `filter_has_ipv4()` or `filter_has_ipv6()` accordingly
- The `input()` statement in `get_addresses_and_probes()` should be removed once you implement your logic

## Troubleshooting

**Issue**: "Total probes exceed the 150,000 limit"
- **Solution**: Reduce the number of probes or IP addresses in your `AddressProbeMapping` objects

**Issue**: No probes found after filtering
- **Solution**: Check your filter criteria. Try using `get_probe_stats()` to see what's available in the dataset

**Issue**: API request fails
- **Solution**: Check your network connection and verify the API endpoint is accessible

## License

This project is for educational purposes as part of CS445 coursework.
