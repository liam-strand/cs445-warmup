import requests
import json
from enum import Enum
from typing import List
from pydantic import BaseModel, field_validator
import pandas as pd
"""
PLEASE READ THE FOLLOWING BEFORE YOU RUN THE SCRIPT:
n_probes*n_ips<150K (number of probes*number of ips shouldn't cross this number)
"""


class MeasurementType(str, Enum):
    TRACEROUTE = "traceroute"
    PING = "ping"
    """
    These are not supported yet.
    """
    # HTTP = "http"
    # DNS = "dns"
    # SSL_CERT = "sslcert"


class AddressProbeMapping(BaseModel):
    address: str
    probes: List[int]


class MeasurementRequest(BaseModel):
    type: MeasurementType 
    addresses_and_probes: List[AddressProbeMapping]
    description: str
    userid: str

    # Pydantic v2 Validator for the 150K safety limit
    @field_validator('addresses_and_probes')
    @classmethod
    def check_probe_limit(cls, v: List[AddressProbeMapping]):
        total_probes = sum(len(item.probes) for item in v)
        if total_probes > 150000:
            raise ValueError(f"Total probes ({total_probes}) exceed the 150,000 limit.")
        return v


USERID = ""

MEASUREMENT_TYPE = MeasurementType.TRACEROUTE

# ============================================================================
# Helper functions for working with ripe_probes data
# ============================================================================

def load_probes(csv_path: str = 'ripe_probes.csv') -> pd.DataFrame:
    """
    Load the ripe_probes CSV file into a pandas DataFrame.
    
    Args:
        csv_path: Path to the ripe_probes CSV file
        
    Returns:
        DataFrame containing all probe data
    """
    return pd.read_csv(csv_path)


def filter_by_status(probes: pd.DataFrame, status_name: str) -> pd.DataFrame:
    """
    Filter probes by status name (e.g., 'Connected', 'Abandoned', 'Written Off').
    
    Args:
        probes: DataFrame of probes
        status_name: Status name to filter by
        
    Returns:
        Filtered DataFrame
    """
    return probes[probes['status_name'] == status_name]


def filter_connected_probes(probes: pd.DataFrame) -> pd.DataFrame:
    """
    Filter to only include currently connected probes.
    
    Args:
        probes: DataFrame of probes
        
    Returns:
        Filtered DataFrame with only connected probes
    """
    return filter_by_status(probes, 'Connected')


def filter_by_country(probes: pd.DataFrame, country_code: str) -> pd.DataFrame:
    """
    Filter probes by country code.
    
    Args:
        probes: DataFrame of probes
        country_code: Two-letter country code (e.g., 'US', 'CZ', 'DE')
        
    Returns:
        Filtered DataFrame
    """
    return probes[probes['country_code'] == country_code]


def filter_by_asn(probes: pd.DataFrame, asn: int, ip_version: str = 'v4') -> pd.DataFrame:
    """
    Filter probes by ASN (Autonomous System Number).
    
    Args:
        probes: DataFrame of probes
        asn: ASN to filter by
        ip_version: 'v4' or 'v6' to specify which ASN column to use
        
    Returns:
        Filtered DataFrame
    """
    column = f'asn_{ip_version}'
    return probes[probes[column] == asn]


def filter_has_ipv4(probes: pd.DataFrame) -> pd.DataFrame:
    """
    Filter to only include probes that have an IPv4 address.
    
    Args:
        probes: DataFrame of probes
        
    Returns:
        Filtered DataFrame with only probes that have IPv4 addresses
    """
    return probes[probes['address_v4'].notna() & (probes['address_v4'] != '')]


def filter_has_ipv6(probes: pd.DataFrame) -> pd.DataFrame:
    """
    Filter to only include probes that have an IPv6 address.
    
    Args:
        probes: DataFrame of probes
        
    Returns:
        Filtered DataFrame with only probes that have IPv6 addresses
    """
    return probes[probes['address_v6'].notna() & (probes['address_v6'] != '')]


def filter_public_probes(probes: pd.DataFrame) -> pd.DataFrame:
    """
    Filter to only include public probes.
    
    Args:
        probes: DataFrame of probes
        
    Returns:
        Filtered DataFrame with only public probes
    """
    return probes[probes['is_public'] == 't']


def filter_anchor_probes(probes: pd.DataFrame) -> pd.DataFrame:
    """
    Filter to only include anchor probes.
    
    Args:
        probes: DataFrame of probes
        
    Returns:
        Filtered DataFrame with only anchor probes
    """
    return probes[probes['is_anchor'] == 't']


def get_probe_ids(probes: pd.DataFrame) -> List[int]:
    """
    Extract probe IDs as a list of integers.
    
    Args:
        probes: DataFrame of probes
        
    Returns:
        List of probe IDs
    """
    return probes['id'].tolist()


def filter_by_geographic_bounds(probes: pd.DataFrame, 
                                min_lon: float = None, max_lon: float = None,
                                min_lat: float = None, max_lat: float = None) -> pd.DataFrame:
    """
    Filter probes by geographic bounds (longitude and latitude).
    
    Args:
        probes: DataFrame of probes
        min_lon: Minimum longitude
        max_lon: Maximum longitude
        min_lat: Minimum latitude
        max_lat: Maximum latitude
        
    Returns:
        Filtered DataFrame
    """
    filtered = probes.copy()
    
    if min_lon is not None:
        filtered = filtered[filtered['lon'] >= min_lon]
    if max_lon is not None:
        filtered = filtered[filtered['lon'] <= max_lon]
    if min_lat is not None:
        filtered = filtered[filtered['lat'] >= min_lat]
    if max_lat is not None:
        filtered = filtered[filtered['lat'] <= max_lat]
    
    return filtered


def get_probes_by_prefix(probes: pd.DataFrame, prefix: str, ip_version: str = 'v4') -> pd.DataFrame:
    """
    Filter probes by IP prefix (e.g., '89.31.40.0/21').
    
    Args:
        probes: DataFrame of probes
        prefix: IP prefix to filter by
        ip_version: 'v4' or 'v6' to specify which prefix column to use
        
    Returns:
        Filtered DataFrame
    """
    column = f'prefix_{ip_version}'
    return probes[probes[column] == prefix]


def get_probe_addresses(probes: pd.DataFrame, ip_version: str = 'v4') -> List[str]:
    """
    Extract probe addresses as a list, filtering out empty values.
    
    Args:
        probes: DataFrame of probes
        ip_version: 'v4' or 'v6' to specify which address column to use
        
    Returns:
        List of probe addresses (non-empty)
    """
    column = f'address_{ip_version}'
    addresses = probes[column].dropna()
    addresses = addresses[addresses != '']
    return addresses.tolist()


def get_probe_stats(probes: pd.DataFrame) -> dict:
    """
    Get basic statistics about the probes DataFrame.
    
    Args:
        probes: DataFrame of probes
        
    Returns:
        Dictionary with statistics
    """
    stats = {
        'total_probes': len(probes),
        'connected': len(filter_by_status(probes, 'Connected')),
        'abandoned': len(filter_by_status(probes, 'Abandoned')),
        'written_off': len(filter_by_status(probes, 'Written Off')),
        'never_connected': len(filter_by_status(probes, 'Never Connected')),
        'with_ipv4': len(filter_has_ipv4(probes)),
        'with_ipv6': len(filter_has_ipv6(probes)),
        'public': len(filter_public_probes(probes)),
        'anchor': len(filter_anchor_probes(probes)),
        'unique_countries': probes['country_code'].nunique(),
        'unique_asn_v4': probes['asn_v4'].nunique(),
    }
    return stats


def get_addresses_and_probes() -> List[AddressProbeMapping]:
    """
    You should fill in this function with the addresses and probes you want to test. Get them via the RIPE API.
    """

    # Load the probes data
    probes = load_probes('ripe_probes.csv')
    
    # Example 1: Print basic statistics
    print("=" * 60)
    print("PROBE STATISTICS")
    print("=" * 60)
    stats = get_probe_stats(probes)
    for key, value in stats.items():
        print(f"{key}: {value}")
    
    # Example 2: Get connected probes
    print("\n" + "=" * 60)
    print("CONNECTED PROBES (first 10)")
    print("=" * 60)
    connected = filter_connected_probes(probes)
    print(connected[['id', 'address_v4', 'country_code', 'status_name']].head(10))
    
    # Example 3: Filter by country
    print("\n" + "=" * 60)
    print("PROBES IN UNITED STATES (first 10)")
    print("=" * 60)
    us_probes = filter_by_country(probes, 'US')
    print(us_probes[['id', 'address_v4', 'status_name']].head(10))
    
    # Example 4: Get probes with IPv4 addresses
    print("\n" + "=" * 60)
    print("PROBES WITH IPv4 ADDRESSES (first 10)")
    print("=" * 60)
    ipv4_probes = filter_has_ipv4(probes)
    print(ipv4_probes[['id', 'address_v4', 'country_code', 'asn_v4']].head(10))
    
    # Example 5: Get public, connected probes
    print("\n" + "=" * 60)
    print("PUBLIC, CONNECTED PROBES (first 10)")
    print("=" * 60)
    public_connected = filter_public_probes(filter_connected_probes(probes))
    print(public_connected[['id', 'address_v4', 'country_code']].head(10))
    
    # Example 6: Get probe IDs from a filtered set
    print("\n" + "=" * 60)
    print("PROBE IDS FROM CONNECTED PROBES IN CZECH REPUBLIC (first 20)")
    print("=" * 60)
    cz_connected = filter_connected_probes(filter_by_country(probes, 'CZ'))
    cz_probe_ids = get_probe_ids(cz_connected)
    print(f"Total CZ connected probes: {len(cz_probe_ids)}")
    print(f"First 20 IDs: {cz_probe_ids[:20]}")
    
    # Example 7: Filter by ASN
    print("\n" + "=" * 60)
    print("PROBES IN ASN 44489 (first 10)")
    print("=" * 60)
    asn_probes = filter_by_asn(probes, 44489, 'v4')
    print(asn_probes[['id', 'address_v4', 'country_code', 'status_name']].head(10))
    
    # Example 8: Get IPv4 addresses from connected probes
    print("\n" + "=" * 60)
    print("IPv4 ADDRESSES FROM CONNECTED PROBES (first 20)")
    print("=" * 60)
    connected_ipv4 = filter_has_ipv4(filter_connected_probes(probes))
    addresses = get_probe_addresses(connected_ipv4, 'v4')
    print(f"Total addresses: {len(addresses)}")
    print(f"First 20 addresses: {addresses[:20]}")
    
    # Example 9: Geographic filtering (Europe region example)
    print("\n" + "=" * 60)
    print("PROBES IN EUROPE REGION (lon: -10 to 40, lat: 35 to 70) - first 10")
    print("=" * 60)
    europe_probes = filter_by_geographic_bounds(probes, min_lon=-10, max_lon=40, min_lat=35, max_lat=70)
    print(europe_probes[['id', 'address_v4', 'country_code', 'lon', 'lat']].head(10))
    
    print("\n" + "=" * 60)
    print("EXAMPLES COMPLETE")
    print("=" * 60)
    input("You have not filled in your address and probes logic yet. Press Enter to continue. Remove this input and fill in your logic.")
    return [
        AddressProbeMapping(
            address="193.124.76.129",
            probes=[
                1001595,
                60792,
                1458,
            ]
        )
    ]

def launch_measurements():
    url = 'http://caitlyn.cs.northwestern.edu/ripeline/schedule'
    headers = {'Content-Type': 'application/json'}
    addresses_and_probes = get_addresses_and_probes()

    # Create the measurement request using Pydantic model
    data = MeasurementRequest(
        type=MEASUREMENT_TYPE,
        addresses_and_probes=addresses_and_probes,
        description=f'testing-{MEASUREMENT_TYPE.value}-{USERID}',
        userid=USERID,
    )

    # Convert to JSON dict for the API request
    response = requests.post(url, data=data.model_dump_json(), headers=headers)
    print('Status code:', response.status_code)
    print('Response body:', response.json())


if __name__ == "__main__":
    launch_measurements()