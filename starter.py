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

USERID = ""

# RIPE Atlas API Key - Required for creating measurements directly via RIPE Atlas API
# Get your API key from: https://atlas.ripe.net/keys/
RIPE_ATLAS_API_KEY = ""

class MeasurementType(str, Enum):
    TRACEROUTE = "traceroute"
    PING = "ping"
    DNS = "dns"
    """
    These are not supported yet.
    """
    # HTTP = "http"
    # SSL_CERT = "sslcert"


class AddressProbeMapping(BaseModel):
    address: str
    probes: List[int]


class DNSQueryType(str, Enum):
    """DNS query types supported by RIPE Atlas"""
    A = "A"
    AAAA = "AAAA"
    TXT = "TXT"
    MX = "MX"
    NS = "NS"
    SOA = "SOA"
    CNAME = "CNAME"
    PTR = "PTR"
    ANY = "ANY"


class DNSProtocol(str, Enum):
    """DNS protocol options"""
    UDP = "UDP"
    TCP = "TCP"


class DNSMeasurementDefinition(BaseModel):
    """
    DNS measurement definition for RIPE Atlas API.
    
    See: https://atlas.ripe.net/docs/apis/rest-api-manual/measurements/types/dns.html
    """
    target: str  # DNS resolver to query (e.g., "8.8.8.8", "1.1.1.1")
    query_argument: str  # Domain to query (e.g., "example.com")
    query_type: DNSQueryType = DNSQueryType.A
    query_class: str = "IN"
    af: int = 4  # Address family: 4 for IPv4, 6 for IPv6
    protocol: DNSProtocol = DNSProtocol.UDP
    use_probe_resolver: bool = False  # If True, uses probe's local resolver instead of target
    set_nsid_bit: bool = False  # Request Name Server ID
    set_rd_bit: bool = True  # Recursion Desired
    set_cd_bit: bool = False  # Checking Disabled (DNSSEC)
    set_do_bit: bool = False  # DNSSEC OK
    udp_payload_size: int = 512  # EDNS0 UDP payload size (set higher for ECS, e.g., 4096)
    include_qbuf: bool = False  # Include query buffer in results
    include_abuf: bool = True  # Include answer buffer in results
    prepend_probe_id: bool = False  # Prepend probe ID to query
    description: str = "DNS measurement"
    # ECS (EDNS Client Subnet) specific fields
    # Note: RIPE Atlas doesn't have native ECS support in the API,
    # but you can query ECS-aware resolvers and analyze responses
    
    
class DNSMeasurementRequest(BaseModel):
    """
    Full DNS measurement request for RIPE Atlas API.
    """
    definitions: List[DNSMeasurementDefinition]
    probes: List[dict]  # Probe specifications
    is_oneoff: bool = True  # One-time measurement vs recurring
    bill_to: str = None  # Optional: billing account


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
        userid="kedar",
    )

    # Convert to JSON dict for the API request
    response = requests.post(url, data=data.model_dump_json(), headers=headers)
    print('Status code:', response.status_code)
    print('Response body:', response.json())


def launch_dns_measurement_ecs(
    domain: str,
    probe_ids: List[int],
    resolver: str = "8.8.8.8",
    query_type: DNSQueryType = DNSQueryType.A,
    description: str = "ECS-enabled DNS measurement",
) -> dict:
    """
    Launch an ECS (EDNS Client Subnet) enabled DNS measurement via RIPE Atlas API.
    
    ECS allows DNS resolvers to return geographically appropriate responses based on
    the client's subnet. This is useful for studying CDN behavior, anycast routing,
    and DNS-based load balancing.
    
    Args:
        domain: Domain name to query (e.g., "www.google.com")
        probe_ids: List of RIPE Atlas probe IDs to use for the measurement
        resolver: DNS resolver to query (use ECS-aware resolvers like 8.8.8.8, 1.1.1.1)
        query_type: Type of DNS query (A, AAAA, TXT, etc.)
        description: Description for the measurement
        
    Returns:
        dict: API response containing measurement ID and status
        
    Note:
        - Requires a valid RIPE_ATLAS_API_KEY
        - ECS-aware public resolvers include:
          - Google DNS: 8.8.8.8, 8.8.4.4
          - Cloudflare: 1.1.1.1, 1.0.0.1
          - OpenDNS: 208.67.222.222
        - Set udp_payload_size >= 512 to enable EDNS0 (required for ECS)
    """
    if not RIPE_ATLAS_API_KEY:
        raise ValueError("RIPE_ATLAS_API_KEY is not set. Get your API key from https://atlas.ripe.net/keys/")
    
    # RIPE Atlas API endpoint for creating measurements
    url = "https://atlas.ripe.net/api/v2/measurements/"
    
    headers = {
        "Authorization": f"Key {RIPE_ATLAS_API_KEY}",
        "Content-Type": "application/json",
    }
    
    # Build the measurement definition
    # Using larger UDP payload size to ensure EDNS0 is enabled (required for ECS)
    measurement_definition = {
        "type": "dns",
        "target": resolver,
        "af": 4,  # IPv4
        "query_class": "IN",
        "query_type": query_type.value,
        "query_argument": domain,
        "use_probe_resolver": False,
        "set_rd_bit": True,  # Recursion Desired
        "set_do_bit": False,  # DNSSEC OK (optional)
        "set_cd_bit": False,  # Checking Disabled
        "set_nsid_bit": True,  # Request Name Server ID
        "protocol": "UDP",
        "udp_payload_size": 4096,  # Large payload to enable EDNS0
        "include_qbuf": True,  # Include query buffer for analysis
        "include_abuf": True,  # Include answer buffer for analysis
        "description": description,
    }
    
    # Build probe specification
    probe_spec = {
        "requested": len(probe_ids),
        "type": "probes",
        "value": ",".join(map(str, probe_ids)),
    }
    
    # Full measurement request
    measurement_request = {
        "definitions": [measurement_definition],
        "probes": [probe_spec],
        "is_oneoff": True,
    }
    
    print(f"Launching DNS measurement for domain: {domain}")
    print(f"Resolver: {resolver}")
    print(f"Query type: {query_type.value}")
    print(f"Number of probes: {len(probe_ids)}")
    
    response = requests.post(url, json=measurement_request, headers=headers)
    
    if response.status_code == 201:
        result = response.json()
        measurement_id = result.get("measurements", [None])[0]
        print(f"✓ Measurement created successfully!")
        print(f"  Measurement ID: {measurement_id}")
        print(f"  View results at: https://atlas.ripe.net/measurements/{measurement_id}/")
        return result
    else:
        print(f"✗ Failed to create measurement")
        print(f"  Status code: {response.status_code}")
        print(f"  Response: {response.text}")
        return {"error": response.text, "status_code": response.status_code}


def get_dns_measurement_results(measurement_id: int) -> dict:
    """
    Fetch results of a DNS measurement from RIPE Atlas.
    
    Args:
        measurement_id: The measurement ID returned from launch_dns_measurement_ecs
        
    Returns:
        dict: Measurement results including DNS responses
    """
    url = f"https://atlas.ripe.net/api/v2/measurements/{measurement_id}/results/"
    
    response = requests.get(url)
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to fetch results: {response.status_code}")
        return {"error": response.text, "status_code": response.status_code}


def example_dns_ecs_measurement():
    """
    Example: Launch an ECS-enabled DNS measurement.
    
    This example queries Google's public DNS (8.8.8.8) for www.google.com
    from probes in different geographic locations to observe ECS behavior.
    """
    # Load probes and filter for connected probes with IPv4
    probes = load_probes('ripe_probes.csv')
    connected = filter_connected_probes(probes)
    with_ipv4 = filter_has_ipv4(connected)
    
    # Get probes from different countries for geographic diversity
    # This helps observe how ECS affects DNS responses across regions
    us_probes = get_probe_ids(filter_by_country(with_ipv4, 'US'))[:5]
    de_probes = get_probe_ids(filter_by_country(with_ipv4, 'DE'))[:5]
    jp_probes = get_probe_ids(filter_by_country(with_ipv4, 'JP'))[:5]
    
    # Combine probes from different regions
    selected_probes = us_probes + de_probes + jp_probes
    
    if not selected_probes:
        print("No suitable probes found!")
        return
    
    print(f"Selected {len(selected_probes)} probes from US, DE, and JP")
    
    # Launch the DNS measurement
    # Google DNS (8.8.8.8) supports ECS and will return different IPs
    # based on the probe's location
    result = launch_dns_measurement_ecs(
        domain="www.google.com",
        probe_ids=selected_probes,
        resolver="8.8.8.8",  # ECS-aware resolver
        query_type=DNSQueryType.A,
        description=f"ECS DNS test - {USERID}",
    )
    
    return result


if __name__ == "__main__":
    # launch_measurements()
    example_dns_ecs_measurement()