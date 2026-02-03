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

USERID = "yhe7443"

# RIPE Atlas API Key - Required for creating measurements directly via RIPE Atlas API
# Get your API key from: https://atlas.ripe.net/keys/
RIPE_ATLAS_API_KEY = "06b9d943-5556-4ecf-8965-8bb5c66743a4"



R_EDGE = [
    "165.124.184.3",
    "129.105.247.167",
    "129.105.253.94",
    "129.105.247.210",
    "129.105.247.227",
    "192.5.143.41",
]

R_CORE = [
    "198.71.46.206",
    "163.253.2.56",
    "163.253.2.23",
    "163.253.1.88",
    "163.253.2.31",
    "163.253.1.252",
    "163.253.1.100",
    "163.253.1.5",
    "200.0.207.9",
    "200.0.204.30",
    "200.0.204.14",
    "200.0.204.152",
]

R_NEAR = [
    "146.83.242.102",
    "146.155.88.35",
]

R_ALL = R_EDGE + R_CORE + R_NEAR

NAIVE_PROBE_MEASUREMENTS = {
    "165.124.184.3": 152680496,
    "129.105.247.167": 152680497,
    "129.105.253.94": 152680500,
    "129.105.247.210": 152680503,
    "129.105.247.227": 152680505,
    "192.5.143.41": 152680510,
    "198.71.46.206": 152680514,
    "163.253.2.56": 152680517,
    "163.253.2.23": 152680519,
    "163.253.1.88": 152680522,
    "163.253.2.31": 152680524,
    "163.253.1.252": 152680527,
    "163.253.1.100": 152680530,
    "163.253.1.5": 152680534,
    "200.0.207.9": 152680537,
    "200.0.204.30": 152680540,
    "200.0.204.14": 152680543,
    "200.0.204.152": 152680547,
    "146.83.242.102": 152680548,
    "146.155.88.35": 152680551
}




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
    use_probe_resolver: bool = (
        False  # If True, uses probe's local resolver instead of target
    )
    set_nsid_bit: bool = False  # Request Name Server ID
    set_rd_bit: bool = True  # Recursion Desired
    set_cd_bit: bool = False  # Checking Disabled (DNSSEC)
    set_do_bit: bool = False  # DNSSEC OK
    udp_payload_size: int = (
        512  # EDNS0 UDP payload size (set higher for ECS, e.g., 4096)
    )
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
    @field_validator("addresses_and_probes")
    @classmethod
    def check_probe_limit(cls, v: List[AddressProbeMapping]):
        total_probes = sum(len(item.probes) for item in v)
        if total_probes > 150000:
            raise ValueError(f"Total probes ({total_probes}) exceed the 150,000 limit.")
        return v


MEASUREMENT_TYPE = MeasurementType.PING

# ============================================================================
# Helper functions for working with ripe_probes data
# ============================================================================


def load_probes(csv_path: str = "ripe_probes.csv") -> pd.DataFrame:
    """Load the ripe_probes CSV file into a pandas DataFrame."""
    return pd.read_csv(csv_path)


def filter_by_status(probes: pd.DataFrame, status_name: str) -> pd.DataFrame:
    """Filter probes by status name (e.g., 'Connected', 'Abandoned', 'Written Off')."""
    return probes[probes["status_name"] == status_name]


def filter_connected_probes(probes: pd.DataFrame) -> pd.DataFrame:
    """Filter to only include currently connected probes."""
    return filter_by_status(probes, "Connected")


def filter_by_country(probes: pd.DataFrame, country_code: str) -> pd.DataFrame:
    """Filter probes by country code."""
    return probes[probes["country_code"] == country_code]


def filter_by_asn(
    probes: pd.DataFrame, asn: int, ip_version: str = "v4"
) -> pd.DataFrame:
    """Filter probes by ASN (Autonomous System Number)."""
    column = f"asn_{ip_version}"
    return probes[probes[column] == asn]


def filter_has_ipv4(probes: pd.DataFrame) -> pd.DataFrame:
    """Filter to only include probes that have an IPv4 address."""
    return probes[probes["address_v4"].notna() & (probes["address_v4"] != "")]


def filter_has_ipv6(probes: pd.DataFrame) -> pd.DataFrame:
    """Filter to only include probes that have an IPv6 address."""
    return probes[probes["address_v6"].notna() & (probes["address_v6"] != "")]


def filter_public_probes(probes: pd.DataFrame) -> pd.DataFrame:
    """Filter to only include public probes."""
    return probes[probes["is_public"] == "t"]


def filter_anchor_probes(probes: pd.DataFrame) -> pd.DataFrame:
    """Filter to only include anchor probes."""
    return probes[probes["is_anchor"] == "t"]


def get_probe_ids(probes: pd.DataFrame) -> List[int]:
    """Extract probe IDs as a list of integers."""
    return probes["id"].tolist()


def filter_by_geographic_bounds(
    probes: pd.DataFrame,
    min_lon: float = None,
    max_lon: float = None,
    min_lat: float = None,
    max_lat: float = None,
) -> pd.DataFrame:
    """Filter probes by geographic bounds (longitude and latitude)."""
    filtered = probes.copy()

    if min_lon is not None:
        filtered = filtered[filtered["lon"] >= min_lon]
    if max_lon is not None:
        filtered = filtered[filtered["lon"] <= max_lon]
    if min_lat is not None:
        filtered = filtered[filtered["lat"] >= min_lat]
    if max_lat is not None:
        filtered = filtered[filtered["lat"] <= max_lat]

    return filtered


def get_probes_by_prefix(
    probes: pd.DataFrame, prefix: str, ip_version: str = "v4"
) -> pd.DataFrame:
    """Filter probes by IP prefix (e.g., '89.31.40.0/21')."""
    column = f"prefix_{ip_version}"
    return probes[probes[column] == prefix]


def get_probe_addresses(probes: pd.DataFrame, ip_version: str = "v4") -> List[str]:
    """Extract probe addresses as a list, filtering out empty values."""
    column = f"address_{ip_version}"
    addresses = probes[column].dropna()
    addresses = addresses[addresses != ""]
    return addresses.tolist()


def get_probe_stats(probes: pd.DataFrame) -> dict:
    """Get basic statistics about the probes DataFrame."""
    stats = {
        "total_probes": len(probes),
        "connected": len(filter_by_status(probes, "Connected")),
        "abandoned": len(filter_by_status(probes, "Abandoned")),
        "written_off": len(filter_by_status(probes, "Written Off")),
        "never_connected": len(filter_by_status(probes, "Never Connected")),
        "with_ipv4": len(filter_has_ipv4(probes)),
        "with_ipv6": len(filter_has_ipv6(probes)),
        "public": len(filter_public_probes(probes)),
        "anchor": len(filter_anchor_probes(probes)),
        "unique_countries": probes["country_code"].nunique(),
        "unique_asn_v4": probes["asn_v4"].nunique(),
    }
    return stats


import dns.resolver
import dns.message
import dns.rdatatype
import dns.edns
import time
from collections import Counter

# ... (existing code) ...

def get_ground_truth_dns(target_subnet: str, domains: List[str]) -> dict:
    """
    Get ground truth DNS responses for a list of domains using ECS.
    
    Args:
        target_subnet: The subnet to use for ECS (e.g. '146.155.4.0/24')
        domains: List of domains to query
        
    Returns:
        Dict mapping domain to set of resolved IPs
    """
    results = {}
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8'] # Use Google Public DNS
    
    # Create ECS option
    ecs = dns.edns.ECSOption.from_text(target_subnet)
    
    for domain in domains:
        try:
            # We need to construct a message to direct the query with EDNS options
            query = dns.message.make_query(domain, dns.rdatatype.A)
            query.use_edns(edns=0, options=[ecs])
            
            response = dns.query.udp(query, '8.8.8.8', timeout=5.0)
            
            ips = set()
            for answer in response.answer:
                if answer.rdtype == dns.rdatatype.A:
                    for item in answer:
                        ips.add(str(item))
            
            results[domain] = ips
            print(f"Ground truth for {domain} (subnet {target_subnet}): {ips}")
            
        except Exception as e:
            print(f"Error querying {domain}: {e}")
            results[domain] = set()
            
    return results

def select_probes_georesolver(
    target_domain: str, 
    candidate_probes: pd.DataFrame,
    domains_to_test: List[str] = ["www.google.com", "www.facebook.com", "www.amazon.com", "www.youtube.com"]
) -> List[int]:
    """
    Select probes based on GeoResolver-style DNS redirection similarity.
    """
    # 1. Resolve target domain to get IP and subnet
    try:
        # We use the IP provided by the user if domain resolution fails/complexity
        # target_ip = socket.gethostbyname(target_domain) 
        # But for this specific task, user gave us:
        target_ip = "146.155.4.188"
        target_subnet = "146.155.4.0/24" # Assuming /24
        print(f"Target: {target_domain} -> {target_ip} -> {target_subnet}")
    except Exception as e:
        print(f"Could not resolve target: {e}")
        return []

    # 2. Get Ground Truth
    print("Fetching ground truth...")
    ground_truth = get_ground_truth_dns(target_subnet, domains_to_test)
    
    # 3. Launch DNS measurements from candidate probes
    probe_ids = get_probe_ids(candidate_probes)
    print(f"Testing {len(probe_ids)} candidate probes...")
    
    measurement_ids = []
    for domain in domains_to_test:
        # Launch one-off DNS measurement for each domain
        # We reuse the existing launch_dns_measurement_ecs but strictly for our purposes
        # We need to query 8.8.8.8 from the probes
        
        # Note: launch_dns_measurement_ecs prints results, we need the IDs to fetch results
        # We'll use a simplified inline logic or call the existing function and parse output if needed
        # But better to just implement the specific call here for clarity/batching
        
        # Actually, let's use the existing function if possible, but it returns a dict 
        # that includes measurement_id
        
        res = launch_dns_measurement_ecs(
            domain=domain,
            probe_ids=probe_ids,
            resolver="8.8.8.8",
            description=f"GeoResolver selection for {target_domain} - {domain}",
            query_type=DNSQueryType.A
        )
        
        m_id = res.get("measurements", [None])[0]
        if m_id:
            measurement_ids.append((domain, m_id))
            
    # 4. Wait for results and compute scores
    if not measurement_ids:
        print("No measurements launched successfully.")
        return []
        
    print("Waiting for measurement results (30s)...")
    time.sleep(30) # Simple wait, ideally poll
    
    probe_scores = Counter()
    
    for domain, m_id in measurement_ids:
        print(f"Fetching results for {domain} (ID: {m_id})...")
        results = get_measurement_results(m_id)
        
        # Analyze results
        for res in results:
            prb_id = res.get('prb_id')
            if not prb_id: continue
            
            # Extract IPs from result
            # RIPE Atlas result structure for DNS is complex, need to parse 'resultset' -> 'result' -> 'abuf' or 'answers'
            # Usually 'result' -> 'answers' contains the parsed RRs if available
            probe_ips = set()
            
            # The structure depends on whether parsing is enabled. Usually 'result' is a list/object.
            # Simplified parsing:
            if 'result' in res and 'answers' in res['result']:
                 for answer in res['result']['answers']:
                     if answer.get('type') == 'A':
                         probe_ips.add(answer.get('rdata'))
            
            # Calculate overlapping IPs
            overlap = len(probe_ips.intersection(ground_truth.get(domain, set())))
            probe_scores[prb_id] += overlap

    # 5. Select top probes
    # Let's say we want top 10
    most_common = probe_scores.most_common(10)
    selected_ids = [pid for pid, score in most_common]
    
    print(f"Selected probes based on GeoResolver: {selected_ids}")
    return selected_ids


def get_addresses_and_probes() -> List[AddressProbeMapping]:
    """Fill in this function with the addresses and probes you want to test. Get them via the RIPE API."""

    # Load the probes data
    probes = load_probes("ripe_probes.csv")

    # Filter for connected probes
    connected = filter_connected_probes(probes)

    # For GeoResolver, we want a pool of candidates. 
    # Let's say we want to test candidates from South America -> "SA" continent, or keep using "Chile" example
    # The prompt implies we want 'candidate probes' which usually means a broad set.
    # Let's filter for South America if possible, or just Chile for safety since we know it works.
    # RIPE data might not have 'continent', let's stick to Chile + Neighbors (manual list if needed)
    # or just all connected probes if dry_run?
    # Let's stick to 'chile_probes' to be consistent with previous logic, but maybe expand it slightly?
    # Actually, let's grab all Connected probes in 'CL' (Chile) as candidates.
    
    chile_probes = filter_by_country(connected, "CL")

    # Use GeoResolver selection
    target_domain = "ialab.ing.uc.cl"
    
    # We only run selection if we are NOT in a dry-run check that avoids API calls?
    # But get_addresses_and_probes is called inside launch_measurements.
    # This selection makes real API calls. This fits the "warmup" exploration.
    
    # WARNING: This will make API calls every time `main.py` is run!
    # Ideally we cache this, but for now we run it.
    
    print("Running GeoResolver selection...")
    # Limiting to first 50 candidates to save credits/time for this demo
    candidates = chile_probes.head(50) 
    
    selected_probe_ids = select_probes_georesolver(target_domain, candidates)
    
    # Fallback if selection fails (empty list)
    if not selected_probe_ids:
        print("GeoResolver selection failed or returned no probes. Falling back to simple list.")
        selected_probe_ids = get_probe_ids(chile_probes)[:10]

    return [AddressProbeMapping(address=address, probes=selected_probe_ids) for address in R_ALL]


def launch_measurements(dry_run: bool = True):
    """Launch measurements directly via RIPE Atlas API."""
    if not RIPE_ATLAS_API_KEY:
        print("Error: RIPE_ATLAS_API_KEY must be set.")
        return

    url = "https://atlas.ripe.net/api/v2/measurements/"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Key {RIPE_ATLAS_API_KEY}"
    }
    
    addresses_and_probes = get_addresses_and_probes()
    
    print(f"Preparing to schedule measurements for {len(addresses_and_probes)} targets...")
    
    # We can group measurements by probe set to minimize API calls, logic-dependent.
    # For simplicity/safety, we will launch one measurement request per target-probe_set pair for now.
    
    for mapping in addresses_and_probes:
        # Construct the definition
        description = f"testing-{MEASUREMENT_TYPE.value}-{USERID}-{mapping.address}"
        
        definition = {
            "target": mapping.address,
            "description": description,
            "type": MEASUREMENT_TYPE.value,
            "af": 4, # IPv4
            "is_oneoff": True
        }
        
        # Add type-specific fields
        if MEASUREMENT_TYPE == MeasurementType.TRACEROUTE:
            definition["protocol"] = "ICMP" 
            definition["paris"] = 16
        elif MEASUREMENT_TYPE == MeasurementType.PING:
            definition["packets"] = 3
        
        # Construct probe specification
        probe_spec = {
            "requested": len(mapping.probes),
            "type": "probes",
            "value": ",".join(map(str, mapping.probes))
        }
        
        # specific to RIPE API: definitions is a list, probes is a list
        payload = {
            "definitions": [definition],
            "probes": [probe_spec],
            "is_oneoff": True
        }
        
        if dry_run:
            print(f"\n[DRY RUN] Would send payload for {mapping.address}:")
            print(json.dumps(payload, indent=2))
        else:
            print(f"Sending request for {mapping.address}...")
            try:
                response = requests.post(url, headers=headers, json=payload)
                if response.status_code == 201:
                    result = response.json()
                    measurements = result.get('measurements', [])
                    print(f"  Success! Measurement IDs: {measurements}")
                else:
                    print(f"  Error {response.status_code}: {response.text}")
            except Exception as e:
                print(f"  Exception occurred: {e}")
                
    if dry_run:
        print("\nDry run complete. Set dry_run=False to execute.")


def launch_dns_measurement_ecs(
    domain: str,
    probe_ids: List[int],
    resolver: str = "8.8.8.8",
    query_type: DNSQueryType = DNSQueryType.A,
    description: str = "ECS-enabled DNS measurement",
) -> dict:
    """Launch an ECS (EDNS Client Subnet) enabled DNS measurement via RIPE Atlas API."""
    if not RIPE_ATLAS_API_KEY:
        raise ValueError(
            "RIPE_ATLAS_API_KEY is not set. Get your API key from https://atlas.ripe.net/keys/"
        )

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
        print(
            f"  View results at: https://atlas.ripe.net/measurements/{measurement_id}/"
        )
        return result
    else:
        print(f"✗ Failed to create measurement")
        print(f"  Status code: {response.status_code}")
        print(f"  Response: {response.text}")
        return {"error": response.text, "status_code": response.status_code}


def get_measurement_results(measurement_id: int) -> dict:
    """Fetch results of a DNS measurement from RIPE Atlas."""
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
    probes = load_probes("ripe_probes.csv")
    connected = filter_connected_probes(probes)
    with_ipv4 = filter_has_ipv4(connected)

    # Get probes from different countries for geographic diversity
    # This helps observe how ECS affects DNS responses across regions
    us_probes = get_probe_ids(filter_by_country(with_ipv4, "US"))[:5]
    de_probes = get_probe_ids(filter_by_country(with_ipv4, "DE"))[:5]
    jp_probes = get_probe_ids(filter_by_country(with_ipv4, "JP"))[:5]

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
    # launch_measurements(dry_run=False)
    # example_dns_ecs_measurement()
