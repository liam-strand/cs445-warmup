import requests
import json
from enum import Enum
from typing import List
from pydantic import BaseModel, field_validator
import pandas as pd
from probe_selector import ProbeSelector
import dns.resolver
import dns.message
import dns.rdatatype
import dns.edns
import time
from collections import Counter

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
    "146.155.88.35": 152680551,
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
    protocol: DNSProtocol = DNSProtocol.TCP
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


# ============================================================================
# Helper functions for working with ripe_probes data
# ============================================================================


# Removed helper functions in favor of ProbeSelector class in probe_selector.py


def get_probes_simple(country_code: str = "CL", limit: int = 50) -> List[int]:
    """
    Get a list of probe IDs using simple filtering criteria.

    Args:
        country_code: Country code to filter by (default "CL")
        limit: Max number of probes to return

    Returns:
        List of probe IDs
    """
    return ()


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
    resolver.nameservers = ["8.8.8.8"]  # Use Google Public DNS

    # Create ECS option
    ecs = dns.edns.ECSOption.from_text(target_subnet)

    for domain in domains:
        try:
            # We need to construct a message to direct the query with EDNS options
            query = dns.message.make_query(domain, dns.rdatatype.A)
            query.use_edns(edns=0, options=[ecs])

            response = dns.query.udp(query, "8.8.8.8", timeout=5.0)

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
    domains_to_test: List[str] = [
        "www.google.com",
        "www.facebook.com",
        "www.amazon.com",
        "www.youtube.com",
    ],
) -> List[int]:
    """
    Select probes based on GeoResolver-style DNS redirection similarity.
    """
    # 1. Resolve target domain to get IP and subnet
    target_ip = "146.155.4.188"
    target_subnet = "146.155.4.0/24"  # Assuming /24
    print(f"Target: {target_domain} -> {target_ip} -> {target_subnet}")

    # 2. Get Ground Truth
    print("Fetching ground truth...")
    ground_truth = get_ground_truth_dns(target_subnet, domains_to_test)

    # 3. Launch DNS measurements from candidate probes
    probe_ids = ProbeSelector(candidate_probes).get_ids()
    print(f"Testing {len(probe_ids)} candidate probes...")

    measurement_ids = []
    for domain in domains_to_test:
        res = launch_dns_measurement_ecs(
            domain=domain,
            probe_ids=probe_ids,
            resolver="8.8.8.8",
            description=f"GeoResolver selection for {target_domain} - {domain}",
            query_type=DNSQueryType.A,
        )

        m_id = res.get("measurements", [None])[0]
        if m_id:
            measurement_ids.append((domain, m_id))

    # 4. Wait for results and compute scores
    if not measurement_ids:
        print("No measurements launched successfully.")
        return []

    print("Waiting for measurement results (30s)...")
    time.sleep(30)  # Simple wait, ideally poll

    probe_scores = Counter()

    for domain, m_id in measurement_ids:
        print(f"Fetching results for {domain} (ID: {m_id})...")
        results = get_measurement_results(m_id)

        # Analyze results
        for res in results:
            prb_id = res.get("prb_id")
            if not prb_id:
                continue

            # Extract IPs from result
            # RIPE Atlas result structure for DNS is complex, need to parse 'resultset' -> 'result' -> 'abuf' or 'answers'
            # Usually 'result' -> 'answers' contains the parsed RRs if available
            probe_ips = set()

            # The structure depends on whether parsing is enabled. Usually 'result' is a list/object.
            # Simplified parsing:
            if "result" in res and "answers" in res["result"]:
                for answer in res["result"]["answers"]:
                    if answer.get("type") == "A":
                        probe_ips.add(answer.get("rdata"))

            # Calculate overlapping IPs
            overlap = len(probe_ips.intersection(ground_truth.get(domain, set())))
            probe_scores[prb_id] += overlap

    # 5. Select top probes
    most_common = probe_scores.most_common(50)
    selected_ids = [pid for pid, score in most_common]

    print(f"Selected probes based on GeoResolver: {selected_ids}")
    return selected_ids


# Removed get_addresses_and_probes in favor of modular approach,
# but keeping R_ALL available for targets.


def launch_measurements(
    probes: List[int],
    targets: List[str],
    type: MeasurementType = MeasurementType.PING,
    dry_run: bool = True,
) -> List[int]:
    """
    Launch measurements directly via RIPE Atlas API.

    Args:
        probes: List of probe IDs
        targets: List of target IP addresses or hostnames
        type: Measurement type (PING or TRACEROUTE)
        dry_run: If True, only print the payloads without sending requests.

    Returns:
        List of created measurement IDs
    """
    if not RIPE_ATLAS_API_KEY:
        print("Error: RIPE_ATLAS_API_KEY must be set.")
        return []

    url = "https://atlas.ripe.net/api/v2/measurements/"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Key {RIPE_ATLAS_API_KEY}",
    }

    print(
        f"Preparing to schedule {type.value} measurements for {len(targets)} targets using {len(probes)} probes..."
    )

    created_ids = []

    for target in targets:
        # Construct the definition
        description = f"testing-{type.value}-{USERID}-{target}"

        definition = {
            "target": target,
            "description": description,
            "type": type.value,
            "af": 4,  # IPv4
            "is_oneoff": True,
        }

        # Add type-specific fields
        if type == MeasurementType.TRACEROUTE:
            definition["protocol"] = "ICMP"
            definition["paris"] = 16
        elif type == MeasurementType.PING:
            definition["packets"] = 3

        # Construct probe specification
        probe_spec = {
            "requested": len(probes),
            "type": "probes",
            "value": ",".join(map(str, probes)),
        }

        # specific to RIPE API: definitions is a list, probes is a list
        payload = {
            "definitions": [definition],
            "probes": [probe_spec],
            "is_oneoff": True,
        }

        if dry_run:
            print(f"\n[DRY RUN] Would send payload for {target}:")
            print(json.dumps(payload, indent=2))
        else:
            print(f"Sending request for {target}...")
            try:
                response = requests.post(url, headers=headers, json=payload)
                if response.status_code == 201:
                    result = response.json()
                    measurements = result.get('measurements', [])
                    print(f"  Success! Measurement IDs: {measurements}")
                    for mid in measurements:
                        created_ids.append({"target": target, "measurement_id": mid})
                else:
                    print(f"  Error {response.status_code}: {response.text}")
            except Exception as e:
                print(f"  Exception occurred: {e}")
                
    if dry_run:
        print("\nDry run complete. Set dry_run=False to execute.")
        
    return created_ids


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


if __name__ == "__main__":
    import datetime

    # 1. Select Targets
    targets = R_ALL

    # Initialize formatted results container
    formatted_results = {
        "simple_filter": [],
        "georesolver": []
    }

    # 2. Strategy A: Simple Filtering
    print("\n--- Strategy A: Simple Filtering ---")
    probes_strategy_a = (
        ProbeSelector.from_csv("ripe_probes.csv")
        .connected()
        .has_ipv4()
        .from_countries(["CL", "AR"])
        .limit(50)
        .get_ids()
    )
    print(f"Strategy A selected {len(probes_strategy_a)} probes.")
    
    if probes_strategy_a:
        results_a = launch_measurements(
            probes=probes_strategy_a,
            targets=targets,
            type=MeasurementType.PING,
            dry_run=False, # Switch to False for actual execution
        )
        for res in results_a:
            res["strategy"] = "simple_filter"
            res["timestamp"] = datetime.datetime.now().isoformat()
        formatted_results["simple_filter"] = results_a

    # 3. Strategy B: GeoResolver
    print("\n--- Strategy B: GeoResolver ---")
    candidates = (
        ProbeSelector.from_csv("ripe_probes.csv")
        .connected()
        .has_ipv4()
        .from_countries(["CL", "AR", "PE", "BO"])
        .to_dataframe()
    )
    # Note: This performs real DNS queries even in dry run
    probes_strategy_b = select_probes_georesolver("ialab.ing.uc.cl", candidates)
    print(f"Strategy B selected {len(probes_strategy_b)} probes.")
    
    if probes_strategy_b:
        results_b = launch_measurements(
            probes=probes_strategy_b,
            targets=targets,
            type=MeasurementType.PING,
            dry_run=False, # Switch to False for actual execution
        )
        for res in results_b:
            res["strategy"] = "georesolver"
            res["timestamp"] = datetime.datetime.now().isoformat()
        formatted_results["georesolver"] = results_b

    # 4. Save Results
    # Check if we have any results in any category
    total_results = sum(len(v) for v in formatted_results.values())
    
    if total_results > 0:
        filename = "measurement_log.json"
        try:
            with open(filename, "w") as f:
                json.dump(formatted_results, f, indent=2)
            print(f"\nSaved {total_results} measurement records to {filename}")
        except Exception as e:
            print(f"Error saving log: {e}")
    else:
        print("\nNo measurements launched (dry run active or no probes selected).")
