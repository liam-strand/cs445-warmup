import json
import requests
import sys


def get_asn_ripenet(ip):
    """
    Fetch ASN information for a given IP using RIPEstat API.
    """
    url = f"https://stat.ripe.net/data/network-info/data.json?resource={ip}"
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        data = response.json()

        # Extract ASN and holder
        asns = data.get("data", {}).get("asns", [])
        holder = "Unknown"

        # RIPEstat often returns a list of ASNs, usually just one
        if asns:
            asn_list = [str(asn) for asn in asns]
            asn_str = ", ".join(asn_list)

            # The API structure can be slightly complex for holder, often it's not directly in this endpoint
            # as clearly as we might want, but let's try to see if 'owner' or similar exists if we dig deeper.
            # Actually, network-info returns 'asns' and 'prefix'.
            # To get specific holder info, 'as-overview' might be better used with the ASN,
            # but usually for a quick check 'whois' data or just the ASN is good.
            # RIPEstat 'network-info' is good for mapping IP->ASN.

            return {"asn": asn_str}
        else:
            return {"asn": "Unknown"}

    except Exception as e:
        return {"asn": "Error", "error": str(e)}


def print_flow_annotations(trace_data):
    """
    Iterate through flows and print IP, Hostname, and ASN for each hop.
    """
    flows = trace_data.get("flows", {})

    # Cache for ASN lookups to avoid redundant API calls
    asn_cache = {}

    flow_id, hops = list(flows.items())[0]
    print(f"\nFlow: {flow_id}")
    print("-" * 80)
    print(f"{'Hop':<5} | {'IP Address':<16} | {'ASN':<10} | {'Hostname'}")
    print("-" * 80)

    for i, hop in enumerate(hops):
        # Get IP
        received = hop.get("received")
        if not received:
            continue
        ip_info = received.get("ip", {})
        src_ip = ip_info.get("src", "Unknown")

        # Get Hostname
        hostname = hop.get("name", "")

        # Get ASN (cached)
        if src_ip not in asn_cache:
            if src_ip != "Unknown":
                asn_info = get_asn_ripenet(src_ip)
                asn_cache[src_ip] = asn_info.get("asn", "Unknown")
            else:
                asn_cache[src_ip] = "Unknown"

        asn_val = asn_cache[src_ip]

        print(f"{i+1:<5} | {src_ip:<16} | {asn_val:<10} | {hostname}")


def main():
    try:
        with open("trace.json", "r") as f:
            trace_data = json.load(f)
    except FileNotFoundError:
        print("Error: trace.json not found.")
        return

    print("Annotating Trace Flows...")
    print_flow_annotations(trace_data)


if __name__ == "__main__":
    main()
