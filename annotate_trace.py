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
        asns = data.get('data', {}).get('asns', [])
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
            
            return {'asn': asn_str}
        else:
            return {'asn': 'Unknown'}
            
    except Exception as e:
        return {'asn': 'Error', 'error': str(e)}

def get_unique_ips(trace_data):
    """
    Extract unique source IPs from the trace data.
    """
    ips = set()
    flows = trace_data.get('flows', {})
    
    for flow_id, hops in flows.items():
        for hop in hops:
            # Check if 'received' -> 'ip' -> 'src' exists
            received = hop.get('received')
            if not received:
                continue
                
            ip_info = received.get('ip', {})
            src_ip = ip_info.get('src')
            
            if src_ip:
                ips.add(src_ip)
                
    return sorted(list(ips))

def get_holder_for_asn(asn):
    """
    Optional: Helper to get holder name if we have an ASN.
    Skipping for now to keep it simple as requested, or can be added if needed.
    Team Cymru whois gives this for free, but RIPEstat splits it.
    """
    pass

def main():
    try:
        with open('trace.json', 'r') as f:
            trace_data = json.load(f)
    except FileNotFoundError:
        print("Error: trace.json not found.")
        return

    unique_ips = get_unique_ips(trace_data)
    print(f"Found {len(unique_ips)} unique IPs.")
    
    print("\nIP -> ASN Mapping:")
    print("--------------------------------------------------")
    print(f"{'IP Address':<20} | {'ASN':<20}")
    print("--------------------------------------------------")
    
    for ip in unique_ips:
        asn_info = get_asn_ripenet(ip)
        asn_val = asn_info.get('asn', 'Unknown')
        print(f"{ip:<20} | {asn_val:<20}")

if __name__ == "__main__":
    main()
