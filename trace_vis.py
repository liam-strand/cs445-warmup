import os
import json
import socket
import matplotlib.pyplot as plt
import cartopy.crs as ccrs
import cartopy.feature as cfeature
import math
import requests
from pprint import pprint
from collections import defaultdict
import itertools
# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------

# Load IPs from measurement_log.json
with open("measurement_log.json", "r") as f:
    log_data = json.load(f)

IP_LIST = [entry["target"] for entry in log_data.get("simple_filter", [])]
IP_LIST.append("146.155.4.188") # Target: ialab.ing.uc.cl

OUTPUT_FILENAME = "traceroute_path.png"
CACHE_FILENAME = "location_cache.json"

# ---------------------------------------------------------
# HELPER: Cache Management
# ---------------------------------------------------------
def load_cache():
    if os.path.exists(CACHE_FILENAME):
        with open(CACHE_FILENAME, "r") as f:
            return json.load(f)
    return {}

def save_cache(cache):
    with open(CACHE_FILENAME, "w") as f:
        json.dump(cache, f, indent=4)

# ---------------------------------------------------------
# HELPER: City Geocoding
# ---------------------------------------------------------
def get_city_coordinates(city_query):
    """
    Geocodes a city name to lat/lon using OpenStreetMap (Nominatim).
    """
    url = "https://nominatim.openstreetmap.org/search"
    # User-Agent is required by Nominatim
    headers = {'User-Agent': 'PythonTraceVis/1.0'}
    params = {'q': city_query, 'format': 'json', 'limit': 1}
    
    try:
        print(f"Geocoding '{city_query}'...")
        response = requests.get(url, params=params, headers=headers, timeout=5)
        response.raise_for_status()
        data = response.json()
        if data:
            return float(data[0]['lat']), float(data[0]['lon'])
        else:
            print(f"No location found for '{city_query}'")
    except Exception as e:
        print(f"Geocoding error: {e}")
    return None, None

def haversine_miles(lat1, lon1, lat2, lon2):
    """
    Calculate the great circle distance in miles between two points 
    on the earth (specified in decimal degrees)
    """
    # Earth radius in miles
    R = 3958.8
    
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    
    return R * c

def format_hop_ranges(indices):
    """
    Converts a list of integers into a string of ranges.
    e.g., [1, 2, 3, 5, 6] -> "1-3, 5-6"
    e.g., [1, 3, 4] -> "1, 3-4"
    """
    if not indices:
        return ""
    
    indices = sorted(list(set(indices)))
    ranges = []
    
    for _, group in itertools.groupby(enumerate(indices), lambda p: p[1] - p[0]):
        group = list(group)
        start = group[0][1]
        end = group[-1][1]
        if start == end:
            ranges.append(str(start))
        else:
            ranges.append(f"{start}-{end}")
            
    return ", ".join(ranges)

# ---------------------------------------------------------
# HELPER: City Geocoding
# ---------------------------------------------------------

# ---------------------------------------------------------
# 1. GEOLOCATION (Using ip-api.com)
# ---------------------------------------------------------
def get_geolocations(ips):
    """
    Batches IP addresses and sends them to ip-api.com to get lat/lon.
    Filters out private IPs or failed lookups.
    """
    print(f"Resolving {len(ips)} IP addresses...")
    
    # Load cache
    geo_cache = load_cache()
    
    # ip-api batch endpoint (Free for non-commercial use)
    url = "http://ip-api.com/batch"
    
    # Prepare payload (ip-api expects a list of objects or strings)
    # We request specific fields to minimize data transfer
    payload = [{"query": ip, "fields": "status,message,lat,lon,city,country"} for ip in ips]
    
    try:
        response = requests.post(url, json=payload, timeout=10)
        response.raise_for_status()
        results = response.json()
        
        path_data = []
        cache_updated = False

        for i, res in enumerate(results):
            ip_addr = ips[i]
            
            # Treat 'Ann Arbor' and 'Montevideo' as failures because they are often defaults for certain networks
            if res['status'] == 'success' and res['city'] not in ['Ann Arbor', 'Montevideo']:
                path_data.append({
                    'ip': ip_addr,
                    'city': res['city'],
                    'country': res['country'],
                    'lat': res['lat'],
                    'lon': res['lon']
                })
            else:
                city = res.get('city')
                if city in ['Ann Arbor', 'Montevideo']:
                     print(f"Checking {ip_addr}: Detected '{city}' (likely imprecise). Triggering manual override.")
                else:
                     msg = res.get('message', 'Unknown error')
                     print(f"Checking {ip_addr}: {msg}")
                
                # CHECK CACHE FIRST
                if ip_addr in geo_cache:
                    print(f"  -> Found in cache: {geo_cache[ip_addr]['city']}")
                    cached_entry = geo_cache[ip_addr]
                    path_data.append({
                        'ip': ip_addr,
                        'city': cached_entry['city'],
                        'country': "Manual Input (Cached)",
                        'lat': cached_entry['lat'],
                        'lon': cached_entry['lon']
                    })
                    continue

                # If ip-api fails and NOT in cache, attempt User-assisted Reverse DNS
                try:
                    hostname = socket.gethostbyaddr(ip_addr)[0]
                    print(f"  -> Reverse DNS: {hostname}")
                    
                    # Ask user for input
                    city_input = input(f"  -> Enter city for {hostname} ({ip_addr}) [Enter to skip]: ").strip()
                    if city_input:
                        lat, lon = get_city_coordinates(city_input)
                        if lat is not None:
                            # Add to path data
                            path_data.append({
                                'ip': ip_addr,
                                'city': city_input,
                                'country': "Manual Input",
                                'lat': lat,
                                'lon': lon
                            })
                            # Update cache
                            geo_cache[ip_addr] = {
                                'city': city_input,
                                'lat': lat,
                                'lon': lon
                            }
                            cache_updated = True
                            
                except Exception:
                    # If reverse DNS fails or user skips
                    print(f"  -> Could not resolve hostname or location for {ip_addr}")
        
        if cache_updated:
            save_cache(geo_cache)
            print("Cache updated.")
                
        pprint(path_data)
        return path_data
        
    except Exception as e:
        print(f"API Request failed: {e}")
        return []

# ---------------------------------------------------------
# 2. MAPPING (Using Cartopy & Matplotlib)
# ---------------------------------------------------------
def create_static_map(path_data):
    if not path_data:
        print("No valid location data found to plot.")
        return

    print("Generating map...")

    # Set up the figure size and resolution
    plt.figure(figsize=(16, 9), dpi=300)
    
    # Extract coordinates
    lats = [d['lat'] for d in path_data]
    lons = [d['lon'] for d in path_data]

    # Use PlateCarree for rectangular projection which allows easy cropping
    ax = plt.axes(projection=ccrs.PlateCarree())

    # Calculate bounds and add padding
    if lats and lons:
        min_lat, max_lat = min(lats), max(lats)
        min_lon, max_lon = min(lons), max(lons)
        
        # Calculate spans used for padding
        lat_span = max(max_lat - min_lat, 1.0) # Ensure non-zero
        lon_span = max(max_lon - min_lon, 1.0)
        
        # Add 10% padding on each side
        pad_lat = lat_span * 0.1
        pad_lon = lon_span * 0.1
        
        extent = [
            min_lon - pad_lon,
            max_lon + pad_lon,
            max(min_lat - pad_lat, -90),
            min(max_lat + pad_lat, 90)
        ]
        ax.set_extent(extent, crs=ccrs.PlateCarree())
    else:
        ax.set_global()

    # Add map features (aesthetic details)
    ax.add_feature(cfeature.LAND, facecolor='#f5f5f5')
    ax.add_feature(cfeature.OCEAN, facecolor='#c9d6de')
    ax.add_feature(cfeature.COASTLINE, linewidth=0.5, color='#444444')
    ax.add_feature(cfeature.BORDERS, linestyle=':', linewidth=0.5, color='#888888')

    # DRAW LINES
    # transform=ccrs.Geodetic() creates the curved "great circle" lines
    plt.plot(lons, lats, color='#d62728', linewidth=2, 
             transform=ccrs.Geodetic(), marker=None, label='Packet Path')

    # GROUP HOPS BY CLUSTERING (approx 50 miles)
    # List of dicts: {'lat': lat, 'lon': lon, 'hops': []}
    clusters = []
    
    for i, (lat, lon) in enumerate(zip(lats, lons)):
        hop_num = i + 1
        found_cluster = False
        
        for cluster in clusters:
            if haversine_miles(lat, lon, cluster['lat'], cluster['lon']) < 50:
                cluster['hops'].append(hop_num)
                # Keep the first point as the anchor for the visual marker
                found_cluster = True
                break
        
        if not found_cluster:
            clusters.append({'lat': lat, 'lon': lon, 'hops': [hop_num]})
        
    # DRAW MARKERS AND ANNOTATIONS FOR CLUSTERS
    transform = ccrs.PlateCarree()._as_mpl_transform(ax)
    
    for cluster in clusters:
        lat = cluster['lat']
        lon = cluster['lon']
        hops = cluster['hops']
        
        # Plot a single dot for this location
        plt.scatter([lon], [lat], color='#1f77b4', s=80, zorder=10, 
                    transform=ccrs.PlateCarree(), edgecolors='white', linewidth=1.5)
        
        # Generate the label
        label_text = format_hop_ranges(hops)
        
        # Annotate
        ax.annotate(label_text, xy=(lon, lat), xycoords=transform,
                    xytext=(5, 5), textcoords="offset points",
                    color='black', weight='bold', fontsize=9,
                    bbox=dict(boxstyle="round,pad=0.3", fc="white", alpha=0.8, ec="none"))

    # Add a title
    plt.title(f"Network Trace: Northwestern → UC Chile", 
              fontsize=16, pad=20, weight='bold')

    # Save the file
    plt.savefig(OUTPUT_FILENAME, bbox_inches='tight')
    print(f"Success! Map saved as {OUTPUT_FILENAME}")
    plt.close()

# ---------------------------------------------------------
# MAIN EXECUTION
# ---------------------------------------------------------
if __name__ == "__main__":
    # 1. Get Coordinates
    data = get_geolocations(IP_LIST)
    
    # 2. Draw Map
    if data:
        create_static_map(data)
