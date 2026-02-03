import json
import requests
import pandas as pd
import matplotlib.pyplot as plt
import cartopy.crs as ccrs
import cartopy.feature as cfeature

# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------
RIPE_ATLAS_API_KEY = "06b9d943-5556-4ecf-8965-8bb5c66743a4"
MEASUREMENT_LOG = "measurement_log.json"
PROBES_CSV = "ripe_probes.csv"
OUTPUT_FILENAME = "vantage_points.png"

# ---------------------------------------------------------
# 1. FETCH DATA
# ---------------------------------------------------------
def get_measurement_results(measurement_id):
    """Fetch results of a measurement from RIPE Atlas."""
    url = f"https://atlas.ripe.net/api/v2/measurements/{measurement_id}/results/"
    headers = {
        "Authorization": f"Key {RIPE_ATLAS_API_KEY}"
    }
    
    print(f"Fetching results for measurement {measurement_id}...")
    try:
        response = requests.get(url, headers=headers, timeout=30)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error fetching {measurement_id}: {response.status_code}")
            return []
    except Exception as e:
        print(f"Exception fetching {measurement_id}: {e}")
        return []

def get_probes_by_strategy():
    """
    Reads measurement_log.json, fetches results, and returns a dict mapping
    strategy names ('naive', 'georesolver') to sets of probe IDs.
    """
    try:
        with open(MEASUREMENT_LOG, 'r') as f:
            log_data = json.load(f)
    except FileNotFoundError:
        print(f"Could not find {MEASUREMENT_LOG}")
        return {}

    probes_by_strategy = {
        'naive': set(),        # corruption of 'simple_filter'
        'georesolver': set()
    }

    # Map file keys to our display labels/categories
    strategy_map = {
        'simple_filter': 'naive',
        'georesolver': 'georesolver'
    }

    for log_strategy, measurements in log_data.items():
        target_category = strategy_map.get(log_strategy)
        if not target_category:
            continue
            
        print(f"\nProcessing strategy: {log_strategy} -> {target_category}")
        for entry in measurements:
            m_id = entry.get('measurement_id')
            if not m_id:
                continue
                
            results = get_measurement_results(m_id)
            for result in results:
                if 'prb_id' in result:
                    probes_by_strategy[target_category].add(result['prb_id'])
                    
    return probes_by_strategy

# ---------------------------------------------------------
# 2. LOAD LOCATIONS
# ---------------------------------------------------------
def get_probe_locations(all_probe_ids):
    """
    Reads ripe_probes.csv and returns a DataFrame with lat/lon for the used probes.
    """
    if not all_probe_ids:
        return pd.DataFrame()

    print(f"\nLoading probe locations from {PROBES_CSV}...")
    try:
        df = pd.read_csv(PROBES_CSV)
        
        if 'id' not in df.columns:
            print("Error: 'id' column not found in CSV")
            return pd.DataFrame()
            
        # Filter for relevant probes
        filtered_df = df[df['id'].isin(all_probe_ids)].copy()
        
        # Keep only necessary columns and drop rows with missing coordinates
        if 'lat' in filtered_df.columns and 'lon' in filtered_df.columns:
            filtered_df = filtered_df[['id', 'lat', 'lon']].dropna()
            return filtered_df
        else:
            print("Error: 'lat' or 'lon' columns missing in CSV")
            return pd.DataFrame()
            
    except Exception as e:
        print(f"Error reading CSV: {e}")
        return pd.DataFrame()

# ---------------------------------------------------------
# 3. VISUALIZATION
# ---------------------------------------------------------
def create_vantage_map(locations_df, probes_by_strategy):
    if locations_df.empty:
        print("No probe data to plot.")
        return

    print(f"\nGenerating map...")

    # Calculate Extent with Padding
    min_lat = locations_df['lat'].min()
    max_lat = locations_df['lat'].max()
    min_lon = locations_df['lon'].min()
    max_lon = locations_df['lon'].max()

    lat_range = max_lat - min_lat
    lon_range = max_lon - min_lon
    
    # 10% padding
    pad_lat = lat_range * 0.1
    pad_lon = lon_range * 0.1
    
    # Avoid zero range if only one point
    if pad_lat == 0: pad_lat = 1.0
    if pad_lon == 0: pad_lon = 1.0

    extent = [
        min_lon - pad_lon, 
        max_lon + pad_lon, 
        min_lat - pad_lat, 
        max_lat + pad_lat
    ]
    
    print(f"Cropping map to: {extent}")

    # Set up the figure size and resolution
    plt.figure(figsize=(12, 10), dpi=300)
    
    # Use PlateCarree for flat map suitable for cropping
    ax = plt.axes(projection=ccrs.PlateCarree())
    ax.set_extent(extent, crs=ccrs.PlateCarree())

    # Add map features
    ax.add_feature(cfeature.LAND, facecolor='#f5f5f5')
    ax.add_feature(cfeature.OCEAN, facecolor='#c9d6de')
    ax.add_feature(cfeature.COASTLINE, linewidth=0.5, color='#444444')
    ax.add_feature(cfeature.BORDERS, linestyle=':', linewidth=0.5, color='#888888')
    ax.add_feature(cfeature.LAKES, facecolor='#c9d6de')
    ax.add_feature(cfeature.RIVERS, linewidth=0.5, color='#c9d6de')

    # Separate DataFrames
    naive_ids = probes_by_strategy.get('naive', set())
    geo_ids = probes_by_strategy.get('georesolver', set())
    
    naive_df = locations_df[locations_df['id'].isin(naive_ids)]
    geo_df = locations_df[locations_df['id'].isin(geo_ids)]

    # Plot Naive Probes (Red)
    if not naive_df.empty:
        plt.scatter(
            naive_df['lon'], naive_df['lat'], 
            color='red', s=40, zorder=10, 
            transform=ccrs.PlateCarree(), marker='o', edgecolors='black', linewidth=0.5,
            label='Naive Strategy', alpha=0.8
        )

    # Plot GeoResolver Probes (Blue)
    if not geo_df.empty:
        plt.scatter(
            geo_df['lon'], geo_df['lat'], 
            color='blue', s=40, zorder=11, 
            transform=ccrs.PlateCarree(), marker='^', edgecolors='black', linewidth=0.5,
            label='GeoResolver Strategy', alpha=0.8
        )

    # Add legend
    plt.legend(loc='lower left', fontsize=10, title="Vantage Points", title_fontsize=11)

    # Add a title
    plt.title(f"Probe Locations", 
              fontsize=14, pad=10, weight='bold')

    # Save the file
    plt.savefig(OUTPUT_FILENAME, bbox_inches='tight')
    print(f"Success! Map saved as {OUTPUT_FILENAME}")
    plt.close()

# ---------------------------------------------------------
# MAIN EXECUTION
# ---------------------------------------------------------
if __name__ == "__main__":
    # 1. Identify used probes by strategy
    probes_by_strategy = get_probes_by_strategy()
    
    all_probe_ids = set()
    for ids in probes_by_strategy.values():
        all_probe_ids.update(ids)
        
    print(f"\nIdentified {len(all_probe_ids)} unique probes used in measurements.")
    
    if all_probe_ids:
        # 2. Get their locations
        locations_df = get_probe_locations(all_probe_ids)
        
        # 3. Draw map
        if not locations_df.empty:
            create_vantage_map(locations_df, probes_by_strategy)
        else:
            print("Could not retrieve locations for the identified probes.")
    else:
        print("No probes identified from measurements.")
