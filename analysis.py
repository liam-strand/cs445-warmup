import json
import requests
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import time
from typing import List, Dict, Any
from measurements import R_ALL

# RIPE Atlas API Key (reused from measurements.py)
RIPE_ATLAS_API_KEY = "06b9d943-5556-4ecf-8965-8bb5c66743a4"

def get_measurement_results(measurement_id: int) -> List[Dict[str, Any]]:
    """Fetch results of a measurement from RIPE Atlas."""
    url = f"https://atlas.ripe.net/api/v2/measurements/{measurement_id}/results/"
    headers = {
        "Authorization": f"Key {RIPE_ATLAS_API_KEY}"
    }
    
    print(f"Fetching results for measurement {measurement_id}...")
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error fetching {measurement_id}: {response.status_code} - {response.text}")
            return []
    except Exception as e:
        print(f"Exception fetching {measurement_id}: {e}")
        return []

def parse_rtts(results: List[Dict[str, Any]], target: str, strategy: str) -> List[Dict[str, Any]]:
    """
    Extract RTTs from measurement results.
    Returns a list of dicts: {'Target': target, 'Strategy': strategy, 'RTT': rtt, 'Probe': prb_id}
    """
    data_points = []
    
    for result in results:
        probe_id = result.get('prb_id')
        # Structure of result depends on type, but for ping:
        # result['result'] is a list of attempts
        if 'result' in result:
            for attempt in result['result']:
                # Each attempt might have 'rtt'
                if 'rtt' in attempt:
                    rtt = attempt['rtt']
                    data_points.append({
                        'Target': target,
                        'Strategy': strategy,
                        'RTT': rtt,
                        'Probe': probe_id
                    })
    return data_points

def main():
    # 1. Load the log
    log_file = "measurement_log.json"
    try:
        with open(log_file, 'r') as f:
            log_data = json.load(f)
    except FileNotFoundError:
        print(f"Could not find {log_file}")
        return

    all_data = []

    # 2. Iterate through strategies and measurements
    for strategy, measurements in log_data.items():
        print(f"\nProcessing strategy: {strategy}")
        for entry in measurements:
            m_id = entry.get('measurement_id')
            target = entry.get('target')
            
            if not m_id or not target:
                continue
                
            # Fetch results from RIPE Atlas
            results = get_measurement_results(m_id)
            
            # Parse RTTs
            points = parse_rtts(results, target, strategy)
            all_data.extend(points)

    if not all_data:
        print("No data collected.")
        return

    # 3. Create DataFrame
    df = pd.DataFrame(all_data)
    if df.empty:
        print("No RTT data found.")
        return

    print(f"\nCollected {len(df)} RTT samples.")
    print(df.head())
    
    # --- Probe Variability Analysis ---
    print("\n--- Probe Variability Analysis ---")
    
    # Extract unique probes per strategy
    # We want to know: For each strategy, which probes participated?
    # And what are their ASN / Country?
    
    # 1. Get unique (Strategy, Probe) pairs from the collected data
    unique_probes = df[['Strategy', 'Probe']].drop_duplicates()
    
    # 2. Load Probe Metadata
    try:
        probes_df = pd.read_csv("ripe_probes.csv")
        # Ensure ID is int for merging
        probes_df['id'] = probes_df['id'].astype(int)
    except Exception as e:
        print(f"Error loading ripe_probes.csv: {e}")
        return

    # 3. Merge Metadata
    # Left join to clean data
    analysis_df = pd.merge(
        unique_probes, 
        probes_df[['id', 'asn_v4', 'country_code']], 
        left_on='Probe', 
        right_on='id', 
        how='left'
    )
    
    # 4. Show the DataFrame
    print("\nProbe Demographics by Strategy:")
    print(analysis_df[['Strategy', 'Probe', 'asn_v4', 'country_code']].to_string(index=False))
    
    # 5. Summary Statistics
    print("\nSummary Validation:")
    summary = analysis_df.groupby('Strategy').agg({
        'Probe': 'count',
        'asn_v4': 'nunique',
        'country_code': 'nunique'
    }).rename(columns={
        'Probe': 'Total Probes', 
        'asn_v4': 'Unique ASNs', 
        'country_code': 'Unique Countries'
    })
    print(summary)
    
    # 4. Generate Violin Plot
    print("\nGenerating violin plot...")
    plt.figure(figsize=(20, 10))
    sns.set_theme(style="whitegrid")
    
    # Create the violin plot
    # x=Target IP, y=RTT, hue=Strategy
    ax = sns.violinplot(
        data=df, 
        x="Target", 
        y="RTT", 
        hue="Strategy", 
        split=True,       # Split the violin for compact comparison
        inner="quartile", # Show quartiles inside
        palette="muted",
        cut=0,            # Limit the violin range to observed data
        order=R_ALL       # Ensure consistent ordering of targets
    )
    
    plt.title("RTT Distribution by Target Router and Selection Strategy")
    plt.xlabel("Target Router IP")
    plt.ylabel("RTT (ms)")
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    
    output_file = "latency_violin_plot.png"
    plt.savefig(output_file)
    print(f"Plot saved to {output_file}")

if __name__ == "__main__":
    main()
