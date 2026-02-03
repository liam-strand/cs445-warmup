---
title: CS 445 Warmup Project
author: Liam Strand
date: February 3, 2026
header-includes:
  - \pagenumbering{gobble}
---

# Target Selection and Context

We selected **`ialab.ing.uc.cl`** (146.155.4.188) as our target server.

*   **Domain:** `ialab.ing.uc.cl` (Resolved IP: 146.155.4.188)
*   **Organization:** Pontificia Universidad Católica de Chile (UC)
*   **Location:** Santiago, Chile (Southern Hemisphere)

**Motivation:**
This target is "messy" because it is an academic server hosted directly by the university's engineering department, not fronted by a global CDN like Cloudflare or Akamai. This exposes the raw routing infrastructure of the university and its upstream providers (likely REUNA or international transit like Level3/Lumen). We expect routing ambiguity due to the potential for educational/research networks (NRENs) to have complex peering arrangements and for international traffic to be routed through major exchange points (likely Miami or similar) before reaching the local Chilean network.

# Traceroute and Router Identification

We performed a traceroute from our local vantage point (Northwestern University network) to the target.

### Router Sets

1.  **R_edge (Source Side):**
    *   `165.124.184.3` (Northwestern)
    *   `129.105.247.167` (Northwestern)
    *   *Observation:* These are the immediate hops from our local network, representing the "last mile" out of the source campus.

2.  **R_core (Transit):**
    *   `198.71.46.206`, `163.253.2.56` (Transit/Backbone)
    *   `200.0.207.9` (likely entering Latin American infrastructure)
    *   *Observation:* These routers handle the long-haul transit. We observed latency jumps corresponding to the transition from US networks to international links.

3.  **R_near (Destination Side):**
    *   `146.83.242.102` (REUNA - Chilean National Research and Education Network)
    *   `146.155.88.35` (Pontificia Universidad Católica de Chile)
    *   *Observation:* These hops are within the destination country and AS, immediately preceding the target server.

**Limitations:**
Traceroute only reveals the forward path at a specific moment. It relies on ICMP time-exceeded messages which may be deprioritized by routers, leading to artificial latency inflation or dropped packets (stars). Furthermore, MPLS tunneling can hide hops or present misleading IP interfaces.

# Vantage Point Selection

We compared two probe selection strategies to measure latency to our three router sets (`R_edge`, `R_core`, `R_near`).

1.  **Naive Selection (Simple Filter):**
    *   **Criteria:** Probes located in Chile (CL) and Argentina (AR) with IPv4 capability.
    *   **Result:** Selected **50** probes.
    *   **Diversity:** Covered **32** unique ASNs across **2** unique countries.

2.  **GeoResolver-style Selection:**
    *   **Criteria:** Selected probes that showed similar DNS redirection behavior to the target network (checking `www.google.com`, `www.facebook.com`, etc. against the target's subnet). This aims to find probes that are topologically close, not just geographically close.
    *   **Result:** Selected **50** probes.
    *   **Diversity:** Successfully recruited more diverse vantage points, covering **38** unique ASNs across **4** unique countries (CL, AR, PE, BO).

**Comparison:**
The GeoResolver strategy proved more effective at finding a diverse set of network locations. By checking 50 candidate probes based on network topology (DNS views), we recruited probes from Peru (PE) and Bolivia (BO) that the naive "Chile/Argentina" filter missed, while also finding more unique observation points (ASNs) within the target region.

# Latency Measurements and Analysis

We measured RTT from our selected probes to the defined router sets.

### Visualizing Latency
![Latency Violin Plot](/home/yhe7443/cs445/warmup/latency_violin_plot.png)
The collected RTT data was visualized using violin plots to show the distribution of latency for each router across the different probes.

### Findings: When Does Latency Mislead?

1.  **Edge Routers (`R_edge`) from Remote Probes:**
    *   Measuring `R_edge` (Northwestern US) from South American probes resulted in consistently high RTT signatures (~150-200ms+), accurately reflecting the intercontinental distance. However, high variance was observed, likely due to queuing delay at the international gateway rather than the "edge" router itself being slow.

2.  **Near Routers (`R_near`) and "Local" Latency:**
    *   Probes selected by the GeoResolver strategy generally showed lower minimum RTTs to `R_near` routers compared to the tail of the Naive selection. This suggests that topological similarity (DNS behavior) correlates well with network proximity.
    *   However, we observed cases where "near" routers (e.g., `146.83.242.102`) had surprisingly high latencies from some "local" probes. This highlights circuitous routing within the region—traffic between two ISPs in Santiago might trombone through Miami, inflating RTT despite geographic proximity.

3.  **The "Last Mile" Effect:**
    *   Early hops in the traceroute (`R_edge`) are physically close to the *source*, but when measured from our *probes* (in SA), they are the furthest. Conversely, variability in the probes' own last-mile connections (many RIPE probes are residential) introduced noise floor issues, where even "close" routers couldn't be reached faster than the probe's access link latency (e.g., DSL/Cable overhead).

4.  **Strategy Effectiveness:**
    *   The **GeoResolver** strategy successfully identified probes with better "visibility" of the target network. The latency distributions from these probes were often tighter (smaller IQR) for `R_near` routers, indicating more direct paths. The Naive strategy included probes that, while in the correct country, might have had poor interconnects to the University network, leading to misleadingly high latencies.

# Conclusion

Locating routers via latency is frail. While the speed of light sets a hard lower bound, routing inefficiencies, last-mile congestion, and indirect peering (circuitous paths) constantly obscure the signal. Our study confirmed that selecting vantage points based on network topology (GeoResolver) yields more reliable measurements than simple geographic selection, as physical proximity does not guarantee network proximity.
