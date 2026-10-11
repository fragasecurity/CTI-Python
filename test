

Notes & Limitations 
SecurityTrails API key is required for all core pivoting and monitoring. The free tier is rate-limited; production use needs a paid plan.
Certificate Transparency logs and Shodan enrichment are mentioned in the skill description but not implemented in the provided code.
Reverse IP / nearby queries can return large result sets — the script limits to 20 per IP to avoid explosions.
The original generate_infrastructure_report was truncated in the source; the version above is a complete, usable implementation.
No built-in rate limiting or retry logic beyond basic try/except. Add time.sleep() or a proper rate limiter for heavy use.
Graph is undirected (nx.Graph) in the original. You can switch to nx.DiGraph if you want directional relationships.

How to RunInstall dependencies: pip install requests networkx
Insert a real SecurityTrails API key.
Replace the seed domain/IP.
Run: python adversary_infra_tracker.py






import numpy as np
import json
from sklearn.metrics.pairwise import cosine_similarity

# 1. Define a Mock Database of Known Threat Actor Profiles (TTP Matrices)
# In a production environment, this data would be fetched via STIX/TAXII from OpenCTI or MISP.
KNOWN_ACTORS = {
    "APT29 (Cozy Bear)": {
        "T1566.001": 1,  # Spearphishing Attachment
        "T1059.001": 1,  # PowerShell
        "T1543.003": 0,  # Windows Service (not heavily prominent in this profile)
        "T1071.001": 1,  # Web Protocols (C2)
        "T1574.002": 1,  # DLL Side-Loading
        "T1020": 0,      # Automated Exfiltration
        "T1486": 0       # Data Encrypted for Impact (Ransomware)
    },
    "APT41 (Double Dragon)": {
        "T1566.001": 0,
        "T1059.001": 1,
        "T1543.003": 1,  # Windows Service creation
        "T1071.001": 1,
        "T1574.002": 1,
        "T1020": 1,      # Automated Exfiltration
        "T1486": 0
    },
    "Wizard Spider (Fin7/Ryuk)": {
        "T1566.001": 1,
        "T1059.001": 1,
        "T1543.003": 0,
        "T1071.001": 0,
        "T1574.002": 0,
        "T1020": 1,
        "T1486": 1       # Data Encrypted for Impact (Ransomware)
    }
}

def attribute_behavior(observed_ttp_list):
    """
    Calculates cosine similarity between observed incidents and known threat actor TTP matrices.
    """
    # Extract the definitive list of tracked techniques to maintain index alignment
    tracked_techniques = list(KNOWN_ACTORS[list(KNOWN_ACTORS.keys())[0]].keys())
    
    # Vectorize the observed campaign behavior
    observed_vector = np.array([1 if tech in observed_ttp_list else 0 for tech in tracked_techniques]).reshape(1, -1)
    
    print("[-] Compiling intelligence vectors...")
    print(f"[-] Tracking Techniques: {tracked_techniques}")
    print(f"[-] Observed Campaign Vector: {observed_vector[0]}\n")
    print(f"{'Threat Actor Group':<28} | {'Behavioral Similarity Score':<25}")
    print("-" * 60)
    
    attributions = []
    
    # Calculate similarity score against each profile
    for actor, profile in KNOWN_ACTORS.items():
        actor_vector = np.array([profile[tech] for tech in tracked_techniques]).reshape(1, -1)
        
        # Compute Cosine Similarity
        similarity = cosine_similarity(observed_vector, actor_vector)[0][0]
        attributions.append((actor, similarity))
        
    # Sort attribution results by highest similarity score
    attributions.sort(key=lambda x: x[1], reverse=True)
    
    for actor, score in attributions:
        print(f"{actor:<28} | {score * 100:>23.2f}%")
        
    return attributions

if __name__ == "__main__":
    # Simulated incoming incident intelligence feed (e.g., observed TTPs extracted from an active incident)
    active_incident_ttps = ["T1566.001", "T1059.001", "T1020", "T1486"]
    
    print("[*] Initiating Engine: CTI Behavioral Attribution Engine")
    print(f"[*] Observed Incident Techniques: {active_incident_ttps}\n")
    
    results = attribute_behavior(active_incident_ttps)
    
    print(f"\n[*] Top Attribution Match: {results[0][0]} ({results[0][1]*100:.2f}%)")
