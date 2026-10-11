#!/usr/bin/env python3
import os
import re
import sys
import argparse
import subprocess
from datetime import datetime, timezone
import networkx as nx
from pyvis.network import Network

# ---------- Optimized Regex Patterns ----------
DOMAIN_REGEX = r'\b[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\[\.\]|\.|\[dot\])[a-zA-Z]{2,6}\b'
IP_REGEX = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\[\.\]|\.|\[dot\])){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
HASH_REGEX = r'\b([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b'

class ThreatGraph:
    def __init__(self, campaign_name="Extracted Intelligence"):
        self.G = nx.DiGraph()
        self.campaign = campaign_name
        self.G.add_node(campaign_name, type="Campaign", added=datetime.now(timezone.utc).isoformat())

    def parse_text_report(self, text_content):
        """Extracts indicators from raw unstructured text and links them to the campaign."""
        raw_domains = re.findall(DOMAIN_REGEX, text_content)
        raw_ips = re.findall(IP_REGEX, text_content)
        hashes = re.findall(HASH_REGEX, text_content)

        # Refang and clean
        domains = set(d.replace("[.]", ".").replace("[dot]", ".").lower() for d in raw_domains)
        ips = set(ip.replace("[.]", ".").replace("[dot]", ".") for ip in raw_ips)
        hashes = set(h.lower() for h in hashes)

        for domain in domains:
            self.G.add_node(domain, type="Domain", added=datetime.now(timezone.utc).isoformat())
            self.G.add_edge(self.campaign, domain, relation="associated_domain")

        for ip in ips:
            self.G.add_node(ip, type="IP", added=datetime.now(timezone.utc).isoformat())
            self.G.add_edge(self.campaign, ip, relation="associated_ip")

        for h in hashes:
            label = "MD5" if len(h) == 32 else "SHA1" if len(h) == 40 else "SHA256"
            self.G.add_node(h, type="Malware", hash_type=label, added=datetime.now(timezone.utc).isoformat())
            self.G.add_edge(self.campaign, h, relation="deploys_sample")

        print(f"[+] Extracted: {len(domains)} Domains, {len(ips)} IPs, {len(hashes)} Hashes.")

    def export_and_launch_pyvis(self, output_html):
        """Generates the stable HTML layout and pops open Firefox on Kali."""
        net = Network(height="800px", width="100%", directed=True, bgcolor="#1e1e1e", font_color="white")
        
        color_map = {
            "Campaign": "#9b59b6", # Purple
            "Domain": "#3498db",   # Blue
            "IP": "#2ecc71",       # Green
            "Malware": "#e67e22"   # Orange
        }

        for node, data in self.G.nodes(data=True):
            node_type = data.get("type", "Unknown")
            color = color_map.get(node_type, "#95a5a6")
            title = f"<b>IOC:</b> {node}<br><b>Type:</b> {node_type}"
            net.add_node(node, label=node, title=title, color=color)

        for source, target, data in self.G.edges(data=True):
            net.add_edge(source, target, label=data.get("relation", ""))

        # Injection of custom layout rules and configuration controls
        net.set_options("""
        {
          "configure": {
            "enabled": true,
            "filter": ["physics"]
          },
          "physics": {
            "barnesHut": {
              "gravitationalConstant": -10000,
              "centralGravity": 0.3,
              "springLength": 180,
              "springConstant": 0.04,
              "damping": 0.09,
              "avoidOverlap": 1
            },
            "stabilization": {
              "enabled": true,
              "iterations": 1000
            }
          },
          "interaction": {
            "dragNodes": true,
            "hideEdgesOnDrag": false,
            "hideNodesOnDrag": false
          }
        }
        """)
        
        net.write_html(output_html)
        print(f"[+] Map saved to: {output_html}")
        
        # AUTOMATION STEP: Launch Firefox automatically on Kali Linux
        print("[+] Launching Firefox to display infrastructure...")
        try:
            # subprocess.Popen runs it in the background so your terminal remains active
            subprocess.Popen(["firefox", output_html], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            print("[!] Could not open Firefox automatically. Manually open the HTML file.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CTI Unstructured Text to Interactive Visual Mapper")
    parser.add_argument("-f", "--file", required=True, help="Path to raw text report/blog copy")
    parser.add_argument("-c", "--campaign", default="Target Campaign", help="Name of the threat group or campaign")
    parser.add_argument("-o", "--output", default="cti_map.html", help="Output HTML file name")
    
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"[-] Error: File {args.file} not found.")
        sys.exit(1)

    with open(args.file, "r", encoding="utf-8") as f:
        report_text = f.read()

    mapper = ThreatGraph(campaign_name=args.campaign)
    mapper.parse_text_report(report_text)
    mapper.export_and_launch_pyvis(args.output)
