# CTI-Python


------------------------------
## Cyber Threat Intelligence Infrastructure Mapper
An automated Cyber Threat Intelligence (CTI) tool designed for security analysts and SOC teams to instantly convert unstructured, defanged OSINT threat reports and security blogs into interactive, localized node-relationship infrastructure graphs.
With a single terminal execution, ThreatNav parses raw text, extracts defanged indicators (IPs, domains, hashes), models their connections, generates a standalone interactive HTML map, and pops it open automatically in Firefox on Kali Linux.
------------------------------
## 🚀 Key Features

* Zero-Configuration Parsing: Copy-paste raw text directly from security blogs or PDF intelligence reports.
* Smart Defang Extraction: Built-in resilient regular expressions automatically refang indicators like evil[.]com, 192[.]0[.]2[.]1, and hxxps[:]//.
* Dynamic Visual Control: Powered by PyVis and NetworkX with embedded physics stabilization configurations to prevent text clumping, overlapping, or floating node distortions.
* Dual-Output Architecture: Generates an immediate interactive interactive browser graphic (.html) and an automated, pre-formatted ingest file (.csv) tailored for direct Maltego Graph imports.

------------------------------
## 🛠️ Installation & Setup
Ensure you are inside your virtual environment or project directory on your analyst workstation (optimized for Kali Linux architecture):

# Clone the repository
git clone https://github.com
cd threatnav
# Install dependencies
pip install pyvis networkx

------------------------------
## 📖 How To Use

   1. Save your raw threat intelligence text into a local file (e.g., intel_report.txt):
   
   Phishing domains:
   cloud.g-drive[.]cam
   googeldrive[.]cam
   
   IP addresses:
   91.107.156[.]29
   
   2. Execute the unified mapper script via the command line:
   
   python3 cti_mapper.py -f intel_report.txt -c "Blackwood_Campaign" -o blackwood_map.html
   
   3. Interact with your data:
   * Firefox Execution: The script will automatically trigger a clean background instance of Firefox to display your graph layout.
      * Physics Control Panel: Toggle forces, adjust spring constraints, or freeze nodes directly using the live control menu embedded at the bottom of the HTML canvas.
   
------------------------------
## 🔄 Maltego Workspaces Integration
The tool auto-generates a maltego_import.csv along with your web visualization layout.

   1. Inside Maltego, open a new graph workspace.
   2. Select Import > Import Graph from Table.
   3. Choose the generated maltego_import.csv.
   4. Map Source and Target fields to establish links. Map SourceType and TargetType explicitly to default infrastructure objects (e.g., maltego.IPv4Address, maltego.Domain).

------------------------------
## 🎨 Entity Visual Mapping Index

| Object Type | Visual Node Color | Default Relationship Link |
|---|---|---|
| Campaign | 🟣 Purple | Root Actor Axis Node |
| Domain Name | 🔵 Blue | associated_domain |
| IP Address | 🟢 Green | associated_ip |
| Malicious Hash | 🟠 Orange | deploys_sample |

------------------------------




