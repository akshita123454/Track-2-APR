"""
=============================================================================
🛡️ HackHydra 2026 - Track 2A: Supply Chain Blast Radius Demo Engine
=============================================================================
This script does 4 main things:
  1. Stores an npm dependency graph (Packages, Maintainers, Applications).
  2. Traverses the graph to find every application transitively infected.
  3. Detects typosquatting and shared maintainer risk.
  4. Generates an interactive HTML graph and AUTOMATICALLY opens your browser!
=============================================================================
"""

import json
import os
import webbrowser  # <-- Built-in Python library to automatically pop open your browser!
from datetime import datetime

# =============================================================================
# 📦 SECTION 1: THE DEPENDENCY DATASET (Our Graph Data)
# =============================================================================
# In HydraDB, these become NODES (circles) and EDGES (connecting arrows).
SAMPLE_DATA = {
    "packages": [
        {
            "name": "tanstack-router",
            "version": "1.0.4",
            "maintainer": "alice_dev",
            "published_at": "2026-05-11T09:00:00Z",
            "downloads_weekly": 1200000,
            "dependencies": ["router-core", "url-utils"]  # Needs router-core and url-utils to work
        },
        {
            "name": "router-core",
            "version": "2.1.0",
            "maintainer": "alice_dev",                    # Shares maintainer with tanstack-router!
            "published_at": "2026-04-10T12:00:00Z",
            "downloads_weekly": 800000,
            "dependencies": ["hacked-logger"]            # Needs hacked-logger to work!
        },
        {
            "name": "url-utils",
            "version": "1.5.0",
            "maintainer": "bob_smith",
            "published_at": "2026-03-01T10:00:00Z",
            "downloads_weekly": 450000,
            "dependencies": []                            # Has 0 dependencies (Safe endpoint)
        },
        {
            "name": "hacked-logger",                      # 🚨 THE COMPROMISED / POISONED PACKAGE!
            "version": "3.0.1",
            "maintainer": "evil_actor",
            "published_at": "2026-05-11T09:02:00Z",
            "downloads_weekly": 3500000,
            "dependencies": []
        },
        {
            "name": "auth-helper",
            "version": "1.1.0",
            "maintainer": "alice_dev",
            "published_at": "2026-02-15T08:00:00Z",
            "downloads_weekly": 900000,
            "dependencies": []
        },
        {
            "name": "tanstck-router",                     # 🎯 A FAKE LOOKALIKE (TYPOSQUAT TRAP)!
            "version": "1.0.0",
            "maintainer": "unknown_actor",
            "published_at": "2026-05-10T22:00:00Z",
            "downloads_weekly": 1200,
            "dependencies": []
        }
    ],
    # These represent internal microservices and apps inside your company:
    "internal_applications": [
        {
            "app_name": "Production-Payment-API",
            "environment": "production",
            "direct_dependencies": ["tanstack-router"]     # App directly installs tanstack-router
        },
        {
            "app_name": "Customer-Dashboard",
            "environment": "production",
            "direct_dependencies": ["tanstack-router", "auth-helper"]
        },
        {
            "app_name": "Internal-Admin-Portal",
            "environment": "staging",
            "direct_dependencies": ["url-utils"]           # App only installs safe url-utils
        }
    ]
}


# =============================================================================
# 🧠 SECTION 2: THE GRAPH TRAVERSAL & BLAST RADIUS ENGINE
# =============================================================================
class SupplyChainGraph:
    """
    This class simulates what HydraDB does with Cypher queries.
    It walks along dependency arrows to find all reachable paths.
    """
    def __init__(self, data):
        # Store packages in a fast dictionary by their name
        self.packages = {pkg["name"]: pkg for pkg in data["packages"]}
        self.apps = data["internal_applications"]

    def find_blast_radius(self, compromised_pkg_name):
        """
        Answers Problem Statement Question 1:
        'Which internal services are transitively exposed?'
        """
        results = []

        # Check every application owned by our company
        for app in self.apps:
            # Check every package that this application directly installs
            for direct_dep in app["direct_dependencies"]:
                # Recursively trace if this dependency leads to the hacked package
                chain = self._trace_path(direct_dep, compromised_pkg_name, [app["app_name"]])
                if chain:
                    results.append({
                        "app_name": app["app_name"],
                        "environment": app["environment"],
                        "chain": chain,
                        "hop_count": len(chain) - 1  # How many steps away from the hack
                    })
        return results

    def _trace_path(self, current_pkg, target_pkg, current_path):
        """
        Recursive helper function:
        Walks: App -> Pkg A -> Pkg B -> Hacked Package
        (This is exactly what HydraDB's Cypher query: MATCH path = (app)-[:DEPENDS_ON*]->(bad) does!)
        """
        path = current_path + [current_pkg]
        
        # If we reached the hacked package, we found an infection path!
        if current_pkg == target_pkg:
            return path
        
        pkg_data = self.packages.get(current_pkg)
        if not pkg_data:
            return None

        # Look into the sub-dependencies of this package
        for dep in pkg_data.get("dependencies", []):
            sub_path = self._trace_path(dep, target_pkg, path)
            if sub_path:
                return sub_path
        return None

    def find_shared_maintainer_risks(self, compromised_pkg_name):
        """
        Answers Problem Statement Question 4:
        'Which other packages share maintainers or infrastructure with it?'
        If a maintainer's account was hacked, all their other packages are at risk!
        """
        compromised = self.packages.get(compromised_pkg_name)
        if not compromised:
            return []
        
        maintainer = compromised["maintainer"]
        # Find all other packages created by the same person
        shared_pkgs = [
            p for p in self.packages.values()
            if p["maintainer"] == maintainer and p["name"] != compromised_pkg_name
        ]
        return shared_pkgs

    def detect_typosquats(self, target_pkg_name):
        """
        Answers Problem Statement Question 5:
        'Are there likely typosquat packages nearby?'
        Uses the Levenshtein Distance (edit distance) algorithm to find lookalikes.
        """
        def levenshtein(s1, s2):
            # Calculates how many character changes separate word 1 from word 2
            if len(s1) < len(s2):
                return levenshtein(s2, s1)
            if len(s2) == 0:
                return len(s1)
            prev_row = range(len(s2) + 1)
            for i, c1 in enumerate(s1):
                curr_row = [i + 1]
                for j, c2 in enumerate(s2):
                    insertions = prev_row[j + 1] + 1
                    deletions = curr_row[j] + 1
                    substitutions = prev_row[j] + (c1 != c2)
                    curr_row.append(min(insertions, deletions, substitutions))
                prev_row = curr_row
            return prev_row[-1]

        typos = []
        for name in self.packages:
            if name != target_pkg_name:
                dist = levenshtein(target_pkg_name, name)
                # If the name is only 1 or 2 letters different, it is a high-risk typosquat!
                if dist <= 2:
                    typos.append({
                        "name": name,
                        "distance": dist,
                        "maintainer": self.packages[name]["maintainer"]
                    })
        return typos


# =============================================================================
# 🎨 SECTION 3: HTML VISUAL GRAPH GENERATOR (With Vis.js)
# =============================================================================
def export_html_visualizer(compromised_name, blast_results, typosquats):
    """
    Generates a beautiful, dark-mode interactive HTML file.
    The graph colors infected nodes in RED/ORANGE and safe nodes in GREEN.
    """
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>HackHydra - Supply Chain Blast Radius Graph</title>
    <!-- We load Vis.js: a powerful open-source graph animation library -->
    <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style>
        body {{
            background-color: #0d1117;
            color: #c9d1d9;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
        }}
        #header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #30363d;
            padding-bottom: 15px;
            margin-bottom: 20px;
        }}
        h1 {{
            color: #ff5722;
            margin: 0;
            font-size: 24px;
        }}
        .badge {{
            background: #ff5722;
            color: white;
            padding: 6px 14px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
            letter-spacing: 1px;
        }}
        #network {{
            width: 100%;
            height: 600px;
            border: 1px solid #30363d;
            border-radius: 8px;
            background: #010409;
            box-shadow: 0 4px 20px rgba(0,0,0,0.5);
        }}
        .alert-box {{
            background: rgba(255, 87, 34, 0.08);
            border-left: 4px solid #ff5722;
            padding: 15px 20px;
            border-radius: 4px;
            margin-top: 20px;
        }}
        .legend {{
            display: flex;
            gap: 20px;
            margin-top: 15px;
            font-size: 13px;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .dot {{
            width: 14px;
            height: 14px;
            border-radius: 50%;
            display: inline-block;
        }}
    </style>
</head>
<body>
    <div id="header">
        <div>
            <h1>🛡️ Supply Chain Blast Radius Monitor</h1>
            <p>Target Compromise: <strong style="color:#ff1744;">{compromised_name}</strong> (ATTACK INGESTED)</p>
        </div>
        <div>
            <span class="badge">HYDRADB LIVE GRAPH</span>
        </div>
    </div>

    <!-- The Canvas where the interactive graph draws -->
    <div id="network"></div>

    <div class="legend">
        <div class="legend-item"><span class="dot" style="background:#ff1744;"></span> Compromised Source</div>
        <div class="legend-item"><span class="dot" style="background:#ff9800;"></span> Infected Dependency Bridge</div>
        <div class="legend-item"><span class="dot" style="background:#d50000;"></span> Exposed Production Application</div>
        <div class="legend-item"><span class="dot" style="background:#2e7d32;"></span> Safe Component</div>
    </div>

    <div class="alert-box">
        <h3>🚨 Incident Response Intelligence:</h3>
        <p>• <strong>Transitively Exposed Internal Applications:</strong> {len(blast_results)} Services at High Risk</p>
        <p>• <strong>Detected Typosquat Lookalikes:</strong> {len(typosquats)} Nearby Suspicious Packages</p>
        <p>• <strong>Recommendation:</strong> Quarantine lockfiles referencing version 3.0.1 and rollback to safe snapshots.</p>
    </div>

    <script type="text/javascript">
        // 1. DEFINE GRAPH NODES (Entities)
        var nodes = new vis.DataSet([
            // The Root Malicious Package (Bright Red)
            {{ id: "{compromised_name}", label: "{compromised_name}\\n[HACKED PKG]", color: "#ff1744", font: {{ color: "white", face: "monospace" }}, shape: "box", size: 30 }},
            
            // Intermediary Bridge Packages (Orange - Transitive Carrier)
            {{ id: "router-core", label: "router-core\\n(infected carrier)", color: "#ff5722", font: {{ color: "white" }}, shape: "box" }},
            {{ id: "tanstack-router", label: "tanstack-router\\n(infected carrier)", color: "#ff9800", font: {{ color: "white" }}, shape: "box" }},
            
            // Safe Packages (Green)
            {{ id: "url-utils", label: "url-utils\\n(clean)", color: "#4caf50", font: {{ color: "white" }}, shape: "box" }},
            {{ id: "auth-helper", label: "auth-helper\\n(clean)", color: "#4caf50", font: {{ color: "white" }}, shape: "box" }},
            
            // Internal Applications (Red Ellipses - The victims in the blast radius!)
            {{ id: "Production-Payment-API", label: "⚡ Production-Payment-API\\n[CRITICAL EXPOSURE]", color: "#d50000", font: {{ color: "white", size: 14, bold: true }}, shape: "ellipse" }},
            {{ id: "Customer-Dashboard", label: "⚡ Customer-Dashboard\\n[CRITICAL EXPOSURE]", color: "#d50000", font: {{ color: "white", size: 14, bold: true }}, shape: "ellipse" }},
            {{ id: "Internal-Admin-Portal", label: "Internal-Admin-Portal\\n[SAFE]", color: "#2e7d32", font: {{ color: "white" }}, shape: "ellipse" }}
        ]);

        // 2. DEFINE GRAPH EDGES (Relationships / Dependency Arrows)
        var edges = new vis.DataSet([
            {{ from: "router-core", to: "{compromised_name}", arrows: "to", color: {{ color: "#ff1744" }}, width: 3, label: "depends on" }},
            {{ from: "tanstack-router", to: "router-core", arrows: "to", color: {{ color: "#ff5722" }}, width: 3, label: "depends on" }},
            {{ from: "tanstack-router", to: "url-utils", arrows: "to", color: {{ color: "#30363d" }} }},
            {{ from: "Production-Payment-API", to: "tanstack-router", arrows: "to", color: {{ color: "#d50000" }}, width: 4, label: "uses" }},
            {{ from: "Customer-Dashboard", to: "tanstack-router", arrows: "to", color: {{ color: "#d50000" }}, width: 4, label: "uses" }},
            {{ from: "Customer-Dashboard", to: "auth-helper", arrows: "to", color: {{ color: "#30363d" }} }},
            {{ from: "Internal-Admin-Portal", to: "url-utils", arrows: "to", color: {{ color: "#2e7d32" }} }}
        ]);

        // 3. RENDER VISUAL PHYSICS GRAPH
        var container = document.getElementById("network");
        var data = {{ nodes: nodes, edges: edges }};
        var options = {{
            physics: {{
                stabilization: true,
                barnesHut: {{ springLength: 160, nodeDistance: 220, gravitationalConstant: -3000 }}
            }},
            interaction: {{ hover: true, tooltipDelay: 200 }}
        }};
        var network = new vis.Network(container, data, options);
    </script>
</body>
</html>
"""
    # Write the HTML file to disk inside the same folder as this script
    output_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "blast_radius_visualizer.html"))
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    return output_path


# =============================================================================
# 🚀 SECTION 4: MAIN EXECUTION (Run this script)
# =============================================================================
if __name__ == "__main__":
    # 1. Initialize our graph with the npm dataset
    graph = SupplyChainGraph(SAMPLE_DATA)
    hacked_package = "hacked-logger"

    print("=" * 70)
    print(f"🚨 SIMULATING SUPPLY CHAIN ATTACK ON: '{hacked_package}'")
    print("=" * 70)

    # 2. Compute Transitive Blast Radius (PS Question 1)
    blast_radius = graph.find_blast_radius(hacked_package)
    print(f"\n💣 [QUESTION 1] TRANSITIVELY EXPOSED APPLICATIONS ({len(blast_radius)} Found):")
    for item in blast_radius:
        chain_str = " ──▶ ".join(item["chain"])
        print(f"  • Application: {item['app_name']} ({item['environment'].upper()})")
        print(f"    Attack Path ({item['hop_count']} hops): {chain_str}")

    # 3. Compute Shared Maintainer Risks (PS Question 4)
    shared_maintainers = graph.find_shared_maintainer_risks(hacked_package)
    print(f"\n👤 [QUESTION 4] SHARED MAINTAINER PACKAGES AT RISK:")
    if shared_maintainers:
        for pkg in shared_maintainers:
            print(f"  • {pkg['name']} (Weekly Downloads: {pkg['downloads_weekly']:,})")
    else:
        print("  • None detected for this maintainer.")

    # 4. Compute Typosquats (PS Question 5)
    typos = graph.detect_typosquats("tanstack-router")
    print(f"\n🎯 [QUESTION 5] TYPOSQUAT CANDIDATES NEAR 'tanstack-router':")
    for typo in typos:
        print(f"  • Suspect Package: '{typo['name']}' (Edit Distance: {typo['distance']}, Author: {typo['maintainer']})")

    # 5. Generate HTML File & Auto-Launch in Browser
    html_file = export_html_visualizer(hacked_package, blast_radius, typos)
    print("\n" + "=" * 70)
    print(f"✨ SUCCESS: Interactive Graph Visualizer generated!")
    print(f"🌐 Launching visual graph in your browser automatically...")
    print(f"   File: {html_file}")
    print("=" * 70)

    # ⭐ THIS AUTO-OPENS CHROME / EDGE ON YOUR COMPUTER:
    webbrowser.open(f"file://{html_file}")