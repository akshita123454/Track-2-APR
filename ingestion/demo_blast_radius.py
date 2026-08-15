"""
HackHydra 2026 - Track 2A: Supply Chain Blast Radius Demo Engine
This script models an npm dependency graph, simulates a package compromise,
and calculates the full transitive blast radius, maintainer risk, and typosquats.
"""

import json
import os
from datetime import datetime

# -------------------------------------------------------------
# 1. REALISTIC NPM DEPENDENCY DATASET (Simulated for Demo)
# -------------------------------------------------------------
SAMPLE_DATA = {
    "packages": [
        {
            "name": "tanstack-router",
            "version": "1.0.4",
            "maintainer": "alice_dev",
            "published_at": "2026-05-11T09:00:00Z",
            "downloads_weekly": 1200000,
            "dependencies": ["router-core", "url-utils"]
        },
        {
            "name": "router-core",
            "version": "2.1.0",
            "maintainer": "alice_dev",  # Shares maintainer with tanstack-router!
            "published_at": "2026-04-10T12:00:00Z",
            "downloads_weekly": 800000,
            "dependencies": ["hacked-logger"]
        },
        {
            "name": "url-utils",
            "version": "1.5.0",
            "maintainer": "bob_smith",
            "published_at": "2026-03-01T10:00:00Z",
            "downloads_weekly": 450000,
            "dependencies": []
        },
        {
            "name": "hacked-logger",
            "version": "3.0.1",  # THE COMPROMISED PACKAGE!
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
            "name": "tanstck-router",  # TYPOSQUAT TRAP!
            "version": "1.0.0",
            "maintainer": "unknown_actor",
            "published_at": "2026-05-10T22:00:00Z",
            "downloads_weekly": 1200,
            "dependencies": []
        }
    ],
    "internal_applications": [
        {
            "app_name": "Production-Payment-API",
            "environment": "production",
            "direct_dependencies": ["tanstack-router"]
        },
        {
            "app_name": "Customer-Dashboard",
            "environment": "production",
            "direct_dependencies": ["tanstack-router", "auth-helper"]
        },
        {
            "app_name": "Internal-Admin-Portal",
            "environment": "staging",
            "direct_dependencies": ["url-utils"]
        }
    ]
}

# -------------------------------------------------------------
# 2. BLAST RADIUS GRAPH ENGINE
# -------------------------------------------------------------
class SupplyChainGraph:
    def __init__(self, data):
        self.packages = {p["name"]: p for p in data["packages"]}
        self.apps = data["internal_applications"]

    def find_blast_radius(self, compromised_pkg_name):
        """Walks backwards along dependency edges to find all affected apps and chains."""
        results = []

        for app in self.apps:
            # Check every direct dependency of the app
            for direct_dep in app["direct_dependencies"]:
                chain = self._trace_path(direct_dep, compromised_pkg_name, [app["app_name"]])
                if chain:
                    results.append({
                        "app_name": app["app_name"],
                        "environment": app["environment"],
                        "chain": chain,
                        "hop_count": len(chain) - 1
                    })
        return results

    def _trace_path(self, current_pkg, target_pkg, current_path):
        """Recursive graph traversal (simulates Cypher MATCH -[:DEPENDS_ON*]->)."""
        path = current_path + [current_pkg]
        if current_pkg == target_pkg:
            return path
        
        pkg_data = self.packages.get(current_pkg)
        if not pkg_data:
            return None

        for dep in pkg_data.get("dependencies", []):
            sub_path = self._trace_path(dep, target_pkg, path)
            if sub_path:
                return sub_path
        return None

    def find_shared_maintainer_risks(self, compromised_pkg_name):
        """Identifies other packages published by the same maintainers."""
        compromised = self.packages.get(compromised_pkg_name)
        if not compromised:
            return []
        
        maintainer = compromised["maintainer"]
        shared_pkgs = [
            p for p in self.packages.values()
            if p["maintainer"] == maintainer and p["name"] != compromised_pkg_name
        ]
        return shared_pkgs

    def detect_typosquats(self, target_pkg_name):
        """Finds similarly named packages using Levenshtein distance."""
        def levenshtein(s1, s2):
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
                if dist <= 2:  # Edit distance 1 or 2
                    typos.append({
                        "name": name,
                        "distance": dist,
                        "maintainer": self.packages[name]["maintainer"]
                    })
        return typos

# -------------------------------------------------------------
# 3. HTML VISUAL GRAPH GENERATOR (Opens in Browser!)
# -------------------------------------------------------------
def export_html_visualizer(compromised_name, blast_results, typosquats):
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>HackHydra - Blast Radius Live Graph</title>
    <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style>
        body {{ background-color: #0d1117; color: #c9d1d9; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; }}
        #header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #30363d; padding-bottom: 15px; margin-bottom: 20px; }}
        h1 {{ color: #ff5722; margin: 0; font-size: 24px; }}
        .badge {{ background: #ff5722; color: white; padding: 4px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; }}
        #network {{ width: 100%; height: 600px; border: 1px solid #30363d; border-radius: 8px; background: #000000; }}
        .alert-box {{ background: rgba(255, 87, 34, 0.1); border: 1px solid #ff5722; padding: 15px; border-radius: 8px; margin-top: 20px; }}
    </style>
</head>
<body>
    <div id="header">
        <div>
            <h1>🛡️ Supply Chain Blast Radius Monitor</h1>
            <p>Incident Target: <strong style="color:#ff5722;">{compromised_name}</strong> (COMPROMISED)</p>
        </div>
        <div>
            <span class="badge">LIVE GRAPH ENGINE</span>
        </div>
    </div>

    <div id="network"></div>

    <div class="alert-box">
        <h3>🚨 Incident Summary:</h3>
        <p>• <strong>Transitively Exposed Applications:</strong> {len(blast_results)}</p>
        <p>• <strong>Detected Typosquat Candidates:</strong> {len(typosquats)}</p>
    </div>

    <script type="text/javascript">
        var nodes = new vis.DataSet([
            // Compromised root node
            {{ id: "{compromised_name}", label: "{compromised_name}\\n(HACKED PKG)", color: "#ff1744", font: {{ color: "white" }}, shape: "box", size: 30 }},
            
            // Intermediary packages
            {{ id: "router-core", label: "router-core\\n(infected)", color: "#ff5722", font: {{ color: "white" }}, shape: "box" }},
            {{ id: "tanstack-router", label: "tanstack-router\\n(infected)", color: "#ff9800", font: {{ color: "white" }}, shape: "box" }},
            {{ id: "url-utils", label: "url-utils\\n(safe)", color: "#4caf50", font: {{ color: "white" }}, shape: "box" }},
            {{ id: "auth-helper", label: "auth-helper\\n(safe)", color: "#4caf50", font: {{ color: "white" }}, shape: "box" }},
            
            // Applications
            {{ id: "Production-Payment-API", label: "⚡ Production-Payment-API\\n[CRITICAL EXPOSURE]", color: "#d50000", font: {{ color: "white", size: 14 }}, shape: "ellipse" }},
            {{ id: "Customer-Dashboard", label: "⚡ Customer-Dashboard\\n[CRITICAL EXPOSURE]", color: "#d50000", font: {{ color: "white", size: 14 }}, shape: "ellipse" }},
            {{ id: "Internal-Admin-Portal", label: "Internal-Admin-Portal\\n[SAFE]", color: "#2e7d32", font: {{ color: "white" }}, shape: "ellipse" }}
        ]);

        var edges = new vis.DataSet([
            {{ from: "router-core", to: "{compromised_name}", arrows: "to", color: {{ color: "#ff1744" }}, width: 3, label: "depends on" }},
            {{ from: "tanstack-router", to: "router-core", arrows: "to", color: {{ color: "#ff5722" }}, width: 3, label: "depends on" }},
            {{ from: "tanstack-router", to: "url-utils", arrows: "to", color: {{ color: "#30363d" }} }},
            {{ from: "Production-Payment-API", to: "tanstack-router", arrows: "to", color: {{ color: "#d50000" }}, width: 4, label: "uses" }},
            {{ from: "Customer-Dashboard", to: "tanstack-router", arrows: "to", color: {{ color: "#d50000" }}, width: 4, label: "uses" }},
            {{ from: "Customer-Dashboard", to: "auth-helper", arrows: "to", color: {{ color: "#30363d" }} }},
            {{ from: "Internal-Admin-Portal", to: "url-utils", arrows: "to", color: {{ color: "#2e7d32" }} }}
        ]);

        var container = document.getElementById("network");
        var data = {{ nodes: nodes, edges: edges }};
        var options = {{
            physics: {{
                stabilization: true,
                barnesHut: {{ springLength: 150, nodeDistance: 200 }}
            }}
        }};
        var network = new vis.Network(container, data, options);
    </script>
</body>
</html>
"""
    output_path = os.path.join(os.path.dirname(__file__), "blast_radius_visualizer.html")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    return output_path

# -------------------------------------------------------------
# 4. MAIN EXECUTION
# -------------------------------------------------------------
if __name__ == "__main__":
    graph = SupplyChainGraph(SAMPLE_DATA)
    hacked_package = "hacked-logger"

    print("=" * 65)
    print(f"🚨 SIMULATING COMPROMISE ON PACKAGE: '{hacked_package}'")
    print("=" * 65)

    # 1. Calculate Transitive Blast Radius
    blast_radius = graph.find_blast_radius(hacked_package)
    print(f"\n💣 [QUESTION 1] TRANSITIVELY EXPOSED SERVICES ({len(blast_radius)} Found):")
    for item in blast_radius:
        chain_str = " ──▶ ".join(item["chain"])
        print(f"  • App: {item['app_name']} ({item['environment'].upper()})")
        print(f"    Attack Path ({item['hop_count']} hops): {chain_str}")

    # 2. Shared Maintainer Risks
    shared_maintainers = graph.find_shared_maintainer_risks(hacked_package)
    print(f"\n👤 [QUESTION 4] SHARED MAINTAINER PACKAGES AT RISK:")
    if shared_maintainers:
        for pkg in shared_maintainers:
            print(f"  • {pkg['name']} (Weekly Downloads: {pkg['downloads_weekly']:,})")
    else:
        print("  • None detected for this maintainer.")

    # 3. Typosquat Candidates
    typos = graph.detect_typosquats("tanstack-router")
    print(f"\n🎯 [QUESTION 5] TYPOSQUAT PACKAGES DETECTED NEAR 'tanstack-router':")
    for typo in typos:
        print(f"  • Suspect Package: '{typo['name']}' (Edit Distance: {typo['distance']}, Author: {typo['maintainer']})")

    # 4. Generate Visual HTML Graph
    html_file = export_html_visualizer(hacked_package, blast_radius, typos)
    print("\n" + "=" * 65)
    print(f"✨ SUCCESS: Interactive Graph Visualizer generated!")
    print(f"🌐 Open this file in your browser:\n   {html_file}")
    print("=" * 65)