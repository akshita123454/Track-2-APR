# HydraGuard - Supply Chain Blast Radius

This project is a submission for the **HackHydra Hackathon (Aug 12-20, 2026)**.

## Track 02: Repos, dependencies and code as graphs
**Option A: Supply chain blast radius**

### Overview
Supply chain attacks are surging. When a package is compromised, security teams need to know their exposure instantly. Traditional databases fail to traverse deep dependency trees fast enough. This project leverages **HydraDB** to construct an ecosystem graph of packages and dependencies, enabling real-time transitive reverse dependency closures to instantly identify the "blast radius" of a compromised package.

### How HydraDB is Used
*(To be expanded as the project is built)*
- **Graph Nodes**: `Package`, `Version`, `Maintainer`, `Service`
- **Graph Edges**: `DEPENDS_ON`, `MAINTAINED_BY`
- **Core Functionality**: Utilizing HydraDB's graph traversal capabilities to recursively trace exposed internal services when a vulnerability is flagged.

### Project Structure
- `/ingestion` - Python scripts for fetching package registry data and loading it into HydraDB.
- `/dashboard` - A web dashboard for visualizing the dependency graph and blast radius.

### Setup Instructions
*(Coming soon...)*

### License
MIT License
