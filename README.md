<div align="center">

# HydraGuard

### Evidence-First Supply-Chain Blast Radius & Containment Engine

**Graph-Native on HydraDB · Fail-Closed by Design · Prevention, Not Just Detection**

`Collect → Persist → Analyse → Prevent → Contain`

</div>

---

## Run It In One Command

```bash
npm run demo
```

Then open **http://localhost:5173**

That's it. The HydraGuard Evidence Console loads immediately — **no database setup, no Docker, no configuration required** to review the full system. We engineered it this way deliberately: a reviewer should never face a blank screen or a setup error.

---

## The Problem Nobody Could Answer Fast Enough

When a malicious version of a popular npm package is published, every engineering team asks the same six questions — and almost none can answer them in time:

| # | Question | Why it's genuinely hard |
|:-:|----------|------------------------|
| 1 | Which internal services are **transitively** exposed? | Needs multi-hop *reverse* dependency traversal |
| 2 | Which **version** introduced the vulnerability? | Needs semver interval reasoning |
| 3 | Which apps resolved the bad version **while it was live**? | Needs time-aware dependency history |
| 4 | Which packages share a **maintainer or infrastructure**? | Needs authority-pivot correlation |
| 5 | Are there likely **typosquat** packages nearby? | Needs similarity **plus** real resolution proof |
| 6 | What is the **complete blast radius**? | Needs all of the above, composed |

> ### This is fundamentally a **graph traversal and dependency problem** — not a semantic similarity problem.

A vector database structurally **cannot** answer questions 1, 3, 4 or 6. Similarity search finds things that *look alike*; it cannot prove *what depends on what, through which path, at which moment in time*. A graph database can.

**That is precisely why HydraGuard is built on HydraDB.**

✅ **All six questions are answered end-to-end in HydraGuard.**

---

## Would This Have Prevented the TanStack-Class Incident? Yes.

We studied that attack chain ourselves and modelled it directly. It looked like this:

```
compromised CI cache → poisoned build → publish credential → malicious release → npm → thousands of apps
```

Every scanner in that chain was pointed at the **wrong end**. They all inspected the package *after* publication. By then the blast radius was already global.

HydraGuard attacks the **origin** of the chain. Our Release Trust Firewall models release provenance as a graph:

```
source-change → workflow-run → cache-entry → build → credential → artifact → release
```

When a **cache entry that crossed a trust boundary** is found to influence a **publishing credential**, HydraGuard returns:

```
╔══════════════════════════════════════╗
║   DECISION: 🛑 BLOCK                 ║
║   Trust boundary crossed             ║
║   Publish denied at the gate         ║
╚══════════════════════════════════════╝
```

**The poisoned artifact never reaches npm. The blast radius is zero — because nothing was ever published.**

> **Had HydraGuard existed at the time, the malicious release would have been blocked at the publish gate — before a single downstream application could resolve it.**

And for teams already exposed, HydraGuard answers *"exactly who resolved it, and when"* in **seconds** instead of days of manual lockfile archaeology.

---

# Our Four Core Innovations

---

## 1️⃣ Graph-Native Blast Radius Analysis 

### The novelty: we return **proof**, not a probability.

Conventional scanners flatten dependencies into a list and match names against a CVE feed. That answers *"is this package present?"* — a far weaker question than *"which of my services are actually exposed, through which path?"*

HydraGuard performs a genuine **reverse traversal** across the HydraDB evidence graph:

```
Incident → affected PackageVersion → reverse dependency paths → internal Services
```

**What makes this different:**

- **Transitive by construction.** Deeply nested indirect dependencies are found because traversal is the *native* operation, not a bolt-on.
- **Every result carries a verifiable proof path.** An analyst can independently retrace exactly why a service was flagged. No opaque risk score.
- **Canonical vs. derived separation.** We maintain a fast reverse index (`USED_BY`), but it is **structurally forbidden** from introducing evidence — every derived edge must be backed by a canonical `DEPENDS_ON` edge with real provenance. This closes a false-positive hole most tools leave wide open.
- **Measurable, not asserted.** Responses include `hydraRead` telemetry — read epoch, query count, rows read, latency, engine — so the graph work is provable rather than claimed.

**Why it wins:** an incident responder doesn't need a number between 0 and 100. They need a defensible list of affected services and the path that proves it. That's what we return.

---

## 2️⃣ Evidence-Backed Typosquat Radar 

### The novelty: **similarity is not maliciousness.**

This is the discipline nearly every typosquat detector lacks. Name-similarity tools drown teams in false positives — `react-dom` vs `react-dom-router` scores high and means nothing. Alert fatigue then destroys the tool's entire usefulness.

HydraGuard scores **nine distinct transformation classes**, not naive edit distance:

`adjacent-transposition` · `insertion` · `deletion` · `substitution` · `separator-variation` · `repeated-character` · `scope-impersonation` · `unicode-confusable` · `prefix-suffix`

But here is the actual innovation — **the evidence gate**:

```
candidate → suspicious → high-confidence → confirmed ✅
                                        ↘  dismissed ❌
```

A finding is **only ever elevated to confirmed exposure when a real lockfile proves your internal environment actually resolved that package.** Similarity alone can never reach `confirmed`. Ever.

**Plus a production-grade analyst workflow:**
- Promotion and dismissal require **bearer authorization** — every decision is attributable
- Each review writes an `Evidence` node carrying the reviewer's identity
- Reviews are **idempotent** and safely replayable, so a network retry can never corrupt state
- Partial-persistence failures are **repaired deterministically**, never silently left half-written

**Why it wins:** we cleanly separate *"this name looks suspicious"* (a hypothesis) from *"this suspicious package is inside our environment"* (a confirmed incident). Collapsing those two is exactly why existing tools get muted and ignored.

---

## 3️⃣ Web Authority Pivot Analysis 

### The novelty: attackers don't compromise one package — they compromise **one publisher**.

Conventional scanners treat packages as isolated units. This is the blind spot real supply-chain attackers exploit relentlessly. A single compromised maintainer account, one leaked publishing token, or one poisoned CI runner can silently poison **dozens of unrelated-looking packages** simultaneously.

HydraGuard models **publishing authority as a first-class graph entity** and pivots across it:

```
compromised Maintainer → MAINTAINS → all their Packages → all dependent Services
```

**What this unlocks:**

- **Correlated compromise detection.** One malicious package instantly becomes an authority-level investigation, not an isolated ticket.
- **Shared-infrastructure clustering.** Packages sharing maintainers, publishing pipelines or credentials are grouped as a single trust unit.
- **Typosquat attribution.** When a lookalike package shares infrastructure with a known-bad actor, its score escalates — because the evidence now points to intent, not coincidence.
- **Pre-emptive exposure mapping.** We surface which services *would* be affected if a given maintainer were compromised, turning incident response into risk forecasting.

**Why it wins:** we answer question 4 — *"which packages share a maintainer or infrastructure?"* — with a graph traversal. This is a question a vector database fundamentally cannot answer, because shared authority is a **structural relationship**, not a textual similarity.

---

## 4️⃣ Release Trust Firewall 

### The novelty: **prevention at the publish gate**, not detection after the damage.

Every other layer of HydraGuard makes response faster. **This layer makes the incident never happen.**

Instead of inspecting the published artifact, we trace backwards through the entire release influence chain and detect **trust-boundary crossings**:

```
source-change → workflow-run → cache-entry → build → credential → artifact → release
```

Three decisive verdicts:

| Verdict | Meaning | Action |
|:-------:|---------|--------|
| ✅ **`allow`** | Clean influence chain, no boundary crossings | Publish proceeds |
| ⚠️ **`quarantine`** | Suspicious influence detected | Hold for human review |
| 🛑 **`block`** | Untrusted input reached a publishing credential | **Publish denied** |

**What this catches that scanners cannot:**

- A **cache entry from an untrusted branch or fork** feeding a trusted production build
- A workflow run that reached a **publishing credential** it should never have touched
- An artifact whose provenance chain **cannot be fully reconstructed** — which we treat as a failure, never as a pass

**Why it wins:** this is the exact mechanism that would have stopped the TanStack-class attack. Detection tools measure blast radius *after* it exists. The Release Firewall makes the blast radius **zero** by refusing to publish.

---

## The Guarantee Behind All Four: Fail-Closed Temporal Reasoning

Underpinning every innovation above is a design decision we consider non-negotiable.

Most tools ask *"does this service depend on the package?"*
HydraGuard asks the **correct, harder** question: **"did this service resolve the affected version while it was live?"**

Implemented with `LockfileSnapshot` nodes, `RESOLVED_IN` canonical edges, temporal `validFrom` / `validUntil` fields on dependency edges, and an `?asOf=<ISO>` replay parameter on the blast-radius route.

| Outcome | Meaning |
|---------|---------|
| `resolved-during-window` | ✅ Confirmed exposure inside the incident window |
| `resolved-outside-window` | ℹ️ Dependency exists, but not while vulnerable |
| `unknown-window` |  **Insufficient history — treated as unsafe** |

**Absence of evidence is never treated as evidence of safety.** Missing lockfile history is *never* silently reported as safe. This single guarantee is what makes HydraGuard's output trustworthy enough to act on during a live incident.

---

## How HydraGuard Advances Beyond Prior Work

Existing academic and commercial approaches largely stop at *detecting known-vulnerable versions inside a manifest*. HydraGuard adds four capabilities that class of tool structurally cannot provide.

| Capability | Prior approaches | HydraGuard |
|-----------|------------------|---------------|
| Dependency exposure | Flat manifest scan | **Multi-hop graph traversal with proof paths** |
| Time awareness | Point-in-time only | **Temporal intervals + `asOf` replay** |
| Missing data handling | Assumed safe | **Fail-closed `unknown-window`** |
| Typosquat detection | Name similarity score only | **Similarity + real resolution evidence** |
| Publisher correlation | Not modelled | **First-class authority pivot** |
| Provenance | Rarely modelled | **Evidence on every node and edge** |
| Prevention | Detection only, post-publish | **Pre-publish release firewall** |
| Human review | Untracked | **Authorized, idempotent, audit-logged** |
| Result explainability | Opaque score | **Independently verifiable traversal** |

**Three capabilities are entirely absent from prior work in this space:** temporal resolution proof, authority-pivot correlation, and pre-publish containment. HydraGuard delivers all three.

---

## The Evidence Console

A HydraDB-inspired black-and-ember interface that walks any reviewer through the complete system in under three minutes.

| Panel | What it demonstrates |
|-------|---------------------|
| **Release History** | Package publication timeline analysis |
| **Lockfile Ingest** | Exactly what a service *actually* resolved |
| **HydraDB Graph** | The evidence graph model and schema |
| **Blast Radius** | Reverse traversal to affected services |
| **Time Machine** | "Who resolved it while it was live?" |
| **Typosquat Radar** | Nine transformation classes + evidence gate |
| **Authority Pivot** | Shared maintainer / infrastructure correlation |
| **Release Firewall** | Allow · Quarantine · Block decisions |
| **Containment** | Response and remediation guidance |
| **Proof & Engine** | Deterministic backend validation matrix |

---

## Running HydraGuard

### Fastest path — the console

```bash
npm run demo
```
→ **http://localhost:5173**

### Full stack — live API + HydraDB

**1. Install dependencies**
```bash
npm run setup
```

**2. Configure environment**
```bash
cp .env.example .env
```
Then set your local HydraDB credentials in `.env`.

**3. Start HydraDB** in Docker with a persistent volume

**4. Start the API**
```bash
npm run api
```

**5. Start the console**
```bash
npm run demo
```

**6. Verify the stack**

| URL | Expected |
|-----|----------|
| http://localhost:3000/health | `"status":"ok"` |
| http://localhost:3000/ready | `"database":"available"` |
| http://localhost:5173 | Evidence Console |

### Run the proof suite

```bash
npm run verify
```

Executes the full deterministic validation matrix — malformed graph facts, tampered payloads, missing evidence, temporal boundary cases, release-firewall decision paths, containment logic and the complete typosquatting analyst lifecycle.

### View the typed API contract

```bash
npm run contract
```
→ **http://localhost:8080**

---

## API Surface

| Method | Endpoint | Purpose |
|--------|----------|---------|
| `GET` | `/health` | Liveness |
| `GET` | `/ready` | HydraDB readiness |
| `POST` | `/ingestions/npm` | Collect real npm registry metadata |
| `POST` | `/ingestions/lockfile` | Ingest real resolved dependencies |
| `GET` | `/ingestions/:id` | Poll async job status |
| `GET` | `/incidents` | Cursor-paginated incident list |
| `POST` | `/incidents` | Create an incident |
| `GET` | `/incidents/:id/blast-radius` | Graph traversal, supports `?asOf=` |
| `POST` | `/typosquatting/scans` | Scan resolved dependencies |
| `GET` | `/typosquatting/findings` | List findings |
| `GET` | `/typosquatting/findings/:id` | Finding detail + evidence |
| `POST` | `/typosquatting/findings/:id/promote` | Analyst promote  |
| `POST` | `/typosquatting/findings/:id/dismiss` | Analyst dismiss  |
| `GET` | `/release-influence/snapshots/:id/firewall` | Release verdict |

 = requires analyst bearer authorization

---

## Try It With a Real npm Package

```powershell
$body = @{
  roots = @(@{ name = "axios"; versions = @("1.7.9") })
  maxPackages = 100
  maxDepth = 3
  includeDevDependencies = $false
} | ConvertTo-Json -Depth 6

$job = Invoke-RestMethod -Uri "http://localhost:3000/ingestions/npm" `
  -Method Post -ContentType "application/json" -Body $body `
  -Headers @{ "Idempotency-Key" = "demo-axios-001" }

Invoke-RestMethod -Uri "http://localhost:3000/ingestions/$($job.ingestionId)"
```

This collects **genuine npm registry data** — real versions, real maintainers, real dependency declarations. Not fixtures.

---

## Architecture

```
┌─────────────────────────────────────────────┐
│         Evidence Console (React)            │
│      Black · Ember · HydraDB-native         │
└────────────────────┬────────────────────────┘
                     │ HTTPS
┌────────────────────▼────────────────────────┐
│         HydraGuard API (Fastify)            │
│   Ingest · Analyse · Prevent · Contain      │
│   Async jobs · Idempotency · Fail-closed    │
└──────┬────────────────────────────┬─────────┘
       │ Bolt                       │ HTTPS
┌──────▼──────────┐        ┌────────▼────────┐
│    HydraDB      │        │  npm Registry   │
│ Evidence Graph  │        │   (real data)   │
└─────────────────┘        └─────────────────┘
```

### Graph Model

**Nodes** — `Package` · `PackageVersion` · `Service` · `Maintainer` · `Evidence` · `Incident` · `Finding` · `LockfileSnapshot`

**Edges** — `DEPENDS_ON` · `USED_BY` · `AFFECTS` · `MAINTAINS` · `LOOKALIKE_OF` · `IMITATES` · `SUPPORTS` · `RESOLVED_IN`

---

## Security Design Principles

- **Fail-closed everywhere.** Unknown is never treated as safe.
- **Evidence required.** No graph fact exists without provenance.
- **Derived ≠ canonical.** Reverse indexes can never fabricate evidence.
- **Bounded reads.** Every list endpoint is cursor-paginated with hard limits.
- **Idempotent writes.** Every mutation is safely replayable.
- **Tamper-evident payloads.** Hashes are verified on read.
- **Authorized human review.** Analyst decisions are authenticated and audited.
- **Secrets stay server-side.** Database and analyst tokens never reach the browser bundle.

---

## Project Layout

```
Track-2-APR/
├── apps/api/                    HydraGuard API
│   └── src/
│       ├── analysis/            Blast radius · temporal · release-trust
│       ├── db/                  HydraDB persistence, serializer, writer
│       ├── domain/              Schema · validator · factories
│       ├── incidents/           Incident service & index
│       ├── ingest/              npm + lockfile collectors, snapshots
│       ├── typosquatting/       Detection & analyst lifecycle
│       └── api/                 Routes · schemas · jobs · config
├── dashboard/                   Evidence Console (React + Vite)
│   └── src/console/             HydraDB-native UI shell
├── contracts/openapi.yaml       Typed API contract
└── .env.example                 Configuration template
```

---



### HydraGuard

**Detection tells you that you were attacked.**

**HydraGuard tells you exactly who was exposed — and stops the next one from ever shipping.**

*Evidence-first · Graph-native · Fail-closed*

</div>
