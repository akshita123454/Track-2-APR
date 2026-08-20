/**
 * Single source of truth for the Evidence Console narrative.
 *
 * Every capability carries a one-line plain-language explanation so the demo
 * can be understood without reading the code, plus the guarantee it proves.
 */

export type PanelId =
  | 'overview'
  | 'history'
  | 'ingest'
  | 'graph'
  | 'blast'
  | 'temporal'
  | 'typosquat'
  | 'authority'
  | 'firewall'
  | 'containment'
  | 'integrity';

export type Maturity = 'live' | 'engine' | 'partial';

export interface Capability {
  readonly id: PanelId;
  readonly nav: string;
  readonly kicker: string;
  readonly headline: string;
  /** One sentence, no jargon. This is what gets said out loud. */
  readonly plain: string;
  /** The guarantee this subsystem enforces. */
  readonly proves: string;
  readonly maturity: Maturity;
  readonly hydra: string;
  readonly bullets: readonly string[];
}

export const MATURITY_LABEL: Record<Maturity, string> = {
  live: 'LIVE',
  engine: 'ENGINE VERIFIED',
  partial: 'PARTIAL',
};

export const CAPABILITIES: readonly Capability[] = [
  {
    id: 'history',
    nav: 'Release History',
    kicker: 'Stage 01 · Collection',
    headline: 'We read the full release history of a package.',
    plain:
      'For any npm package we collect every published version, when it went live, and who maintains it.',
    proves:
      'Version and time are recorded as facts, so later questions can be answered instead of guessed.',
    maturity: 'live',
    hydra: 'Package, PackageVersion and Maintainer nodes written to HydraDB',
    bullets: [
      'Live fetch from registry.npmjs.org with sha256 content hashing',
      'Publish timestamps captured per version',
      'Maintainer ownership recorded as a MAINTAINS edge',
    ],
  },
  {
    id: 'ingest',
    nav: 'Lockfile Ingest',
    kicker: 'Stage 02 · Ground truth',
    headline: 'We read what your services actually installed.',
    plain:
      'We parse your real package-lock.json to see the exact version each service resolved — not what it was allowed to install.',
    proves:
      'A declared version range is a possibility. A lockfile is proof. We never confuse the two.',
    maturity: 'live',
    hydra: 'DEPENDS_ON + LockfileSnapshot written with a verified write receipt',
    bullets: [
      'package-lock v1, v2 and v3 supported',
      'Each snapshot is content-addressed, so re-ingesting is idempotent',
      'A new lockfile closes the previous one, which builds real history',
    ],
  },
  {
    id: 'graph',
    nav: 'HydraDB Graph',
    kicker: 'Stage 03 · Storage',
    headline: 'Every fact becomes a graph node with its evidence.',
    plain:
      'Packages, versions, services, maintainers and incidents are stored in HydraDB, and each one points at the evidence that proves it.',
    proves:
      'Nothing enters the graph without provenance. Delete the evidence and the claim disappears with it.',
    maturity: 'live',
    hydra: 'Guarded upserts, preflight identity checks, post-write verification',
    bullets: [
      '16 node kinds, 20 relationship kinds, one derived index',
      'DEPENDS_ON is canonical; USED_BY is a derived reverse index that may never hold its own evidence',
      'Deterministic 53-bit IDs, so the same fact always lands on the same node',
    ],
  },
  {
    id: 'blast',
    nav: 'Blast Radius',
    kicker: 'Question 01 · Reach',
    headline: 'Which of our services can this reach?',
    plain:
      'Starting from the compromised package we walk the dependency graph backwards to every internal service, and show the exact chain.',
    proves:
      'A similarity search cannot answer this. It is a reverse reachability problem over a versioned graph.',
    maturity: 'live',
    hydra: 'Bounded reverse traversal over HydraDB with LIMIT + 1 and a read epoch',
    bullets: [
      'Every path is a chain of canonical DEPENDS_ON edges you can inspect',
      'Depth, fan-out and path budgets are enforced inside the query',
      'Results state their own limits and warnings',
    ],
  },
  {
    id: 'temporal',
    nav: 'Time Machine',
    kicker: 'Question 02 · Timing',
    headline: 'Who installed it while the attack was live?',
    plain:
      'Drag the timeline. We show which services had the bad version installed during the compromise window, and which did not.',
    proves:
      'Services with no recorded history are reported as unknown, never as safe.',
    maturity: 'live',
    hydra: 'asOf predicate pushed into the HydraDB traversal itself',
    bullets: [
      'Three outcomes: resolved during the window, outside it, or unknown',
      'Unknown is a first-class answer, never folded into safe',
      'Boundary cases resolve toward reporting exposure',
    ],
  },
  {
    id: 'typosquat',
    nav: 'Typosquat Radar',
    kicker: 'Question 03 · Impersonation',
    headline: 'Which names are pretending to be popular packages?',
    plain:
      'We compare installed package names against a trusted list and flag lookalikes such as a swapped letter or a hidden Unicode character.',
    proves:
      'Similarity alone is never called malicious. A finding is only escalated once a real lockfile resolved it.',
    maturity: 'live',
    hydra: 'Finding nodes with LOOKALIKE_OF and IMITATES relationships',
    bullets: [
      'Weighted edit distance, Unicode confusables and scope impersonation',
      'Score is a ranking hint, explicitly not a probability',
      'Only an authenticated analyst can confirm a finding',
    ],
  },
  {
    id: 'authority',
    nav: 'Authority Pivot',
    kicker: 'Question 04 · Shared trust',
    headline: 'What else does this attacker already control?',
    plain:
      'If a maintainer, token or CI workflow was compromised, we show every other package that same authority can publish.',
    proves:
      'Shared authority is reported as reachable, never as compromised. That distinction is kept in the wording.',
    maturity: 'engine',
    hydra: 'MAINTAINS, CAN_PUBLISH, OWNS and CAN_ACCESS traversal',
    bullets: [
      'Turns one bad package into a full list of at-risk packages',
      'Every hop is a canonical edge with evidence',
      'Results labelled authority-reachability-candidate',
    ],
  },
  {
    id: 'firewall',
    nav: 'Release Firewall',
    kicker: 'Prevention · Our differentiator',
    headline: 'Stop the bad release before it is published.',
    plain:
      'We walk backwards through the build that produced a release. If its provenance crosses a trust boundary, we block the publish.',
    proves:
      'Everything else answers how bad it was. This is the only part that can stop it happening.',
    maturity: 'engine',
    hydra: 'Separate release-influence trust graph, ecosystem agnostic',
    bullets: [
      'Verdict per release: ALLOW, QUARANTINE or BLOCK',
      'Catches poisoned caches, untrusted credentials and unattested artifacts',
      'This is the class of attack that produced the TanStack worm',
    ],
  },
  {
    id: 'containment',
    nav: 'Containment',
    kicker: 'Response · What now',
    headline: 'Simulate the fix before you ship it.',
    plain:
      'Pin a version, revoke a token or disable a workflow, and see how much of the blast radius actually disappears.',
    proves:
      'Simulation only. It models the outcome and never touches a live system.',
    maturity: 'engine',
    hydra: 'Control nodes overlaid on the graph to recompute residual paths',
    bullets: [
      'Ten control actions, from pin-dependency to revoke-credential',
      'Ranks actions by how many paths each one removes',
      'Truncated comparisons are reported as inconclusive',
    ],
  },
  {
    id: 'integrity',
    nav: 'Proof & Engine',
    kicker: 'Assurance',
    headline: 'Every guarantee has a test behind it.',
    plain:
      'Nineteen deterministic suites prove the rules hold, including the ones that must fail closed.',
    proves:
      'Claims are backed by runnable checks, not by assertion.',
    maturity: 'live',
    hydra: 'Includes the HydraDB compatibility matrix we characterised',
    bullets: [
      'Malformed graphs, tampered payloads and missing evidence all fail closed',
      'One command: npm run validate:all',
      'HydraDB OpenCypher support documented shape by shape',
    ],
  },
];

export const PIPELINE: readonly {
  readonly step: string;
  readonly label: string;
  readonly note: string;
}[] = [
  { step: '01', label: 'Collect', note: 'Registry history + real lockfiles' },
  { step: '02', label: 'Persist', note: 'Evidence-backed graph in HydraDB' },
  { step: '03', label: 'Analyse', note: 'Reach, timing, impersonation, authority' },
  { step: '04', label: 'Prevent', note: 'Block untrusted releases at publish' },
  { step: '05', label: 'Contain', note: 'Simulate the fix, measure the reduction' },
];

export const HEADLINE_STATS: readonly {
  readonly value: string;
  readonly label: string;
}[] = [
  { value: '19', label: 'Verified suites' },
  { value: '16', label: 'Graph node kinds' },
  { value: '20', label: 'Relationship kinds' },
  { value: '6', label: 'Questions answered' },
];

/** HydraDB OpenCypher support, characterised by running against v0.1.1. */
export const HYDRA_MATRIX: readonly {
  readonly shape: string;
  readonly ok: boolean;
  readonly note: string;
}[] = [
  { shape: 'UNWIND + MERGE by id + SET', ok: true, note: 'vertex upsert, special-cased' },
  { shape: 'one-hop relationship MERGE', ok: true, note: 'works with identical labels' },
  { shape: 'MATCH (r) SET r.prop', ok: true, note: 'relationship property write' },
  { shape: 'USED_BY + OPTIONAL MATCH', ok: true, note: 'our reverse traversal' },
  { shape: 'asOf temporal predicate', ok: true, note: 'time-travel filter' },
  { shape: 'MATCH (a),(b) same label', ok: false, note: 'cannot plan two same-label bindings' },
  { shape: 'WITH + count() aggregation', ok: false, note: 'WITH must pass all bindings' },
  { shape: 'UNWIND batch read', ok: false, note: 'one-hop relationships only' },
  { shape: 'unlabelled MATCH (n)', ok: false, note: 'no full scan' },
  { shape: 'non-matching MATCH', ok: true, note: 'returns one all-null row, not zero' },
];
