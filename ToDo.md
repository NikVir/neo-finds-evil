# ToDo — VIGÍA Integration & Accuracy Benchmarking

**Audience:** any team member picking up the next phase of `neo-finds-evil`.
**Assumes:** you have NOT been part of the earlier discussion. Everything you need
is below. Read top to bottom once before doing anything.

**This document does not contain a schedule.** Items are ordered by priority and
by what depends on what, not by date. Do them in the order listed unless you have
a reason not to.

---

## CURRENT STATE — what's actually left (updated 2026-06-09)

**Read this section first.** The numbered work items further down (§§3–6) are the
*original* plan and are kept for their build detail, but several are now finished —
this section is the honest at-a-glance picture so you don't redo completed work.
Same framing as the rest of the doc: no schedule, ordered by priority and by what
unblocks what.

### DONE (verified present in the repo)

- **MCP server + tests** — `src/forensics/`; `forensics-graph` exposes the 5
  read-only tools; the full test suite is green.
- **Accuracy report incl. the VIGÍA benchmark** — `docs/accuracy-report.md`
  (§6 "Benchmark: vigia-cases"); deterministic scorer `tools/vigia_score.py` with
  `tests/test_vigia_score.py`; raw blind verdicts + report JSON under
  `docs/benchmark/`. **This is Work Item 1 *and* Work Item 2 — both complete
  (see §§3–4).**
- **Submission compliance table + judge runbook** — `README.md` §"Submission
  compliance".
- **Evidence-dataset doc** — `docs/evidence-dataset.md`.
- **Architecture diagram** — `docs/architecture.png` + editable
  `docs/architecture.svg`.
- **Apache-2.0 license** — `LICENSE`.
- **Cold-clone "judge test"** — a first-time judge followed the README runbook
  literally on a fresh clone; report at `~/judge-test-report.md` (**outside the
  repo**, read-only dry-run). It confirmed that **once the graph is restored, the
  headline cross-host capability genuinely works for a first-time user** (`uv sync`,
  node-count sanity check `359788`, MCP `✔ Connected` with all 5 tools, the `spsql`
  6-host correlation, and the `get_event` traceback all succeeded). It also surfaced
  the doc gaps captured in (a)/(b) below.

### REMAINING — the real priority order

These are guaranteed-scored or unblock other items, so they come **before** the
additive work in §§5–6. Do them in this order.

**(a) GitHub flip + publish the graph release asset `graph-srl2018.tar.gz` —
HIGHEST.** The judge test proved the runbook is **non-reproducible without this
asset**: README Step 3 tells the reader to download `graph-srl2018.tar.gz`, which is
currently *pending / unpublished*, so a true cold clone dead-ends before there is
any graph to query. Publishing the repo to GitHub and attaching this release asset
(with the real `gh release download` command wired into Step 3) is the single
highest-value remaining task. The §7 integrity issue to file for Anna also waits on
this flip.

**(b) Small README fixes surfaced by the judge test** (all sourced from
`~/judge-test-report.md`):
- Note that the **restored data dir already carries credentials**, so `NEO4J_AUTH`
  is **ignored on restore** (the password is baked into the backup's
  `dbms/auth.ini`; changing it needs an in-DB `ALTER USER`, not just editing
  `NEO4J_AUTH`).
- State that the **`forensics-graph` MCP server runs independently of Protocol
  SIFT** (the graph layer works without the Step 1 install).
- Make the **`spsql` example self-contained**: give the actual working query
  (`spsql` is a `targetUser` property on `WindowsEvent`, *not* a `UserAccount`; the
  obvious `failed_logons` hunt is buried under `BASE-HUNT$` noise), and frame the
  agent's schema-probe as **intended self-correction**, not a doc gap.
- **Drop the unnecessary Node.js prerequisite** (Claude Code is a self-contained
  binary here; every step worked without Node).

**(c) Demo video (<5 min).** Must show a **self-correction** moment — candidates:
the `df0398a` missing-`imagePath` recovery (accuracy report), or the `spsql` schema
self-correction from the judge test. Wire the link into the README compliance
table's "Demonstration video" row.

**(d) Devpost write-up.**

### Then — additive, only with room to spare (below (a)–(d))

- **Work Item 3 — verdict/adjudication output layer (§5): VIABLE / unblocked.**
  Item 2 landed well, so this is no longer conditional — but it is **additive polish
  that sits BELOW the guaranteed-scored deliverables above.** The build guidance in
  §5 still stands.
- **Work Item 4 — case-file export bridge (§6): stretch goal, unchanged.**

---

## 0. Where the project stands (one screen of context)

`neo-finds-evil` is our SANS **FIND EVIL!** hackathon submission. What it does
today:

- Takes raw forensic evidence (disk + memory images, EVTX, etc.) from a 7-host
  Windows intrusion case (SRL-2018 / SHIELDBASE, the SANS FOR508 scenario).
- Ingests it into a **Neo4j correlation graph** (~360k nodes, ~1.9M relationships)
  via an out-of-band pipeline.
- Exposes that graph to a Claude Code agent through a **read-only MCP server**
  (`forensics-graph`) with five tools: `list_hunts`, `run_hunt`,
  `get_host_summary`, `get_event`, `query_graph`. The server is **architecturally
  read-only** — it registers no write tool, and the one free-form query path runs
  inside a Neo4j READ transaction the driver itself refuses to let write.
- The agent then reasons **across hosts and across time** (lateral movement,
  credential-theft chains, cross-host tool reuse) — correlation that single-tool
  forensic outputs cannot express.

**This is our differentiator: cross-host/time correlation as an extension of
Protocol SIFT** (which gives the agent per-artifact tools but no memory across
hosts). The repo already contains: the MCP server + tests, an architecture
diagram, an accuracy report, an evidence-dataset doc, an execution-log sample, a
judge runbook README, and an Apache-2.0 license.

**What this ToDo adds:** a second dimension the current submission does not yet
have — **intentionality adjudication and accuracy benchmarking** — by engaging
with a community asset called **VIGÍA**. The rest of this document explains what
VIGÍA is and exactly what to build.

---

## 1. What VIGÍA is (and what it is NOT)

VIGÍA is a body of work by **Anna Tchijova**, shared in the hackathon Slack and
endorsed by Rob T. Lee (the hackathon organiser) as a scoring template. It comes
in TWO public repositories. We have both as zips; the live versions are on GitHub.

### 1a. `vigia-cases` — a DFIR benchmark dataset (THE IMPORTANT ONE)

Repo: `github.com/annatchijova/vigia-cases` · License: **Apache-2.0**

A set of **10 real forensic cases** converted to a canonical JSON format for
benchmarking "forensic intent analysis" agents. Each case lives in
`cases/VIGIA-REAL-0NN/` and has three files:

| File | What it is | Who reads it |
|---|---|---|
| `case.json` | The incident descriptor + a list of curated **artifacts** (the agent's INPUT). **Contains no answers.** | The agent |
| `ground_truth.json` | The canonical **verdict** (MALICE / SUSPICION / BENIGN), a confidence threshold, MITRE ATT&CK TTPs, key IOCs, a Peirce classification, and a `null_hypothesis` (the devil's-advocate reading). | The scorer only — **never the agent** |
| `manifest.json` | Per-file SHA-256 hashes for integrity. | Verification |

Plus, at the repo root: `index.json` (all cases + tiers), `SCORING_GUIDE.md`
(metrics + report format), `hashes.sha256` (repo integrity), `LICENSE`, `README.md`.

**Critical conceptual point:** a `case.json` artifact list is a **curated
abstraction** — Anna hand-extracted the forensically relevant signals from each
raw case. It is NOT the raw evidence. So "scoring an agent on `case.json`"
measures **verdict reasoning over pre-digested artifacts**, not evidence
processing at scale. (This matters — see §4.)

### 1b. `vigia` — the explainer / philosophy site (NOT the engine)

Repo: `github.com/annatchijova/vigia-intent-analysis` is the real engine
(`run_case.py`, etc.). **We do NOT have the engine code** — the zip labelled
"vigia-main" turned out to be four HTML files: a polished trilingual explainer
website (`vigia.html` EN, `vigia-es.html` ES, `vigia-ru.html` RU) plus
`mutante.html` (a separate adversarial/jailbreak-evaluation tool).

The site documents VIGÍA's design: deterministic decimal arithmetic (no
floating-point, reproducible byte-for-byte), an 8-state verdict cascade, a
risk functional where **ABSTAIN is a first-class named outcome**, a causal-closure
veto, ENFSI likelihood-ratio scoring, and an epistemology grounded in Peirce
(signs/abduction), Eco (limits of interpretation), Grice (cooperative maxims),
and Daubert/ENFSI (admissibility). The math is implemented live in the page's
JavaScript as interactive demos, so the protocol is real — but **demo-scale, and
the runnable engine is not in our possession.** Do not assume engine behaviour
from the marketing pages.

**Do not spend time on MUTANTE.** It is jailbreak-evaluation tooling, tangential
to our submission. Our guardrail-bypass story is already covered by the MCP
server's existing bypass-battery test.

---

## 2. Why this matters — the two systems are complementary halves of one pipeline

`neo-finds-evil` and VIGÍA solve **different layers** of the same problem:

- **`neo-finds-evil`** answers *"what happened and how is it all connected?"* —
  raw evidence → correlation graph → cross-host findings, with traceability back
  to source artifacts. It STOPS at findings. It does not emit a formal verdict.
- **VIGÍA** answers *"was this malicious, how confident are we, and could we be
  wrong?"* — it adjudicates **intent** over already-curated artifacts and outputs
  a verdict + confidence + TTPs, with abstention when uncertain. It does NOT
  process raw evidence or correlate at scale (Anna curates the artifacts by hand).

So the full community pipeline looks like:

```
raw evidence → extraction → CORRELATION (us) → curated findings → INTENT ADJUDICATION (VIGÍA)
```

We own the left half; VIGÍA owns the right half. This is the lens for everything
below: we are not competing with VIGÍA, we are **benchmarking against its dataset**
and **optionally borrowing its verdict vocabulary** to make our own output sharper.

Relevant judging criteria this engages (all equally weighted in the official
rules): **IR Accuracy** ("are findings correct? hallucinations caught and flagged?
confirmed findings distinguished from inferences?"), **Breadth/Depth of Analysis**,
and **Audit Trail Quality**. Honesty is explicitly rewarded over perfection.

---

## 3. WORK ITEM 1 — Submission compliance table in the README (do first, it's a hard gate)

> **STATUS: ✅ DONE** (committed `89c194b`). `README.md` now has a "Submission
> compliance" section mapping each required component to its exact location. The
> guidance below is kept for reference. Remaining parenthesised cells (repo URL,
> demo-video link) fill in as part of the (a)/(c) items in the current-state
> section above.

**Why:** Rob T. Lee warned in Slack that ~20% of projects in the last hackathon
were **eliminated** for missing a required component (often just the open-source
license file). He asked every team to put a table in the README mapping each
required submission component to its exact location, so judges can verify
completeness in seconds.

**What to do:** add a "Submission Compliance" section near the top of the repo
`README.md` — a table with one row per required component and a link to where it
lives:

| Requirement | Location |
|---|---|
| Public code repository | (repo URL) |
| Open-source license (MIT/Apache-2.0) | `LICENSE` |
| README with setup instructions | this file, §Setup |
| Run instructions for judges | this file, §Setup/Run |
| Text description of features | this file + `docs/` |
| Demonstration video | (YouTube/Vimeo link) |
| Architecture diagram | `docs/architecture.png` |
| Evidence Dataset Documentation | `docs/evidence-dataset.md` |
| Accuracy Report | `docs/accuracy-report.md` |
| Agent Execution Logs | `docs/execution-logs/` |

Fill in the parenthesised items as they become available. This is low-effort and
removes the single dumbest way to lose. It does not depend on any VIGÍA work.

---

## 4. WORK ITEM 2 — Benchmark our agent against `vigia-cases` (the main task)

> **STATUS: ✅ DONE** (committed `4e7856b`). Section "Benchmark: vigia-cases" is in
> `docs/accuracy-report.md`; the deterministic scorer is `tools/vigia_score.py`
> (tests in `tests/test_vigia_score.py`); the blind per-case verdicts and the report
> JSON are under `docs/benchmark/`.
>
> **Results — score_against tier (VIGIA-REAL-001 / 002 / 007, all truth MALICE):**
> - **Verdict Accuracy 100% (3/3)**, **FPR 0%**, **FNR-MAL 0%** — all PASS their
>   `SCORING_GUIDE.md` thresholds.
> - **TTP Coverage: 14.3% exact / 42.9% family — FAILED the ≥60% bar.** Reported
>   honestly: the misses are parent-vs-subtechnique granularity (e.g. agent `T1566`
>   vs canonical `T1566.001`) plus defensible-but-divergent technique selection, not
>   wrong verdicts.
> - **Specificity gate VIGIA-REAL-005: PASS** — the agent emitted `SUSPICION` and did
>   **not** over-call `MALICE`. Reported separately, never folded into the headline.
>
> **Method notes for whoever maintains this:** the result is committed; the eval
> working dirs (`~/vigia-eval`) stay **outside** the repo; and the `vigia-cases`
> dataset is **NOT vendored** — it is cited by URL + cloned commit `5453805`. The
> isolation discipline (agent never sees `ground_truth.json`) is described in the
> report's methodology block.
>
> The build guidance below is kept for reference / re-runs.

**Why:** this produces a community-standard, source-backed accuracy report section
using the exact dataset and metrics the organiser pointed teams at. It directly
feeds the IR Accuracy judging criterion, and it is one of the hackathon's officially
encouraged project patterns ("accuracy benchmarking framework").

**What "benchmarking" means here, concretely:** for each scored case, give the
agent the `case.json` artifacts, ask it to emit a **verdict + confidence + MITRE
TTPs**, then compare to `ground_truth.json` and compute the metrics. Note this
exercises the agent's **reasoning over curated artifacts** — it does not need our
Neo4j graph at all (the cases are small JSON). That's fine and expected; it's a
distinct, complementary evaluation from our graph-correlation demo.

### Which cases to run

From `index.json` / `README.md`, the tiers are:

- **score_against** (the ONLY tier valid for headline accuracy claims):
  - `VIGIA-REAL-001` NIST Hacking Case (verdict MALICE)
  - `VIGIA-REAL-002` NIST Data Leakage (verdict MALICE)
  - `VIGIA-REAL-007` Nitroba Harassment (verdict MALICE) — strongest case, hashes confirmed
- **build_and_test** (report SEPARATELY; note training-data risk):
  - `VIGIA-REAL-005` Encrypt Them All — **THE FALSE-POSITIVE GATE, see below**
  - `VIGIA-REAL-003` Ali Hadi Web Server
  - `VIGIA-REAL-009` DFRWS 2008 Linux
- **practice_only** (`004`, `006`) and **not_ready** (`008`, `010`): do NOT use
  for accuracy claims.

Run the **3 score_against cases plus VIGIA-REAL-005** (the gate). Optionally run
the rest of build_and_test in a clearly-separated section.

### The metrics (from `SCORING_GUIDE.md`)

Primary, with the dataset's own thresholds: **Verdict Accuracy ≥80%** (score_against
only), **FPR ≤20%**, **FNR-MAL ≤10%** (malicious mis-classified as benign),
**TTP Coverage ≥60%**. Secondary: Peirce alignment, IOC recall, abstention rate.
Emit results in the report-JSON format defined at the bottom of `SCORING_GUIDE.md`
and drop it into `docs/accuracy-report.md`.

### THREE non-negotiable rules when running this

1. **Never let the agent see `ground_truth.json`.** It sits in the same directory
   as `case.json`. If you run the agent anywhere it can read the filesystem (e.g.
   Claude Code with the repo checked out), it could read the answers and the
   benchmark becomes worthless. **Isolate the `case.json` files** into a separate
   working directory the agent is pointed at, with no ground-truth files present.
2. **State the training-data caveat honestly.** The NIST cases especially are
   heavily documented across the public internet, so the model may **recall** the
   answer rather than **reason** to it — you cannot tell which. Rob explicitly said
   to say so in the accuracy report. Write it plainly: for score_against NIST cases,
   note "cannot distinguish reasoned from recalled." Our own SRL-2018 case is also
   the FOR508 scenario and documented online — same caveat applies wherever we cite it.
3. **VIGIA-REAL-005 is the specificity gate, and it is the most important single
   case.** Its ground truth is **SUSPICION, not MALICE**, on purpose — multiple
   encryption layers can be legitimate personal security. The agent **passes only
   if it emits SUSPICION** (or abstains appropriately); firing MALICE is an
   automatic fail, no partial credit. An agent that correctly *declines to
   over-call* here is the single best honesty artifact we can produce — it pairs
   directly with our existing "ATTEMPTED vs CONFIRMED" SAM-theft story in the
   accuracy report.

### Deliverable

A new section in `docs/accuracy-report.md`: the report JSON, a short prose summary
of how we scored, the training-data caveat, and an explicit call-out of the -005
specificity result. Cite the dataset (see §6).

---

## 5. WORK ITEM 3 — A verdict/adjudication output layer (VIABLE / unblocked — additive polish)

> **STATUS: VIABLE / unblocked.** This was originally conditional on Item 2 landing
> well; Item 2 (§4) landed well, so the condition is met. **But priority-wise it is
> ADDITIVE polish and sits BELOW the guaranteed-scored deliverables** — see items
> (a)–(d) in the "CURRENT STATE" section at the top. Build it only with room to
> spare. The build guidance below is unchanged and still applies.

**Why:** today our agent produces an investigative *narrative*. VIGÍA's framing
shows the next step up: an *adjudicated* output with a formal verdict. Adding this
strengthens the "analytical reasoning — structured investigative narrative, not a
raw execution log" requirement and the "confirmed vs inferred" criterion.

**What to build — and what NOT to build.** Do **NOT** try to reimplement VIGÍA's
Protocol P2 math engine (deterministic decimal arithmetic, 22 canonical vectors,
etc.) — that is Anna's substantial work, it isn't in our possession, and there
isn't room to redo it well. Instead, add a **lightweight final-adjudication stage**
to our own investigation output: when the agent concludes, it emits a structured
object containing:

- `verdict` ∈ {MALICE, SUSPICION, BENIGN, ABSTAIN}
- `confidence`
- `mitre_ttps`
- the `null_hypothesis` it considered (the devil's-advocate reading it ruled out
  or couldn't)
- per-claim **confirmed-vs-inferred** status (we already make this distinction in
  prose; this formalises it)

Make the JSON **shape-compatible with VIGÍA's `ground_truth.json`** where sensible,
so our output and the benchmark speak the same language. This is mostly a
prompt + output-schema change, plus possibly one small template; it is not a new
engine. Keep ABSTAIN as a real, available outcome — abstaining when evidence is
insufficient is rewarded, not penalised.

---

## 6. WORK ITEM 4 — Case-file export bridge (stretch goal only — do not start unless 1–3 are done with room to spare)

**The idea:** a tool that converts one of our graph investigations into a VIGÍA
`case.json` — i.e. our system **auto-generates** the curated artifact descriptors
that Anna currently produces by hand. This is the genuinely novel integration:
*"neo-finds-evil is the missing automated front-end to VIGÍA; VIGÍA is the missing
verdict back-end to neo-finds-evil."* It is a strong write-up line and a real
contribution to the community pipeline.

It is also the largest and least certain piece, so it is explicitly a stretch
goal. Note the Tdungan VIGIA file Anna posted in Slack (same SHIELDBASE/FOR508
family as our case) shows where her schema is heading — per-artifact
`provenance_chain`, `raw_score`, `prior_trust`, `acquisition_tool`. Our
`get_event` tool already provides exactly that provenance chain, which is why this
bridge is feasible at all. If you build it, target that richer schema.

---

## 7. Caveats, attribution, and one good-faith contribution

- **Attribution is mandatory.** VIGÍA is Anna Tchijova's published work under
  Apache-2.0. Wherever we benchmark against, cite, or borrow vocabulary from it,
  credit it. Use the citation block at the bottom of `vigia-cases/SCORING_GUIDE.md`
  (Tchijova, A. (2026). vigia-cases ...). Same principle by which we credit Rob
  Lee for Protocol SIFT — crediting upstream work is correct, not optional.
- **Integrity nit worth reporting back — STILL OPEN, re-confirmed 2026-06-09
  during the benchmark run:** when you run `sha256sum --check hashes.sha256` in
  `vigia-cases` (cloned commit `5453805`), every case and ground-truth file verifies
  EXCEPT `README.md`, which fails — almost certainly because the README was edited
  (a contributor-credit section added) after the hash file was generated. It's
  benign, but a stale hash in an integrity-focused benchmark is worth a friendly
  GitHub issue to Anna. **File it when we flip to GitHub** (it pairs with item (a)
  above) — cheap, genuine community engagement in a Slack the judges read.
- **Don't conflate the layers in the write-up.** Be precise that the VIGÍA
  benchmark measures verdict reasoning over *curated artifacts*, while our graph
  demo measures *cross-host correlation over raw-scale evidence*. They are two
  different, complementary evaluations. Claiming the benchmark validates the graph
  engine (or vice versa) would be inaccurate and a judge would catch it.
- **The VIGÍA engine code is not ours.** We have the benchmark (`vigia-cases`) and
  the explainer site only. Don't reference engine internals we can't run.

---

## 8. Quick reference — files you'll touch / read

- `vigia-cases/cases/VIGIA-REAL-0NN/case.json` — agent inputs (isolate before running)
- `vigia-cases/cases/VIGIA-REAL-0NN/ground_truth.json` — answers (scorer only)
- `vigia-cases/SCORING_GUIDE.md` — metrics, thresholds, report JSON format
- `vigia-cases/index.json` — tier assignments
- `docs/accuracy-report.md` — where the benchmark results go (Item 2)
- `README.md` — where the compliance table goes (Item 1)
- our MCP server: `src/forensics/mcp_server.py` — if Item 3 touches output schema

If anything here is unclear, the original analysis that produced this document
went through both VIGÍA repos file-by-file; ask whoever has that context before
guessing.
