# Plan A — "PatchProof": Problem Plan

**Problem statement (given):** *AI-Driven Adaptive Web Application Firewall (WAF) & Vulnerability Triage — Traditional web application security systems struggle to adapt to evolving attack patterns and prioritise vulnerabilities effectively. Identifying malicious requests and addressing critical security weaknesses before exploitation remains a challenge.*

**This document:** the problem decomposition for Plan A, the exact slice of the problem Plan A owns, and the hard boundary that keeps it from overlapping Plan B (ShieldLens). It is a planning artifact, not a contract. Where it conflicts with the master prompt, the master prompt wins.

---

## 1. Decomposing the problem statement

The statement is not one problem. It is four, and they are separable:

| # | Sub-problem | Question it asks | Who owns it |
|---|---|---|---|
| **P-1** | **Adaptation to evolving attacks** | When an attacker re-encodes, re-cases, or re-locates the same payload, does the defence still hold? | **Plan A** |
| **P-2** | **Prioritisation** | Of 200 findings, which 5 actually matter? | **Plan B** |
| **P-3** | **Identification of malicious requests** | Is *this* request, right now, hostile? | **Plan B** (traffic-shape) + shared engine (signature) |
| **P-4** | **Addressing weaknesses before exploitation** | Can we close the hole, and *prove* it is closed, before someone uses it? | **Plan A** |

The shared skeleton (Part 1 of both master prompts) already answers a fifth, unstated need — *find the holes at all* — via the Recipe Runner and ZAP import. That is common ground, not a differentiator, and neither plan should pitch it as its contribution.

**The split in one line:** Plan B adapts to what *normal users* do. Plan A adapts to what *attackers* do. Both are "adaptive"; they learn from opposite distributions.

---

## 2. Plan A's problem thesis

> **A firewall rule is a hypothesis, and nobody tests it.**
>
> The industry's failure mode is not "no rule" — it is a rule that was written, looked correct, was deployed, and silently fails against the first attacker who changes an encoding. The 2026 evidence is direct: OWASP CRS shipped three critical bypass fixes on 2 Oct 2026, one of which never inspected the path even at paranoia level 4; CVE-2026-21876 let encoded XSS slip past a charset rule that checked only the last multipart segment. Classic virtual-patch evasion via path parameters, odd encodings and parser differences (Black Hat 2012) is still the template. And an LLM wrote a syntactically valid WAF rule that failed against the real exploit until it was tested.

So Plan A's problem is **P-1 + P-4 fused**: *the gap between "a rule exists" and "a rule holds under adversarial variation, and you can prove it."*

Plan A's answer is not a smarter rule generator. It is a **verification loop that attacks its own output**:

1. **Mutation Gauntlet** — systematically mutate the exploit the rule was written for (encodings, case, whitespace, comment injection, HPP, location/content-type shifts, path variants). Only mutants that *still exploit the bare app* count, so the denominator can't be inflated by broken payloads.
2. **Auto-Tighten** — if any effective mutant bypasses, derive a tighter rule (normalizer fix → scope/inspection fix → positive-security allowlist → optional LLM refinement), re-test, and keep every past bypass in a regression set so improvement is monotonic.
3. **Train/exam split** — grade the final rule on a *fresh, unseen* mutation seed. Report training and exam bypass rates separately, with Wilson 95% CIs, and refuse to make a claim when effective mutants < 30.
4. **Signed Proof Report** — a tamper-evident artifact (canonical JSON → SHA-256 → ed25519) carrying the exploit confirmation, the rule, mutation stats with CIs, benign-safety result, latency, AI involvement, and an auto-generated limitations section.

**The product category this implies:** continuous verification of firewall rules — a CI gate for WAF rules and a compliance-evidence artifact. That is a different product from "a WAF that learns your app."

---

## 3. Why this problem is worth solving (and defensible)

- **It is the failure mode the market has not closed.** Cloudflare Managed Defense (early access, Sept 2026) proposes mitigations but requires customer-authorized code access and human approval, inside Cloudflare's proxy. F5's virtual patches are locked to the F5 estate. Miggo relies on its own production sensors. Edgescan only emits rules inside Edgescan. None of them ship a portable, independently verifiable proof that a rule survives mutation.
- **It is measurable.** Bypass rate over effective mutants, with a confidence interval, on a named seed, against a named target. That is a number a judge can interrogate, unlike "AI-powered."
- **It is honest by construction.** The exam split, the effective-mutant filter, the CI, and the limitations section are all *anti-overselling* devices. They make the demo credible precisely because it can show a non-zero exam bypass rate and say so.
- **It compounds.** The mutator catalog and the regression set are the moat hypothesis: a growing corpus of attacks that beat naive patches.

---

## 4. Feature → problem mapping (what each Plan A feature is *for*)

| Plan A feature | Sub-problem served | What it proves to a judge |
|---|---|---|
| Mutation Gauntlet (`suite: mutation`) | P-1 | The rule was attacked, not just written. Bypasses are visible per-mutator. |
| Effective-mutant oracle filter | P-1 (rigor) | The bypass-rate denominator is honest; broken payloads are excluded, not counted as wins. |
| Auto-Tighten loop (`hardening_runs`) | P-1 | The system *adapts* to evasion — the literal "adaptive" claim, on the attacker's distribution. |
| Regression set | P-1 | Improvement is monotonic; no whack-a-mole. |
| Train/exam split + Wilson CI | P-1 (honesty) | The number generalises beyond the mutants it was tuned on — or we say it doesn't. |
| Patch lineage (`parent_patch_id`) | P-4 | Every tightening step is auditable root→leaf. |
| Signed Proof Report | P-4 | "Addressed before exploitation" is a verifiable artifact, not a claim. |
| Tamper demo (`/proof/verify` → `valid:false`) | P-4 | The proof is tamper-*evident*, and we show the failure case live. |
| Benchmark arms (bare / naive_canonical / shield_v1 / shield_hardened) | P-1 | The delta between "advisory-derived rule" and "hardened rule" is measured, not asserted. |

**Note on triage:** Plan A *consumes* the shared `base-v1` triage score (§8.3b) to order the findings queue. It does not extend it. Triage is Plan B's differentiator; for Plan A it is plumbing.

---

## 5. The non-overlap boundary (the important section)

Both plans share a byte-identical Part 1. Overlap is therefore only possible in Part 2. The rule is: **if a feature appears in Part 2B, Plan A does not build it — not even a "small version."**

### 5.1 Plan A MUST NOT build (owned by Plan B)

| Forbidden in Plan A | Why | Plan B's section |
|---|---|---|
| `route_profiles` table, profile builder, route templating | Traffic-shape learning is B's core | B§B-1, B§B-4 |
| `POST /profiles/rebuild`, `GET /profiles`, `GET /profiles/:id`, `POST /profiles/:id/lock` | B's routes | B§B-2 |
| `GET /internal/v1/profiles/active` | B's proxy polling | B§B-2 |
| `exposure-v1` triage model, any new triage signal | B's differentiator | B§B-3 |
| `GET /triage/compare`, `GET /findings/:id/exposure` | B's routes | B§B-2 |
| `baseline_conformance` suite | B's suite | B§B-4 |
| Promotion checklist (`GET /patches/:id/promotion`) | B's shadow→enforce gate | B§B-5 |
| `patches.source = 'baseline'` | B's lock patches | B§B-1 |
| Anomaly scoring (`packages/waf-engine/anomaly.js`), `meta.anomaly` | B's live detection | B§B-4 |
| SSE `profile.rebuilt`, `anomaly.detected` | B's events | B§B-2 |
| Learning dashboard, Route Atlas, triage waterfall, rank-shift slider | B's screens | B§B-7 |
| `TRIAGE_MODEL` env, `model_version:'exposure-v1'` | B's config | B§B-2 |

### 5.2 Plan B MUST NOT build (owned by Plan A)

Stated here so the boundary is symmetric and can be quoted back at either team:

| Forbidden in Plan B | Plan A's section |
|---|---|
| `hardening_runs`, `proof_reports` tables | A§A-1 |
| `POST /patches/:id/harden`, `GET /hardening-runs/:id`, `GET /patches/:id/lineage`, `POST/GET /patches/:id/proof`, `POST /proof/verify` | A§A-2 |
| Mutator registry, effective-mutant oracle, exam split, Wilson CI | A§A-3 |
| Auto-Tighten strategies S1–S4, regression set | A§A-4 |
| `patches.source = 'hardened'` | A§A-1 |
| SSE `hardening.progress`, `proof.created` | A§A-2 |
| Gauntlet view, Proof page, tamper toggle | A§A-7 |
| ed25519 signing, `npm run keys:gen` | A§A-5 |

### 5.3 Shared surfaces that both plans touch — collision register

These are *not* overlaps in product scope; they are shared files or shared enums where two teams can collide mechanically. Each needs a named owner and a rule, agreed at G0.

| # | Shared surface | Collision risk | Resolution |
|---|---|---|---|
| C1 | `verification_cases.suite` enum (`'mutation'`, `'baseline_conformance'`) | Both values exist in the shared DDL; each team might implement both | A implements only `mutation`; B implements only `baseline_conformance`. Neither writes the other's suite file. |
| C2 | `patches.source` enum (`'baseline'`, `'hardened'`) | Same | A writes only `'hardened'`; B writes only `'baseline'`. |
| C3 | `triage_results.model_version` (`'base-v1'`, `'exposure-v1'`) | A might be tempted to add signals | A writes only `base-v1` rows. `exposure-v1` is B-only. |
| C4 | `verify/suites/index.js` registry | Both append a line → merge conflict | **Append-only, one line each, both lines added at G0 by R2.** Nobody edits it after G0. |
| C5 | `packages/waf-engine/` | A adds path canonicalization + golden normalization tests; B adds `anomaly.js` | File-level ownership: A owns `normalize.js` + `__tests__/normalize.*`; B owns `anomaly.js`. `evaluate.js` is R1-shared and frozen after G0. |
| C6 | `benchmark_runs` table + Benchmark UI | Both write runs with different `config` shapes; UI could mix them | `config.arm_family` discriminator: `'mutation'` (A) vs `'baseline'` (B). Benchmark UI filters by family. |
| C7 | CRS container arm in benchmark | Both plans list a CRS arm as Tier 2 | **One harness, owned by R5, config-driven.** If both teams want it, it is built once and both call it. Do not build two. |
| C8 | SecLang export syntax check in the CRS container | A (Tier 2) and B (Tier 2) both want it | Same: one script, `scripts/seclang-check.js`, shared. |
| C9 | Second lab target (Log4Shell) | A lists it Tier 2; B lists it Tier 2 with nuclei import | **At most one team builds it.** Default: neither, unless the vertical slice is green by T+3:15. If built, it lands in shared `fixtures/real/` and both may use it. |
| C10 | SSE event namespace | Both add types to the same stream | Types are namespaced by prefix (`hardening.*`, `proof.*` vs `profile.*`, `anomaly.*`). No shared type names. |

**The one-sentence boundary test:** *If a judge asks "does this adapt to your app's normal traffic?", the answer must be "that's the other prototype." If they ask "does this rule survive an attacker changing the payload?", the answer must be "watch."*

---

## 6. What "solved" means — measurable success criteria

Plan A is done when all of the following are true, each backed by a stored run:

| # | Criterion | Threshold | Evidence |
|---|---|---|---|
| S1 | Gauntlet produces enough effective mutants to make a claim | E ≥ 30 on recipe R1 | `hardening_runs.iterations[].effective` |
| S2 | Hardening is monotonic | final training `bypass_rate` ≤ v1's | iteration series in `hardening_runs.iterations` |
| S3 | The rule generalises, or we say it doesn't | exam `bypass_rate` reported with CI, whatever it is | `hardening_runs.exam` |
| S4 | No over-blocking introduced by tightening | benign `fp_rate` ≤ 0.005 at every iteration | `verification_cases` + summary |
| S5 | Proof is tamper-evident | sign → verify `true`; flip one byte → `false` | `POST /proof/verify` |
| S6 | Proof is only issued on real evidence | 409 `PATCH_NOT_VERIFIED` unless status ∈ {verified, deployed}; 409/refusal if E < 30 | route behaviour |
| S7 | The delta is measured, not claimed | benchmark table with all four arms, including any arm where we lose | `evidence/benchmark-<ts>.json` |
| S8 | Determinism | same seed → identical mutant-list hash | `smoke:gauntlet` |

**Explicitly not a success criterion:** beating CRS. If the CRS arm wins on some metric, that is reported, not hidden.

---

## 7. What Plan A does not claim (write these into the UI and the pitch)

- **Not "adaptive" in the traffic-learning sense.** Plan A adapts to attacker variation, not to user behaviour. Say it before a judge does.
- **Not a production WAF.** It is a Node prototype of the control loop; the rules export to ModSecurity/Coraza, which are the production data planes.
- **Not a guarantee.** A clean exam run is evidence, not proof of safety. The report says so in its own `limitations[]` array.
- **Not a trust anchor.** The signing key is a demo key; the UI labels it "demo signing key — not a trust anchor."
- **Not a competitor benchmark.** `naive_canonical` is *our model* of an advisory-derived rule, not any vendor's product.
- **Not HTTP-layer-complete.** HTTP only, lab target only, bounded mutation catalog (state N), benign corpus is scripted user simulation (state N).

---

## 8. Build sequence mapped to the shared gates

Plan A adds work *on top of* the shared G0–G5. It does not move them.

| Phase | Shared gate | Plan A work |
|---|---|---|
| T+0:00–0:30 | — | Bring-up. R2 adds A's route stubs (`/harden`, `/hardening-runs/:id`, `/lineage`, `/proof`, `/proof/verify`) returning 501. R2 adds both suite-registry lines (C4). |
| T+0:30 | **G0** | `002_feature_a.sql` frozen. `rule.schema.json` unchanged (A adds no DSL fields — this is deliberate: A must work with the *same* rule language B uses). |
| T+0:30–1:45 | — | R3 builds mutator registry + oracle filter. R1 adds path canonicalization + golden normalization tests. R5 builds `canonical.js` and the sign/verify script. |
| T+1:45 | **G1** | A's additions: `npm run smoke:gauntlet` (E ≥ 30 on R1, same seed → same mutant-list hash); `npm run smoke:proof` (sign → verify true; tamper one byte → false). |
| T+2:00 | **G2** | Unchanged. A's S4 (LLM refinement) is Tier 2 and must not block G2. |
| T+2:15 | **G3** | Unchanged. A adds no mock data; mutators are code, not fixtures. |
| T+2:45 | **G4** | A's extra steps: (12) harden from canonical → final training bypass ≤ v1's; (13) exam stored with its own seed; (14) proof generated, verifies true; (15) tampered proof verifies false. |
| T+3:15–4:00 | — | Gauntlet UI + Proof page polish; benchmark run stored to `evidence/`. |
| T+4:00 | **N10** | Feature freeze. |
| T+4:15 | **G5** | 3 consecutive clean runs from a fresh DB. |

**Cut order if behind (from A§A-9):** chunked mutator → regression-set persistence in DB (keep in memory) → proof PDF styling → CRS arms → S4 LLM refinement → SecLang syntax check → Log4Shell target.

---

## 9. Demo narrative tied to the problem (4 minutes)

The demo must *show the problem* before it shows the solution.

1. **20 s — the problem, concretely.** "Every WAF vendor will tell you they block SQL injection. Here is a rule that blocks it." Fire the canonical payload → 403. "Here is the same attack, URL-encoded twice." → 200, data leaks. "That is the gap. The rule was never attacked."
2. **Bare app.** Fire recipe R1 → data leaks. This is the ground truth.
3. **Findings queue.** Real ZAP noise + the confirmed exploit floating to P0 (shared `base-v1` triage — do not pitch this as ours).
4. **Gauntlet on canonical v1.** The grid fills; red bypasses appear. Show the per-mutator breakdown: *which* encoding got through. Use the real numbers.
5. **Harden.** Iterations tick down; show the rule diff; benign replay stays at 0 blocked; exam runs on unseen mutants. **If exam bypass > 0, say so out loud.**
6. **Deploy enforce.** Re-run the exploit → 403. Live event feed.
7. **Proof page.** Signature valid → tamper → invalid. Read the limitations aloud.
8. **20 s close.** "Continuous verification of firewall rules: a CI gate and a compliance artifact. Vendor-neutral, black-box, portable."

The emotional beat is step 1 → step 4: the audience watches a rule they just saw "work" fail, then watches it get fixed and *proven* fixed.

---

## 10. Plan A risk register (beyond the shared §15)

| Risk | Impact | Mitigation |
|---|---|---|
| **Mutants don't reproduce on the bare app** → E < 30 → no claim allowed | Kills the headline number | Validate each mutator family against R1 by T+1:00; if a family yields no effective mutants, drop it from the catalog and state the reduced N. Never lower the E ≥ 30 bar. |
| **Auto-tighten overfits to the training mutants** | Exam looks bad on stage | That is the honest story, not a failure. The exam split exists to surface it. Rehearse the "exam bypass > 0" line. |
| **Tightening breaks benign traffic** | fp_rate > 0.005 → gate fails | S3 (positive-security switch) is the highest-risk strategy; it must re-run the benign gate before being accepted. Prefer S1/S2. |
| **Rule DSL can't express the fix** | Tightening stalls | The DSL is frozen and shared with B — do not add fields. If a bypass needs a new normalizer, that is a CCR to the Owner, not a unilateral change. |
| **Proof signing key handling** | Demo breaks on stage | `keys/` gitignored; generate at bootstrap; public key shown in UI; label as demo key. |
| **Scope creep into B's territory under time pressure** | Overlap, duplicated work, confused pitch | §5.1 is a hard list. If someone proposes a profile or an exposure signal, the answer is "that's B." |
| **Benchmark arms take longer than the feature** | No stored evidence at G5 | Benchmark is Tier 1 but *last*; the four-arm table can run on a reduced mutation budget if needed — state the budget. |

---

## 11. One-paragraph summary for the Owner agent

Plan A owns sub-problems P-1 (adaptation to evolving attacks) and P-4 (addressing weaknesses before exploitation, with proof). Its thesis is that the industry's failure is unverified rules, not missing rules, and its product is a verification loop that mutates its own exploit, tightens the rule until effective mutants stop bypassing, grades the result on an unseen seed with confidence intervals, and emits a signed, tamper-evident proof report. It consumes the shared skeleton and the shared `base-v1` triage unchanged. It must not build traffic profiling, exposure scoring, anomaly detection, baseline locks, or promotion checklists — those are Plan B. The boundary test is: Plan B adapts to normal traffic; Plan A adapts to attacker variation. Shared files (suite registry, waf-engine, benchmark table, CRS arm, second target) are governed by the collision register in §5.3, agreed at G0.
