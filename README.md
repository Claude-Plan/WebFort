# WebFort 🛡️

> **AI-Driven Adaptive Web Application Firewall (WAF) & Vulnerability Triage**  
> *Continuous Firewall Rule Verification, Mutation Gauntlet & Tamper-Evident Proof Reports (Plan A — "PatchProof")*

---

## 📌 Problem Statement

> *Traditional web application security systems struggle to adapt to evolving attack patterns and prioritise vulnerabilities effectively. Identifying malicious requests and addressing critical security weaknesses before exploitation remains a challenge.*

### The Problem Decomposition

The problem statement encompasses four distinct challenges:

| # | Sub-Problem | Core Question | Ownership |
|---|---|---|---|
| **P-1** | **Adaptation to Evolving Attacks** | When an attacker re-encodes, re-cases, or re-locates a payload, does the defence hold? | **Plan A (PatchProof)** |
| **P-2** | **Prioritisation** | Out of hundreds of vulnerability findings, which critical items matter right now? | **Plan B (ShieldLens)** |
| **P-3** | **Identification of Malicious Requests** | Is this specific inbound traffic request hostile? | **Plan B** (traffic-shape) + Shared Engine (signatures) |
| **P-4** | **Addressing Weaknesses Before Exploitation** | Can we close the security hole and cryptographically *prove* it is closed before exploitation? | **Plan A (PatchProof)** |

**The Core Distinction:**  
Plan B adapts to what *normal users* do (traffic baseline & anomaly detection). **Plan A adapts to what *attackers* do (adversarial variation & mutation verification).**

---

## 💡 Plan A Thesis: "PatchProof"

> *"A firewall rule is a hypothesis, and nobody tests it."*

In modern application security, the most dangerous failure mode is not having "no rule" — it is deploying a rule that appears correct on paper but silently fails when an attacker introduces encodings, path parameter tricks, or parser differential quirks. Naive or LLM-generated rules frequently fail under adversarial variations unless subjected to automated, systematic verification.

Plan A solves **P-1 + P-4 fused**: **closing the gap between "a rule exists" and "a rule holds under adversarial variation, with verifiable proof."**

---

## ⚙️ Core Architecture & Capabilities

```
+-----------------------------------------------------------------------------------+
|                                  WebFort Engine                                   |
+-----------------------------------------------------------------------------------+
                                         │
                   1. Vulnerability Ingestion & Exploitation
                                         ▼
                   +────────────────────────────────────────+
                   | Recipe Runner & ZAP Import (base-v1)   |
                   +────────────────────────────────────────+
                                         │
                                2. Verification Loop
                                         ▼
                   +────────────────────────────────────────+
                   |           Mutation Gauntlet            |
                   |  - Encodings, Case, Whitespace, HPP    |
                   |  - Effective-Mutant Oracle Filter      |
                   +────────────────────────────────────────+
                                         │ (Bypasses detected)
                                         ▼
                   +────────────────────────────────────────+
                   |           Auto-Tighten Loop            |
                   |  - S1: Normalizer fix                  |
                   |  - S2: Scope / Inspection fix          |
                   |  - S3: Positive-security allowlist     |
                   |  - S4: Guided LLM refinement           |
                   |  - Monotonic regression test suite     |
                   +────────────────────────────────────────+
                                         │
                             3. Generalisation Check
                                         ▼
                   +────────────────────────────────────────+
                   |         Train / Exam Split             |
                   |  - Tested on unseen mutation seeds     |
                   |  - Wilson 95% Confidence Intervals     |
                   +────────────────────────────────────────+
                                         │
                               4. Verifiable Evidence
                                         ▼
                   +────────────────────────────────────────+
                   |       Signed Proof Report              |
                   |  - Canonical JSON -> SHA-256 -> ed25519|
                   |  - Tamper-evident verification         |
                   +────────────────────────────────────────+
```

### 1. Mutation Gauntlet (`suite: mutation`)
Systematically attacks candidate WAF rules with mutation families:
- Multi-layer URL encodings, hex, and unicode escapes
- Casing variations, whitespace padding, and comment injections
- HTTP Parameter Pollution (HPP) and parameter relocation
- Content-Type / multipart manipulation and path canonicalization anomalies
- **Effective-Mutant Oracle Filter:** Verifies that mutants still exploit the bare target before counting them, ensuring the bypass denominator cannot be gamed by broken payloads.

### 2. Auto-Tighten Hardening Loop (`hardening_runs`)
When a mutation slips through a naive rule:
- Iteratively applies tightening strategies (Normalizer correction $\rightarrow$ Scope/inspection fix $\rightarrow$ Positive-security allowlist $\rightarrow$ Refinement).
- Preserves every historical bypass in a monotonic regression set to prevent regression ("whack-a-mole").
- Enforces benign replay gating (ensuring false positive rate $\text{FP} \le 0.005$).

### 3. Train / Exam Split & Wilson Confidence Intervals
- Measures performance on training mutants, then validates against a fresh, completely unseen mutation seed.
- Accurately reports training vs. exam bypass rates alongside Wilson 95% Confidence Intervals, refusing to overstate confidence when effective mutants $E < 30$.

### 4. Signed Tamper-Evident Proof Report
- Produces a verifiable compliance & security artifact (Canonical JSON $\rightarrow$ SHA-256 hash $\rightarrow$ ed25519 digital signature).
- Endpoints allow instant verification (`POST /proof/verify`), returning `valid: true` for authentic certificates and immediately flagging single-byte tampering.

---

## 📊 Success Criteria & Evaluation Standards

WebFort Plan A is evaluated against strict, quantifiable metrics:

- **S1 (Sufficient Power):** Effective mutants $E \ge 30$ on test recipes.
- **S2 (Monotonic Hardening):** Final training bypass rate is strictly less than or equal to initial version $v_1$.
- **S3 (Honest Generalisation):** Exam bypass rate reported with 95% Wilson CI.
- **S4 (Benign Traffic Safety):** Benign false positive rate $\text{FP} \le 0.005$ across all iterations.
- **S5 (Tamper Evident):** Cryptographic verification validates legitimate proofs and fails on tampered payloads.
- **S6 (Gated Issuance):** Proof certificates are issued only when verified status and $E \ge 30$ are met.
- **S7 (Four-Arm Benchmark):** Measured comparison across:
  1. Bare Application
  2. Naive Canonical Rule
  3. Shield $v_1$ (Baseline)
  4. Shield Hardened (Auto-tightened)
- **S8 (Determinism):** Identical seeds yield identical mutant-list hashes.

---

## 🛠️ Technology Stack & Shared Boundaries

- **Runtime & Backend:** Node.js, Express, SQLite / PostgreSQL
- **Signatures & Crypto:** ed25519 digital signatures, canonical JSON hashing
- **WAF Export Targets:** ModSecurity / Coraza SecLang rules
- **Testing & Verification:** Custom Mutation Runner, ZAP format ingestor

### Plan A vs. Plan B Ownership

```
               ┌───────────────────────────────────────────────┐
               │           Shared Foundation (Part 1)          │
               │  - Recipe Runner & ZAP Ingestion              │
               │  - base-v1 Triage Scoring                     │
               │  - Core WAF Rule DSL & Engine                 │
               └──────────────────────┬────────────────────────┘
                                      │
               ┌──────────────────────┴────────────────────────┐
               ▼                                               ▼
   ┌───────────────────────┐                       ┌───────────────────────┐
   │  Plan A: PatchProof   │                       │  Plan B: ShieldLens   │
   ├───────────────────────┤                       ├───────────────────────┤
   │ • Mutation Gauntlet   │                       │ • Route Profiles      │
   │ • Auto-Tighten Loop   │                       │ • Traffic Profiling   │
   │ • Regression Sets     │                       │ • Anomaly Scoring     │
   │ • Train/Exam Split    │                       │ • exposure-v1 Triage  │
   │ • Signed Proof Report │                       │ • Shadow/Enforce Gate │
   └───────────────────────┘                       └───────────────────────┘
```

---

## 🚀 Getting Started

### Prerequisites
- Node.js (v18+)
- npm or pnpm

### Quick Setup
```bash
# Clone the repository
git clone https://github.com/Claude-Plan/WebFort.git
cd WebFort

# Generate cryptographic keys
npm run keys:gen

# Run smoke tests
npm run smoke:gauntlet
npm run smoke:proof
```

---

## 📄 License

This project is licensed under the terms specified in the [LICENSE](file:///d:/Mohan%20files/WebFort/LICENSE) file.
