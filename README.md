# PATCHPROOF 🛡️

> **AI-Driven Adaptive Web Application Firewall (WAF) & Vulnerability Triage**  
> *Continuous Firewall Rule Verification, Mutation Gauntlet & Tamper-Evident Proof Reports*  
> **Hackathon:** RNSIT CSE (Cyber Security), 5th sem · 17 Nov 2026 · Problem Statement 3

---

## ⚡ The One-Paragraph Pitch

A website has holes. A scanner finds them but buries the team in noise. A firewall could block attacks, but nobody has time to write precise rules, and nobody can tell if a hand-written rule actually works or breaks real users. **PatchProof is a security engineer in a box:** it attacks a lab app to find and prove holes, ranks what matters with transparent deterministic scoring, writes a virtual patch rule, **attacks the rule itself with mutated exploits in the Mutation Gauntlet**, **auto-tightens** it until it survives, grades it on an unseen exam set, deploys it to the live proxy, and issues an **ed25519-signed proof report**. The LLM (Ollama, local) only drafts explanations — it is never in the request path and never decides a verdict.

---

## 🚀 Quick Start (One Command)

```bash
cd WebFort
npm install
npm run dev
```

This starts all four services automatically:
1. **Lab Target (Juice Shop Replica):** `http://localhost:3001`
2. **API Control Plane:** `http://localhost:4000`
3. **Data-Plane Proxy (WAF):** `http://localhost:8080`
4. **React Security Console:** `http://localhost:5173`

To run the automated verification test covering the entire vertical slice:
```bash
node scripts/test-vertical-slice.js
```

---

## 🏛️ Architecture & Data-Plane

```
 attacker / curl / browser
            │
            ▼
 ┌─────────────────────┐   allow   ┌──────────────────────────┐
 │ Proxy :8080         │ ────────▶ │ Juice Shop Target :3001  │ (Victim App)
 │ (Data-Plane Engine) │           └──────────────────────────┘
 └──────────┬──────────┘
            │ events (fire-and-forget)
            │ ▲ rules (poll every 2s, ETag cache)
            ▼ │
 ┌──────────────────────────────────────┐        ┌──────────────────────┐
 │ API Control Plane :4000              │ ─────▶ │ Postgres / Embedded  │
 │ findings·triage·patches·gauntlet·    │        └──────────────────────┘
 │ harden·proof·benchmark               │
 └──────────────────┬───────────────────┘
                    │                 └────────▶ Ollama :11434 (Advisor only)
                    ▼
 React Web Console :5173 (Dark Security-Console UI)
```

---

## 💎 Five Demo Screens

1. **Command Center (`/`):**
   - Live health monitors (DB, Ollama, Proxy :8080, Juice Shop :3001)
   - Allow / Block counters and engine latency meter (p50: 0.45 ms, p95: 1.18 ms)
   - One-click trigger for Recipe R1 (Product Search UNION SQLi) and Recipe R2 (Login Auth Bypass SQLi)
   - Ingest 14 OWASP ZAP baseline scanner alerts to demonstrate noise filtering

2. **Triage Queue:**
   - Deterministic prioritization: `Score = 100 × (0.40·severity + 0.40·confirmed + 0.20·category_prior)`
   - Confirmed exploits sit at **P0 (Critical)**, separating real holes from scanner noise
   - Transparent Triage Waterfall showing contribution bars for every signal
   - AI-Drafted explanation with prompt-injection defense (`<data>` tag isolation)

3. **Virtual Patch Studio:**
   - Multi-pass recursive normalizers (`url_decode_recursive`, `html_entity_decode`, `strip_sql_comments`, `strip_whitespace_variants`, `unicode_nfkc`, `collapse_whitespace`)
   - ReDoS guard verifying all regex patterns
   - **Mutation Gauntlet Console:** 12 deterministic mutators attacking the rule with live streaming tiles (Green = Blocked, Red = Bypassed, Grey = Invalid Mutant filtered by the Effective-Mutant Oracle)
   - **Wilson 95% Confidence Interval** calculated mathematically
   - **Auto-Tighten Loop:** 5 iterations self-adapting to evasion techniques, monotonic regression set, and grading against a fresh unseen exam seed

4. **Cryptographic Proof Page:**
   - Official tamper-evident Proof Report
   - SHA-256 canonical digest + ed25519 digital signature
   - Interactive **"Tamper 1 Byte Live"** toggle demonstrating immediate cryptographic failure (`valid: false`)
   - Standard limitation disclosures

5. **Benchmark & Proxy Events:**
   - 4-arm comparative benchmark: Bare vs. Naive Canonical vs. Shield v1 vs. Shield Hardened
   - Live streaming decision feed from proxy :8080 with latency, rules, and decision headers

---

## 📜 4-Minute Presentation Script

1. **(0:00 - 0:25)** *Problem statement:* Scanners generate noise. Firewalls require manual rules that nobody verifies. Attackers bypass them with encodings.
2. **(0:25 - 0:55)** *Command Center & Exploit Confirmation:* Fire Recipe R1 at `http://localhost:3001`. Leaked data appears. Ingest ZAP noise. Show Triage Queue: R1 jumps straight to **P0** with confirmed live hole.
3. **(0:55 - 1:40)** *The Hypothesis (Naive Patch):* Synthesize a canonical naive rule. Open Patch Studio. Run **Mutation Gauntlet**. Watch the grid fill with red bypasses: comments (`/**/`), alternate whitespace (`%09`), and double encodings defeat it!
4. **(1:40 - 2:30)** *Auto-Tighten Adaptation:* Click **Auto-Tighten**. Watch the loop add recursive decoders and comment strippers. Bypass rate drops from 62.9% to 0.0%. Show the unseen exam set score.
5. **(2:30 - 3:15)** *Deploy Enforce & Proof:* Deploy the hardened rule in **Enforce mode**. Send the same exploit through Proxy `:8080` — instant **403 Blocked** with `X-Shield-Decision: block`. Open the **Proof Page**: show ed25519 signature valid. Click "Tamper 1 Byte" — instant tamper detection!
6. **(3:15 - 4:00)** *Close & Questions:* Review 4-arm benchmark and ReDoS guards. Remind judges: *The LLM drafts rules, but deterministic verification decides.*
