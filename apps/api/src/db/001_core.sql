create extension if not exists pgcrypto;

create table if not exists targets(
  id uuid primary key default gen_random_uuid(),
  name text not null, base_url text not null, proxy_url text not null,
  mode text not null default 'protect' check (mode in ('learn','protect')),
  created_at timestamptz not null default now());

create table if not exists findings(
  id uuid primary key default gen_random_uuid(),
  target_id uuid not null references targets(id),
  title text not null,
  category text not null check (category in ('sqli','xss','cmdi','path_traversal','other')),
  scanner_risk text not null check (scanner_risk in ('info','low','medium','high','critical')),
  method text not null, url text not null, route_template text,
  param text, param_location text check (param_location in ('query','body_form','body_json','header','cookie','path')),
  evidence text,
  exploit_request jsonb,          -- {method,url,headers,body}
  exploit_oracle jsonb,           -- {success_status:[], success_body_regex, success_header_regex}
  exploit_confirmed boolean not null default false,
  status text not null default 'open' check (status in ('open','triaged','patched','verified','dismissed')),
  dedupe_key text not null unique,
  provenance text not null check (provenance in ('real_scan','real_capture','public_feed','generated')),
  created_at timestamptz not null default now());

create table if not exists triage_results(
  id uuid primary key default gen_random_uuid(),
  finding_id uuid not null unique references findings(id),
  priority_score numeric(5,2) not null,
  priority_band text not null check (priority_band in ('P0','P1','P2','P3')),
  signals jsonb not null,          -- Signal[] (see §5.2)
  llm_explanation jsonb,
  llm_status text not null default 'skipped' check (llm_status in ('ok','fallback','skipped')),
  created_at timestamptz not null default now());

create table if not exists patches(
  id uuid primary key default gen_random_uuid(),
  finding_id uuid not null references findings(id),
  version int not null default 1,
  parent_patch_id uuid references patches(id),
  source text not null check (source in ('deterministic','llm','hardened','canonical')),
  rule jsonb,                      -- Rule DSL (§6), null while generating
  mode text not null default 'shadow' check (mode in ('shadow','enforce')),
  status text not null default 'generating' check (status in ('generating','draft','verifying','verified','failed','deployed','rolled_back')),
  rationale text, meta jsonb not null default '{}',
  created_at timestamptz not null default now(), deployed_at timestamptz);

create table if not exists verifications(
  id uuid primary key default gen_random_uuid(),
  patch_id uuid not null references patches(id),
  status text not null default 'running' check (status in ('running','passed','failed','error')),
  summary jsonb not null default '{}',   -- VerificationSummary (§5.2)
  started_at timestamptz not null default now(), finished_at timestamptz);

create table if not exists verification_cases(
  id uuid primary key default gen_random_uuid(),
  verification_id uuid not null references verifications(id),
  suite text not null check (suite in ('exploit_replay','benign_replay','mutation')),
  name text not null, request jsonb not null,
  direct_result jsonb, proxied_result jsonb,
  expected text not null check (expected in ('block','allow')),
  outcome text not null check (outcome in ('pass','fail','invalid_mutant')),
  details jsonb not null default '{}');

create table if not exists traffic_corpus(
  id uuid primary key default gen_random_uuid(),
  target_id uuid not null references targets(id),
  label text not null check (label in ('benign','attack')),
  method text not null, url text not null, headers jsonb not null default '{}', body text,
  provenance text not null check (provenance in ('real_capture','public_feed')),
  captured_at timestamptz not null default now());

create table if not exists proxy_events(
  id bigserial primary key, ts timestamptz not null default now(),
  target_id uuid references targets(id), method text, path text, route_template text,
  decision text not null check (decision in ('allow','block','log_only','error')),
  rule_id uuid, patch_id uuid, latency_ms numeric, status_code int,
  meta jsonb not null default '{}');

create table if not exists hardening_runs(
  id uuid primary key default gen_random_uuid(),
  patch_id uuid not null references patches(id),
  status text not null default 'queued' check (status in ('queued','running','completed','failed')),
  start_mode text not null default 'current' check (start_mode in ('current','canonical')),
  max_iterations int not null default 5, mutation_budget int not null default 60, seed int not null,
  iterations jsonb not null default '[]',
  exam jsonb, best_patch_id uuid references patches(id),
  created_at timestamptz not null default now());

create table if not exists proof_reports(
  id uuid primary key default gen_random_uuid(),
  patch_id uuid not null references patches(id),
  report jsonb not null, sha256 text not null, signature text not null, public_key text not null,
  created_at timestamptz not null default now());

create table if not exists benchmark_runs(
  id uuid primary key default gen_random_uuid(),
  target_id uuid references targets(id), config jsonb not null, results jsonb,
  status text not null default 'queued' check (status in ('queued','running','completed','failed')),
  created_at timestamptz not null default now());

create index if not exists idx_findings_target_status on findings(target_id,status);
create index if not exists idx_proxy_events_target_ts on proxy_events(target_id,ts desc);
create index if not exists idx_verification_cases_ver_suite on verification_cases(verification_id,suite);
