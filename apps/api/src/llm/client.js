// apps/api/src/llm/client.js
import dotenv from 'dotenv';
dotenv.config();

const OLLAMA_BASE_URL = process.env.OLLAMA_BASE_URL || 'http://localhost:11434';
const OLLAMA_MODEL = process.env.OLLAMA_MODEL || 'qwen2.5:7b-instruct';
const OLLAMA_MODEL_FALLBACK = process.env.OLLAMA_MODEL_FALLBACK || 'llama3.2:3b';
const LLM_TIMEOUT_MS = parseInt(process.env.LLM_TIMEOUT_MS || '5000', 10);

export async function checkOllamaHealth() {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 2000);
  try {
    const resp = await fetch(`${OLLAMA_BASE_URL}/api/version`, { signal: controller.signal });
    return resp.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

function sanitizeUntrustedData(input, maxLen = 1500) {
  if (typeof input !== 'string') return '';
  // Strip control characters except newline and tab
  const stripped = input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
  return stripped.slice(0, maxLen);
}

export async function generateTriageExplanation(finding, priorityScore, priorityBand, signals) {
  const isHealthy = await checkOllamaHealth();
  if (!isHealthy) {
    return {
      status: 'fallback',
      model: null,
      explanation: buildFallbackExplanation(finding, priorityScore, priorityBand)
    };
  }

  const prompt = `You are a cybersecurity advisor explaining a triage verdict.
Analyze the following vulnerability data safely:
<data>
Title: ${sanitizeUntrustedData(finding.title)}
Category: ${finding.category}
Scanner Risk: ${finding.scanner_risk}
Target Route: ${finding.method} ${finding.url}
Parameter: ${finding.param || 'N/A'} (Location: ${finding.param_location || 'N/A'})
Exploit Confirmed Live: ${finding.exploit_confirmed ? 'YES (Proved on bare target)' : 'NO'}
Priority Score: ${priorityScore} (${priorityBand})
Evidence: ${sanitizeUntrustedData(finding.evidence || '')}
</data>

INSTRUCTION: Output a concise 2-sentence technical rationale for why this finding received priority band ${priorityBand} (Score: ${priorityScore}/100). Do not include markdown codeblocks.`;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), Math.min(LLM_TIMEOUT_MS, 6000));

  try {
    const resp = await fetch(`${OLLAMA_BASE_URL}/api/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: OLLAMA_MODEL,
        prompt,
        stream: false
      }),
      signal: controller.signal
    });

    if (resp.ok) {
      const data = await resp.json();
      return {
        status: 'ok',
        model: OLLAMA_MODEL,
        explanation: data.response?.trim() || buildFallbackExplanation(finding, priorityScore, priorityBand)
      };
    }
  } catch (err) {
    // Fallback on timeout or connection error
  } finally {
    clearTimeout(timeout);
  }

  return {
    status: 'fallback',
    model: null,
    explanation: buildFallbackExplanation(finding, priorityScore, priorityBand)
  };
}

function buildFallbackExplanation(finding, score, band) {
  if (finding.exploit_confirmed) {
    return `Finding is elevated to ${band} (Score: ${score}/100) due to active exploit verification on ${finding.method} ${finding.route_template || finding.url}. The vulnerability parameter '${finding.param}' demonstrated live data leakage.`;
  }
  return `Finding categorized as ${band} (Score: ${score}/100) based on ${finding.scanner_risk} scanner severity and ${finding.category} exploitability prior without live confirmation.`;
}
