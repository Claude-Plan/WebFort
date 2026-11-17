import { CATEGORY_PRIORS, SEVERITY_WEIGHTS } from '../../../../packages/contracts/src/index.js';

export function calculateTriageScore(finding) {
  // 1. Severity normalized (0..1)
  const sevKey = (finding.scanner_risk || 'info').toLowerCase();
  const sevNorm = SEVERITY_WEIGHTS[sevKey] ?? 0.0;
  const sevWeight = 0.40;
  const sevContrib = sevWeight * sevNorm * 100;

  // 2. Confirmed normalized (0 or 1)
  const isConfirmed = Boolean(finding.exploit_confirmed);
  const confNorm = isConfirmed ? 1.0 : 0.0;
  const confWeight = 0.40;
  const confContrib = confWeight * confNorm * 100;

  // 3. Category prior normalized (0..1)
  const catKey = (finding.category || 'other').toLowerCase();
  const catNorm = CATEGORY_PRIORS[catKey] ?? 0.30;
  const catWeight = 0.20;
  const catContrib = catWeight * catNorm * 100;

  // Total deterministic score
  const totalScore = Number((sevContrib + confContrib + catContrib).toFixed(2));

  // Determine priority band
  let band = 'P3';
  if (totalScore >= 75) band = 'P0';
  else if (totalScore >= 50) band = 'P1';
  else if (totalScore >= 25) band = 'P2';

  const signals = [
    {
      id: 'severity',
      label: 'Scanner Severity',
      raw: finding.scanner_risk,
      normalized: sevNorm,
      weight: sevWeight,
      contribution: Number(sevContrib.toFixed(2)),
      applicable: true,
      evidence: `Base scanner severity classified as ${finding.scanner_risk}`
    },
    {
      id: 'exploit_confirmed',
      label: 'Exploit Confirmation',
      raw: isConfirmed,
      normalized: confNorm,
      weight: confWeight,
      contribution: Number(confContrib.toFixed(2)),
      applicable: true,
      evidence: isConfirmed
        ? 'Exploit payload verified active against target application'
        : 'Scanner alert without validated exploit confirmation'
    },
    {
      id: 'category_prior',
      label: 'Category Attack Prior',
      raw: finding.category,
      normalized: catNorm,
      weight: catWeight,
      contribution: Number(catContrib.toFixed(2)),
      applicable: true,
      evidence: `Intrinsic threat ranking for ${finding.category}`
    }
  ];

  return {
    score: totalScore,
    band,
    signals
  };
}
