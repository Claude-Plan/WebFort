/**
 * Seeded PRNG & Wilson Score Confidence Interval (§9.1)
 */

export class SeededRandom {
  constructor(seed = 12345) {
    this.seed = (seed >>> 0) || 12345;
  }

  // 32-bit Mulberry32 PRNG
  next() {
    let t = (this.seed += 0x6D2B79F5);
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }

  nextInt(min, max) {
    return Math.floor(this.next() * (max - min + 1)) + min;
  }

  choice(arr) {
    if (!arr || arr.length === 0) return null;
    return arr[this.nextInt(0, arr.length - 1)];
  }

  shuffle(arr) {
    const copy = [...arr];
    for (let i = copy.length - 1; i > 0; i--) {
      const j = this.nextInt(0, i);
      [copy[i], copy[j]] = [copy[j], copy[i]];
    }
    return copy;
  }
}

/**
 * Calculates Wilson Score 95% Confidence Interval
 * @param {number} x - Number of successes / bypasses
 * @param {number} n - Denominator (effective mutants)
 * @param {number} [z=1.96] - Normal distribution 95% z-score
 * @returns {[number, number]} [lower, upper] rounded to 4 decimals
 */
export function computeWilsonCI(x, n, z = 1.96) {
  if (n <= 0) return [0, 0];

  const p = x / n;
  const z2 = z * z;
  const denominator = 1 + z2 / n;
  const center = (p + z2 / (2 * n)) / denominator;
  const radicand = (p * (1 - p)) / n + z2 / (4 * n * n);
  const margin = (z * Math.sqrt(Math.max(0, radicand))) / denominator;

  const lower = Math.max(0, center - margin);
  const upper = Math.min(1, center + margin);

  return [Number(lower.toFixed(4)), Number(upper.toFixed(4))];
}
