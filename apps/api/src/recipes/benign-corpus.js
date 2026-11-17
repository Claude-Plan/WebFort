/**
 * Generates scripted benign corpus (≥200 requests) for Juice Shop
 * Used for false positive verification (§5.2 & §8.4)
 */

export function generateBenignCorpus(count = 200) {
  const benignSearchTerms = [
    'apple', 'orange', 'banana', 'strawberry', 'eggfruit', 'lemon', 'juice', 'smoothie',
    'water', 'soda', 'tea', 'coffee', 'cup', 'glass', 'bottle', 'shirt', 'hoodie',
    'sticker', 'mask', 'mug', 'organic', 'fresh', 'sweet', 'pure', 'cold', 'pressed',
    'vegan', 'gluten-free', 'sugar-free', 'pack', 'box', 'gift', 'discount', 'sale',
    'best', 'popular', 'new', 'featured', 'combo', 'deluxe', 'premium', 'berry'
  ];

  const staticPaths = [
    '/rest/products/search?q=',
    '/api/Challenges',
    '/rest/admin/application-version',
    '/rest/admin/application-configuration',
    '/api/Quantitys',
    '/rest/languages',
    '/api/SecurityQuestions'
  ];

  const corpus = [];

  for (let i = 0; i < count; i++) {
    const term = benignSearchTerms[i % benignSearchTerms.length];
    const pathIdx = i % staticPaths.length;
    let url = staticPaths[pathIdx];

    if (url.includes('?q=')) {
      url = `${url}${encodeURIComponent(term)}_${i}`;
    }

    corpus.push({
      id: `benign-${i + 1}`,
      method: 'GET',
      url: url,
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) BenignTester/1.0'
      },
      body: null
    });
  }

  return corpus;
}
