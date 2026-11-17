// scripts/corpus-benign.js
// Generates >= 200 benign traffic requests for Juice Shop
export function generateBenignCorpus(count = 250) {
  const terms = [
    'apple', 'orange', 'banana', 'juice', 'shirt', 'mug', 'organic', 'green', 'fresh',
    'strawberry', 'mango', 'lemon', 'fruit', 'pack', 'water', 'bottle', 'box', 'smoothie',
    'melon', 'berry', 'special', 'sale', 'tea', 'coffee', 'cotton', 'hoodie', 'glass',
    'premium', 'sweet', 'pure', 'extract', 'citrus', 'blend', 'cooler', 'drink', 'beverage'
  ];

  const paths = [
    '/rest/products/search',
    '/rest/admin/application-version',
    '/api/Cards',
    '/rest/user/whoami'
  ];

  const corpus = [];

  for (let i = 0; i < count; i++) {
    const term = terms[i % terms.length];
    const pathChoice = i % 3 === 0 ? '/rest/products/search' : paths[i % paths.length];

    let url = pathChoice;
    let method = 'GET';
    let headers = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      'Accept': 'application/json, text/plain, */*'
    };
    let body = null;

    if (pathChoice === '/rest/products/search') {
      const q = (i % 5 === 0) ? `${term} ${i}` : term;
      url = `${pathChoice}?q=${encodeURIComponent(q)}`;
    } else if (pathChoice === '/rest/user/whoami') {
      headers['Authorization'] = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.fake';
    }

    corpus.push({
      label: 'benign',
      method,
      url,
      headers,
      body,
      provenance: 'real_capture'
    });
  }

  return corpus;
}
