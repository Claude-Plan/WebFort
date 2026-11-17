// scripts/lab-target.js
// Standalone local Juice Shop replica for R1 & R2 validation on port 3001
import http from 'node:http';

const PORT = 3001;

const PRODUCTS = [
  { id: 1, name: 'Apple Juice (1000ml)', description: 'The all-time classic.', price: 1.99 },
  { id: 2, name: 'Orange Juice (1000ml)', description: 'Made from 100% fresh oranges.', price: 2.99 },
  { id: 3, name: 'Eggfruit Juice (500ml)', description: 'Now with even more exotic taste.', price: 3.49 },
  { id: 4, name: 'Banana Juice (1000ml)', description: 'Monkeys love it.', price: 1.99 },
  { id: 5, name: 'Best Juice Shop T-Shirt', description: 'Real cotton, high quality.', price: 19.99 }
];

const USERS = [
  { id: 1, email: 'admin@juice-sh.op', role: 'admin', token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ' },
  { id: 2, email: 'jim@juice-sh.op', role: 'user', token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiamltIn0' },
  { id: 3, email: 'bender@juice-sh.op', role: 'user', token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYmVuZGVyIn0' }
];

function normalizeSqlForLab(str) {
  let s = String(str || '');
  try { s = decodeURIComponent(s); } catch {}
  return s
    .toLowerCase()
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/[\t\r\n\v\f\u00A0\uFF07]/g, ' ')
    .replace(/&#39;/g, "'")
    .replace(/\s+/g, ' ');
}

const server = http.createServer((req, res) => {
  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsedUrl.pathname;

  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Shield-Verify-Patch, X-Shield-Verify-Token');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // R1: Search endpoint
  if (pathname === '/rest/products/search' && req.method === 'GET') {
    const q = parsedUrl.searchParams.get('q') || '';
    const qNorm = normalizeSqlForLab(q);

    // SQLi check: Does q contain UNION or ' OR 1=1 or comment or tautology?
    const hasUnion = qNorm.includes('union') && (qNorm.includes('select') || qNorm.includes('from'));
    const hasTautology = qNorm.includes("' or 1=1") || qNorm.includes("' or '1'='1") || qNorm.includes("' or true");

    if (hasUnion) {
      // Simulate UNION injection leaking data from users table
      const leaked = PRODUCTS.slice(0, 1).concat(
        USERS.map(u => ({
          id: 100 + u.id,
          name: `User: ${u.email}`,
          description: `role: ${u.role}, hash_secret: $2a$10$JuiceShop${u.id}`,
          price: 0.0
        }))
      );
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'success', data: leaked }));
      return;
    }

    if (hasTautology) {
      // Returns all products
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'success', data: PRODUCTS }));
      return;
    }

    // Normal filter
    const qLower = q.toLowerCase();
    const filtered = PRODUCTS.filter(p => p.name.toLowerCase().includes(qLower) || p.description.toLowerCase().includes(qLower));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'success', data: filtered }));
    return;
  }

  // R2: Login endpoint
  if (pathname === '/rest/user/login' && req.method === 'POST') {
    let bodyStr = '';
    req.on('data', chunk => bodyStr += chunk);
    req.on('end', () => {
      let body = {};
      try {
        body = JSON.parse(bodyStr);
      } catch {}

      const email = String(body.email || '');
      const emailNorm = normalizeSqlForLab(email);

      // Check SQLi login bypass: "' or 1=1--" or "' or 1=1#" or "' or true"
      const hasSqlBypass = emailNorm.includes("' or 1=1") ||
                           emailNorm.includes("' or '1'='1") ||
                           emailNorm.includes("' or true") ||
                           (emailNorm.includes("'") && emailNorm.includes("or") && (emailNorm.includes("--") || emailNorm.includes("#")));

      if (hasSqlBypass || email.includes("' or 1=1")) {
        // SQL injection succeeds! Returns 200 + token
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          authentication: {
            token: USERS[0].token,
            bid: USERS[0].id,
            umail: USERS[0].email
          }
        }));
        return;
      }

      // Normal auth
      const user = USERS.find(u => u.email === email);
      if (user && body.password === 'validPassword123') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          authentication: {
            token: user.token,
            bid: user.id,
            umail: user.email
          }
        }));
        return;
      }

      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid email or password.' }));
    });
    return;
  }

  // R3: Path Traversal / Arbitrary File Read endpoint
  if (pathname === '/rest/file/download' && req.method === 'GET') {
    const file = parsedUrl.searchParams.get('file') || '';
    let fileDecoded = file;
    try { fileDecoded = decodeURIComponent(fileDecoded); } catch {}
    try { fileDecoded = decodeURIComponent(fileDecoded); } catch {} // double decode

    const hasTraversal = fileDecoded.includes('../') || fileDecoded.includes('..\\') || fileDecoded.includes('etc/passwd') || fileDecoded.includes('win.ini');

    if (hasTraversal) {
      // Simulate /etc/passwd or secret file disclosure
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end(`root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\njuice-admin:x:1000:1000:JuiceAdmin,,,:/home/juice-admin:/bin/bash\nJUICE_SECRET_FLAG=flag{patchproof_lfi_exploit_confirmed_2026}\n`);
      return;
    }

    if (file === 'sample.pdf' || file === 'legal.md' || file === 'terms.txt') {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end(`Sample legitimate file content for ${file}`);
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'File not found.' }));
    return;
  }

  // Other standard Juice Shop endpoints (for benign corpus)
  if (pathname === '/rest/admin/application-version') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ version: '15.0.0' }));
    return;
  }

  if (pathname === '/api/Cards') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'success', data: [] }));
    return;
  }

  if (pathname === '/rest/user/whoami') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ user: { email: 'anonymous' } }));
    return;
  }

  // Root or generic
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ message: 'Juice Shop Lab Target Ready', status: 'online' }));
});

server.listen(PORT, () => {
  console.log(`[Lab Target] Juice Shop Target listening on http://localhost:${PORT}`);
});
