import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadEnv } from '../../api/src/load-env.js';
import { createProxyServer } from './proxy-server.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
loadEnv(path.resolve(__dirname, '../../../.env'));

const port = process.env.PROXY_PORT || 8080;
const targetUrl = process.env.TARGET_URL || 'http://localhost:3001';
const apiUrl = process.env.API_URL || 'http://localhost:4000';

const proxyApp = createProxyServer({
  targetUrl,
  apiUrl,
  failMode: process.env.FAIL_MODE || 'open',
  internalToken: process.env.INTERNAL_TOKEN || 'patchproof_secret_internal_token_2026'
});

proxyApp.listen(port, () => {
  console.log(`[PatchProof Proxy] Listening on port ${port}`);
  console.log(`[PatchProof Proxy] Forwarding to target: ${targetUrl}`);
  console.log(`[PatchProof Proxy] Control plane API: ${apiUrl}`);
});

process.on('SIGINT', () => {
  proxyApp.close(() => process.exit(0));
});

process.on('SIGTERM', () => {
  proxyApp.close(() => process.exit(0));
});
