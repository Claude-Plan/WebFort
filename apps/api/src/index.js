import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadEnv } from './load-env.js';
import { createApiServer } from './server.js';
import { runMigrations } from './db/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
loadEnv(path.resolve(__dirname, '../../../.env'));

const port = process.env.API_PORT || 4000;

export function createApiApp() {
  return createApiServer();
}

// Only listen if executed directly
const isDirectExecution = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename);

if (isDirectExecution) {
  const apiServer = createApiServer();
  runMigrations().then(() => {
    apiServer.listen(port, () => {
      console.log(`[PatchProof API] Control Plane running on http://localhost:${port}`);
      console.log(`[PatchProof Console] Security Dashboard available at http://localhost:${port}/`);
    });
  });

  process.on('SIGINT', () => {
    apiServer.close(() => process.exit(0));
  });

  process.on('SIGTERM', () => {
    apiServer.close(() => process.exit(0));
  });
}
