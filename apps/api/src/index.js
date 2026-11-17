// apps/api/src/index.js
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { initDb } from './db/index.js';
import { router } from './routes/index.js';

dotenv.config();

const app = express();
const PORT = parseInt(process.env.API_PORT || '4000', 10);

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Mount API routes
app.use('/api/v1', router);
app.use('/', router); // Also root for internal convenience

async function start() {
  await initDb();
  app.listen(PORT, () => {
    console.log(`[PatchProof API] Control-plane listening on http://localhost:${PORT}`);
  });
}

start().catch(err => {
  console.error('[PatchProof API Init Error]', err);
  process.exit(1);
});
