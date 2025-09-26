import 'dotenv/config';
import express from 'express';
import crypto from 'crypto';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import fs from 'fs';
import path from 'path';
import url from 'url';

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
const app = express();

app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors());
app.use(morgan('dev'));
app.use(express.json());

// ---- Config & demo key ------------------------------------------------------
const PORT = parseInt(process.env.PORT || '4000', 10);
const SESSION_TTL_SECONDS = parseInt(process.env.SESSION_TTL_SECONDS || '300', 10);

// Lấy khóa demo theo thứ tự ưu tiên:
// 1) DEMO_KEY_B64 trong .env
// 2) server/keys/demo_key.bin (do encrypt.js sinh ra)
// 3) (fallback) tạo mới ngẫu nhiên (không khuyến nghị vì sẽ lệch khóa)
let DEMO_KEY = Buffer.alloc(0);
if (process.env.DEMO_KEY_B64) {
  try {
    DEMO_KEY = Buffer.from(process.env.DEMO_KEY_B64, 'base64');
  } catch { /* ignore */ }
}
if (!DEMO_KEY.length) {
  const keyFile = path.join(__dirname, 'keys', 'demo_key.bin');
  if (fs.existsSync(keyFile)) DEMO_KEY = fs.readFileSync(keyFile);
}
if (!DEMO_KEY.length) {
  console.warn('[WARN] No DEMO_KEY found. Generating a random one (re-encrypt models!).');
  DEMO_KEY = crypto.randomBytes(32);
}

const SESS_SIGN = crypto.randomBytes(32); // demo HMAC key (ephemeral)

// ---- Tiny signed token (demo) ----------------------------------------------
const b64url = (buf) =>
  buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/,'');

const sessions = new Map(); // token -> { key: Buffer, exp: number }

function signToken(payload) {
  const header = b64url(Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'DEMO' })));
  const body = b64url(Buffer.from(JSON.stringify(payload)));
  const mac = crypto.createHmac('sha256', SESS_SIGN).update(`${header}.${body}`).digest();
  return `${header}.${body}.${b64url(mac)}`;
}
function verifyToken(tok) {
  try {
    const [h,b,s] = tok.split('.');
    const mac = crypto.createHmac('sha256', SESS_SIGN).update(`${h}.${b}`).digest();
    if (b64url(mac) !== s) return null;
    const payload = JSON.parse(Buffer.from(b.replace(/-/g,'+').replace(/_/g,'/'),'base64'));
    if (!payload?.exp || payload.exp < Math.floor(Date.now()/1000)) return null;
    return payload;
  } catch { return null; }
}

// ---- APIs -------------------------------------------------------------------
app.post('/api/session', (req, res) => {
  const exp = Math.floor(Date.now()/1000) + SESSION_TTL_SECONDS;
  const token = signToken({ exp });
  sessions.set(token, { key: DEMO_KEY, exp });
  // Trả luôn keyB64 cho client (ưu tiên dùng từ session)
  res.json({ token, exp, keyB64: DEMO_KEY.toString('base64') });
});

function requireSession(req, res, next) {
  const auth = req.headers.authorization || '';
  const tok = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!tok) return res.status(401).json({ error: 'No token' });
  const p = verifyToken(tok);
  const s = sessions.get(tok);
  if (!p || !s || s.exp < Math.floor(Date.now()/1000)) {
    return res.status(401).json({ error: 'Invalid/expired token' });
  }
  req.session = s;
  next();
}

// Danh sách model
app.get('/api/models', requireSession, (req, res) => {
  const dir = path.join(__dirname, 'public', 'models');
  if (!fs.existsSync(dir)) return res.json([]);
  const out = [];
  for (const f of fs.readdirSync(dir)) {
    if (f.endsWith('.glb.json')) {
      try {
        const j = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
        out.push((j.encName || f.replace(/\.json$/, '').replace(/\.enc$/, '')));
      } catch {}
    }
  }
  res.json([...new Set(out)].sort());
});

// Manifest (kèm fallback keyB64 để client dùng nếu vì lý do nào đó không có key từ session)
app.get('/api/model/enc/:name', requireSession, (req, res) => {
  const { name } = req.params;
  const encPath = path.join(__dirname, 'public', 'models', `${name}.enc`);
  const manPath = path.join(__dirname, 'public', 'models', `${name}.json`);
  if (!fs.existsSync(encPath) || !fs.existsSync(manPath)) return res.status(404).json({ error: 'Not found' });
  const manifest = JSON.parse(fs.readFileSync(manPath, 'utf8'));
  res.json({
    name,
    size: manifest.size,
    chunkSize: manifest.chunkSize,
    ivs: manifest.ivs,
    tagPerChunk: manifest.tagPerChunk ?? 16,
    layout: manifest.layout || 'enc+tag',
    keyB64: DEMO_KEY.toString('base64')   // fallback
  });
});

// Lấy chunk enc+tag
app.get('/api/model/enc/:name/chunk/:idx', requireSession, (req, res) => {
  const { name, idx } = req.params;
  const encPath = path.join(__dirname, 'public', 'models', `${name}.enc`);
  const manPath = path.join(__dirname, 'public', 'models', `${name}.json`);
  if (!fs.existsSync(encPath) || !fs.existsSync(manPath)) return res.status(404).end();

  const manifest = JSON.parse(fs.readFileSync(manPath, 'utf8'));
  const i = parseInt(idx, 10);
  if (Number.isNaN(i) || i < 0 || i >= manifest.ivs.length) return res.status(400).end();

  const tag = manifest.tagPerChunk ?? 16;
  const perChunkOnDisk = manifest.chunkSize + tag; // ciphertext + tag
  const start = i * perChunkOnDisk;
  const endExclusive = Math.min(start + perChunkOnDisk, fs.statSync(encPath).size);

  res.setHeader('Content-Type', 'application/octet-stream');
  fs.createReadStream(encPath, { start, end: endExclusive - 1 }).pipe(res);
});

app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});
