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
app.use(helmet({crossOriginResourcePolicy: { policy: "cross-origin" }}));
app.use(cors());
app.use(morgan('dev'));
app.use(express.json());

const PORT = process.env.PORT || 3000;
const SESSION_TTL_SECONDS = parseInt(process.env.SESSION_TTL_SECONDS||"300",10);
const SIGN_KEY = Buffer.from(process.env.SESSION_SIGN_KEY||"", "base64");
if (!SIGN_KEY.length) {
  console.warn("[WARN] SESSION_SIGN_KEY is not set. For demo, generating ephemeral key.");
}

const sessions = new Map(); // token -> { key: Buffer, exp: number }

function b64url(buf){ return buf.toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }

function signToken(payloadObj){
  const header = b64url(Buffer.from(JSON.stringify({alg:"HS256",typ:"DEMO"})));
  const payload = b64url(Buffer.from(JSON.stringify(payloadObj)));
  const mac = crypto.createHmac('sha256', SIGN_KEY.length?SIGN_KEY:crypto.randomBytes(32));
  mac.update(header+"."+payload);
  const sig = b64url(mac.digest());
  return `${header}.${payload}.${sig}`;
}

function verifyToken(tok){
  try{
    const [h,p,sig] = tok.split('.');
    const mac = crypto.createHmac('sha256', SIGN_KEY.length?SIGN_KEY:crypto.randomBytes(32));
    mac.update(h+"."+p);
    if (b64url(mac.digest()) !== sig) return null;
    const payload = JSON.parse(Buffer.from(p.replace(/-/g,'+').replace(/_/g,'/'),'base64').toString('utf8'));
    if (!payload || !payload.exp || payload.exp < Math.floor(Date.now()/1000)) return null;
    return payload;
  }catch(e){ return null; }
}

app.post('/api/session', (req,res)=>{
  const key = crypto.randomBytes(32); // AES-256 (demo; not used server-side here)
  const exp = Math.floor(Date.now()/1000) + SESSION_TTL_SECONDS;
  const token = signToken({exp});
  sessions.set(token, { key, exp });
  res.json({ token, exp });
});

function requireSession(req,res,next){
  const auth = req.headers.authorization||"";
  const tok = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!tok) return res.status(401).json({error:"No token"});
  const payload = verifyToken(tok);
  if (!payload) return res.status(401).json({error:"Invalid/expired token"});
  const sess = sessions.get(tok);
  if (!sess || sess.exp < Math.floor(Date.now()/1000)) return res.status(401).json({error:"Session expired"});
  req.session = { token: tok, ...sess };
  next();
}

app.get('/api/model/raw/:name', requireSession, (req,res)=>{
  const { name } = req.params;
  const p = path.join(__dirname, 'public', 'models', name);
  if (!fs.existsSync(p)) return res.status(404).json({error:"Not found"});
  res.setHeader('Content-Type', 'application/octet-stream');
  fs.createReadStream(p).pipe(res);
});

app.get('/api/model/enc/:name', requireSession, (req,res)=>{
  const { name } = req.params;
  const encPath = path.join(__dirname, 'public', 'models', name + '.enc');
  const manPath = path.join(__dirname, 'public', 'models', name + '.json');
  if (!fs.existsSync(encPath) || !fs.existsSync(manPath)) return res.status(404).json({error:"Not found"});
  const manifest = JSON.parse(fs.readFileSync(manPath,'utf8'));
  res.json({ name, size: manifest.size, chunkSize: manifest.chunkSize, ivs: manifest.ivs });
});

app.get('/api/model/enc/:name/chunk/:idx', requireSession, (req,res)=>{
  const { name, idx } = req.params;
  const encPath = path.join(__dirname, 'public', 'models', name + '.enc');
  const manPath = path.join(__dirname, 'public', 'models', name + '.json');
  if (!fs.existsSync(encPath) || !fs.existsSync(manPath)) return res.status(404).json({error:"Not found"});
  const manifest = JSON.parse(fs.readFileSync(manPath,'utf8'));
  const i = parseInt(idx,10);
  if (isNaN(i) || i<0 || i>=manifest.ivs.length) return res.status(400).json({error:"Bad index"});
 const perChunkOnDisk = manifest.chunkSize + (manifest.tagPerChunk || 16); // enc + tag(16B)
const start = i * perChunkOnDisk;
const endExclusive = Math.min(start + perChunkOnDisk, manifest.size);
  res.setHeader('Content-Type','application/octet-stream');
  fs.createReadStream(encPath, { start, end: endExclusive-1 }).pipe(res);
});

// Liệt kê model có sẵn (đọc *.glb.json trong public/models)
app.get('/api/models', requireSession, (req, res) => {
  const dir = path.join(__dirname, 'public', 'models');
  if (!fs.existsSync(dir)) return res.json([]);

  const out = [];
  for (const f of fs.readdirSync(dir)) {
    if (f.endsWith('.glb.json')) {
      try {
        const j = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
        // Ưu tiên lấy tên hiển thị trong manifest, fallback tên file .glb
        const name = j.encName || f.replace(/\.json$/, '').replace(/\.enc$/, '');
        out.push(name);
      } catch (_) {}
    }
  }
  // Loại trùng + sort cho gọn
  res.json([...new Set(out)].sort());
});


app.listen(PORT, ()=>{
  console.log("Server listening on http://localhost:"+PORT);
});
