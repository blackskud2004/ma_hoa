import fs from 'fs';
import path from 'path';
import url from 'url';
import crypto from 'crypto';

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));

const [,, inPath, outName, chunkArg] = process.argv;
if (!inPath || !outName){
  console.log("Usage: node encrypt.js <inputModelPath> <outputBaseName> [chunkSizeBytes]");
  process.exit(1);
}

const chunkSize = parseInt(chunkArg||"1048576",10);
const data = fs.readFileSync(inPath);
const size = data.length;

const DEMO_KEY_PATH = path.join(__dirname, 'keys', 'demo_key.bin');
let key;
if (fs.existsSync(DEMO_KEY_PATH)) {
  key = fs.readFileSync(DEMO_KEY_PATH);
} else {
  key = crypto.randomBytes(32);
  fs.writeFileSync(DEMO_KEY_PATH, key);
  console.log("[encrypt] Generated demo key at server/keys/demo_key.bin");
}

const chunks = Math.ceil(size / chunkSize);
const ivs = [];
const outPath = path.join(__dirname, 'public', 'models', outName + '.enc');
const manPath = path.join(__dirname, 'public', 'models', outName + '.json');
const fd = fs.openSync(outPath, 'w');

for (let i=0;i<chunks;i++){
  const start = i*chunkSize;
  const end = Math.min(start+chunkSize, size);
  const plain = data.subarray(start, end);
  const iv = crypto.randomBytes(12);
  ivs.push(iv.toString('base64'));
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  fs.writeFileSync(fd, enc);
  fs.writeFileSync(fd, tag); // 16 bytes
}

fs.closeSync(fd);
fs.writeFileSync(manPath, JSON.stringify({ size: fs.statSync(outPath).size, chunkSize, ivs, tagPerChunk: 16, layout: "enc+tag" }, null, 2));
console.log(`[encrypt] Wrote ${outPath} and ${manPath}`);
