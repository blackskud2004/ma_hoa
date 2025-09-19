Quick start:
1) cd server && cp .env.example .env && (set SESSION_SIGN_KEY to random base64) && npm install
2) Put a test model at server/public/models/model.glb
3) node encrypt.js ./public/models/model.glb model.glb 1048576
4) npm run dev (server on http://localhost:3000)
5) Serve client/index.html (e.g., python -m http.server 8080) then open:
   http://localhost:8080?auto=1&model=model.glb
