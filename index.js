/* ============================================================
   VITARA SYNC — the free personal server for the Vitara app
   ------------------------------------------------------------
   · accounts: email+password (scrypt), email OTP, phone OTP
   · Google sign-in: standard OAuth 2.0 code flow (no SDK)
   · data roam: one JSON blob per user, last-write-wins
   · storage: plain JSON files in ./data (no DB to babysit)
   Deploy free: Render / Railway / Fly.io — see README.md
   Node 18+ (uses global fetch). Two npm deps: express, nodemailer.
   ============================================================ */
'use strict';

const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

let mailer = null;
try { mailer = require('nodemailer'); } catch (e) { /* optional */ }

const PORT = process.env.PORT || 8787;
const DATA_DIR = path.join(__dirname, 'data');
const VERSION = '1.3.0';

/* ---------------- env ---------------- */
const ENV = {
  SECRET: process.env.SECRET || '',
  SMTP_HOST: process.env.SMTP_HOST || '',
  SMTP_PORT: +process.env.SMTP_PORT || 587,
  SMTP_USER: process.env.SMTP_USER || '',
  SMTP_PASS: process.env.SMTP_PASS || '',
  MAIL_FROM: process.env.MAIL_FROM || '',
  GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID || '',
  GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET || '',
  PUBLIC_URL: process.env.PUBLIC_URL || '',           // e.g. https://vitara-sync.onrender.com
  TWILIO_ACCOUNT_SID: process.env.TWILIO_ACCOUNT_SID || '',
  TWILIO_AUTH_TOKEN: process.env.TWILIO_AUTH_TOKEN || '',
  TWILIO_FROM: process.env.TWILIO_FROM || '',
  DEV_OTP: process.env.DEV_OTP === '1'                // DEV ONLY: return OTP in response
};
const HAS_SMTP = !!(mailer && ENV.SMTP_HOST && ENV.SMTP_USER && ENV.SMTP_PASS);
const HAS_SMS = !!(ENV.TWILIO_ACCOUNT_SID && ENV.TWILIO_AUTH_TOKEN && ENV.TWILIO_FROM);
const HAS_GOOGLE = !!(ENV.GOOGLE_CLIENT_ID && ENV.GOOGLE_CLIENT_SECRET);
const TOKEN_DAYS = 30;

/* ---------------- tiny JSON storage ---------------- */
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
function loadJson(name, fallback) {
  try { return JSON.parse(fs.readFileSync(path.join(DATA_DIR, name), 'utf8')); }
  catch (e) { return fallback; }
}
function saveJson(name, obj) {
  const tmp = path.join(DATA_DIR, name + '.tmp');
  fs.writeFileSync(tmp, JSON.stringify(obj));
  fs.renameSync(tmp, path.join(DATA_DIR, name));
}
const users = loadJson('users.json', {});   // email -> {name, phone, salt, hash, provider, verified, created}
const blobs = loadJson('data.json', {});    // email -> {payload, updated}
const otps  = loadJson('otps.json', {});    // key -> {code, exp, tries}

/* secret for HMAC tokens — generated once, kept on disk */
let SECRET = ENV.SECRET;
if (!SECRET) {
  const f = path.join(DATA_DIR, 'secret.key');
  try { SECRET = fs.readFileSync(f, 'utf8').trim(); } catch (e) { SECRET = ''; }
  if (!SECRET) { SECRET = crypto.randomBytes(32).toString('hex'); fs.writeFileSync(f, SECRET); }
}

/* ---------------- crypto helpers ---------------- */
function scryptHash(password, salt) {
  return crypto.scryptSync(String(password), salt, 32).toString('hex');
}
function b64url(buf) { return Buffer.from(buf).toString('base64url'); }
function sign(data) { return crypto.createHmac('sha256', SECRET).update(data).digest('base64url'); }
function makeToken(email) {
  const payload = b64url(JSON.stringify({ u: email, e: Date.now() + TOKEN_DAYS * 86400000 }));
  return payload + '.' + sign(payload);
}
function readToken(token) {
  if (!token || typeof token !== 'string' || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)) return null;
  const [payload, sig] = token.split('.');
  const want = sign(payload);
  if (sig.length !== want.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(want))) return null;
  try {
    const p = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!p.u || !p.e || Date.now() > p.e) return null;
    return p.u;
  } catch (e) { return null; }
}
function publicUser(u) {
  return { name: u.name || '', phone: u.phone || '', provider: u.provider || 'email',
           verified: !!u.verified, created: u.created || 0 };
}

/* ---------------- rate limiting (per IP, in memory) ---------------- */
const hits = new Map();
function limited(bucket, max, windowMs) {
  return (req, res, next) => {
    const key = bucket + ':' + (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '?');
    const now = Date.now();
    const rec = hits.get(key) || { n: 0, t0: now };
    if (now - rec.t0 > windowMs) { rec.n = 0; rec.t0 = now; }
    rec.n++;
    hits.set(key, rec);
    if (rec.n > max) return res.status(429).json({ error: 'Too many requests — try again later.' });
    next();
  };
}

/* ---------------- mail & SMS ---------------- */
let transporter = null;
if (HAS_SMTP) {
  transporter = mailer.createTransport({
    host: ENV.SMTP_HOST, port: ENV.SMTP_PORT, secure: ENV.SMTP_PORT === 465,
    auth: { user: ENV.SMTP_USER, pass: ENV.SMTP_PASS }
  });
}
async function sendOtpMail(email, code) {
  if (!transporter) throw new Error('SMTP not configured');
  const from = ENV.MAIL_FROM || ENV.SMTP_USER;
  await transporter.sendMail({
    from: `"Vitara" <${from}>`, to: email,
    subject: `Your Vitara sign-in code: ${code}`,
    text: `Your Vitara sign-in code is ${code}\n\nIt expires in 10 minutes.\nIf you didn't request it, you can ignore this email.\n\n— Vitara (Nourish · Move · Learn)`,
    html: `<div style="font-family:sans-serif;max-width:420px;margin:0 auto;padding:24px;background:#0B1120;color:#EAF0FF;border-radius:18px">
      <h2 style="margin:0 0 6px">Your Vitara code</h2>
      <p style="color:#94A3B8;font-size:14px;margin:0 0 18px">Enter this code in the app to sign in. It expires in 10 minutes.</p>
      <div style="font-size:34px;font-weight:800;letter-spacing:8px;color:#6EE7B7">${code}</div>
      <p style="color:#64748B;font-size:12px;margin-top:22px">If you didn't request it, ignore this email.<br/>— Vitara · Nourish · Move · Learn</p></div>`
  });
}
async function sendOtpSms(phone, code) {
  if (!HAS_SMS) throw new Error('SMS not configured');
  const sid = ENV.TWILIO_ACCOUNT_SID, auth = ENV.TWILIO_AUTH_TOKEN;
  const res = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${sid}/Messages.json`, {
    method: 'POST',
    headers: { 'Authorization': 'Basic ' + Buffer.from(sid + ':' + auth).toString('base64'),
               'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ To: phone, From: ENV.TWILIO_FROM, Body: `Vitara code: ${code} (expires in 10 min)` })
  });
  if (!res.ok) throw new Error('SMS provider error ' + res.status);
}

/* ---------------- app setup ---------------- */
const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '2mb' }));
app.use((req, res, next) => {           /* CORS: the APK WebView sends Origin null */
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const email = readToken(h.startsWith('Bearer ') ? h.slice(7) : '');
  if (!email || !users[email]) return res.status(401).json({ error: 'Not signed in' });
  req.user = email;
  next();
}
function validEmail(e) { return typeof e === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) && e.length < 200; }
function validPhone(p) { return typeof p === 'string' && /^\+?\d{7,15}$/.test(p); }

/* ---------------- landing page ---------------- */
app.get('/', (req, res) => {
  res.type('html').send(`<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Vitara Sync</title><style>
  body{background:#070B14;color:#EAF0FF;font-family:system-ui,sans-serif;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
  .card{background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.12);border-radius:24px;padding:34px 38px;max-width:430px}
  h1{margin:0 0 4px;font-size:24px} .sub{color:#94A3B8;font-size:13px;margin:0 0 20px}
  .row{display:flex;justify-content:space-between;padding:9px 0;border-bottom:1px solid rgba(255,255,255,.07);font-size:14px}
  .row:last-child{border:0} .k{color:#94A3B8} .ok{color:#6EE7B7;font-weight:700} .no{color:#FB7185;font-weight:700}
  .hint{margin-top:18px;font-size:12px;color:#64748B;line-height:1.6}
  </style></head><body><div class="card">
  <h1>🌿 Vitara Sync</h1><p class="sub">Your personal server for the Vitara app · v${VERSION}</p>
  <div class="row"><span class="k">Status</span><span class="ok">running</span></div>
  <div class="row"><span class="k">Accounts</span><span>${Object.keys(users).length}</span></div>
  <div class="row"><span class="k">Email codes (SMTP)</span><span class="${HAS_SMTP ? 'ok' : 'no'}">${HAS_SMTP ? 'ready' : 'not configured'}</span></div>
  <div class="row"><span class="k">Google sign-in</span><span class="${HAS_GOOGLE ? 'ok' : 'no'}">${HAS_GOOGLE ? 'ready' : 'not configured'}</span></div>
  <div class="row"><span class="k">Phone SMS codes</span><span class="${HAS_SMS ? 'ok' : 'no'}">${HAS_SMS ? 'ready' : 'not configured'}</span></div>
  <p class="hint">Point the Vitara app at this URL: <b>Profile → Cloud &amp; sync</b>.<br/>
  Setup guide ships with the app package (server/README.md).</p>
  </div></body></html>`);
});

app.get('/api/health', (req, res) => res.json({ ok: true, name: 'Vitara Sync', version: VERSION, ts: Date.now() }));

/* ---------------- register / login ---------------- */
app.post('/api/register', limited('reg', 10, 15 * 60000), (req, res) => {
  const { name, email, phone, password } = req.body || {};
  const mail = String(email || '').trim().toLowerCase();
  if (!name || String(name).trim().length < 2) return res.status(400).json({ error: 'Name too short' });
  if (!validEmail(mail)) return res.status(400).json({ error: 'Invalid email' });
  if (phone && !validPhone(phone)) return res.status(400).json({ error: 'Invalid phone number' });
  if (!password || String(password).length < 6) return res.status(400).json({ error: 'Password needs 6+ characters' });
  if (users[mail]) return res.status(409).json({ error: 'That email already has an account' });
  const salt = crypto.randomBytes(16).toString('hex');
  users[mail] = { name: String(name).trim().slice(0, 60), phone: phone || '', salt,
                  hash: scryptHash(password, salt), provider: 'email', verified: false, created: Date.now() };
  saveJson('users.json', users);
  res.json({ token: makeToken(mail), email: mail, user: publicUser(users[mail]) });
});

app.post('/api/login', limited('login', 20, 15 * 60000), (req, res) => {
  const { email, password } = req.body || {};
  const mail = String(email || '').trim().toLowerCase();
  const u = users[mail];
  if (!u || !u.hash) return res.status(401).json({ error: 'Wrong email or password' });
  const got = scryptHash(password || '', u.salt);
  if (got.length !== u.hash.length || !crypto.timingSafeEqual(Buffer.from(got), Buffer.from(u.hash)))
    return res.status(401).json({ error: 'Wrong email or password' });
  res.json({ token: makeToken(mail), email: mail, name: u.name, user: publicUser(u) });
});

app.get('/api/me', auth, (req, res) => {
  const u = users[req.user];
  res.json({ email: req.user, name: u.name, user: publicUser(u) });
});

/* ---------------- one-time codes (email free / SMS optional) ---------------- */
function issueOtp(key) {
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  otps[key] = { code, exp: Date.now() + 10 * 60000, tries: 0 };
  saveJson('otps.json', otps);
  return code;
}
app.post('/api/otp/send', limited('otp', 5, 3600000), async (req, res) => {
  const { email, phone } = req.body || {};
  try {
    if (email) {
      const mail = String(email).trim().toLowerCase();
      if (!validEmail(mail)) return res.status(400).json({ error: 'Invalid email' });
      const code = issueOtp('m:' + mail);
      if (HAS_SMTP) { await sendOtpMail(mail, code); return res.json({ ok: true, via: 'email' }); }
      if (ENV.DEV_OTP) return res.json({ ok: true, via: 'dev', devCode: code });
      return res.status(503).json({ error: 'SMTP not configured on this server' });
    }
    if (phone) {
      const p = String(phone).trim();
      if (!validPhone(p)) return res.status(400).json({ error: 'Invalid phone number' });
      if (!users[p] && !Object.values(users).some(u => u.phone === p))
        return res.status(404).json({ error: 'No account with this phone number — sign up first' });
      const code = issueOtp('p:' + p);
      if (HAS_SMS) { await sendOtpSms(p, code); return res.json({ ok: true, via: 'sms' }); }
      if (ENV.DEV_OTP) return res.json({ ok: true, via: 'dev', devCode: code });
      return res.status(503).json({ error: 'SMS not configured on this server (Twilio env vars)' });
    }
    res.status(400).json({ error: 'Provide email or phone' });
  } catch (e) { res.status(502).json({ error: 'Could not send the code: ' + e.message }); }
});

app.post('/api/otp/verify', limited('otpv', 20, 3600000), (req, res) => {
  const { email, phone, code } = req.body || {};
  const key = email ? 'm:' + String(email).trim().toLowerCase() : phone ? 'p:' + String(phone).trim() : null;
  const rec = key && otps[key];
  if (!rec || Date.now() > rec.exp) { if (key) delete otps[key]; saveJson('otps.json', otps); return res.status(401).json({ error: 'Code expired — request a new one' }); }
  if (rec.tries >= 5) return res.status(429).json({ error: 'Too many attempts — request a new code' });
  const got = String(code || '');
  if (got.length !== rec.code.length || !crypto.timingSafeEqual(Buffer.from(got), Buffer.from(rec.code))) {
    rec.tries++; saveJson('otps.json', otps);
    return res.status(401).json({ error: 'Wrong code' });
  }
  delete otps[key]; saveJson('otps.json', otps);
  if (email) {
    const mail = String(email).trim().toLowerCase();
    if (!users[mail]) { users[mail] = { name: mail.split('@')[0], phone: '', salt: '', hash: '', provider: 'email-otp', verified: true, created: Date.now() }; }
    users[mail].verified = true;
    saveJson('users.json', users);
    return res.json({ token: makeToken(mail), email: mail, name: users[mail].name, user: publicUser(users[mail]) });
  }
  /* phone sign-in: find the account holding this number */
  const p = String(phone).trim();
  const mail = users[p] ? p : Object.keys(users).find(m => users[m].phone === p);
  if (!mail) return res.status(404).json({ error: 'No account with this phone number' });
  users[mail].verified = true; saveJson('users.json', users);
  res.json({ token: makeToken(mail), email: mail, name: users[mail].name, user: publicUser(users[mail]) });
});

/* ---------------- data sync ---------------- */
app.get('/api/data', auth, (req, res) => {
  const b = blobs[req.user];
  res.json({ payload: b ? b.payload : null, updated: b ? b.updated : 0 });
});
app.put('/api/data', auth, (req, res) => {
  const { payload, updated } = req.body || {};
  if (!payload || typeof payload !== 'object') return res.status(400).json({ error: 'Bad payload' });
  blobs[req.user] = { payload, updated: +updated || Date.now() };
  saveJson('data.json', blobs);
  res.json({ ok: true, updated: blobs[req.user].updated });
});

/* ---------------- Google OAuth (standard code flow) ---------------- */
function publicBase(req) {
  return (ENV.PUBLIC_URL || `${req.protocol}://${req.get('host')}`).replace(/\/+$/, '');
}
app.get('/api/google/config', (req, res) => res.json({ enabled: HAS_GOOGLE }));
app.get('/api/google/start', (req, res) => {
  if (!HAS_GOOGLE) return res.status(503).json({ error: 'GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET not set on this server' });
  const state = crypto.randomBytes(12).toString('hex');
  otps['g:' + state] = { code: '1', exp: Date.now() + 10 * 60000, tries: 0 };
  saveJson('otps.json', otps);
  const url = 'https://accounts.google.com/o/oauth2/v2/auth?' + new URLSearchParams({
    client_id: ENV.GOOGLE_CLIENT_ID,
    redirect_uri: publicBase(req) + '/api/google/callback',
    response_type: 'code', scope: 'openid email profile', state,
    prompt: 'select_account'
  });
  res.redirect(url);
});
app.get('/api/google/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    const st = otps['g:' + state];
    if (!code || !st || Date.now() > st.exp) return res.status(400).send('Invalid OAuth state — try again from the app.');
    delete otps['g:' + state]; saveJson('otps.json', otps);
    const tokRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code, client_id: ENV.GOOGLE_CLIENT_ID, client_secret: ENV.GOOGLE_CLIENT_SECRET,
        redirect_uri: publicBase(req) + '/api/google/callback', grant_type: 'authorization_code'
      })
    });
    const tok = await tokRes.json();
    if (!tok.access_token) return res.status(401).send('Google token exchange failed.');
    const uiRes = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
      headers: { Authorization: 'Bearer ' + tok.access_token }
    });
    const ui = await uiRes.json();
    if (!ui.email) return res.status(401).send('Google did not share an email.');
    const mail = String(ui.email).toLowerCase();
    if (!users[mail]) users[mail] = { name: ui.name || mail.split('@')[0], phone: '', salt: '', hash: '', provider: 'google', verified: !!ui.email_verified, created: Date.now() };
    else users[mail].provider = users[mail].hash ? users[mail].provider : 'google';
    if (ui.email_verified) users[mail].verified = true;
    saveJson('users.json', users);
    /* hand the token back to the APK via its custom scheme */
    res.redirect('vitara://oauth#token=' + makeToken(mail));
  } catch (e) { res.status(500).send('Google sign-in failed: ' + e.message); }
});

/* ---------------- 404 ---------------- */
app.use((req, res) => res.status(404).json({ error: 'Unknown endpoint' }));

app.listen(PORT, () => {
  console.log(`🌿 Vitara Sync v${VERSION} on :${PORT}  (SMTP ${HAS_SMTP ? 'on' : 'off'} · Google ${HAS_GOOGLE ? 'on' : 'off'} · SMS ${HAS_SMS ? 'on' : 'off'}${ENV.DEV_OTP ? ' · DEV-OTP' : ''})`);
});
