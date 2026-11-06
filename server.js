const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const crypto = require('crypto');

const app = express();
const isProduction = process.env.NODE_ENV === 'production';
const port = Number(process.env.PORT || 3000);
if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL Railway Variable is required.');

app.set('trust proxy', 1);
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: isProduction ? { rejectUnauthorized: false } : undefined,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com", "data:"],
      imgSrc: ["'self'", "data:", "https://i.ibb.co", "https://*.ibb.co", "https://picsum.photos", "https://fastly.picsum.photos"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'self'"],
      upgradeInsecureRequests: isProduction ? [] : null
    }
  },
  crossOriginEmbedderPolicy: false
}));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

if (isProduction && !process.env.SESSION_SECRET) throw new Error('SESSION_SECRET Railway Variable is required.');
const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(48).toString('hex');
app.use(session({
  store: new PgSession({ pool, tableName: 'user_sessions', createTableIfMissing: true }),
  name: 'zyepam.sid',
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'strict',
    maxAge: 8 * 60 * 60 * 1000
  }
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 8,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Twòp tantativ koneksyon. Eseye ankò nan 15 minit.' }
});
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024, files: 1 },
  fileFilter: (_req, file, cb) => {
    if (!['image/jpeg', 'image/png', 'image/webp', 'image/gif'].includes(file.mimetype)) {
      return cb(new Error('Fòma imaj sa a pa aksepte.'));
    }
    cb(null, true);
  }
});

function sameOrigin(req, res, next) {
  const origin = req.get('origin');
  if (origin) {
    const expected = `${req.protocol}://${req.get('host')}`;
    if (origin !== expected) return res.status(403).json({ error: 'Demann sa a pa otorize.' });
  }
  next();
}
app.use('/api', (req, res, next) => {
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return sameOrigin(req, res, next);
  next();
});

function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Ou dwe konekte.' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'superadmin') {
    return res.status(403).json({ error: 'Se Super Admin sèlman ki gen dwa fè aksyon sa a.' });
  }
  next();
}
function cleanText(value, max) {
  return typeof value === 'string' ? value.trim().slice(0, max) : '';
}

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_users (
      id BIGSERIAL PRIMARY KEY,
      name VARCHAR(120) NOT NULL,
      username VARCHAR(60) NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role VARCHAR(20) NOT NULL CHECK (role IN ('superadmin','journalist')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS articles (
      id BIGSERIAL PRIMARY KEY,
      title VARCHAR(240) NOT NULL,
      category VARCHAR(80) NOT NULL,
      image TEXT NOT NULL,
      excerpt TEXT NOT NULL DEFAULT '',
      content TEXT NOT NULL,
      author VARCHAR(120) NOT NULL,
      is_blacklisted BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS article_moderation (
      article_id BIGINT PRIMARY KEY,
      is_hidden BOOLEAN NOT NULL DEFAULT FALSE,
      is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS articles_created_at_idx ON articles(created_at DESC);
  `);

  await pool.query("SELECT setval(pg_get_serial_sequence('articles','id'), GREATEST(COALESCE((SELECT MAX(id) FROM articles), 999999), 999999), true)");

  const username = cleanText(process.env.ADMIN_USERNAME, 60).toLowerCase();
  const password = process.env.ADMIN_PASSWORD;
  if (!username || !/^[a-z0-9._-]{3,60}$/.test(username) || !password || password.length < 12) {
    throw new Error('Set ADMIN_USERNAME and ADMIN_PASSWORD (minimum 12 characters) in Railway Variables.');
  }
  const found = await pool.query('SELECT id, role FROM app_users WHERE username = $1', [username]);
  const hash = await bcrypt.hash(password, 12);
  if (found.rowCount === 0) {
    await pool.query(
      'INSERT INTO app_users (name, username, password_hash, role) VALUES ($1,$2,$3,$4)',
      ['Super Admin', username, hash, 'superadmin']
    );
    console.log('Initial Super Admin account created from Railway Variables.');
  } else if (found.rows[0].role === 'superadmin') {
    await pool.query('UPDATE app_users SET password_hash = $1, name = $2 WHERE id = $3', [hash, 'Super Admin', found.rows[0].id]);
    console.log('Super Admin password synchronized from Railway Variables.');
  } else {
    throw new Error('ADMIN_USERNAME is already used by a journalist account. Choose a different admin username.');
  }
}

app.get('/api/health', async (_req, res) => {
  try { await pool.query('SELECT 1'); res.json({ ok: true, database: 'connected' }); }
  catch { res.status(503).json({ ok: false, database: 'unavailable' }); }
});

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const username = cleanText(req.body.username, 60).toLowerCase();
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  if (!username || !password) return res.status(400).json({ error: 'Antre username ak modpas ou.' });
  const result = await pool.query(
    'SELECT id, name, username, password_hash, role FROM app_users WHERE username = $1',
    [username]
  );
  const user = result.rows[0];
  const valid = user && await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Username oswa modpas pa bon.' });
  await new Promise((resolve, reject) => req.session.regenerate(err => err ? reject(err) : resolve()));
  req.session.user = { id: user.id, name: user.name, username: user.username, role: user.role };
  res.json({ user: req.session.user });
});

app.get('/api/auth/me', (req, res) => res.json({ user: req.session.user || null }));
app.post('/api/auth/logout', requireAuth, (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: 'Logout pa reyisi.' });
    res.clearCookie('zyepam.sid', { httpOnly: true, secure: isProduction, sameSite: 'strict' });
    res.json({ ok: true });
  });
});

app.get('/api/journalists', requireAdmin, async (_req, res) => {
  const result = await pool.query(
    "SELECT id, name, username, created_at FROM app_users WHERE role = 'journalist' ORDER BY created_at DESC"
  );
  res.json({ journalists: result.rows });
});
app.post('/api/journalists', requireAdmin, async (req, res) => {
  const name = cleanText(req.body.name, 120);
  const username = cleanText(req.body.username, 60).toLowerCase();
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  if (!name || !/^[a-z0-9._-]{3,60}$/.test(username) || password.length < 12) {
    return res.status(400).json({ error: 'Non obligatwa. Username dwe gen 3 a 60 karaktè. Modpas la dwe gen omwen 12 karaktè.' });
  }
  try {
    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      "INSERT INTO app_users (name, username, password_hash, role) VALUES ($1,$2,$3,'journalist') RETURNING id, name, username, created_at",
      [name, username, hash]
    );
    res.status(201).json({ journalist: result.rows[0] });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Username sa a deja egziste.' });
    throw err;
  }
});
app.delete('/api/journalists/:id', requireAdmin, async (req, res) => {
  await pool.query("DELETE FROM app_users WHERE id = $1 AND role = 'journalist'", [req.params.id]);
  res.json({ ok: true });
});

app.get('/api/articles', async (_req, res) => {
  const result = await pool.query(
    'SELECT id, title, category, image, excerpt, content, author, is_blacklisted AS "isBlacklisted", created_at AS date FROM articles WHERE is_blacklisted = FALSE ORDER BY created_at DESC'
  );
  res.json({ articles: result.rows });
});
app.get('/api/articles/manage', requireAuth, async (req, res) => {
  const result = await pool.query(
    'SELECT id, title, category, image, excerpt, content, author, is_blacklisted AS "isBlacklisted", created_at AS date FROM articles ORDER BY created_at DESC'
  );
  res.json({ articles: result.rows, role: req.session.user.role });
});
app.post('/api/articles', requireAuth, async (req, res) => {
  const title = cleanText(req.body.title, 240);
  const category = cleanText(req.body.category, 80);
  const image = cleanText(req.body.image, 2000);
  const content = cleanText(req.body.content, 30000);
  if (!title || !category || !content || !/^https:\/\/(?:i\.ibb\.co|ibb\.co)\//i.test(image)) {
    return res.status(400).json({ error: 'Verifye tit, kategori, kontni ak imaj la.' });
  }
  const author = req.session.user.name;
  const excerpt = content.slice(0, 160);
  const result = await pool.query(
    'INSERT INTO articles (title, category, image, excerpt, content, author) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id,title,category,image,excerpt,content,author,is_blacklisted AS "isBlacklisted",created_at AS date',
    [title, category, image, excerpt, content, author]
  );
  res.status(201).json({ article: result.rows[0] });
});
app.patch('/api/articles/:id/visibility', requireAdmin, async (req, res) => {
  const hidden = Boolean(req.body.hidden);
  await pool.query('UPDATE articles SET is_blacklisted = $1 WHERE id = $2', [hidden, req.params.id]);
  res.json({ ok: true });
});
app.delete('/api/articles/:id', requireAdmin, async (req, res) => {
  await pool.query('DELETE FROM articles WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
});

app.get('/api/moderation', async (_req, res) => {
  const result = await pool.query('SELECT article_id AS id, is_hidden AS hidden, is_deleted AS deleted FROM article_moderation');
  res.json({ items: result.rows });
});
app.patch('/api/moderation/:id', requireAdmin, async (req, res) => {
  const hidden = Boolean(req.body.hidden);
  const deleted = Boolean(req.body.deleted);
  await pool.query(
    `INSERT INTO article_moderation (article_id, is_hidden, is_deleted)
     VALUES ($1,$2,$3)
     ON CONFLICT (article_id) DO UPDATE SET is_hidden = EXCLUDED.is_hidden, is_deleted = EXCLUDED.is_deleted, updated_at = NOW()`,
    [req.params.id, hidden, deleted]
  );
  res.json({ ok: true });
});

app.post('/api/upload-image', requireAuth, upload.single('image'), async (req, res) => {
  if (!process.env.IMGBB_API_KEY) return res.status(503).json({ error: 'IMGBB_API_KEY poko mete nan Railway Variables.' });
  if (!req.file) return res.status(400).json({ error: 'Chwazi yon imaj valid.' });
  const body = new URLSearchParams();
  body.set('image', req.file.buffer.toString('base64'));
  const upstream = await fetch(`https://api.imgbb.com/1/upload?key=${encodeURIComponent(process.env.IMGBB_API_KEY)}`, {
    method: 'POST', body
  });
  const data = await upstream.json();
  if (!upstream.ok || !data.success || !data.data?.url) {
    return res.status(502).json({ error: 'ImgBB pa t kapab resevwa imaj la.' });
  }
  res.json({ url: data.data.url });
});

app.use(express.static('public', { extensions: ['html'] }));
app.use((err, _req, res, _next) => {
  console.error(err);
  if (err instanceof multer.MulterError) return res.status(400).json({ error: 'Imaj la twò gwo. Limit la se 5 MB.' });
  res.status(500).json({ error: 'Gen yon erè sou sèvè a. Eseye ankò.' });
});

initDatabase().then(() => {
  app.listen(port, '0.0.0.0', () => console.log(`ZYEPAM INFO server listening on ${port}`));
}).catch(err => {
  console.error('Database initialization failed:', err);
  process.exit(1);
});
