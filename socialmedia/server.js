const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const { DatabaseSync } = require('node:sqlite');
const Busboy = require('busboy');
const { pipeline } = require('node:stream/promises');

const scrypt = promisify(crypto.scrypt);
const port = Number(process.env.PORT || 3000);
const host = process.env.HOST || '127.0.0.1';
const databasePath = path.resolve(process.env.DATABASE_PATH || path.join(__dirname, 'data', 'gather.sqlite'));
const uploadsPath = path.resolve(process.env.UPLOADS_PATH || path.join(__dirname, 'data', 'uploads'));
const sessionLifetime = 7 * 24 * 60 * 60 * 1000;
const cookieName = 'gather_session';
const maxRequestBytes = 8 * 1024;
const maxUploadBytes = 130 * 1024 * 1024;
const maxSingleFileBytes = 105 * 1024 * 1024;
const maxPhotoBytes = 12 * 1024 * 1024;
const maxMusicBytes = 20 * 1024 * 1024;
const rateLimitWindow = 15 * 60 * 1000;
const rateLimitMaximum = 10;
const authAttempts = new Map();

fs.mkdirSync(path.dirname(databasePath), { recursive: true });
fs.mkdirSync(uploadsPath, { recursive: true });
const database = new DatabaseSync(databasePath);
database.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
  CREATE TABLE IF NOT EXISTS media (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('photo', 'video', 'music')),
    mime_type TEXT NOT NULL,
    file_name TEXT NOT NULL,
    original_name TEXT NOT NULL DEFAULT '',
    file_size INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    caption TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL CHECK (kind IN ('text', 'photo', 'reel')),
    media_id TEXT REFERENCES media(id) ON DELETE SET NULL,
    music_id TEXT REFERENCES media(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS posts_created_at ON posts(created_at DESC);
  CREATE INDEX IF NOT EXISTS media_owner_kind ON media(user_id, kind, created_at DESC);
`);
if (!database.prepare('PRAGMA table_info(media)').all().some(column => column.name === 'original_name')) {
  database.exec("ALTER TABLE media ADD COLUMN original_name TEXT NOT NULL DEFAULT ''");
}

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function sendJson(response, status, body, extraHeaders = {}) {
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...extraHeaders
  });
  response.end(JSON.stringify(body));
}

async function readJson(request) {
  if (!request.headers['content-type']?.toLowerCase().startsWith('application/json')) {
    throw new HttpError(415, 'Please submit the form as JSON.');
  }
  const chunks = [];
  let length = 0;
  for await (const chunk of request) {
    length += chunk.length;
    if (length > maxRequestBytes) throw new HttpError(413, 'The submitted form is too large.');
    chunks.push(chunk);
  }
  try {
    const data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('Invalid object');
    return data;
  } catch {
    throw new HttpError(400, 'Please check the submitted form and try again.');
  }
}

function requestCookie(request, name) {
  const cookies = request.headers.cookie || '';
  for (const cookie of cookies.split(';')) {
    const separator = cookie.indexOf('=');
    if (separator !== -1 && cookie.slice(0, separator).trim() === name) {
      return cookie.slice(separator + 1).trim();
    }
  }
  return '';
}

function cookieHeader(value, maxAge) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  return `${cookieName}=${value}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}${secure}`;
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function userDetails(row) {
  return { id: row.id, name: row.name, email: row.email };
}

function getSessionUser(request) {
  const token = requestCookie(request, cookieName);
  if (!/^[a-f0-9]{64}$/.test(token)) return null;
  const session = database.prepare(`
    SELECT users.id, users.name, users.email, sessions.expires_at
    FROM sessions JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ?
  `).get(hashToken(token));
  if (!session || session.expires_at <= Date.now()) return null;
  return userDetails(session);
}

const fileTypes = {
  image: {
    'image/jpeg': { extension: '.jpg', kind: 'photo' },
    'image/png': { extension: '.png', kind: 'photo' },
    'image/webp': { extension: '.webp', kind: 'photo' },
    'image/gif': { extension: '.gif', kind: 'photo' }
  },
  video: {
    'video/mp4': { extension: '.mp4', kind: 'video' },
    'video/webm': { extension: '.webm', kind: 'video' }
  },
  audio: {
    'audio/mpeg': { extension: '.mp3', kind: 'music' },
    'audio/mp3': { extension: '.mp3', kind: 'music' },
    'audio/wav': { extension: '.wav', kind: 'music' },
    'audio/x-wav': { extension: '.wav', kind: 'music' },
    'audio/ogg': { extension: '.ogg', kind: 'music' },
    'audio/flac': { extension: '.flac', kind: 'music' },
    'audio/mp4': { extension: '.m4a', kind: 'music' },
    'audio/x-m4a': { extension: '.m4a', kind: 'music' }
  }
};

function validateFileSignature(file, mimeType) {
  const descriptor = fs.openSync(file.path, 'r');
  const bytes = Buffer.alloc(12);
  try {
    fs.readSync(descriptor, bytes, 0, bytes.length, 0);
  } finally {
    fs.closeSync(descriptor);
  }
  const isMp4 = bytes.length >= 8 && bytes.toString('ascii', 4, 8) === 'ftyp';
  const signatures = {
    'image/jpeg': bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff,
    'image/png': bytes.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])),
    'image/webp': bytes.toString('ascii', 0, 4) === 'RIFF' && bytes.toString('ascii', 8, 12) === 'WEBP',
    'image/gif': bytes.toString('ascii', 0, 3) === 'GIF',
    'video/mp4': isMp4,
    'video/webm': bytes.subarray(0, 4).equals(Buffer.from([0x1a, 0x45, 0xdf, 0xa3])),
    'audio/mpeg': bytes.toString('ascii', 0, 3) === 'ID3' || (bytes[0] === 0xff && (bytes[1] & 0xe0) === 0xe0),
    'audio/mp3': bytes.toString('ascii', 0, 3) === 'ID3' || (bytes[0] === 0xff && (bytes[1] & 0xe0) === 0xe0),
    'audio/wav': bytes.toString('ascii', 0, 4) === 'RIFF' && bytes.toString('ascii', 8, 12) === 'WAVE',
    'audio/x-wav': bytes.toString('ascii', 0, 4) === 'RIFF' && bytes.toString('ascii', 8, 12) === 'WAVE',
    'audio/ogg': bytes.toString('ascii', 0, 4) === 'OggS',
    'audio/flac': bytes.toString('ascii', 0, 4) === 'fLaC',
    'audio/mp4': isMp4,
    'audio/x-m4a': isMp4
  };
  if (!signatures[mimeType]) throw new HttpError(415, 'That file content does not match its selected file type.');
}

async function parseMultipart(request, maximumFiles = 2) {
  const contentLength = Number(request.headers['content-length'] || 0);
  if (contentLength > maxUploadBytes) {
    request.resume();
    throw new HttpError(413, 'The upload is too large. Please choose smaller files.');
  }
  let parser;
  try {
    parser = Busboy({
      headers: request.headers,
      limits: { files: maximumFiles, fields: 5, fieldSize: 1000, fileSize: maxSingleFileBytes }
    });
  } catch {
    throw new HttpError(400, 'Choose a file and try uploading again.');
  }

  const fields = {};
  const files = [];
  const tasks = [];
  let failure = null;
  let totalBytes = 0;
  const markFailure = error => {
    failure ||= error;
  };

  parser.on('field', (name, value, info) => {
    if (info.valueTruncated) markFailure(new HttpError(400, 'A form field is too long.'));
    else fields[name] = value;
  });
  parser.on('filesLimit', () => markFailure(new HttpError(400, 'Too many files were submitted.')));
  parser.on('fieldsLimit', () => markFailure(new HttpError(400, 'Too many form fields were submitted.')));
  parser.on('file', (fieldName, stream, info) => {
    const id = crypto.randomBytes(16).toString('hex');
    const temporaryPath = path.join(uploadsPath, `${id}.upload`);
    const file = {
      fieldName,
      originalName: path.basename(path.win32.basename(info.filename || 'upload')).replace(/[\u0000-\u001f\u007f]/g, '').slice(0, 180),
      mimeType: (info.mimeType || '').toLowerCase().split(';')[0],
      path: temporaryPath,
      size: 0,
      truncated: false
    };
    files.push(file);
    stream.on('limit', () => {
      file.truncated = true;
      markFailure(new HttpError(413, 'The upload is too large. Please choose a smaller file.'));
    });
    stream.on('data', chunk => {
      totalBytes += chunk.length;
      if (totalBytes > maxUploadBytes) markFailure(new HttpError(413, 'The upload is too large.'));
    });
    const writeTask = pipeline(stream, fs.createWriteStream(temporaryPath, { flags: 'wx' }))
      .then(() => {
        file.size = fs.statSync(temporaryPath).size;
      })
      .catch(error => {
        markFailure(error);
      });
    tasks.push(writeTask);
  });

  try {
    await new Promise((resolve, reject) => {
      parser.once('error', reject);
      parser.once('close', resolve);
      request.pipe(parser);
    });
    await Promise.all(tasks);
    if (failure) throw failure;
    return { fields, files };
  } catch (error) {
    await Promise.all(files.map(file => fs.promises.rm(file.path, { force: true })));
    throw error;
  }
}

function saveMedia(userId, file, expectedCategory, maximumSize) {
  const allowedTypes = fileTypes[expectedCategory];
  const type = allowedTypes[file.mimeType];
  if (!type) throw new HttpError(415, `Choose a supported ${expectedCategory} file.`);
  if (!file.size || file.size > maximumSize) {
    throw new HttpError(413, `Choose a ${expectedCategory} file smaller than ${Math.floor(maximumSize / (1024 * 1024))} MB.`);
  }
  validateFileSignature(file, file.mimeType);
  const destination = path.join(uploadsPath, `${path.basename(file.path, '.upload')}${type.extension}`);
  fs.renameSync(file.path, destination);
  try {
    database.prepare(`
      INSERT INTO media (id, user_id, kind, mime_type, file_name, original_name, file_size)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(path.basename(destination, type.extension), userId, type.kind, file.mimeType, destination, file.originalName, file.size);
  } catch (error) {
    fs.rmSync(destination, { force: true });
    throw error;
  }
  return path.basename(destination, type.extension);
}

async function cleanMultipartFiles(files) {
  await Promise.all(files.map(file => fs.promises.rm(file.path, { force: true })));
}

async function createSession(response, user) {
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = Date.now() + sessionLifetime;
  database.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(Date.now());
  database.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)')
    .run(hashToken(token), user.id, expiresAt);
  response.setHeader('Set-Cookie', cookieHeader(token, Math.floor(sessionLifetime / 1000)));
  return userDetails(user);
}

function rateLimit(request) {
  const now = Date.now();
  const key = request.socket.remoteAddress || 'unknown';
  const attempt = authAttempts.get(key);
  if (attempt && now - attempt.startedAt < rateLimitWindow && attempt.count >= rateLimitMaximum) {
    throw new HttpError(429, 'Too many sign-in attempts. Please wait a little and try again.');
  }
  if (!attempt || now - attempt.startedAt >= rateLimitWindow) {
    authAttempts.set(key, { startedAt: now, count: 1 });
  } else {
    attempt.count++;
  }
}

async function handleApi(request, response, url) {
  if (url.pathname.startsWith('/api/') && !['/api/me', '/api/login', '/api/signup'].includes(url.pathname)) {
    const user = getSessionUser(request);
    if (!user) {
      sendJson(response, 401, { error: 'Please log in before uploading or viewing community media.' }, {
        'Set-Cookie': cookieHeader('', 0)
      });
      return;
    }

    if (request.method === 'GET' && url.pathname === '/api/posts') {
      const posts = database.prepare(`
        SELECT posts.id, posts.caption, posts.kind, posts.created_at,
          users.id AS user_id, users.name AS user_name,
          media.id AS media_id, media.mime_type AS media_mime_type,
          music.id AS music_id, music.original_name AS music_original_name
        FROM posts
        JOIN users ON users.id = posts.user_id
        LEFT JOIN media ON media.id = posts.media_id
        LEFT JOIN media AS music ON music.id = posts.music_id
        ORDER BY posts.created_at DESC, posts.id DESC
        LIMIT 100
      `).all().map(post => ({
        id: post.id,
        caption: post.caption,
        kind: post.kind,
        createdAt: post.created_at,
        author: { id: post.user_id, name: post.user_name },
        media: post.media_id ? { url: `/media/${post.media_id}`, mimeType: post.media_mime_type } : null,
        music: post.music_id ? { url: `/media/${post.music_id}`, name: post.music_original_name || 'Music track' } : null
      }));
      sendJson(response, 200, { posts });
      return;
    }

    if (request.method === 'GET' && url.pathname === '/api/music') {
      const tracks = database.prepare(`
        SELECT id, original_name, created_at
        FROM media WHERE user_id = ? AND kind = 'music'
        ORDER BY created_at DESC, id DESC LIMIT 50
      `).all(user.id).map(track => ({
        id: track.id,
        name: track.original_name || 'My music',
        url: `/media/${track.id}`
      }));
      sendJson(response, 200, { tracks });
      return;
    }

    if (request.method === 'POST' && url.pathname === '/api/music') {
      const upload = await parseMultipart(request, 1);
      try {
        const file = upload.files.find(item => item.fieldName === 'music');
        if (!file) throw new HttpError(400, 'Choose a music file to upload.');
        const id = saveMedia(user.id, file, 'audio', maxMusicBytes);
        sendJson(response, 201, { track: { id, url: `/media/${id}`, name: file.originalName || 'My music' } });
      } catch (error) {
        await cleanMultipartFiles(upload.files);
        throw error;
      }
      return;
    }

    if (request.method === 'POST' && url.pathname === '/api/posts') {
      const upload = await parseMultipart(request, 1);
      let mediaId = null;
      const savedMediaIds = [];
      try {
        const kind = upload.fields.kind;
        const caption = typeof upload.fields.caption === 'string' ? upload.fields.caption.trim() : '';
        if (!['text', 'photo', 'reel'].includes(kind)) throw new HttpError(400, 'Choose a post or reel.');
        if (caption.length > 500) throw new HttpError(400, 'Captions must be 500 characters or fewer.');
        const expectedField = kind === 'photo' ? 'photo' : 'video';
        const mediaFile = upload.files.find(file => file.fieldName === expectedField);
        const musicFiles = upload.files.filter(file => file.fieldName === 'music');
        if (kind === 'photo' && !mediaFile) throw new HttpError(400, 'Choose a photo to share.');
        if (kind === 'reel' && !mediaFile) throw new HttpError(400, 'Choose a video to create your reel.');
        if (upload.files.some(file => file !== mediaFile && !(file.fieldName === 'music' && kind === 'reel'))) {
          throw new HttpError(400, 'The uploaded file does not match this post type.');
        }
        if (musicFiles.length > 1) throw new HttpError(400, 'Choose one music track for your reel.');

        if (mediaFile) {
          mediaId = saveMedia(user.id, mediaFile, kind === 'photo' ? 'image' : 'video', kind === 'photo' ? maxPhotoBytes : maxSingleFileBytes);
          savedMediaIds.push(mediaId);
        }
        let musicId = upload.fields.musicId || null;
        if (musicFiles.length) {
          if (musicId) throw new HttpError(400, 'Choose either an uploaded track or a saved track.');
          musicId = saveMedia(user.id, musicFiles[0], 'audio', maxMusicBytes);
          savedMediaIds.push(musicId);
        }
        if (musicId) {
          const track = database.prepare("SELECT id FROM media WHERE id = ? AND user_id = ? AND kind = 'music'").get(musicId, user.id);
          if (!track) throw new HttpError(400, 'Choose a music track from your library.');
        }
        if (kind !== 'reel' && musicId) throw new HttpError(400, 'Music can only be added to a reel.');

        const result = database.prepare(`
          INSERT INTO posts (user_id, caption, kind, media_id, music_id)
          VALUES (?, ?, ?, ?, ?)
        `).run(user.id, caption, kind, mediaId, musicId);
        sendJson(response, 201, { id: Number(result.lastInsertRowid) });
      } catch (error) {
        await cleanMultipartFiles(upload.files);
        for (const savedMediaId of savedMediaIds) {
          const media = database.prepare('SELECT file_name FROM media WHERE id = ?').get(savedMediaId);
          if (media) {
            database.prepare('DELETE FROM media WHERE id = ?').run(savedMediaId);
            await fs.promises.rm(media.file_name, { force: true });
          }
        }
        throw error;
      }
      return;
    }
  }

  const mediaMatch = request.method === 'GET' && url.pathname.match(/^\/media\/([a-f0-9]{32})$/);
  if (mediaMatch) {
    const user = getSessionUser(request);
    if (!user) {
      sendJson(response, 401, { error: 'Please log in to view this media.' });
      return;
    }
    const media = database.prepare(`
      SELECT media.file_name, media.mime_type, media.file_size, media.kind
      FROM media
      WHERE media.id = ? AND (
        media.user_id = ? OR EXISTS (SELECT 1 FROM posts WHERE posts.media_id = media.id OR posts.music_id = media.id)
      )
    `).get(mediaMatch[1], user.id);
    if (!media) {
      sendJson(response, 404, { error: 'This media could not be found.' });
      return;
    }
    const headers = {
      'Content-Type': media.mime_type,
      'Content-Length': media.file_size,
      'Cache-Control': 'private, max-age=3600',
      'Accept-Ranges': 'bytes',
      'X-Content-Type-Options': 'nosniff'
    };
    const range = request.headers.range;
    if (range) {
      const match = range.match(/^bytes=(\d*)-(\d*)$/);
      if (!match) {
        response.writeHead(416, { 'Content-Range': `bytes */${media.file_size}` });
        response.end();
        return;
      }
      const start = match[1] ? Number(match[1]) : 0;
      const end = match[2] ? Math.min(Number(match[2]), media.file_size - 1) : media.file_size - 1;
      if (start > end || start >= media.file_size) {
        response.writeHead(416, { 'Content-Range': `bytes */${media.file_size}` });
        response.end();
        return;
      }
      headers['Content-Range'] = `bytes ${start}-${end}/${media.file_size}`;
      headers['Content-Length'] = end - start + 1;
      response.writeHead(206, headers);
      fs.createReadStream(media.file_name, { start, end }).pipe(response);
      return;
    }
    response.writeHead(200, headers);
    fs.createReadStream(media.file_name).pipe(response);
    return;
  }

  if (request.method === 'GET' && url.pathname === '/api/me') {
    const token = requestCookie(request, cookieName);
    if (!/^[a-f0-9]{64}$/.test(token)) {
      sendJson(response, 200, { user: null });
      return;
    }
    const session = database.prepare(`
      SELECT users.id, users.name, users.email, sessions.expires_at
      FROM sessions JOIN users ON users.id = sessions.user_id
      WHERE sessions.token_hash = ?
    `).get(hashToken(token));
    if (!session || session.expires_at <= Date.now()) {
      if (session) database.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hashToken(token));
      sendJson(response, 200, { user: null }, { 'Set-Cookie': cookieHeader('', 0) });
      return;
    }
    sendJson(response, 200, { user: userDetails(session) });
    return;
  }

  if (request.method === 'POST' && (url.pathname === '/api/signup' || url.pathname === '/api/login')) {
    rateLimit(request);
    const data = await readJson(request);
    const email = typeof data.email === 'string' ? data.email.trim().toLowerCase() : '';
    const password = typeof data.password === 'string' ? data.password : '';
    if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      throw new HttpError(400, 'Enter a valid email address.');
    }
    if (password.length < (url.pathname === '/api/signup' ? 8 : 1) || password.length > 128) {
      throw new HttpError(400, url.pathname === '/api/signup'
        ? 'Your password must be between 8 and 128 characters.'
        : 'Enter your email and password.');
    }

    if (url.pathname === '/api/signup') {
      const name = typeof data.name === 'string' ? data.name.trim() : '';
      if (name.length < 1 || name.length > 48) {
        throw new HttpError(400, 'Your name must be between 1 and 48 characters.');
      }
      if (database.prepare('SELECT id FROM users WHERE email = ?').get(email)) {
        throw new HttpError(409, 'An account with that email already exists. Try logging in instead.');
      }
      const salt = crypto.randomBytes(16);
      const passwordHash = await scrypt(password, salt, 64);
      let result;
      try {
        result = database.prepare('INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)')
          .run(name, email, `${salt.toString('hex')}:${passwordHash.toString('hex')}`);
      } catch (error) {
        if (error.code === 'ERR_SQLITE_ERROR' && /unique/i.test(error.message)) {
          throw new HttpError(409, 'An account with that email already exists. Try logging in instead.');
        }
        throw error;
      }
      const user = { id: Number(result.lastInsertRowid), name, email };
      sendJson(response, 201, { user: await createSession(response, user) }, {
        'Set-Cookie': response.getHeader('Set-Cookie')
      });
      return;
    }

    const user = database.prepare('SELECT id, name, email, password_hash FROM users WHERE email = ?').get(email);
    let validPassword = false;
    if (user) {
      const [saltHex, expectedHex] = user.password_hash.split(':');
      const actual = await scrypt(password, Buffer.from(saltHex, 'hex'), 64);
      const expected = Buffer.from(expectedHex, 'hex');
      validPassword = actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
    }
    if (!validPassword) throw new HttpError(401, 'That email and password combination was not recognized.');
    sendJson(response, 200, { user: await createSession(response, user) }, {
      'Set-Cookie': response.getHeader('Set-Cookie')
    });
    return;
  }

  if (request.method === 'POST' && url.pathname === '/api/logout') {
    const token = requestCookie(request, cookieName);
    if (/^[a-f0-9]{64}$/.test(token)) {
      database.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hashToken(token));
    }
    sendJson(response, 200, { ok: true }, { 'Set-Cookie': cookieHeader('', 0) });
    return;
  }

  sendJson(response, 404, { error: 'That API route was not found.' });
}

const server = http.createServer(async (request, response) => {
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  response.setHeader('X-Frame-Options', 'DENY');
  try {
    const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
    if (url.pathname.startsWith('/api/')) {
      await handleApi(request, response, url);
      return;
    }
    if (request.method !== 'GET' || (url.pathname !== '/' && url.pathname !== '/index.html')) {
      sendJson(response, 404, { error: 'Page not found.' });
      return;
    }
    const page = await fs.promises.readFile(path.join(__dirname, 'index.html'));
    response.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-cache',
      'Content-Length': page.length
    });
    response.end(page);
  } catch (error) {
    if (response.headersSent) {
      response.destroy(error);
      return;
    }
    if (error instanceof HttpError) {
      sendJson(response, error.status, { error: error.message });
      return;
    }
    console.error('Request failed:', error);
    sendJson(response, 500, { error: 'Something went wrong. Please try again.' });
  }
});

server.listen(port, host, () => {
  console.log(`Gather is running at http://${host}:${port}`);
  console.log(`SQLite database: ${databasePath}`);
});

function shutdown() {
  server.close(() => {
    database.close();
    process.exit(0);
  });
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
