import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const int = (v, d) => (v === undefined || v === '' ? d : Number(v));

export function loadConfig(env = process.env, overrides = {}) {
  const dataDir = path.resolve(overrides.dataDir ?? env.FREESPACE_DATA_DIR ?? './data');
  fs.mkdirSync(dataDir, { recursive: true });
  // Instance secret signs viewer cookies and document tokens; generated once, kept next to the data.
  const secretFile = path.join(dataDir, 'secret.key');
  if (!fs.existsSync(secretFile)) fs.writeFileSync(secretFile, crypto.randomBytes(48).toString('base64url'), { mode: 0o600 });
  return {
    dataDir,
    blobsDir: path.join(dataDir, 'blobs'),
    tmpDir: path.join(dataDir, 'tmp'),
    dbFile: path.join(dataDir, 'control.db'),
    secret: fs.readFileSync(secretFile, 'utf8').trim(),
    host: env.HOST ?? '127.0.0.1',
    port: int(env.PORT, 8080),
    publicUrl: env.FREESPACE_PUBLIC_URL ?? '',
    trustProxy: env.FREESPACE_TRUST_PROXY === '1', // take the client IP from X-Forwarded-For (last hop)
    maxUploadBytes: int(env.FREESPACE_MAX_UPLOAD_BYTES, 200 * 1024 * 1024),
    maxFileBytes: int(env.FREESPACE_MAX_FILE_BYTES, 100 * 1024 * 1024),
    maxJsonBytes: int(env.FREESPACE_MAX_JSON_BYTES, 24 * 1024 * 1024),
    maxSpaceBytes: int(env.FREESPACE_MAX_SPACE_BYTES, 2 * 1024 ** 3),
    maxTotalBytes: int(env.FREESPACE_MAX_TOTAL_BYTES, 20 * 1024 ** 3),
    sessionDays: int(env.FREESPACE_SESSION_DAYS, 30),
    viewerMinutes: int(env.FREESPACE_VIEWER_MINUTES, 60),
    gcIntervalHours: int(env.FREESPACE_GC_INTERVAL_HOURS, 12),
    ...overrides,
  };
}
