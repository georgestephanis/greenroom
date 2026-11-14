export const ALLOWED_STATUS_CODES = new Set([200, 301, 302, 303, 307, 308, 404]);

// Rule 2 (issue #214 section 4): tenant _headers may never set these.
export const FORBIDDEN_HEADER_NAMES = new Set([
  'content-security-policy',
  'content-security-policy-report-only',
  'service-worker-allowed',
  'x-content-type-options',
  'referrer-policy',
  'x-robots-tag',
  'set-cookie',
  'host',
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailers',
  'transfer-encoding',
  'upgrade',
  'basic-auth',
  'x-sendfile',
  'x-accel-redirect',
]);

// Patterns come from user-published _redirects files, so this cache is keyed on
// attacker-influenced strings. It is bounded, and evicts oldest-first rather than simply
// refusing new entries once full: a fixed cap with no eviction lets one tenant fill the
// cache with junk patterns and permanently disable caching for every other site.
const PATTERN_CACHE_LIMIT = 5000;
const patternCache = new Map();

function cachePattern(pattern, compiled) {
  if (patternCache.size >= PATTERN_CACHE_LIMIT) {
    const oldest = patternCache.keys().next();
    if (!oldest.done) patternCache.delete(oldest.value);
  }
  patternCache.set(pattern, compiled);
}

// Convert route pattern (/blog/:post or /assets/*) to RegExp and capture names
export function compilePattern(pattern) {
  const cached = patternCache.get(pattern);
  if (cached) return cached;

  const splatCount = (pattern.match(/\*/g) || []).length;
  if (splatCount > 1) {
    throw new Error(
      `Pattern '${pattern}' contains more than one wildcard (*) which is not permitted`
    );
  }

  const keys = [];

  // Escape regex special chars except * and :name
  const regexStr = pattern
    .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
    .replace(/:([a-zA-Z0-9_]+)/g, (_, key) => {
      keys.push(key);
      return '([^/]+)';
    })
    .replace(/\*/g, () => {
      keys.push('splat');
      return '(.*)';
    });

  const compiled = {
    regex: new RegExp(`^${regexStr}$`),
    keys,
  };

  cachePattern(pattern, compiled);

  return compiled;
}

export function matchRule(
  pattern,
  pathname,
  searchParams,
  declaredQuery,
  _headers
) {
  try {
    const { regex, keys } = compilePattern(pattern);
    const match = pathname.match(regex);
    if (!match) return { matched: false, params: {} };

    const params = {};
    for (let i = 0; i < keys.length; i++) {
      params[keys[i]] = match[i + 1] || '';
    }

    // Query parameter check
    if (declaredQuery) {
      for (const [key, valPlaceholder] of Object.entries(declaredQuery)) {
        const incomingVal = searchParams.get(key);
        if (incomingVal === null) return { matched: false, params: {} };
        if (valPlaceholder.startsWith(':')) {
          params[valPlaceholder.slice(1)] = incomingVal;
        }
      }
    }

    return { matched: true, params };
  } catch {
    return { matched: false, params: {} };
  }
}

export function substituteDestination(destination, params) {
  let result = destination;

  // Substitute only the keys declared in the pattern
  for (const [key, val] of Object.entries(params)) {
    result = result.replace(new RegExp(`:${key}\\b`, 'g'), encodeURI(val));
  }

  // Remove unmatched segment placeholders in path (e.g. /from/:missing -> /from/)
  // without touching port numbers like :8080 in http://example.com:8080/
  if (result.startsWith('http://') || result.startsWith('https://')) {
    try {
      const url = new URL(result);
      url.pathname = url.pathname.replace(/:[a-zA-Z_][a-zA-Z0-9_]*\b/g, '');
      result = url.toString();
    } catch {}
  } else {
    result = result.replace(/:[a-zA-Z_][a-zA-Z0-9_]*\b/g, '');
  }

  return result;
}

export function parseRedirectsFile(content)

  {
  const lines = content.split('\n');
  const rules = [];
  const diagnostics = [];

  for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
    let line = lines[lineIndex].trim();
    if (!line || line.startsWith('#')) continue;

    // Check for comments at end of line
    const commentIdx = line.indexOf('#');
    if (commentIdx !== -1) {
      line = line.substring(0, commentIdx).trim();
    }

    const parts = line.split(/\s+/);
    if (parts.length < 2) continue;

    const source = parts[0];
    let destination;
    let status = 302;
    let force = false;
    let query;
    let conditions;

    let partIdx;

    // Check for query matcher tokens like `q=:term` (only if there are further parts for destination)
    if (
      parts.length >= 3 &&
      parts[1].includes('=') &&
      !parts[1].startsWith('/') &&
      !parts[1].startsWith('http://') &&
      !parts[1].startsWith('https://')
    ) {
      const eqIdx = parts[1].indexOf('=');
      const qKey = parts[1].slice(0, eqIdx);
      const qVal = parts[1].slice(eqIdx + 1);
      query = { [qKey]: qVal };
      destination = parts[2];
      partIdx = 3;
    } else {
      destination = parts[1];
      partIdx = 2;
    }

    if (parts[partIdx]) {
      const statusStr = parts[partIdx];
      if (statusStr.endsWith('!')) {
        force = true;
        const code = parseInt(statusStr.slice(0, -1), 10);
        if (!isNaN(code)) status = code;
      } else if (!isNaN(parseInt(statusStr, 10))) {
        status = parseInt(statusStr, 10);
      } else if (statusStr.includes('=')) {
        const [cKey, cVal] = statusStr.split('=');
        conditions = { ...conditions, [cKey]: cVal };
      }
      partIdx++;
    }

    while (parts[partIdx]) {
      if (parts[partIdx].includes('=')) {
        const [cKey, cVal] = parts[partIdx].split('=');
        conditions = { ...conditions, [cKey]: cVal };
      }
      partIdx++;
    }

    if (!ALLOWED_STATUS_CODES.has(status)) {
      diagnostics.push({
        level: 'error',
        message: `Line ${lineIndex + 1}: Unsupported redirect status code ${status}. Must be one of: 200, 301, 302, 303, 307, 308, 404.`,
      });
      continue;
    }

    try {
      compilePattern(source);
    } catch (err) {
      diagnostics.push({
        level: 'error',
        message: `Line ${lineIndex + 1}: Invalid source pattern "${source}": ${err.message}`,
      });
      continue;
    }

    rules.push({
      source,
      destination,
      status,
      force,
      query,
      conditions,
    });
  }

  return { rules, diagnostics };
}

export function parseHeadersFile(content)

  {
  const lines = content.split('\n');
  const blocks = [];
  const diagnostics = [];
  let currentBlock = null;

  for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
    const rawLine = lines[lineIndex];
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    if (!rawLine.startsWith(' ') && !rawLine.startsWith('\t')) {
      // New block matcher
      try {
        compilePattern(trimmed);
        currentBlock = { source: trimmed, headers: [] };
        blocks.push(currentBlock);
      } catch (err) {
        diagnostics.push({
          level: 'error',
          message: `Line ${lineIndex + 1}: Invalid header source pattern "${trimmed}": ${err.message}`,
        });
        currentBlock = null;
      }
    } else if (currentBlock) {
      if (trimmed.startsWith('!')) {
        const key = trimmed.slice(1).trim();
        currentBlock.headers.push({ key, remove: true });
      } else {
        const colonIdx = trimmed.indexOf(':');
        if (colonIdx !== -1) {
          const key = trimmed.substring(0, colonIdx).trim();
          const value = trimmed.substring(colonIdx + 1).trim();
          const lowerKey = key.toLowerCase();

          if (
            FORBIDDEN_HEADER_NAMES.has(lowerKey) ||
            lowerKey.startsWith('cross-origin-') ||
            lowerKey.startsWith('access-control-')
          ) {
            diagnostics.push({
              level: 'warning',
              message: `Line ${lineIndex + 1}: Header "${key}" is platform-managed and cannot be set by tenant`,
            });
            continue;
          }

          currentBlock.headers.push({ key, value });
        }
      }
    }
  }

  return { blocks, diagnostics };
}

export function computeHeadersForPath(
  blocks,
  pathname
) {
  const result = {};

  for (const block of blocks) {
    try {
      const { regex } = compilePattern(block.source);
      if (regex.test(pathname)) {
        for (const op of block.headers) {
          const lowerKey = op.key.toLowerCase();
          if (op.remove) {
            delete result[lowerKey];
          } else if (op.value !== undefined) {
            if (result[lowerKey]) {
              result[lowerKey] = `${result[lowerKey]}, ${op.value}`;
            } else {
              result[lowerKey] = op.value;
            }
          }
        }
      }
    } catch {}
  }

  return result;
}
