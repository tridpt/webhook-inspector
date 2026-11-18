/**
 * NetPulse - Webhook & Request Inspector + API Replay & Fuzzer
 * Zero-dependency Node.js server (Node v18+)
 */

const http = require('node:http');
const https = require('node:https');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const net = require('node:net');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { URL } = require('node:url');
const { performance } = require('node:perf_hooks');

const PORT = Number(process.env.PORT || 4080);
const DATA_DIR = path.join(__dirname, 'data');
const STORE_FILE = path.join(DATA_DIR, 'store.json');
const PUBLIC_DIR = path.join(__dirname, 'public');
const MAX_REQUESTS = 300;

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// Default fuzzing payload presets
const FUZZ_PRESETS = {
  sqli: {
    name: 'SQL / NoSQL Injection Probes',
    description: 'Kiểm tra lỗi xử lý chuỗi truy vấn SQL/NoSQL cơ bản',
    payloads: [
      "' OR '1'='1",
      "' OR 1=1--",
      "\" OR \"1\"=\"1",
      "admin'--",
      "1; SELECT 1--",
      "' UNION SELECT NULL,NULL--",
      "{\"$gt\": \"\"}",
      "{\"$ne\": null}"
    ]
  },
  xss_ssti: {
    name: 'XSS & Template Injection (SSTI)',
    description: 'Kiểm tra phản xạ đầu vào HTML/JS và Server-Side Template Injection',
    payloads: [
      "<script>alert(1)</script>",
      "\"><svg/onload=alert(1)>",
      "javascript:alert(1)",
      "{{7*7}}",
      "${7*7}",
      "<%= 7*7 %>",
      "#{7*7}"
    ]
  },
  boundary: {
    name: 'Boundary & Logic Edge Cases (Payment/Webhook)',
    description: 'Kiểm tra số âm, tràn số, rỗng, kiểu dữ liệu lạ trong API/Webhook',
    payloads: [
      "0",
      "-1",
      "-999999",
      "99999999999999999999",
      "null",
      "undefined",
      "NaN",
      "true",
      "false",
      "",
      "   ",
      "../../../../etc/passwd",
      "..\\..\\..\\Windows\\win.ini"
    ]
  },
  idor: {
    name: 'IDOR / Numeric Sequence (1..15)',
    description: 'Dò quét tham số ID tuần tự để kiểm tra phân quyền (IDOR)',
    payloads: Array.from({ length: 15 }, (_, i) => String(i + 1))
  }
};

// Default store state
function createDefaultStore() {
  return {
    endpoints: [
      {
        id: 'ep-payment',
        slug: 'payment-webhook',
        name: 'Cổng Thanh Toán (VietQR / Stripe)',
        statusCode: 200,
        contentType: 'application/json',
        responseBody: JSON.stringify({ success: true, message: 'Webhook received', timestamp: '{{timestamp}}', requestId: '{{requestId}}' }, null, 2),
        delayMs: 0,
        secret: 'whsec_demo_secret_2026',
        forwardUrl: '',
        createdAt: new Date().toISOString()
      },
      {
        id: 'ep-telegram',
        slug: 'telegram-bot',
        name: 'Telegram Bot Webhook',
        statusCode: 200,
        contentType: 'application/json',
        responseBody: JSON.stringify({ ok: true, result: 'processed' }, null, 2),
        delayMs: 0,
        secret: 'tg_bot_secret_token',
        forwardUrl: '',
        createdAt: new Date().toISOString()
      },
      {
        id: 'ep-default',
        slug: 'catch-all',
        name: 'Endpoint Mặc Định (Catch-All)',
        statusCode: 200,
        contentType: 'application/json',
        responseBody: JSON.stringify({ status: 'ok', capturedBy: 'NetPulse Inspector', id: '{{requestId}}' }, null, 2),
        delayMs: 0,
        secret: '',
        forwardUrl: '',
        notifyWebhookUrl: '',
        notifyOnlyOnAnomaly: false,
        createdAt: new Date().toISOString()
      }
    ],
    envVars: {
      BASE_URL: `http://localhost:${PORT}`,
      WEBHOOK_SLUG: 'payment-webhook',
      API_TOKEN: 'whsec_demo_secret_2026',
      MERCHANT_ID: 'VN_SHOP_01'
    },
    requests: [],
    replays: []
  };
}

let store = createDefaultStore();

function loadStore() {
  try {
    if (fs.existsSync(STORE_FILE)) {
      const raw = fs.readFileSync(STORE_FILE, 'utf8');
      const parsed = JSON.parse(raw);
      if (parsed && Array.isArray(parsed.endpoints)) {
        const defaults = createDefaultStore();
        store = {
          endpoints: parsed.endpoints.length > 0 ? parsed.endpoints : defaults.endpoints,
          envVars: (parsed.envVars && typeof parsed.envVars === 'object') ? parsed.envVars : defaults.envVars,
          requests: Array.isArray(parsed.requests) ? parsed.requests.slice(0, MAX_REQUESTS) : [],
          replays: Array.isArray(parsed.replays) ? parsed.replays.slice(0, 100) : []
        };
      }
    }
  } catch (err) {
    console.error('[Store] Failed to load store.json, using default:', err.message);
  }
}

function saveStore() {
  try {
    fs.writeFileSync(STORE_FILE, JSON.stringify(store, null, 2), 'utf8');
  } catch (err) {
    console.error('[Store] Failed to save store.json:', err.message);
  }
}

loadStore();

// Active SSE clients
const sseClients = new Set();

function broadcastEvent(event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of sseClients) {
    try {
      res.write(payload);
    } catch {
      sseClients.delete(res);
    }
  }
}

// ============================================================================
// PUBLIC INTERNET TUNNEL MANAGER (localhost.run SSH / ngrok / pinggy.io)
// ============================================================================
let tunnelState = {
  active: false,
  status: 'stopped', // 'stopped' | 'starting' | 'online' | 'error'
  provider: null,
  publicBaseUrl: null,
  error: null,
  startedAt: null,
  proc: null
};

function getTunnelPublicInfo() {
  return {
    active: tunnelState.active,
    status: tunnelState.status,
    provider: tunnelState.provider,
    publicBaseUrl: tunnelState.publicBaseUrl,
    error: tunnelState.error,
    startedAt: tunnelState.startedAt
  };
}

function stopPublicTunnel() {
  if (tunnelState.proc) {
    try {
      tunnelState.proc.kill('SIGKILL');
    } catch {}
    tunnelState.proc = null;
  }
  tunnelState = {
    active: false,
    status: 'stopped',
    provider: null,
    publicBaseUrl: null,
    error: null,
    startedAt: null,
    proc: null
  };
  broadcastEvent('tunnel_updated', getTunnelPublicInfo());
  return getTunnelPublicInfo();
}

function startPublicTunnel(localPort, preferredProvider = 'localhost.run') {
  return new Promise((resolve) => {
    stopPublicTunnel();

    tunnelState.status = 'starting';
    tunnelState.provider = preferredProvider;
    broadcastEvent('tunnel_updated', getTunnelPublicInfo());

    let resolved = false;
    const finish = (info) => {
      if (!resolved) {
        resolved = true;
        resolve(info);
      }
    };

    const sshPath = fs.existsSync('C:\\Windows\\System32\\OpenSSH\\ssh.exe')
      ? 'C:\\Windows\\System32\\OpenSSH\\ssh.exe'
      : 'ssh';

    let cmd = sshPath;
    let args = [];

    if (preferredProvider === 'ngrok') {
      const wingetNgrok = path.join(
        process.env.LOCALAPPDATA || '',
        'Microsoft\\WinGet\\Packages\\Ngrok.Ngrok_Microsoft.Winget.Source_8wekyb3d8bbwe\\ngrok.exe'
      );
      cmd = fs.existsSync(wingetNgrok) ? wingetNgrok : 'ngrok';
      args = ['http', String(localPort), '--log=stdout'];
    } else if (preferredProvider === 'pinggy') {
      args = [
        '-p', '443',
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'UserKnownHostsFile=NUL',
        '-o', 'ServerAliveInterval=30',
        `-R0:127.0.0.1:${localPort}`,
        'a.pinggy.io'
      ];
    } else {
      // Default: localhost.run via OpenSSH (zero-signup, instant HTTPS tunnel)
      args = [
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'UserKnownHostsFile=NUL',
        '-o', 'ServerAliveInterval=30',
        '-R', `80:127.0.0.1:${localPort}`,
        'nokey@localhost.run'
      ];
    }

    let proc;
    try {
      proc = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    } catch (err) {
      tunnelState.status = 'error';
      tunnelState.error = `Không thể khởi chạy ${preferredProvider}: ${err.message}`;
      broadcastEvent('tunnel_updated', getTunnelPublicInfo());
      return finish(getTunnelPublicInfo());
    }

    tunnelState.proc = proc;

    const handleOutputChunk = (chunk) => {
      const text = chunk.toString('utf8');
      // Match https://xxxx.lhr.life, https://xxxx.ngrok-free.app, https://xxxx.a.free.pinggy.link, etc.
      const urlMatch = text.match(/https:\/\/[a-zA-Z0-9.-]+\.(?:lhr\.life|localhost\.run|ngrok-free\.app|ngrok\.io|ngrok\.app|pinggy\.link|pinggy\.io|loca\.lt)\b/i);
      if (urlMatch && !tunnelState.publicBaseUrl) {
        tunnelState.active = true;
        tunnelState.status = 'online';
        tunnelState.publicBaseUrl = urlMatch[0].replace(/\/$/, '');
        tunnelState.startedAt = new Date().toISOString();
        tunnelState.error = null;
        broadcastEvent('tunnel_updated', getTunnelPublicInfo());
        finish(getTunnelPublicInfo());
      }
      if (/ERR_NGROK|authentication failed|permission denied/i.test(text) && !tunnelState.publicBaseUrl) {
        tunnelState.status = 'error';
        tunnelState.error = 'Ngrok yêu cầu Authtoken hoặc lỗi xác thực. Hãy chọn chế độ "localhost.run (SSH miễn phí)"!';
        broadcastEvent('tunnel_updated', getTunnelPublicInfo());
      }
    };

    proc.stdout.on('data', handleOutputChunk);
    proc.stderr.on('data', handleOutputChunk);

    // If provider is ngrok, also poll ngrok's local API (127.0.0.1:4040/api/tunnels)
    let ngrokPollTimer = null;
    if (preferredProvider === 'ngrok') {
      ngrokPollTimer = setInterval(async () => {
        if (tunnelState.publicBaseUrl || resolved) {
          clearInterval(ngrokPollTimer);
          return;
        }
        const apiRes = await executeHttpRequest({
          method: 'GET',
          targetUrl: 'http://127.0.0.1:4040/api/tunnels',
          timeoutMs: 800
        });
        if (apiRes.statusCode === 200 && apiRes.body) {
          try {
            const parsed = JSON.parse(apiRes.body);
            const httpsTunnel = (parsed.tunnels || []).find((t) => String(t.public_url || '').startsWith('https://')) || (parsed.tunnels || [])[0];
            if (httpsTunnel && httpsTunnel.public_url) {
              clearInterval(ngrokPollTimer);
              tunnelState.active = true;
              tunnelState.status = 'online';
              tunnelState.publicBaseUrl = httpsTunnel.public_url.replace(/\/$/, '');
              tunnelState.startedAt = new Date().toISOString();
              tunnelState.error = null;
              broadcastEvent('tunnel_updated', getTunnelPublicInfo());
              finish(getTunnelPublicInfo());
            }
          } catch {}
        }
      }, 450);
    }

    proc.on('exit', () => {
      if (ngrokPollTimer) clearInterval(ngrokPollTimer);
      if (tunnelState.proc === proc) {
        tunnelState.active = false;
        if (tunnelState.status !== 'error') {
          tunnelState.status = 'stopped';
        }
        tunnelState.publicBaseUrl = null;
        tunnelState.proc = null;
        broadcastEvent('tunnel_updated', getTunnelPublicInfo());
        finish(getTunnelPublicInfo());
      }
    });

    // Timeout after 10 seconds if URL hasn't appeared yet
    setTimeout(() => {
      if (ngrokPollTimer) clearInterval(ngrokPollTimer);
      if (!tunnelState.publicBaseUrl && !resolved) {
        tunnelState.status = 'error';
        tunnelState.error = `Quá thời gian chờ kết nối (${preferredProvider}). Vui lòng thử đổi sang chế độ Tunnel khác.`;
        try { proc.kill('SIGKILL'); } catch {}
        tunnelState.proc = null;
        broadcastEvent('tunnel_updated', getTunnelPublicInfo());
        finish(getTunnelPublicInfo());
      }
    }, 10000);
  });
}

// Utility: Smart decoder for JWTs, Base64 strings, Hex dump, and HMAC signatures
function tryDecodeJwt(tokenStr) {
  if (typeof tokenStr !== 'string') return null;
  const cleaned = tokenStr.replace(/^Bearer\s+/i, '').trim();
  const parts = cleaned.split('.');
  if (parts.length !== 3) return null;
  if (!/^[A-Za-z0-9_-]+$/.test(parts[0]) || !/^[A-Za-z0-9_-]+$/.test(parts[1])) return null;
  try {
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (!header || typeof header !== 'object' || !payload || typeof payload !== 'object') return null;
    let expStatus = null;
    if (typeof payload.exp === 'number') {
      const nowSec = Math.floor(Date.now() / 1000);
      expStatus = {
        expiresAt: new Date(payload.exp * 1000).toISOString(),
        expired: payload.exp < nowSec,
        remainingSeconds: payload.exp - nowSec
      };
    }
    return {
      raw: cleaned,
      header,
      payload,
      signatureHex: Buffer.from(parts[2], 'base64url').toString('hex'),
      expStatus
    };
  } catch {
    return null;
  }
}

function tryDecodeBase64(str) {
  if (typeof str !== 'string') return null;
  const trimmed = str.trim();
  // Must look like Base64 and have reasonable length
  if (trimmed.length < 12 || trimmed.length > 4096) return null;
  if (/^https?:\/\//i.test(trimmed) || /\s/.test(trimmed)) return null;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(trimmed) || trimmed.length % 4 !== 0) return null;
  try {
    const buf = Buffer.from(trimmed, 'base64');
    const decoded = buf.toString('utf8');
    // Verify it resolves to printable UTF-8 characters
    if (!decoded || decoded.length < 4) return null;
    let printable = 0;
    for (let i = 0; i < decoded.length; i++) {
      const code = decoded.charCodeAt(i);
      if ((code >= 32 && code <= 126) || code === 9 || code === 10 || code === 13 || code >= 160) {
        printable++;
      }
    }
    if (printable / decoded.length < 0.9) return null;
    // Re-encode check to avoid false positives on plain English words
    if (Buffer.from(decoded, 'utf8').toString('base64') !== trimmed) return null;
    return decoded;
  } catch {
    return null;
  }
}

function createHexPreview(buffer, maxBytes = 512) {
  const slice = buffer.subarray(0, maxBytes);
  const lines = [];
  for (let offset = 0; offset < slice.length; offset += 16) {
    const chunk = slice.subarray(offset, offset + 16);
    const hexCols = [];
    let ascii = '';
    for (let i = 0; i < 16; i++) {
      if (i < chunk.length) {
        const b = chunk[i];
        hexCols.push(b.toString(16).padStart(2, '0'));
        ascii += b >= 32 && b <= 126 ? String.fromCharCode(b) : '.';
      } else {
        hexCols.push('  ');
        ascii += ' ';
      }
    }
    const leftHex = hexCols.slice(0, 8).join(' ');
    const rightHex = hexCols.slice(8).join(' ');
    lines.push(`${offset.toString(16).padStart(4, '0')}  ${leftHex}  ${rightHex}  |${ascii}|`);
  }
  if (buffer.length > maxBytes) {
    lines.push(`... (${buffer.length - maxBytes} bytes truncated)`);
  }
  return lines.join('\n');
}

function scanObjectForTokens(obj, pathPrefix, decodedItems) {
  if (!obj || typeof obj !== 'object') return;
  for (const [k, v] of Object.entries(obj)) {
    const currentPath = pathPrefix ? `${pathPrefix}.${k}` : k;
    if (typeof v === 'string') {
      const jwt = tryDecodeJwt(v);
      if (jwt) {
        decodedItems.jwts.push({ location: currentPath, ...jwt });
        continue;
      }
      // Also check Basic Auth header
      if (/^Basic\s+/i.test(v)) {
        const b64Part = v.replace(/^Basic\s+/i, '').trim();
        const b64Decoded = tryDecodeBase64(b64Part);
        if (b64Decoded) {
          decodedItems.base64.push({ location: `${currentPath} (Basic Auth)`, original: v, decoded: b64Decoded });
          continue;
        }
      }
      const b64 = tryDecodeBase64(v);
      if (b64) {
        decodedItems.base64.push({ location: currentPath, original: v, decoded: b64 });
      }
    } else if (typeof v === 'object' && v !== null) {
      scanObjectForTokens(v, currentPath, decodedItems);
    }
  }
}

function computeHmacSignatures(rawBody, secret) {
  if (!secret) return null;
  const sha256Hex = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
  const sha256Base64 = crypto.createHmac('sha256', secret).update(rawBody).digest('base64');
  const sha1Hex = crypto.createHmac('sha1', secret).update(rawBody).digest('hex');
  const sha512Hex = crypto.createHmac('sha512', secret).update(rawBody).digest('hex');
  return {
    secretUsed: secret,
    sha256Hex,
    sha256GitHub: `sha256=${sha256Hex}`,
    sha256Base64,
    sha1Hex,
    sha512Hex
  };
}

function analyzeIncomingSignature(headers, rawBody, secret) {
  const sigHeaders = {};
  const candidates = [
    'x-hub-signature-256',
    'x-hub-signature',
    'x-signature',
    'x-webhook-signature',
    'stripe-signature',
    'x-telegram-bot-api-secret-token',
    'x-hmac-sha256'
  ];
  for (const h of candidates) {
    if (headers[h]) {
      sigHeaders[h] = headers[h];
    }
  }

  const computed = secret ? computeHmacSignatures(rawBody, secret) : null;
  let verified = null;
  let matchedRule = null;

  if (secret && Object.keys(sigHeaders).length > 0) {
    verified = false;
    for (const [headerName, headerVal] of Object.entries(sigHeaders)) {
      const val = String(headerVal).trim();
      if (
        val === computed.sha256Hex ||
        val === computed.sha256GitHub ||
        val === computed.sha256Base64 ||
        val === computed.sha1Hex ||
        val === `sha1=${computed.sha1Hex}` ||
        val === secret // e.g. x-telegram-bot-api-secret-token
      ) {
        verified = true;
        matchedRule = `${headerName} khớp với secret`;
        break;
      }
      // Stripe style: t=12345,v1=abcdef
      if (headerName === 'stripe-signature' && val.includes('v1=')) {
        const parts = Object.fromEntries(val.split(',').map(p => p.trim().split('=')));
        if (parts.t && parts.v1) {
          const stripePayload = `${parts.t}.${rawBody}`;
          const expectedV1 = crypto.createHmac('sha256', secret).update(stripePayload).digest('hex');
          if (parts.v1 === expectedV1) {
            verified = true;
            matchedRule = `Stripe-Signature (t=${parts.t}, v1) hợp lệ`;
            break;
          }
        }
      }
    }
  }

  return {
    detectedHeaders: sigHeaders,
    computed,
    verified,
    matchedRule
  };
}

function analyzeRequestPayload(headers, queryParams, rawBuffer, endpointSecret) {
  const rawBody = rawBuffer.toString('utf8');
  const contentType = (headers['content-type'] || '').toLowerCase();
  let parsedBody = null;
  let bodyFormat = 'text';

  if (rawBuffer.length === 0) {
    bodyFormat = 'empty';
  } else if (contentType.includes('application/json') || (rawBody.trim().startsWith('{') || rawBody.trim().startsWith('['))) {
    try {
      parsedBody = JSON.parse(rawBody);
      bodyFormat = 'json';
    } catch {
      bodyFormat = 'text';
    }
  } else if (contentType.includes('application/x-www-form-urlencoded')) {
    try {
      const params = new URLSearchParams(rawBody);
      parsedBody = Object.fromEntries(params.entries());
      bodyFormat = 'urlencoded';
    } catch {
      bodyFormat = 'text';
    }
  }

  const decodedItems = { jwts: [], base64: [] };
  scanObjectForTokens(headers, 'headers', decodedItems);
  scanObjectForTokens(queryParams, 'query', decodedItems);
  if (parsedBody && typeof parsedBody === 'object') {
    scanObjectForTokens(parsedBody, 'body', decodedItems);
  } else if (rawBody) {
    const jwt = tryDecodeJwt(rawBody);
    if (jwt) decodedItems.jwts.push({ location: 'rawBody', ...jwt });
    const b64 = tryDecodeBase64(rawBody);
    if (b64) decodedItems.base64.push({ location: 'rawBody', original: rawBody, decoded: b64 });
  }

  const signatureAnalysis = analyzeIncomingSignature(headers, rawBody, endpointSecret);

  return {
    bodyFormat,
    parsedBody,
    decodedItems,
    signatureAnalysis,
    hexPreview: createHexPreview(rawBuffer)
  };
}

// Perform outgoing HTTP/HTTPS request (used for Replay, Forwarding, Fuzzing, and API Hunter)
function executeHttpRequest({ method = 'POST', targetUrl, headers = {}, body = '', timeoutMs = 10000, followRedirects = true, maxRedirects = 5 }) {
  return new Promise((resolve) => {
    const startTime = performance.now();
    let parsedUrl;
    try {
      parsedUrl = new URL(targetUrl);
    } catch (err) {
      return resolve({
        ok: false,
        error: `URL không hợp lệ: ${err.message}`,
        statusCode: 0,
        durationMs: 0,
        headers: {},
        body: '',
        sizeBytes: 0,
        finalUrl: targetUrl
      });
    }

    const isHttps = parsedUrl.protocol === 'https:';
    const transport = isHttps ? https : http;

    const cleanHeaders = {
      'Accept-Encoding': 'identity',
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) NetPulse-Inspector/1.0'
    };
    for (const [k, v] of Object.entries(headers || {})) {
      const lower = k.toLowerCase();
      if (['host', 'content-length', 'connection', 'transfer-encoding', 'accept-encoding'].includes(lower)) continue;
      if (v !== undefined && v !== null && String(v).trim() !== '') {
        cleanHeaders[k] = String(v);
      }
    }

    const bodyBuffer = Buffer.from(typeof body === 'string' ? body : JSON.stringify(body || ''), 'utf8');
    if (bodyBuffer.length > 0 && !['GET', 'HEAD'].includes(method.toUpperCase())) {
      cleanHeaders['Content-Length'] = String(bodyBuffer.length);
    }

    const reqOptions = {
      protocol: parsedUrl.protocol,
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (isHttps ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: method.toUpperCase(),
      headers: cleanHeaders,
      timeout: timeoutMs,
      rejectUnauthorized: false // Allow testing local self-signed certs
    };

    const req = transport.request(reqOptions, (res) => {
      // Handle HTTP Redirects (301, 302, 303, 307, 308)
      if (
        followRedirects &&
        maxRedirects > 0 &&
        [301, 302, 303, 307, 308].includes(res.statusCode) &&
        res.headers.location
      ) {
        res.resume();
        let redirectUrl;
        try {
          redirectUrl = new URL(res.headers.location, parsedUrl).toString();
        } catch {
          redirectUrl = null;
        }
        if (redirectUrl) {
          const nextMethod = res.statusCode === 303 ? 'GET' : method;
          return executeHttpRequest({
            method: nextMethod,
            targetUrl: redirectUrl,
            headers,
            body: nextMethod === 'GET' ? '' : body,
            timeoutMs,
            followRedirects,
            maxRedirects: maxRedirects - 1
          }).then(resolve);
        }
      }

      const chunks = [];
      let totalBytes = 0;
      const MAX_RES_BYTES = 4 * 1024 * 1024; // 4MB cap per response
      res.on('data', (chunk) => {
        totalBytes += chunk.length;
        if (totalBytes <= MAX_RES_BYTES) {
          chunks.push(chunk);
        }
      });
      res.on('end', () => {
        const durationMs = Math.round((performance.now() - startTime) * 100) / 100;
        const fullBuffer = Buffer.concat(chunks);
        const responseText = fullBuffer.toString('utf8');
        resolve({
          ok: res.statusCode >= 200 && res.statusCode < 400,
          statusCode: res.statusCode,
          statusMessage: res.statusMessage || '',
          durationMs,
          headers: res.headers,
          body: responseText,
          sizeBytes: fullBuffer.length,
          finalUrl: parsedUrl.toString()
        });
      });
    });

    req.on('timeout', () => {
      req.destroy(new Error(`Timeout sau ${timeoutMs}ms`));
    });

    req.on('error', (err) => {
      const durationMs = Math.round((performance.now() - startTime) * 100) / 100;
      resolve({
        ok: false,
        error: err.message,
        statusCode: 0,
        statusMessage: 'Network Error',
        durationMs,
        headers: {},
        body: '',
        sizeBytes: 0,
        finalUrl: targetUrl
      });
    });

    if (bodyBuffer.length > 0 && !['GET', 'HEAD'].includes(method.toUpperCase())) {
      req.write(bodyBuffer);
    }
    req.end();
  });
}

// Helper to read request body buffer
function readRequestBody(req, maxBytes = 5 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', (chunk) => {
      total += chunk.length;
      if (total <= maxBytes) {
        chunks.push(chunk);
      }
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function sendJson(res, statusCode, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*'
  });
  res.end(body);
}

// Replace template tokens in mock response
function renderResponseTemplate(template, context) {
  if (!template) return '';
  return String(template)
    .replace(/\{\{timestamp\}\}/g, new Date().toISOString())
    .replace(/\{\{requestId\}\}/g, context.requestId || '')
    .replace(/\{\{method\}\}/g, context.method || '')
    .replace(/\{\{slug\}\}/g, context.slug || '');
}

// Interpolate {{ENV_VAR}} placeholders (preserving {{FUZZ}}, {{timestamp}}, {{requestId}}, {{slug}})
function interpolateEnvVars(inputStr, envVars = store.envVars) {
  if (!inputStr || typeof inputStr !== 'string') return inputStr || '';
  const reserved = new Set(['FUZZ', 'timestamp', 'requestId', 'method', 'slug']);
  return inputStr.replace(/\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}/g, (match, varName) => {
    if (reserved.has(varName)) return match;
    if (envVars && Object.prototype.hasOwnProperty.call(envVars, varName)) {
      return String(envVars[varName]);
    }
    return match;
  });
}

function interpolateHeaders(headersObj, envVars = store.envVars) {
  const out = {};
  for (const [k, v] of Object.entries(headersObj || {})) {
    out[interpolateEnvVars(k, envVars)] = interpolateEnvVars(String(v ?? ''), envVars);
  }
  return out;
}

// Evaluate automated response assertions (e.g. "status == 200", "durationMs < 1000", "json.success == true", "body contains ok")
function evaluateAssertions(assertionRules = [], response = {}) {
  const rules = (Array.isArray(assertionRules) ? assertionRules : String(assertionRules || '').split('\n'))
    .map((r) => String(r).trim())
    .filter(Boolean);

  if (rules.length === 0) {
    return { total: 0, passed: 0, failed: 0, allPassed: true, items: [] };
  }

  let parsedJson = null;
  try {
    parsedJson = JSON.parse(response.body || '');
  } catch {
    parsedJson = null;
  }

  function getDotPath(obj, dotPath) {
    if (!obj || typeof obj !== 'object') return undefined;
    return dotPath.split('.').reduce((acc, part) => (acc && acc[part] !== undefined ? acc[part] : undefined), obj);
  }

  const items = rules.map((rule) => {
    const m = rule.match(/^([a-zA-Z0-9_.\-[\]]+)\s*(==|!=|<=|>=|<|>|!contains|contains)\s*(.+)$/i);
    if (!m) {
      return { rule, passed: false, actual: 'N/A', expected: rule, reason: 'Cú pháp không hợp lệ' };
    }
    const lhsKey = m[1].trim();
    const op = m[2].toLowerCase();
    const rawExpected = m[3].trim().replace(/^['"]|['"]$/g, '');

    let actualVal;
    const lowerKey = lhsKey.toLowerCase();
    if (lowerKey === 'status' || lowerKey === 'statuscode') {
      actualVal = Number(response.statusCode || 0);
    } else if (lowerKey === 'time' || lowerKey === 'duration' || lowerKey === 'durationms') {
      actualVal = Number(response.durationMs || 0);
    } else if (lowerKey === 'size' || lowerKey === 'sizebytes') {
      actualVal = Number(response.sizeBytes || 0);
    } else if (lowerKey === 'body') {
      actualVal = String(response.body || '');
    } else if (lowerKey.startsWith('header.') || lowerKey.startsWith('headers.')) {
      const hName = lowerKey.replace(/^headers?\./, '');
      actualVal = String((response.headers && response.headers[hName]) || '');
    } else if (lhsKey.startsWith('json.') || lhsKey.startsWith('body.')) {
      const jsonPath = lhsKey.replace(/^(?:json|body)\./, '');
      actualVal = getDotPath(parsedJson, jsonPath);
    } else {
      actualVal = getDotPath(parsedJson, lhsKey);
    }

    let passed = false;
    if (op === 'contains') {
      passed = String(actualVal ?? '').toLowerCase().includes(rawExpected.toLowerCase());
    } else if (op === '!contains') {
      passed = !String(actualVal ?? '').toLowerCase().includes(rawExpected.toLowerCase());
    } else if (['<', '<=', '>', '>='].includes(op)) {
      const numA = Number(actualVal);
      const numB = Number(rawExpected);
      if (!Number.isNaN(numA) && !Number.isNaN(numB)) {
        if (op === '<') passed = numA < numB;
        if (op === '<=') passed = numA <= numB;
        if (op === '>') passed = numA > numB;
        if (op === '>=') passed = numA >= numB;
      }
    } else if (op === '==' || op === '!=') {
      const strA = String(actualVal);
      const strB = String(rawExpected);
      const eq = strA === strB || (Number(actualVal) === Number(rawExpected) && !Number.isNaN(Number(rawExpected)));
      passed = op === '==' ? eq : !eq;
    }

    return {
      rule,
      passed,
      actual: typeof actualVal === 'object' ? JSON.stringify(actualVal) : String(actualVal ?? 'undefined'),
      expected: `${op} ${rawExpected}`
    };
  });

  const passedCount = items.filter((i) => i.passed).length;
  return {
    total: items.length,
    passed: passedCount,
    failed: items.length - passedCount,
    allPassed: passedCount === items.length,
    items
  };
}

// Send Webhook Alert to Telegram Bot, Discord Webhook, or Custom Webhook URL
async function dispatchWebhookAlert(endpoint, record) {
  const alertUrl = String(endpoint.notifyWebhookUrl || '').trim();
  if (!alertUrl) return null;

  const isHmacBad = record.signatureAnalysis?.verified === false || record.responseSent?.hmacRejected;
  const isSuspicious = /(?:'\s*OR\s*|<script|union\s+select|javascript:)/i.test(record.rawBody || '');
  const isAnomaly = isHmacBad || isSuspicious || (record.responseSent?.statusCode >= 400);

  if (endpoint.notifyOnlyOnAnomaly && !isAnomaly) {
    return { skipped: true, reason: 'Normal traffic (notifyOnlyOnAnomaly = true)' };
  }

  const summaryText = [
    `🔔 [NetPulse Alert] ${endpoint.name} (/hook/${endpoint.slug})`,
    `• Method & URL: ${record.method} ${record.url}`,
    `• Status trả về: HTTP ${record.responseSent?.statusCode || 200} (${record.sizeBytes} B)`,
    `• Chữ ký HMAC: ${record.signatureAnalysis?.verified === true ? '✅ Hợp lệ' : record.signatureAnalysis?.verified === false ? '❌ SAI CHỮ KÝ' : 'ℹ️ Không dùng'}`,
    `• Body Preview: ${(record.rawBody || '(Trống)').slice(0, 220)}`
  ].join('\n');

  let payloadObj = {
    source: 'NetPulse',
    event: isAnomaly ? 'webhook.anomaly' : 'webhook.captured',
    content: summaryText, // Discord compatible
    text: summaryText,    // Telegram / Slack compatible
    recordSummary: {
      id: record.id,
      slug: record.slug,
      method: record.method,
      statusCode: record.responseSent?.statusCode,
      hmacVerified: record.signatureAnalysis?.verified,
      createdAt: record.createdAt
    }
  };

  try {
    const u = new URL(alertUrl);
    if (u.hostname.includes('api.telegram.org')) {
      const chatId = u.searchParams.get('chat_id');
      if (chatId) {
        payloadObj = { chat_id: chatId, text: summaryText };
      }
    }
  } catch {
    // ignore URL parse error
  }

  const res = await executeHttpRequest({
    method: 'POST',
    targetUrl: alertUrl,
    headers: { 'Content-Type': 'application/json', 'X-NetPulse-Alert-Dispatch': '1' },
    body: JSON.stringify(payloadObj),
    timeoutMs: 6000
  });

  return {
    notifiedTo: alertUrl,
    statusCode: res.statusCode,
    ok: res.statusCode >= 200 && res.statusCode < 300
  };
}

// Handle incoming Webhook Capture on /hook/:slug/*
async function handleWebhookCapture(req, res, parsedUrl) {
  const startTime = performance.now();
  const pathParts = parsedUrl.pathname.replace(/^\/hook\/?/, '').split('/').filter(Boolean);
  const slug = pathParts[0] || 'catch-all';
  const subPath = '/' + pathParts.slice(1).join('/');

  let endpoint = store.endpoints.find((e) => e.slug === slug);
  if (!endpoint) {
    // Auto-create endpoint if unknown slug arrives
    endpoint = {
      id: 'ep-' + crypto.randomBytes(4).toString('hex'),
      slug,
      name: `Auto: /hook/${slug}`,
      statusCode: 200,
      contentType: 'application/json',
      responseBody: JSON.stringify({ ok: true, slug, requestId: '{{requestId}}', timestamp: '{{timestamp}}' }, null, 2),
      delayMs: 0,
      secret: '',
      forwardUrl: '',
      createdAt: new Date().toISOString()
    };
    store.endpoints.unshift(endpoint);
  }

  const rawBuffer = await readRequestBody(req);
  const rawBody = rawBuffer.toString('utf8');
  const queryParams = Object.fromEntries(parsedUrl.searchParams.entries());
  const requestId = 'req_' + Date.now().toString(36) + '_' + crypto.randomBytes(3).toString('hex');

  const analysis = analyzeRequestPayload(req.headers, queryParams, rawBuffer, endpoint.secret);

  // Optional simulated delay
  const delayMs = Math.min(Math.max(Number(endpoint.delayMs) || 0, 0), 15000);
  if (delayMs > 0) {
    await new Promise((r) => setTimeout(r, delayMs));
  }

  // Optional auto-forwarding proxy (supports single URL or multiple URLs separated by comma/newline)
  let forwardResult = null;
  let forwardResults = [];
  if (endpoint.forwardUrl && endpoint.forwardUrl.trim()) {
    const targets = endpoint.forwardUrl
      .split(/[\r\n,]+/)
      .map((u) => u.trim())
      .filter(Boolean)
      .slice(0, 5);

    forwardResults = await Promise.all(
      targets.map(async (tUrl) => {
        const r = await executeHttpRequest({
          method: req.method,
          targetUrl: tUrl,
          headers: req.headers,
          body: rawBody,
          timeoutMs: 8000
        });
        return { targetUrl: tUrl, statusCode: r.statusCode, durationMs: r.durationMs, ok: r.ok };
      })
    );
    forwardResult = forwardResults[0] || null;
  }

  // Conditional HMAC Enforcement Rule
  const hmacRejected = Boolean(endpoint.requireValidHmac && endpoint.secret && analysis.signatureAnalysis.verified !== true);

  const finalStatusCode = hmacRejected ? 401 : (Number(endpoint.statusCode) || 200);
  const renderedResponseBody = hmacRejected
    ? JSON.stringify({
        ok: false,
        error: 'Rejected by NetPulse Conditional Rule: Missing or invalid HMAC signature',
        requestId,
        timestamp: new Date().toISOString()
      }, null, 2)
    : renderResponseTemplate(endpoint.responseBody, {
        requestId,
        method: req.method,
        slug
      });

  const durationMs = Math.round((performance.now() - startTime) * 100) / 100;

  const capturedRecord = {
    id: requestId,
    endpointId: endpoint.id,
    slug: endpoint.slug,
    endpointName: endpoint.name,
    method: req.method,
    url: req.url,
    fullUrl: `http://${req.headers.host || `localhost:${PORT}`}${req.url}`,
    subPath,
    query: queryParams,
    headers: req.headers,
    clientIp: req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1',
    userAgent: req.headers['user-agent'] || 'Unknown',
    sizeBytes: rawBuffer.length,
    rawBody,
    bodyFormat: analysis.bodyFormat,
    parsedBody: analysis.parsedBody,
    decodedItems: analysis.decodedItems,
    signatureAnalysis: analysis.signatureAnalysis,
    hexPreview: analysis.hexPreview,
    responseSent: {
      statusCode: finalStatusCode,
      contentType: endpoint.contentType || 'application/json',
      body: renderedResponseBody,
      delayMs,
      durationMs,
      hmacRejected
    },
    forwardResult,
    forwardResults,
    alertResult: null,
    createdAt: new Date().toISOString()
  };

  if (endpoint.notifyWebhookUrl && req.headers['x-netpulse-alert-dispatch'] !== '1') {
    try {
      capturedRecord.alertResult = await dispatchWebhookAlert(endpoint, capturedRecord);
    } catch {
      // ignore alert dispatch errors
    }
  }

  store.requests.unshift(capturedRecord);
  if (store.requests.length > MAX_REQUESTS) {
    store.requests.length = MAX_REQUESTS;
  }
  saveStore();

  broadcastEvent('request_captured', capturedRecord);

  res.writeHead(capturedRecord.responseSent.statusCode, {
    'Content-Type': capturedRecord.responseSent.contentType,
    'X-NetPulse-Request-Id': requestId,
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': '*',
    'Access-Control-Allow-Methods': '*'
  });
  res.end(renderedResponseBody);
}

// Helper for replace {{FUZZ}} in strings/objects
function injectFuzzPayload(templateStr, payload) {
  if (typeof templateStr !== 'string') return '';
  return templateStr.replace(/\{\{FUZZ\}\}/g, payload);
}

// ============================================================================
// CURL PARSER (Supports Chrome/Edge F12 "Copy as cURL (bash)" & "Copy as cURL (cmd)")
// ============================================================================
function parseCurlCommand(rawCurl) {
  if (!rawCurl || typeof rawCurl !== 'string') {
    return { ok: false, error: 'Chuỗi lệnh cURL trống.' };
  }

  // Normalize Windows CMD caret continuations (^\n, ^", ^%, etc.) and bash backslash continuations
  const normalized = rawCurl
    .replace(/\^\r?\n\s*/g, ' ')
    .replace(/\\\r?\n\s*/g, ' ')
    .replace(/\^"/g, '"')
    .replace(/\^\^/g, '^')
    .replace(/\^([&|<>%{}$])/g, '$1')
    .trim();

  // Tokenize respecting single and double quotes
  const tokens = [];
  let current = '';
  let quoteChar = null;
  for (let i = 0; i < normalized.length; i++) {
    const ch = normalized[i];
    if (quoteChar) {
      if (ch === '\\' && quoteChar === '"' && i + 1 < normalized.length) {
        current += normalized[++i];
      } else if (ch === quoteChar) {
        quoteChar = null;
      } else {
        current += ch;
      }
    } else {
      if (ch === "'" || ch === '"') {
        quoteChar = ch;
      } else if (/\s/.test(ch)) {
        if (current.length > 0) {
          tokens.push(current);
          current = '';
        }
      } else {
        current += ch;
      }
    }
  }
  if (current.length > 0) tokens.push(current);

  let method = null;
  let url = '';
  const headers = {};
  const bodyParts = [];

  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (i === 0 && /^curl(?:\.exe)?$/i.test(t)) continue;

    if ((t === '-X' || t === '--request') && tokens[i + 1]) {
      method = tokens[++i].toUpperCase();
    } else if ((t === '-H' || t === '--header') && tokens[i + 1]) {
      const hLine = tokens[++i];
      const colonIdx = hLine.indexOf(':');
      if (colonIdx > 0) {
        const k = hLine.slice(0, colonIdx).trim();
        const v = hLine.slice(colonIdx + 1).trim();
        if (k && !k.startsWith(':')) headers[k] = v;
      }
    } else if ((t === '-b' || t === '--cookie') && tokens[i + 1]) {
      headers['Cookie'] = tokens[++i];
    } else if ((t === '-A' || t === '--user-agent') && tokens[i + 1]) {
      headers['User-Agent'] = tokens[++i];
    } else if ((t === '-u' || t === '--user') && tokens[i + 1]) {
      headers['Authorization'] = 'Basic ' + Buffer.from(tokens[++i]).toString('base64');
    } else if (['-d', '--data', '--data-raw', '--data-binary', '--data-ascii', '--data-urlencode'].includes(t) && tokens[i + 1] !== undefined) {
      bodyParts.push(tokens[++i]);
    } else if (/^https?:\/\//i.test(t) && !url) {
      url = t;
    } else if (t === '--url' && tokens[i + 1]) {
      url = tokens[++i];
    }
  }

  const body = bodyParts.join('&');
  if (!method) {
    method = body ? 'POST' : 'GET';
  }

  if (!url) {
    return { ok: false, error: 'Không tìm thấy URL hợp lệ (http/https) trong lệnh cURL.' };
  }

  return {
    ok: true,
    method,
    url,
    targetUrl: url,
    headers,
    body
  };
}

// ============================================================================
// CORS & API SECURITY AUDITOR
// ============================================================================
async function auditTargetSecurity({ method = 'GET', targetUrl = '', headers = {}, body = '' }) {
  const probeOrigin = 'https://evil-scanner.example.com';
  const findings = [];
  let score = 100;

  // 1. Send normal request with custom Origin header to test CORS reflection
  const corsHeaders = { ...headers, Origin: probeOrigin };
  const mainRes = await executeHttpRequest({
    method,
    targetUrl,
    headers: corsHeaders,
    body,
    timeoutMs: 8000
  });

  if (!mainRes.statusCode) {
    return { ok: false, error: mainRes.error || 'Không thể kết nối tới API mục tiêu.' };
  }

  const resHeaders = mainRes.headers || {};
  const acao = String(resHeaders['access-control-allow-origin'] || '').trim();
  const acac = String(resHeaders['access-control-allow-credentials'] || '').trim().toLowerCase() === 'true';

  // CORS Checks
  if (acao === probeOrigin && acac) {
    score -= 35;
    findings.push({
      severity: 'HIGH',
      title: 'Lỗ hổng CORS Misconfiguration Nghiêm Trọng (Reflect Origin + Credentials)',
      detail: `Server phản xạ lại Origin lạ (${probeOrigin}) kèm Access-Control-Allow-Credentials: true. Trang web độc hại có thể đọc trộm dữ liệu xác thực của người dùng.`
    });
  } else if (acao === probeOrigin) {
    score -= 20;
    findings.push({
      severity: 'MEDIUM',
      title: 'CORS Phản Xạ Origin Bất Kỳ (Reflected Origin)',
      detail: `Access-Control-Allow-Origin phản xạ lại chính xác Origin lạ (${probeOrigin}). Chỉ nên cho phép danh sách domain (whitelist) cố định.`
    });
  } else if (acao === '*') {
    score -= 10;
    findings.push({
      severity: 'LOW',
      title: 'CORS Mở Công Khai Toàn Cầu (Access-Control-Allow-Origin: *)',
      detail: 'API cho phép mọi trang web gọi và đọc dữ liệu qua trình duyệt. An toàn nếu là API công khai, nhưng rủi ro nếu chứa dữ liệu nội bộ.'
    });
  } else {
    findings.push({
      severity: 'PASS',
      title: 'Cấu hình CORS an toàn',
      detail: acao ? `Chỉ cho phép Origin: ${acao}` : 'Không bật mở CORS tùy tiện cho domain lạ.'
    });
  }

  // Security Headers Checks
  if (!resHeaders['strict-transport-security'] && targetUrl.startsWith('https://')) {
    score -= 10;
    findings.push({
      severity: 'LOW',
      title: 'Thiếu Header Strict-Transport-Security (HSTS)',
      detail: 'Nên bật HSTS để ép trình duyệt luôn kết nối qua HTTPS.'
    });
  }
  if (!resHeaders['x-content-type-options']) {
    score -= 10;
    findings.push({
      severity: 'LOW',
      title: 'Thiếu Header X-Content-Type-Options: nosniff',
      detail: 'Nên thêm X-Content-Type-Options: nosniff để chống lỗi MIME-sniffing.'
    });
  }
  if (!resHeaders['x-frame-options'] && !resHeaders['content-security-policy']) {
    score -= 10;
    findings.push({
      severity: 'LOW',
      title: 'Thiếu X-Frame-Options / Content-Security-Policy',
      detail: 'Chưa có cơ chế chống nhúng trang (Clickjacking) hoặc giới hạn nguồn tài nguyên CSP.'
    });
  }
  if (resHeaders['x-powered-by'] || (resHeaders['server'] && /\d+\.\d+/.test(resHeaders['server']))) {
    score -= 8;
    findings.push({
      severity: 'LOW',
      title: 'Lộ phiên bản công nghệ trong Header (Server / X-Powered-By)',
      detail: `Phát hiện: Server="${resHeaders['server'] || ''}", X-Powered-By="${resHeaders['x-powered-by'] || ''}". Nên ẩn phiên bản cụ thể.`
    });
  }

  // Sensitive Data Exposure in Response Body
  const bodyStr = String(mainRes.body || '');
  if (/(?:sk_live_[0-9a-zA-Z]{16,}|AIza[0-9A-Za-z\-_]{30,}|ghp_[0-9A-Za-z]{30,})/.test(bodyStr)) {
    score -= 35;
    findings.push({
      severity: 'HIGH',
      title: 'Phát hiện API Key / Secret Token nhạy cảm trong Response Body',
      detail: 'Nội dung trả về có chứa chuỗi định dạng khóa bí mật (Stripe/Google/GitHub API Key).'
    });
  }
  if (/(?:sql syntax|sqlite_error|postgresql.*error|ora-\d{5}|ReferenceError:|TypeError:|at Object\.<anonymous>)/i.test(bodyStr)) {
    score -= 25;
    findings.push({
      severity: 'MEDIUM',
      title: 'Rò rỉ Stack Trace / Thông báo lỗi hệ thống trong Response',
      detail: 'Phản hồi chứa chi tiết lỗi kỹ thuật nội bộ giúp kẻ tấn công dò cấu trúc code/database.'
    });
  }

  score = Math.max(0, Math.min(100, score));
  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';

  return {
    ok: true,
    targetUrl,
    statusCode: mainRes.statusCode,
    durationMs: mainRes.durationMs,
    score,
    grade,
    corsHeader: acao || '(Không có)',
    allowCredentials: acac,
    corsHeaders: {
      allowOrigin: acao || '(Không trả về)',
      allowCredentials: acac ? 'true' : 'false'
    },
    findings
  };
}

// ============================================================================
// JWT STUDIO: Encode, Sign, Alg:None Generator & Weak Secret Dictionary Auditor
// ============================================================================
const DEFAULT_WEAK_JWT_SECRETS = [
  'secret',
  'whsec_demo_secret_2026',
  '123456',
  '12345678',
  'password',
  'admin',
  'jwt_secret',
  'jwt-secret',
  'mysecret',
  'supersecret',
  'changeme',
  'default',
  'development',
  'dev_secret',
  'test',
  'test_secret',
  'private_key',
  'apikey',
  'app_secret',
  'token_secret',
  'secretkey',
  'secret123',
  'qwerty',
  'laravel',
  'django-insecure',
  'express-secret',
  'nextjs-secret',
  'supabase-secret',
  '000000',
  'master'
];

function signJwtHmac(alg, signingInput, secret) {
  const hashMap = { HS256: 'sha256', HS384: 'sha384', HS512: 'sha512' };
  const digestAlg = hashMap[alg.toUpperCase()] || 'sha256';
  return crypto.createHmac(digestAlg, String(secret ?? '')).update(signingInput).digest('base64url');
}

function encodeJwtToken({ header = { alg: 'HS256', typ: 'JWT' }, payload = {}, secret = 'secret', mode = 'sign', noneVariant = 'none' }) {
  const cleanHeader = { ...(header || {}) };
  if (mode === 'alg_none') {
    cleanHeader.alg = noneVariant || 'none';
    const hB64 = Buffer.from(JSON.stringify(cleanHeader)).toString('base64url');
    const pB64 = Buffer.from(JSON.stringify(payload || {})).toString('base64url');
    return {
      token: `${hB64}.${pB64}.`,
      header: cleanHeader,
      payload,
      mode: 'alg_none'
    };
  }

  const alg = ['HS256', 'HS384', 'HS512'].includes(String(cleanHeader.alg || '').toUpperCase())
    ? String(cleanHeader.alg).toUpperCase()
    : 'HS256';
  cleanHeader.alg = alg;
  if (!cleanHeader.typ) cleanHeader.typ = 'JWT';

  const hB64 = Buffer.from(JSON.stringify(cleanHeader)).toString('base64url');
  const pB64 = Buffer.from(JSON.stringify(payload || {})).toString('base64url');
  const sig = signJwtHmac(alg, `${hB64}.${pB64}`, secret);

  return {
    token: `${hB64}.${pB64}.${sig}`,
    header: cleanHeader,
    payload,
    algorithm: alg,
    mode: 'signed'
  };
}

function auditJwtWeakSecret(rawToken, customSecrets = []) {
  const startTime = performance.now();
  const cleaned = String(rawToken || '').replace(/^Bearer\s+/i, '').trim();
  const parts = cleaned.split('.');
  if (parts.length !== 3) {
    return { ok: false, error: 'Chuỗi JWT không hợp lệ (phải có 3 phần ngăn cách bởi dấu chấm).' };
  }

  let header;
  try {
    header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
  } catch {
    return { ok: false, error: 'Không thể giải mã phần Header của JWT.' };
  }

  const alg = String(header.alg || 'HS256').toUpperCase();
  if (!['HS256', 'HS384', 'HS512'].includes(alg)) {
    return {
      ok: false,
      error: `Thuật toán của token là ${alg} (chỉ kiểm tra từ điển cho chuẩn đối xứng HS256/HS384/HS512).`
    };
  }

  const signingInput = `${parts[0]}.${parts[1]}`;
  const targetSig = parts[2];

  const candidates = Array.from(new Set([
    ...customSecrets.map((s) => String(s).trim()).filter(Boolean),
    ...DEFAULT_WEAK_JWT_SECRETS,
    '' // also test empty string secret
  ]));

  for (let i = 0; i < candidates.length; i++) {
    const candidate = candidates[i];
    const computedSig = signJwtHmac(alg, signingInput, candidate);
    if (computedSig === targetSig) {
      return {
        ok: true,
        found: true,
        matchedSecret: candidate,
        algorithm: alg,
        testedCount: i + 1,
        durationMs: Math.round((performance.now() - startTime) * 100) / 100
      };
    }
  }

  return {
    ok: true,
    found: false,
    matchedSecret: null,
    algorithm: alg,
    testedCount: candidates.length,
    durationMs: Math.round((performance.now() - startTime) * 100) / 100
  };
}

// ============================================================================
// HEADLESS BROWSER DYNAMIC API SNIFFER (Chrome / Edge via DevTools Protocol)
// ============================================================================
function findBrowserExecutable() {
  const candidates = [
    process.env.CHROME_PATH,
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
    'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe'
  ].filter(Boolean);

  for (const p of candidates) {
    try {
      if (fs.existsSync(p)) return p;
    } catch {
      // ignore
    }
  }
  return null;
}

function getFreeLocalPort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
    srv.on('error', reject);
  });
}

async function sniffDynamicApisWithBrowser(targetUrl, { waitMs = 3000 } = {}) {
  const browserPath = findBrowserExecutable();
  if (!browserPath || typeof WebSocket === 'undefined') {
    return {
      ok: false,
      reason: !browserPath ? 'Không tìm thấy Chrome hoặc Edge trên máy' : 'Node runtime không hỗ trợ WebSocket',
      requests: []
    };
  }

  const debugPort = await getFreeLocalPort();
  const userDataDir = path.join(os.tmpdir(), `netpulse-cdp-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`);
  fs.mkdirSync(userDataDir, { recursive: true });

  const args = [
    '--headless=new',
    '--disable-gpu',
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-extensions',
    '--disable-popup-blocking',
    '--ignore-certificate-errors',
    `--remote-debugging-port=${debugPort}`,
    `--user-data-dir=${userDataDir}`,
    'about:blank'
  ];

  const proc = spawn(browserPath, args, { stdio: 'ignore', windowsHide: true });
  const capturedRequests = new Map();

  try {
    // Poll /json/list until browser DevTools HTTP endpoint is ready
    let wsUrl = null;
    for (let attempt = 0; attempt < 25; attempt++) {
      await new Promise((r) => setTimeout(r, 150));
      const res = await executeHttpRequest({
        method: 'GET',
        targetUrl: `http://127.0.0.1:${debugPort}/json/list`,
        timeoutMs: 1000
      });
      if (res.statusCode === 200 && res.body) {
        try {
          const targets = JSON.parse(res.body);
          const pageTarget = targets.find((t) => t.type === 'page' && t.webSocketDebuggerUrl);
          if (pageTarget) {
            wsUrl = pageTarget.webSocketDebuggerUrl;
            break;
          }
        } catch {
          // wait next poll
        }
      }
    }

    if (!wsUrl) {
      return { ok: false, reason: 'Không kết nối được cổng Debug của trình duyệt ngầm', requests: [] };
    }

    await new Promise((resolve) => {
      const ws = new WebSocket(wsUrl);
      let msgId = 1;
      const sendCdp = (method, params = {}) => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ id: msgId++, method, params }));
        }
      };

      const finishTimer = setTimeout(() => {
        try { ws.close(); } catch {}
        resolve();
      }, Math.min(Math.max(waitMs + 4500, 5000), 12000));

      ws.addEventListener('open', () => {
        sendCdp('Network.enable');
        sendCdp('Page.enable');
        sendCdp('Page.navigate', { url: targetUrl });
      });

      ws.addEventListener('message', (event) => {
        try {
          const msg = JSON.parse(typeof event.data === 'string' ? event.data : event.data.toString());
          if (msg.method === 'Network.requestWillBeSent') {
            const { requestId, request, type } = msg.params || {};
            if (!request || !request.url) return;
            const u = request.url;
            if (u.startsWith('data:') || STATIC_ASSET_EXT.test(u)) return;
            const isApiLike =
              type === 'XHR' ||
              type === 'Fetch' ||
              type === 'WebSocket' ||
              /\/(?:api|v[1-9]|graphql|rest|trpc|rpc|wp-json|webhook|auth|oauth)\b/i.test(u) ||
              /\.json(?:[?#]|$)/i.test(u);

            if (isApiLike) {
              capturedRequests.set(requestId, {
                method: (request.method || 'GET').toUpperCase(),
                fullUrl: u,
                rawPath: u,
                resourceType: type || 'XHR',
                requestHeaders: request.headers || {},
                postData: request.postData || '',
                statusCode: null,
                mimeType: ''
              });
            }
          } else if (msg.method === 'Network.responseReceived') {
            const { requestId, response, type } = msg.params || {};
            if (!response || !response.url) return;
            const mime = (response.mimeType || '').toLowerCase();
            if (capturedRequests.has(requestId)) {
              const item = capturedRequests.get(requestId);
              item.statusCode = response.status;
              item.mimeType = response.mimeType || '';
            } else if (mime.includes('json') && !STATIC_ASSET_EXT.test(response.url)) {
              capturedRequests.set(requestId, {
                method: 'GET',
                fullUrl: response.url,
                rawPath: response.url,
                resourceType: type || 'JSON',
                requestHeaders: {},
                postData: '',
                statusCode: response.status,
                mimeType: response.mimeType || 'application/json'
              });
            }
          } else if (msg.method === 'Page.loadEventFired') {
            // Trigger scroll to fire lazy-loaded API requests
            sendCdp('Runtime.evaluate', {
              expression: 'window.scrollTo(0, document.body.scrollHeight / 2); setTimeout(() => window.scrollTo(0, document.body.scrollHeight), 400);'
            });
            setTimeout(() => {
              clearTimeout(finishTimer);
              try { ws.close(); } catch {}
              resolve();
            }, waitMs);
          }
        } catch {
          // ignore malformed event
        }
      });

      ws.addEventListener('error', () => {
        clearTimeout(finishTimer);
        resolve();
      });
    });

    return {
      ok: true,
      browserUsed: path.basename(browserPath),
      requests: Array.from(capturedRequests.values())
    };
  } finally {
    try { proc.kill('SIGKILL'); } catch {}
    setTimeout(() => {
      try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch {}
    }, 800);
  }
}

// Website API Hunter: Scan HTML + JS Bundles + Optional OpenAPI specs to discover endpoints
const STATIC_ASSET_EXT = /\.(?:png|jpe?g|gif|svg|webp|ico|css|less|scss|woff2?|ttf|eot|mp4|mp3|wav|pdf|zip|map)(?:[?#]|$)/i;
const IGNORED_HOSTS = /(?:w3\.org|schema\.org|googleapis\.com\/css|fonts\.gstatic\.com|reactjs\.org|mozilla\.org|example\.com\/ns)/i;

function scanSourceForApis(sourceText, sourceLabel, baseOriginUrl, discoveredMap, configsList) {
  if (!sourceText || typeof sourceText !== 'string') return;

  function addEndpoint(rawPath, method = 'GET', category = 'API Route') {
    if (!rawPath || typeof rawPath !== 'string') return;
    const cleaned = rawPath.trim().replace(/^['"`]|['"`]$/g, '');
    if (cleaned.length < 3 || cleaned.length > 260) return;
    if (/^(?:javascript:|mailto:|tel:|data:|#)/i.test(cleaned)) return;
    if (STATIC_ASSET_EXT.test(cleaned)) return;
    if (IGNORED_HOSTS.test(cleaned)) return;
    if (/^\/\/[^/]/.test(cleaned) && !cleaned.includes('/api') && !cleaned.includes('/v1')) return;

    let fullUrl = cleaned;
    try {
      if (/^wss?:\/\//i.test(cleaned)) {
        fullUrl = cleaned;
        category = 'WebSocket';
        method = 'WS';
      } else {
        fullUrl = new URL(cleaned, baseOriginUrl).toString();
      }
    } catch {
      return;
    }

    const key = `${method.toUpperCase()}:${fullUrl}`;
    if (!discoveredMap.has(key)) {
      discoveredMap.set(key, {
        method: method.toUpperCase(),
        rawPath: cleaned,
        fullUrl,
        category,
        source: sourceLabel
      });
    }
  }

  // 1. Axios explicit calls: axios.get('/api/...'), api.post('/v1/...')
  const axiosRegex = /\b(?:axios|api|client|http)\s*\.\s*(get|post|put|patch|delete)\s*\(\s*(['"`])([^'"`\s]{3,200})\2/gi;
  let m;
  while ((m = axiosRegex.exec(sourceText)) !== null) {
    addEndpoint(m[3], m[1].toUpperCase(), 'Axios/HTTP Client');
  }

  // 2. Fetch calls: fetch('/api/...', { method: 'POST' })
  const fetchRegex = /\bfetch\s*\(\s*(['"`])([^'"`\s]{3,200})\1(?:\s*,\s*\{([^}]{0,220})\})?/gi;
  while ((m = fetchRegex.exec(sourceText)) !== null) {
    const urlStr = m[2];
    const optsBlock = m[3] || '';
    const methodMatch = optsBlock.match(/method\s*:\s*['"`](GET|POST|PUT|PATCH|DELETE)['"`]/i);
    const method = methodMatch ? methodMatch[1].toUpperCase() : 'GET';
    addEndpoint(urlStr, method, 'Fetch API');
  }

  // 3. Full HTTP/HTTPS URLs containing API-like patterns
  const fullApiUrlRegex = /(['"`])(https?:\/\/[^\s'"`<>)]{4,220}\/(?:api|v[1-9]|graphql|rest|trpc|rpc|wp-json|webhook|oauth|auth)\b[^\s'"`<>)]*)\1/gi;
  while ((m = fullApiUrlRegex.exec(sourceText)) !== null) {
    const urlStr = m[2];
    const method = /graphql|rpc|webhook|login|token/i.test(urlStr) ? 'POST' : 'GET';
    addEndpoint(urlStr, method, 'Full API URL');
  }

  // 4. Relative API paths: "/api/...", "/v1/...", "/graphql", "/wp-json/..."
  const relApiRegex = /(['"`])(\/(?:api|v[1-9]|graphql|rest|trpc|rpc|wp-json|oauth|auth|webhook)(?:\/[a-zA-Z0-9_\-./?=&{}%:]*)?)\1/gi;
  while ((m = relApiRegex.exec(sourceText)) !== null) {
    const rel = m[2];
    const method = /graphql|login|logout|register|token|webhook|create|update|checkout/i.test(rel) ? 'POST' : 'GET';
    addEndpoint(rel, method, 'API Route');
  }

  // 5. WebSocket URLs
  const wsRegex = /(['"`])(wss?:\/\/[^\s'"`<>)]{5,200})\1/gi;
  while ((m = wsRegex.exec(sourceText)) !== null) {
    addEndpoint(m[2], 'WS', 'WebSocket');
  }

  // 6. Frontend Configs (baseURL, apiEndpoint, NEXT_PUBLIC_*, VITE_*, REACT_APP_*)
  const configRegex = /\b(baseURL|apiUrl|apiBase|graphqlEndpoint|NEXT_PUBLIC_[A-Z0-9_]+|VITE_[A-Z0-9_]+|REACT_APP_[A-Z0-9_]+)\s*[:=]\s*(['"`])([^'"`\n]{4,180})\2/g;
  while ((m = configRegex.exec(sourceText)) !== null) {
    const key = m[1];
    const val = m[3];
    if (!configsList.some((c) => c.key === key && c.value === val)) {
      configsList.push({ key, value: val, source: sourceLabel });
    }
    if (/^https?:\/\//i.test(val) || val.startsWith('/')) {
      addEndpoint(val, 'GET', `Config (${key})`);
    }
  }
}

async function extractApisFromWebsite(rawTargetUrl, { maxScripts = 10, probeCommonPaths = true, useHeadless = false } = {}) {
  let normalizedUrl = String(rawTargetUrl || '').trim();
  if (!/^https?:\/\//i.test(normalizedUrl)) {
    normalizedUrl = 'https://' + normalizedUrl;
  }

  const mainRes = await executeHttpRequest({
    method: 'GET',
    targetUrl: normalizedUrl,
    headers: {
      'Accept': 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8'
    },
    timeoutMs: 10000
  });

  if (!mainRes.statusCode) {
    return {
      ok: false,
      error: mainRes.error || 'Không thể kết nối tới trang web mục tiêu.'
    };
  }

  const baseOriginUrl = mainRes.finalUrl || normalizedUrl;
  const parsedBase = new URL(baseOriginUrl);
  const originRoot = parsedBase.origin;

  const discoveredMap = new Map();
  const configsList = [];
  const scannedScripts = [];
  let headlessSummary = { enabled: Boolean(useHeadless), ok: false, capturedCount: 0, browserUsed: null };

  // 0. If useHeadless is enabled, launch real Headless Chrome/Edge and intercept live XHR/Fetch
  if (useHeadless) {
    const sniffRes = await sniffDynamicApisWithBrowser(baseOriginUrl, { waitMs: 2200 });
    headlessSummary = {
      enabled: true,
      ok: sniffRes.ok,
      browserUsed: sniffRes.browserUsed || sniffRes.reason || null,
      capturedCount: sniffRes.requests.length
    };
    for (const r of sniffRes.requests) {
      const key = `${r.method}:${r.fullUrl}`;
      discoveredMap.set(key, {
        method: r.method,
        rawPath: r.rawPath,
        fullUrl: r.fullUrl,
        category: `🔥 Bắt sống ${r.resourceType}${r.statusCode ? ` (HTTP ${r.statusCode})` : ''}`,
        source: `Trình duyệt ngầm (${sniffRes.browserUsed || 'Browser'})`,
        isLiveCaptured: true,
        requestHeaders: r.requestHeaders || {},
        postData: r.postData || ''
      });
    }
  }

  // Check if the URL itself returned JSON (e.g., user pasted an API or OpenAPI URL directly)
  const mainContentType = (mainRes.headers['content-type'] || '').toLowerCase();
  if (mainContentType.includes('application/json')) {
    discoveredMap.set(`GET:${baseOriginUrl}`, {
      method: 'GET',
      rawPath: parsedBase.pathname + parsedBase.search,
      fullUrl: baseOriginUrl,
      category: 'Direct JSON API',
      source: 'URL chính'
    });
  }

  // Scan main HTML body
  scanSourceForApis(mainRes.body, 'HTML Trang chính', baseOriginUrl, discoveredMap, configsList);

  // Extract <script src="..."> tags from HTML
  const scriptUrls = [];
  const scriptTagRegex = /<script\b[^>]*\bsrc\s*=\s*(['"])([^'"]+)\1/gi;
  let sm;
  while ((sm = scriptTagRegex.exec(mainRes.body || '')) !== null) {
    try {
      const resolvedScript = new URL(sm[2], baseOriginUrl).toString();
      if (!scriptUrls.includes(resolvedScript)) {
        scriptUrls.push(resolvedScript);
      }
    } catch {
      // ignore invalid script URL
    }
  }

  // Also extract <form action="..."> endpoints from HTML
  const formRegex = /<form\b[^>]*\baction\s*=\s*(['"])([^'"]+)\1[^>]*>/gi;
  while ((sm = formRegex.exec(mainRes.body || '')) !== null) {
    const formTag = sm[0];
    const actionPath = sm[2];
    const methodMatch = formTag.match(/\bmethod\s*=\s*(['"]?)(GET|POST)\1/i);
    const formMethod = methodMatch ? methodMatch[2].toUpperCase() : 'POST';
    try {
      const fullAction = new URL(actionPath, baseOriginUrl).toString();
      const key = `${formMethod}:${fullAction}`;
      if (!discoveredMap.has(key)) {
        discoveredMap.set(key, {
          method: formMethod,
          rawPath: actionPath,
          fullUrl: fullAction,
          category: 'HTML Form Action',
          source: 'HTML Trang chính'
        });
      }
    } catch {
      // ignore
    }
  }

  // Fetch up to maxScripts JS bundles in parallel (concurrency 4)
  const scriptsToFetch = scriptUrls.slice(0, Math.min(Math.max(Number(maxScripts) || 10, 1), 20));
  let sIdx = 0;
  async function scriptWorker() {
    while (sIdx < scriptsToFetch.length) {
      const current = scriptsToFetch[sIdx++];
      const shortName = current.split('/').pop().split('?')[0] || current;
      const jsRes = await executeHttpRequest({
        method: 'GET',
        targetUrl: current,
        timeoutMs: 6000
      });
      if (jsRes.statusCode >= 200 && jsRes.statusCode < 400 && jsRes.body) {
        scannedScripts.push({ url: current, sizeBytes: jsRes.sizeBytes, status: jsRes.statusCode });
        scanSourceForApis(jsRes.body, `JS: ${shortName.slice(0, 40)}`, baseOriginUrl, discoveredMap, configsList);
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(4, scriptsToFetch.length) }, () => scriptWorker()));

  // Optionally probe common OpenAPI / Swagger / WP-JSON / GraphQL paths
  if (probeCommonPaths) {
    const commonProbes = ['/openapi.json', '/swagger.json', '/wp-json/', '/api', '/graphql'];
    await Promise.all(
      commonProbes.map(async (probePath) => {
        const probeUrl = `${originRoot}${probePath}`;
        const pRes = await executeHttpRequest({
          method: 'GET',
          targetUrl: probeUrl,
          timeoutMs: 4000
        });
        const ct = (pRes.headers['content-type'] || '').toLowerCase();
        if (pRes.statusCode >= 200 && pRes.statusCode < 300 && (ct.includes('json') || pRes.body.trim().startsWith('{'))) {
          discoveredMap.set(`GET:${probeUrl}`, {
            method: 'GET',
            rawPath: probePath,
            fullUrl: probeUrl,
            category: `Active Endpoint (HTTP ${pRes.statusCode})`,
            source: 'Auto-Probe'
          });
          // If it's an OpenAPI/Swagger spec, extract its paths!
          try {
            const spec = JSON.parse(pRes.body);
            if (spec && spec.paths && typeof spec.paths === 'object') {
              for (const [apiPath, methodsObj] of Object.entries(spec.paths)) {
                for (const mName of Object.keys(methodsObj || {})) {
                  if (['get', 'post', 'put', 'patch', 'delete'].includes(mName.toLowerCase())) {
                    const fullSpecUrl = new URL(apiPath, originRoot).toString();
                    const k = `${mName.toUpperCase()}:${fullSpecUrl}`;
                    discoveredMap.set(k, {
                      method: mName.toUpperCase(),
                      rawPath: apiPath,
                      fullUrl: fullSpecUrl,
                      category: 'OpenAPI Spec',
                      source: probePath
                    });
                  }
                }
              }
            }
          } catch {
            // not a valid OpenAPI JSON
          }
        }
      })
    );
  }

  const endpoints = Array.from(discoveredMap.values());

  return {
    ok: true,
    targetUrl: baseOriginUrl,
    pageInfo: {
      statusCode: mainRes.statusCode,
      durationMs: mainRes.durationMs,
      sizeBytes: mainRes.sizeBytes,
      server: mainRes.headers['server'] || mainRes.headers['x-powered-by'] || 'Ẩn / Cloudflare',
      contentType: mainRes.headers['content-type'] || '',
      cors: mainRes.headers['access-control-allow-origin'] || 'Không cấu hình CORS công khai',
      scriptsFound: scriptUrls.length,
      scriptsScanned: scannedScripts.length,
      headless: headlessSummary
    },
    endpoints,
    configs: configsList,
    scannedScripts
  };
}

// Static file serving
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon'
};

function serveStaticFile(req, res, pathname) {
  const safePath = pathname === '/' ? '/index.html' : pathname;
  const resolvedPath = path.normalize(path.join(PUBLIC_DIR, safePath));
  if (!resolvedPath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    return res.end('Forbidden');
  }
  if (!fs.existsSync(resolvedPath) || fs.statSync(resolvedPath).isDirectory()) {
    res.writeHead(404);
    return res.end('Not Found');
  }
  const ext = path.extname(resolvedPath).toLowerCase();
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';
  res.writeHead(200, {
    'Content-Type': contentType,
    'Cache-Control': 'no-cache'
  });
  fs.createReadStream(resolvedPath).pipe(res);
}

// Main HTTP Server
const server = http.createServer(async (req, res) => {
  try {
    // Handle CORS preflight
    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD',
        'Access-Control-Allow-Headers': '*'
      });
      return res.end();
    }

    const parsedUrl = new URL(req.url, `http://${req.headers.host || `localhost:${PORT}`}`);
    const pathname = parsedUrl.pathname;

    // 1. Webhook capture route: /hook or /hook/*
    if (pathname === '/hook' || pathname.startsWith('/hook/')) {
      return await handleWebhookCapture(req, res, parsedUrl);
    }

    // 2. SSE Live Stream
    if (pathname === '/api/stream' && req.method === 'GET') {
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Access-Control-Allow-Origin': '*'
      });
      res.write(`event: connected\ndata: ${JSON.stringify({ time: new Date().toISOString() })}\n\n`);
      sseClients.add(res);
      req.on('close', () => sseClients.delete(res));
      return;
    }

    // 3. Get initial state
    if (pathname === '/api/state' && req.method === 'GET') {
      return sendJson(res, 200, {
        serverOrigin: `http://${req.headers.host || `localhost:${PORT}`}`,
        endpoints: store.endpoints,
        envVars: store.envVars || {},
        requests: store.requests,
        replays: store.replays,
        fuzzPresets: FUZZ_PRESETS,
        tunnel: getTunnelPublicInfo()
      });
    }

    // 3.1 Save Environment Variables (/api/env)
    if (pathname === '/api/env' && req.method === 'POST') {
      const raw = (await readRequestBody(req)).toString('utf8');
      const { envVars = {} } = JSON.parse(raw || '{}');
      const cleaned = {};
      for (const [k, v] of Object.entries(envVars || {})) {
        const key = String(k || '').trim();
        if (key) cleaned[key] = String(v ?? '');
      }
      store.envVars = cleaned;
      saveStore();
      return sendJson(res, 200, { ok: true, envVars: store.envVars });
    }

    // 3.2 Export & Restore Full Workspace Backup (/api/backup & /api/restore)
    if (pathname === '/api/backup' && req.method === 'GET') {
      return sendJson(res, 200, {
        ok: true,
        exportedAt: new Date().toISOString(),
        app: 'NetPulse',
        store
      });
    }

    if (pathname === '/api/restore' && req.method === 'POST') {
      const raw = (await readRequestBody(req)).toString('utf8');
      const parsed = JSON.parse(raw || '{}');
      const data = parsed.store || parsed;
      if (!data || !Array.isArray(data.endpoints)) {
        return sendJson(res, 400, { ok: false, error: 'File backup không hợp lệ (thiếu danh sách endpoints).' });
      }
      store.endpoints = data.endpoints;
      if (data.envVars && typeof data.envVars === 'object') store.envVars = data.envVars;
      if (Array.isArray(data.requests)) store.requests = data.requests.slice(0, MAX_REQUESTS);
      if (Array.isArray(data.replays)) store.replays = data.replays.slice(0, 100);
      saveStore();
      broadcastEvent('endpoints_updated', store.endpoints);
      return sendJson(res, 200, { ok: true, store });
    }

    // 3.5 Public Tunnel Control (/api/tunnel/start & /api/tunnel/stop)
    if (pathname === '/api/tunnel/start' && req.method === 'POST') {
      const raw = (await readRequestBody(req)).toString('utf8');
      const { provider = 'ngrok' } = JSON.parse(raw || '{}');
      const activePort = server.address()?.port || PORT;
      const info = await startPublicTunnel(activePort, provider);
      return sendJson(res, 200, { ok: Boolean(info.publicBaseUrl), tunnel: info });
    }

    if (pathname === '/api/tunnel/stop' && req.method === 'POST') {
      const info = stopPublicTunnel();
      return sendJson(res, 200, { ok: true, tunnel: info });
    }

    // 4. Create or Update Endpoint
    if (pathname === '/api/endpoints' && req.method === 'POST') {
      const raw = (await readRequestBody(req)).toString('utf8');
      const data = JSON.parse(raw || '{}');
      const cleanSlug = String(data.slug || '')
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9-_]/g, '-')
        .replace(/-+/g, '-')
        .replace(/^-|-$/g, '') || ('hook-' + crypto.randomBytes(3).toString('hex'));

      let existing = store.endpoints.find((e) => e.id === data.id || e.slug === cleanSlug);
      if (existing) {
        existing.slug = cleanSlug;
        existing.name = data.name || existing.name;
        existing.statusCode = Number(data.statusCode) || 200;
        existing.contentType = data.contentType || 'application/json';
        existing.responseBody = data.responseBody ?? existing.responseBody;
        existing.delayMs = Math.min(Math.max(Number(data.delayMs) || 0, 0), 15000);
        existing.secret = data.secret ?? '';
        existing.requireValidHmac = Boolean(data.requireValidHmac);
        existing.forwardUrl = data.forwardUrl ?? '';
        existing.notifyWebhookUrl = data.notifyWebhookUrl ?? existing.notifyWebhookUrl ?? '';
        existing.notifyOnlyOnAnomaly = Boolean(data.notifyOnlyOnAnomaly);
      } else {
        existing = {
          id: 'ep-' + crypto.randomBytes(4).toString('hex'),
          slug: cleanSlug,
          name: data.name || `Endpoint /hook/${cleanSlug}`,
          statusCode: Number(data.statusCode) || 200,
          contentType: data.contentType || 'application/json',
          responseBody: data.responseBody || JSON.stringify({ ok: true, id: '{{requestId}}' }, null, 2),
          delayMs: Math.min(Math.max(Number(data.delayMs) || 0, 0), 15000),
          secret: data.secret || '',
          requireValidHmac: Boolean(data.requireValidHmac),
          forwardUrl: data.forwardUrl || '',
          notifyWebhookUrl: data.notifyWebhookUrl || '',
          notifyOnlyOnAnomaly: Boolean(data.notifyOnlyOnAnomaly),
          createdAt: new Date().toISOString()
        };
        store.endpoints.unshift(existing);
      }
      saveStore();
      broadcastEvent('endpoints_updated', store.endpoints);
      return sendJson(res, 200, { ok: true, endpoint: existing, endpoints: store.endpoints });
    }

    // 4.1 Test Endpoint Alert Notification (Telegram / Discord / Custom Webhook)
    if (pathname === '/api/endpoints/test-notify' && req.method === 'POST') {
      const raw = (await readRequestBody(req)).toString('utf8');
      const { notifyWebhookUrl = '', slug = 'payment-webhook', name = 'Test Endpoint' } = JSON.parse(raw || '{}');
      if (!notifyWebhookUrl.trim()) {
        return sendJson(res, 400, { ok: false, error: 'Vui lòng nhập URL Telegram / Discord / Webhook nhận thông báo.' });
      }
      const mockRecord = {
        id: 'req_test_notify',
        slug,
        method: 'POST',
        url: `/hook/${slug}?test=1`,
        sizeBytes: 128,
        rawBody: JSON.stringify({ event: 'test.notification', message: 'Tin nhắn kiểm tra cảnh báo từ NetPulse!' }),
        signatureAnalysis: { verified: true },
        responseSent: { statusCode: 200 },
        createdAt: new Date().toISOString()
      };
      const result = await dispatchWebhookAlert(
        { name, slug, notifyWebhookUrl: notifyWebhookUrl.trim(), notifyOnlyOnAnomaly: false },
        mockRecord
      );
      return sendJson(res, 200, { ok: Boolean(result && result.ok), result });
    }

    // 5. Delete Endpoint
    if (pathname.startsWith('/api/endpoints/') && req.method === 'DELETE') {
      const id = pathname.replace('/api/endpoints/', '');
      store.endpoints = store.endpoints.filter((e) => e.id !== id);
      saveStore();
      broadcastEvent('endpoints_updated', store.endpoints);
      return sendJson(res, 200, { ok: true, endpoints: store.endpoints });
    }

    // 6. Clear captured requests
    if (pathname === '/api/requests' && req.method === 'DELETE') {
      const slugFilter = parsedUrl.searchParams.get('slug');
      if (slugFilter) {
        store.requests = store.requests.filter((r) => r.slug !== slugFilter);
      } else {
        store.requests = [];
      }
      saveStore();
      broadcastEvent('requests_cleared', { slug: slugFilter || null });
      return sendJson(res, 200, { ok: true, requests: store.requests });
    }

    // 7. Delete single request
    if (pathname.startsWith('/api/requests/') && req.method === 'DELETE') {
      const id = pathname.replace('/api/requests/', '');
      store.requests = store.requests.filter((r) => r.id !== id);
      saveStore();
      return sendJson(res, 200, { ok: true });
    }

    // 8. Re-verify HMAC signature with custom secret on a request or payload
    if (pathname === '/api/hmac-verify' && req.method === 'POST') {
      const raw = (await readRequestBody(req)).toString('utf8');
      const { rawBody = '', secret = '', headers = {} } = JSON.parse(raw || '{}');
      const result = analyzeIncomingSignature(headers, rawBody, secret);
      return sendJson(res, 200, result);
    }

    // 9. Replay / Custom Request Execution (with Env Vars interpolation & Automated Assertions)
    if (pathname === '/api/replay' && req.method === 'POST') {
      const raw = (await readRequestBody(req)).toString('utf8');
      const payload = JSON.parse(raw || '{}');
      const targetUrl = interpolateEnvVars(String(payload.targetUrl || '').trim());
      const method = String(payload.method || 'POST').toUpperCase();
      const headers = interpolateHeaders(payload.headers || {});
      const body = interpolateEnvVars(String(payload.body ?? ''));
      const timeoutMs = Number(payload.timeoutMs) || 10000;

      const response = await executeHttpRequest({
        method,
        targetUrl,
        headers,
        body,
        timeoutMs
      });

      const assertionResults = evaluateAssertions(payload.assertions || [], response);

      const replayEntry = {
        id: 'rep_' + Date.now().toString(36) + '_' + crypto.randomBytes(2).toString('hex'),
        sourceRequestId: payload.sourceRequestId || null,
        method,
        targetUrl,
        headers,
        body,
        request: { method, targetUrl, headers, body },
        response,
        assertionResults,
        createdAt: new Date().toISOString()
      };

      store.replays.unshift(replayEntry);
      if (store.replays.length > 100) store.replays.length = 100;
      saveStore();

      return sendJson(res, 200, replayEntry);
    }

    // 9.1 Clear Replay History
    if (pathname === '/api/replays' && req.method === 'DELETE') {
      store.replays = [];
      saveStore();
      return sendJson(res, 200, { ok: true, replays: [] });
    }

    // 9.2 Parse cURL Command (Import from Chrome F12)
    if (pathname === '/api/parse-curl' && req.method === 'POST') {
      const raw = (await readRequestBody(req)).toString('utf8');
      const { curl = '' } = JSON.parse(raw || '{}');
      const parsed = parseCurlCommand(curl);
      return sendJson(res, 200, parsed);
    }

    // 9.3 CORS & Security Header Auditor
    if (pathname === '/api/security-audit' && req.method === 'POST') {
      const raw = (await readRequestBody(req)).toString('utf8');
      const payload = JSON.parse(raw || '{}');
      const result = await auditTargetSecurity({
        method: String(payload.method || 'GET').toUpperCase(),
        targetUrl: interpolateEnvVars(String(payload.targetUrl || '').trim()),
        headers: interpolateHeaders(payload.headers || {}),
        body: interpolateEnvVars(String(payload.body ?? ''))
      });
      return sendJson(res, 200, result);
    }

    // 10. API Fuzzer Engine
    if (pathname === '/api/fuzz' && req.method === 'POST') {
      const raw = (await readRequestBody(req)).toString('utf8');
      const config = JSON.parse(raw || '{}');
      const targetUrlTemplate = interpolateEnvVars(String(config.targetUrl || '').trim());
      const method = String(config.method || 'POST').toUpperCase();
      const headersTemplateStr = JSON.stringify(interpolateHeaders(config.headers || {}));
      const bodyTemplate = interpolateEnvVars(String(config.body ?? ''));
      const payloads = Array.isArray(config.payloads)
        ? config.payloads.slice(0, 60)
        : [];
      const concurrency = Math.min(Math.max(Number(config.concurrency) || 3, 1), 10);
      const delayMs = Math.min(Math.max(Number(config.delayMs) || 0, 0), 2000);

      if (!targetUrlTemplate || payloads.length === 0) {
        return sendJson(res, 400, { error: 'Vui lòng nhập URL mục tiêu và ít nhất 1 payload.' });
      }

      // Run baseline request first (replacing {{FUZZ}} with "baseline_test")
      const baselineUrl = injectFuzzPayload(targetUrlTemplate, 'baseline_test');
      const baselineHeaders = JSON.parse(injectFuzzPayload(headersTemplateStr, 'baseline_test'));
      const baselineBody = injectFuzzPayload(bodyTemplate, 'baseline_test');
      const baselineRes = await executeHttpRequest({
        method,
        targetUrl: baselineUrl,
        headers: baselineHeaders,
        body: baselineBody,
        timeoutMs: 8000
      });

      const results = [];
      let index = 0;

      async function worker() {
        while (index < payloads.length) {
          const currentIdx = index++;
          const fuzzValue = String(payloads[currentIdx]);

          if (delayMs > 0 && currentIdx > 0) {
            await new Promise((r) => setTimeout(r, delayMs));
          }

          const finalUrl = injectFuzzPayload(targetUrlTemplate, encodeURIComponent(fuzzValue));
          // If {{FUZZ}} was in URL, use encoded; for body/headers, use raw or JSON-escaped as appropriate
          let finalHeaders = {};
          try {
            const escapedForJson = fuzzValue.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
            finalHeaders = JSON.parse(injectFuzzPayload(headersTemplateStr, escapedForJson));
          } catch {
            finalHeaders = config.headers || {};
          }
          const finalBody = injectFuzzPayload(bodyTemplate, fuzzValue);

          const resData = await executeHttpRequest({
            method,
            targetUrl: targetUrlTemplate.includes('{{FUZZ}}') ? finalUrl : targetUrlTemplate,
            headers: finalHeaders,
            body: finalBody,
            timeoutMs: 8000
          });

          // Anomaly detection against baseline
          const anomalies = [];
          if (resData.statusCode !== baselineRes.statusCode) {
            anomalies.push(`Khác mã HTTP (${resData.statusCode} vs ${baselineRes.statusCode})`);
          }
          if (resData.statusCode >= 500) {
            anomalies.push('Lỗi Server 5xx');
          }
          const sizeDiff = Math.abs(resData.sizeBytes - baselineRes.sizeBytes);
          if (sizeDiff > Math.max(50, fuzzValue.length * 2)) {
            anomalies.push(`Chênh lệch kích thước (${resData.sizeBytes}B vs ${baselineRes.sizeBytes}B)`);
          }
          if (resData.durationMs > Math.max(baselineRes.durationMs * 3, 1000)) {
            anomalies.push(`Phản hồi chậm (${resData.durationMs}ms)`);
          }
          const lowerBody = (resData.body || '').toLowerCase();
          if (
            lowerBody.includes('sql syntax') ||
            lowerBody.includes('sqlite_error') ||
            lowerBody.includes('ora-') ||
            lowerBody.includes('unterminated') ||
            lowerBody.includes('stack trace') ||
            lowerBody.includes('root:x:0:0')
          ) {
            anomalies.push('Rò rỉ thông báo lỗi / nhạy cảm');
          }

          results.push({
            index: currentIdx + 1,
            payload: fuzzValue,
            statusCode: resData.statusCode,
            durationMs: resData.durationMs,
            sizeBytes: resData.sizeBytes,
            anomalies,
            isAnomaly: anomalies.length > 0,
            responseBodyPreview: (resData.body || '').slice(0, 2000),
            responseHeaders: resData.headers,
            error: resData.error || null
          });
        }
      }

      const workers = Array.from({ length: Math.min(concurrency, payloads.length) }, () => worker());
      await Promise.all(workers);
      results.sort((a, b) => a.index - b.index);

      return sendJson(res, 200, {
        baseline: {
          statusCode: baselineRes.statusCode,
          durationMs: baselineRes.durationMs,
          sizeBytes: baselineRes.sizeBytes
        },
        total: results.length,
        anomalyCount: results.filter((r) => r.isAnomaly).length,
        results
      });
    }

    // 11. Built-in Simulation Traffic Generator ("Bắn thử mẫu")
    if (pathname === '/api/simulate' && req.method === 'POST') {
      const raw = (await readRequestBody(req)).toString('utf8');
      const { scenario = 'payment' } = JSON.parse(raw || '{}');
      const activePort = server.address()?.port || PORT;
      const baseOrigin = `http://127.0.0.1:${activePort}`;

      if (scenario === 'payment') {
        const ep = store.endpoints.find((e) => e.slug === 'payment-webhook') || store.endpoints[0];
        const secret = (ep && ep.secret) || 'whsec_demo_secret_2026';
        // Create sample JWT for Authorization header
        const jwtHeader = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
        const jwtPayload = Buffer.from(JSON.stringify({
          iss: 'vietqr-gateway.vn',
          sub: 'merchant_tris_01',
          scope: 'webhook:payment',
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 3600
        })).toString('base64url');
        const jwtSig = crypto.createHmac('sha256', secret).update(`${jwtHeader}.${jwtPayload}`).digest('base64url');
        const sampleJwt = `${jwtHeader}.${jwtPayload}.${jwtSig}`;

        const bodyObj = {
          event: 'payment.succeeded',
          transactionId: 'TXN_' + Date.now(),
          amount: 450000,
          currency: 'VND',
          bankCode: 'MBBANK',
          accountNumber: '0987654321',
          transferContent: 'SEVQR DH88291 THANH TOAN DON HANG',
          metadataBase64: Buffer.from(JSON.stringify({ orderId: 'DH88291', customer: 'vip_user', tier: 'pro' })).toString('base64'),
          paidAt: new Date().toISOString()
        };
        const rawBodyStr = JSON.stringify(bodyObj, null, 2);
        const hmacHex = crypto.createHmac('sha256', secret).update(rawBodyStr).digest('hex');

        const simRes = await executeHttpRequest({
          method: 'POST',
          targetUrl: `${baseOrigin}/hook/${ep ? ep.slug : 'payment-webhook'}?source=vietqr&env=prod`,
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'VietQR-Webhook-Dispatcher/2.4',
            'Authorization': `Bearer ${sampleJwt}`,
            'X-Hub-Signature-256': `sha256=${hmacHex}`,
            'X-Webhook-Id': 'wh_' + crypto.randomBytes(6).toString('hex')
          },
          body: rawBodyStr
        });
        return sendJson(res, 200, { ok: true, scenario, status: simRes.statusCode });
      }

      if (scenario === 'telegram') {
        const ep = store.endpoints.find((e) => e.slug === 'telegram-bot') || store.endpoints[0];
        const secret = (ep && ep.secret) || 'tg_bot_secret_token';
        const bodyObj = {
          update_id: Math.floor(100000000 + Math.random() * 900000000),
          message: {
            message_id: 4021,
            from: { id: 591827364, is_bot: false, first_name: 'Minh', username: 'minh_dev', language_code: 'vi' },
            chat: { id: 591827364, first_name: 'Minh', username: 'minh_dev', type: 'private' },
            date: Math.floor(Date.now() / 1000),
            text: '/buy_account premium_12m',
            entities: [{ offset: 0, length: 12, type: 'bot_command' }]
          }
        };
        const simRes = await executeHttpRequest({
          method: 'POST',
          targetUrl: `${baseOrigin}/hook/${ep ? ep.slug : 'telegram-bot'}`,
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'TelegramBot (like TwitterBot)',
            'X-Telegram-Bot-Api-Secret-Token': secret
          },
          body: JSON.stringify(bodyObj, null, 2)
        });
        return sendJson(res, 200, { ok: true, scenario, status: simRes.statusCode });
      }

      if (scenario === 'suspicious') {
        const basicAuth = Buffer.from('admin:SuperSecretPass!2026').toString('base64');
        const bodyObj = {
          action: 'update_profile',
          userId: "105' OR '1'='1",
          role: 'administrator',
          apiTokenBase64: Buffer.from('internal_api_key=sk_live_9988776655443322').toString('base64'),
          redirectUrl: 'javascript:alert(document.cookie)'
        };
        const simRes = await executeHttpRequest({
          method: 'PUT',
          targetUrl: `${baseOrigin}/hook/catch-all/api/v1/users?debug=true&trace=1`,
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) CustomScanner/1.0',
            'Authorization': `Basic ${basicAuth}`,
            'X-Forwarded-For': '185.220.101.45',
            'X-Hub-Signature-256': 'sha256=deadbeef0000invalid_signature_example'
          },
          body: JSON.stringify(bodyObj, null, 2)
        });
        return sendJson(res, 200, { ok: true, scenario, status: simRes.statusCode });
      }

      return sendJson(res, 400, { error: 'Kịch bản không hợp lệ' });
    }

    // 11.5 Website API Hunter (/api/extract-apis)
    if (pathname === '/api/extract-apis' && req.method === 'POST') {
      const raw = (await readRequestBody(req)).toString('utf8');
      const { targetUrl = '', maxScripts = 10, probeCommonPaths = true, useHeadless = false } = JSON.parse(raw || '{}');
      if (!targetUrl.trim()) {
        return sendJson(res, 400, { ok: false, error: 'Vui lòng nhập địa chỉ trang web cần dò API.' });
      }
      const result = await extractApisFromWebsite(targetUrl.trim(), { maxScripts, probeCommonPaths, useHeadless });
      return sendJson(res, 200, result);
    }

    // 11.6 JWT Studio Endpoints (/api/jwt/encode & /api/jwt/audit-secret)
    if (pathname === '/api/jwt/encode' && req.method === 'POST') {
      const raw = (await readRequestBody(req)).toString('utf8');
      const { header, payload, secret, mode, noneVariant } = JSON.parse(raw || '{}');
      const result = encodeJwtToken({ header, payload, secret, mode, noneVariant });
      return sendJson(res, 200, { ok: true, ...result });
    }

    if (pathname === '/api/jwt/audit-secret' && req.method === 'POST') {
      const raw = (await readRequestBody(req)).toString('utf8');
      const { token = '', customSecrets = [] } = JSON.parse(raw || '{}');
      const result = auditJwtWeakSecret(token, Array.isArray(customSecrets) ? customSecrets : []);
      return sendJson(res, 200, result);
    }

    // Built-in Demo Web App for testing API Hunter
    if (pathname === '/demo-webapp' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(`<!DOCTYPE html>
<html>
<head><title>Demo E-Commerce Portal</title></head>
<body>
  <h1>Demo Shop Portal</h1>
  <form action="/hook/payment-webhook" method="POST"></form>
  <script src="/demo-webapp/bundle.js"></script>
</body>
</html>`);
    }

    if (pathname === '/demo-webapp/bundle.js' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8' });
      return res.end(`
        const NEXT_PUBLIC_API_BASE = "/hook/catch-all";
        const baseURL = "https://jsonplaceholder.typicode.com";
        async function loadCatalog() {
          await fetch("/hook/catch-all/api/v1/products?limit=20", { method: "GET" });
          await fetch("https://jsonplaceholder.typicode.com/posts/1", { method: "GET" });
          await axios.post("/hook/payment-webhook", { orderId: "DH001" });
          await axios.put("/hook/catch-all/api/v1/users/profile");
        }
        // Automatically fire live XHR when page loads in Headless Browser!
        fetch("/hook/catch-all/api/v1/live-cart?session=active", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Dynamic-Auth": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ2aXBfYbuyerIsInJvbGUiOiJ1c2VyIn0.sig"
          },
          body: JSON.stringify({ cartId: "CART_8899", items: 3 })
        }).catch(() => {});
        const wsStream = "wss://echo.websocket.events/v1/live";
      `);
    }

    // 12. Static frontend files
    return serveStaticFile(req, res, pathname);
  } catch (err) {
    console.error('[Server Error]', err);
    return sendJson(res, 500, { error: err.message || 'Internal Server Error' });
  }
});

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`\n========================================================`);
    console.log(`⚡ NetPulse - Webhook Inspector & API Fuzzer đang chạy!`);
    console.log(`🌐 Giao diện Web : http://localhost:${PORT}`);
    console.log(`🎯 URL bắt gói tin: http://localhost:${PORT}/hook/payment-webhook`);
    console.log(`========================================================\n`);
  });
}

module.exports = { server, analyzeRequestPayload, tryDecodeJwt, tryDecodeBase64, computeHmacSignatures };
