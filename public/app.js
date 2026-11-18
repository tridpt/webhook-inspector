/**
 * NetPulse Frontend Application
 */

const state = {
  serverOrigin: window.location.origin,
  endpoints: [],
  envVars: {},
  requests: [],
  replays: [],
  fuzzPresets: {},
  activeEndpointSlug: '',
  selectedRequestId: null,
  streamPaused: false,
  selectedCodeLang: 'curl',
  hunterEndpoints: [],
  tunnel: { active: false, status: 'stopped', publicBaseUrl: null, provider: null },
  diffPinA: null,
  diffPinB: null
};

// Utility: Escape HTML
function esc(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function formatBytes(bytes) {
  const b = Number(bytes) || 0;
  if (b < 1024) return `${b} B`;
  return `${(b / 1024).toFixed(1)} KB`;
}

function formatTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return d.toLocaleTimeString('vi-VN', { hour12: false }) + '.' + String(d.getMilliseconds()).padStart(3, '0');
}

function statusClass(code) {
  const c = Number(code) || 0;
  if (c >= 200 && c < 300) return 'status-2xx';
  if (c >= 300 && c < 400) return 'status-3xx';
  if (c >= 400 && c < 500) return 'status-4xx';
  return 'status-5xx';
}

function showToast(msg) {
  const container = document.getElementById('toast-container');
  const el = document.createElement('div');
  el.className = 'toast';
  el.textContent = msg;
  container.appendChild(el);
  setTimeout(() => el.remove(), 3200);
}

// Parse headers textarea (supports JSON object or Key: Value lines)
function parseHeadersInput(rawText) {
  const trimmed = (rawText || '').trim();
  if (!trimmed) return {};
  if (trimmed.startsWith('{')) {
    try {
      return JSON.parse(trimmed);
    } catch {
      // fallback to line parser
    }
  }
  const headers = {};
  for (const line of trimmed.split('\n')) {
    const idx = line.indexOf(':');
    if (idx > 0) {
      const k = line.slice(0, idx).trim();
      const v = line.slice(idx + 1).trim();
      if (k) headers[k] = v;
    }
  }
  return headers;
}

function formatHeadersForTextarea(headersObj) {
  const skip = new Set(['host', 'connection', 'content-length', 'accept-encoding']);
  const lines = [];
  for (const [k, v] of Object.entries(headersObj || {})) {
    if (skip.has(k.toLowerCase())) continue;
    lines.push(`${k}: ${v}`);
  }
  return lines.join('\n');
}

function parseEnvVarsInput(rawText) {
  const trimmed = (rawText || '').trim();
  if (!trimmed) return {};
  if (trimmed.startsWith('{')) {
    try {
      return JSON.parse(trimmed);
    } catch {
      // fallback to line parser
    }
  }
  const out = {};
  for (const line of trimmed.split('\n')) {
    const clean = line.trim();
    if (!clean || clean.startsWith('#')) continue;
    const eqIdx = clean.indexOf('=');
    const colonIdx = clean.indexOf(':');
    const idx = eqIdx > 0 ? eqIdx : colonIdx;
    if (idx > 0) {
      const k = clean.slice(0, idx).trim();
      const v = clean.slice(idx + 1).trim();
      if (k) out[k] = v;
    }
  }
  return out;
}

function formatEnvVarsForTextarea(envObj) {
  return Object.entries(envObj || {})
    .map(([k, v]) => `${k} = ${v}`)
    .join('\n');
}

// Generate Code Snippets (cURL, PowerShell, Python, Fetch)
function generateCodeSnippet(req, lang) {
  const url = req.fullUrl || `${state.serverOrigin}${req.url}`;
  const method = req.method || 'POST';
  const headers = {};
  const skip = new Set(['host', 'connection', 'content-length', 'accept-encoding']);
  for (const [k, v] of Object.entries(req.headers || {})) {
    if (!skip.has(k.toLowerCase())) headers[k] = v;
  }
  const body = req.rawBody || '';

  if (lang === 'curl') {
    const lines = [`curl -X ${method} "${url}"`];
    for (const [k, v] of Object.entries(headers)) {
      lines.push(`  -H "${k}: ${String(v).replace(/"/g, '\\"')}"`);
    }
    if (body && !['GET', 'HEAD'].includes(method)) {
      lines.push(`  -d '${body.replace(/'/g, "'\\''")}'`);
    }
    return lines.join(' \\\n');
  }

  if (lang === 'powershell') {
    const lines = [
      `$headers = @{`,
      ...Object.entries(headers).map(([k, v]) => `  "${k}" = "${String(v).replace(/"/g, '`"')}"`),
      `}`
    ];
    if (body && !['GET', 'HEAD'].includes(method)) {
      lines.push(`$body = @'\n${body}\n'@`);
      lines.push(`Invoke-RestMethod -Uri "${url}" -Method ${method} -Headers $headers -Body $body`);
    } else {
      lines.push(`Invoke-RestMethod -Uri "${url}" -Method ${method} -Headers $headers`);
    }
    return lines.join('\n');
  }

  if (lang === 'python') {
    return [
      `import requests`,
      ``,
      `url = ${JSON.stringify(url)}`,
      `headers = ${JSON.stringify(headers, null, 2)}`,
      body ? `data = ${JSON.stringify(body)}` : `data = None`,
      ``,
      `response = requests.request(${JSON.stringify(method)}, url, headers=headers, data=data)`,
      `print(response.status_code)`,
      `print(response.text)`
    ].join('\n');
  }

  // fetch
  const fetchOpts = {
    method,
    headers
  };
  if (body && !['GET', 'HEAD'].includes(method)) {
    fetchOpts.body = body;
  }
  return `fetch(${JSON.stringify(url)}, ${JSON.stringify(fetchOpts, null, 2)})\n  .then(res => res.text())\n  .then(console.log);`;
}

// Render Endpoint Selector Bar & Endpoints Manager Tab
function renderEndpoints() {
  const select = document.getElementById('active-endpoint-select');
  const currentVal = state.activeEndpointSlug;

  select.innerHTML = `<option value="">-- Tất cả Endpoints (${state.endpoints.length}) --</option>` +
    state.endpoints.map((ep) => `<option value="${esc(ep.slug)}">${esc(ep.name)} (/hook/${esc(ep.slug)})</option>`).join('');

  if (currentVal && state.endpoints.some((e) => e.slug === currentVal)) {
    select.value = currentVal;
  } else {
    state.activeEndpointSlug = '';
    select.value = '';
  }

  updateActiveEndpointBanner();

  // Render Endpoints list in Tab 4
  const listEl = document.getElementById('endpoints-list');
  listEl.innerHTML = state.endpoints.map((ep) => {
    const hookUrl = `${state.serverOrigin}/hook/${ep.slug}`;
    return `
      <div class="ep-item">
        <div>
          <h4>${esc(ep.name)}</h4>
          <code>${esc(hookUrl)}</code>
          <div style="margin-top:6px; display:flex; gap:6px; flex-wrap:wrap;">
            <span class="meta-tag">HTTP ${ep.statusCode}</span>
            <span class="meta-tag">${esc(ep.contentType)}</span>
            ${ep.delayMs ? `<span class="meta-tag">Trễ: ${ep.delayMs}ms</span>` : ''}
            ${ep.secret ? `<span class="mini-tag hmac-ok">🔐 Có HMAC Secret</span>` : ''}
            ${ep.requireValidHmac ? `<span class="mini-tag hmac-bad">🔒 Bắt buộc HMAC (401)</span>` : ''}
            ${ep.forwardUrl ? `<span class="mini-tag jwt">↪ Proxy: ${esc(ep.forwardUrl)}</span>` : ''}
            ${ep.notifyWebhookUrl ? `<span class="mini-tag b64">🔔 Cảnh báo (${ep.notifyOnlyOnAnomaly ? 'Khi dị thường' : 'Mọi gói tin'})</span>` : ''}
          </div>
        </div>
        <div class="btn-row">
          <button class="btn btn-secondary btn-sm" onclick="editEndpoint('${esc(ep.id)}')">✏️ Sửa</button>
          <button class="btn btn-danger btn-sm" onclick="deleteEndpoint('${esc(ep.id)}')">🗑️</button>
        </div>
      </div>
    `;
  }).join('');
}

function updateActiveEndpointBanner() {
  const ep = state.endpoints.find((e) => e.slug === state.activeEndpointSlug) || state.endpoints[0];
  const urlCode = document.getElementById('active-webhook-url');
  const metaEl = document.getElementById('active-endpoint-meta');
  const publicBox = document.getElementById('public-tunnel-url-box');
  const publicCode = document.getElementById('active-public-webhook-url');
  const toggleBtn = document.getElementById('btn-toggle-tunnel');

  const slug = ep ? ep.slug : 'payment-webhook';
  if (ep) {
    urlCode.textContent = `${state.serverOrigin}/hook/${slug}`;
    metaEl.textContent = `Trả về HTTP ${ep.statusCode} • ${ep.secret ? 'Đã bật HMAC' : 'Không dùng Secret'}${ep.delayMs ? ` • Trễ ${ep.delayMs}ms` : ''}`;
  }

  if (state.tunnel && state.tunnel.active && state.tunnel.publicBaseUrl) {
    publicBox.classList.remove('hidden');
    publicCode.textContent = `${state.tunnel.publicBaseUrl}/hook/${slug}`;
    toggleBtn.textContent = `🛑 Tắt Tunnel (${state.tunnel.provider || 'Online'})`;
    toggleBtn.className = 'btn btn-danger btn-sm';
  } else if (state.tunnel && state.tunnel.status === 'starting') {
    publicBox.classList.add('hidden');
    toggleBtn.textContent = '⏳ Đang mở Tunnel...';
    toggleBtn.className = 'btn btn-warning btn-sm';
  } else {
    publicBox.classList.add('hidden');
    toggleBtn.textContent = '🌍 Bật Public Tunnel';
    toggleBtn.className = 'btn btn-secondary btn-sm';
  }
}

// Render Captured Requests Sidebar
function renderRequestList() {
  const search = (document.getElementById('search-requests').value || '').toLowerCase().trim();
  const methodFilter = document.getElementById('filter-method').value;
  const slugFilter = state.activeEndpointSlug;

  const filtered = state.requests.filter((r) => {
    if (slugFilter && r.slug !== slugFilter) return false;
    if (methodFilter && r.method !== methodFilter) return false;
    if (search) {
      const hay = `${r.url} ${r.clientIp} ${r.rawBody || ''} ${JSON.stringify(r.headers || {})}`.toLowerCase();
      if (!hay.includes(search)) return false;
    }
    return true;
  });

  document.getElementById('req-count-badge').textContent = String(state.requests.length);
  populateDiffSelectors();

  const listEl = document.getElementById('request-list');
  if (filtered.length === 0) {
    listEl.innerHTML = `<div class="empty-state small"><p>Chưa có gói tin nào khớp bộ lọc.</p></div>`;
    return;
  }

  listEl.innerHTML = filtered.map((r) => {
    const isSelected = r.id === state.selectedRequestId;
    const jwtCount = r.decodedItems?.jwts?.length || 0;
    const b64Count = r.decodedItems?.base64?.length || 0;
    const sigVerified = r.signatureAnalysis?.verified;

    return `
      <div class="req-item ${isSelected ? 'active' : ''}" onclick="selectRequest('${esc(r.id)}')">
        <div class="req-item-top">
          <div style="display:flex; align-items:center; gap:6px; min-width:0;">
            <span class="method-badge ${esc(r.method)}">${esc(r.method)}</span>
            <span class="req-item-path" title="${esc(r.url)}">${esc(r.url)}</span>
          </div>
          <span class="status-pill ${statusClass(r.responseSent?.statusCode)}">${r.responseSent?.statusCode || 200}</span>
        </div>
        <div class="req-badges">
          ${jwtCount > 0 ? `<span class="mini-tag jwt">JWT (${jwtCount})</span>` : ''}
          ${b64Count > 0 ? `<span class="mini-tag b64">Base64 (${b64Count})</span>` : ''}
          ${sigVerified === true ? `<span class="mini-tag hmac-ok">✓ HMAC Hợp lệ</span>` : ''}
          ${sigVerified === false ? `<span class="mini-tag hmac-bad">✗ Sai Chữ ký</span>` : ''}
        </div>
        <div class="req-item-bottom">
          <span>${esc(r.clientIp)} • ${formatBytes(r.sizeBytes)}</span>
          <span>${formatTime(r.createdAt)}</span>
        </div>
      </div>
    `;
  }).join('');
}

// Render Selected Request Detail
function renderRequestDetail() {
  const req = state.requests.find((r) => r.id === state.selectedRequestId);
  const emptyEl = document.getElementById('empty-detail-state');
  const contentEl = document.getElementById('detail-content');

  if (!req) {
    emptyEl.classList.remove('hidden');
    contentEl.classList.add('hidden');
    return;
  }

  emptyEl.classList.add('hidden');
  contentEl.classList.remove('hidden');

  const methodEl = document.getElementById('det-method');
  methodEl.className = `method-badge ${req.method}`;
  methodEl.textContent = req.method;

  document.getElementById('det-url').textContent = req.url;

  const statusEl = document.getElementById('det-status');
  const stCode = req.responseSent?.statusCode || 200;
  statusEl.className = `status-pill ${statusClass(stCode)}`;
  statusEl.textContent = `HTTP ${stCode}`;

  document.getElementById('det-time').textContent = `${req.responseSent?.durationMs || 0} ms`;
  document.getElementById('det-size').textContent = formatBytes(req.sizeBytes);

  // Overview Meta
  const metaList = document.getElementById('det-meta-list');
  metaList.innerHTML = [
    ['Request ID', req.id],
    ['Endpoint', `${req.endpointName} (/hook/${req.slug})`],
    ['Full URL', req.fullUrl],
    ['Client IP', req.clientIp],
    ['User-Agent', req.userAgent],
    ['Thời điểm nhận', new Date(req.createdAt).toLocaleString('vi-VN')]
  ].map(([k, v]) => `<div class="kv-row"><span class="kv-key">${esc(k)}</span><span class="kv-val">${esc(v)}</span></div>`).join('');

  const resSummary = document.getElementById('det-response-summary');
  const forwardInfo = Array.isArray(req.forwardResults) && req.forwardResults.length > 0
    ? req.forwardResults.map((f) => `${f.forwardedTo}: HTTP ${f.statusCode} (${f.durationMs}ms)`).join(' | ')
    : (req.forwardResult
        ? `HTTP ${req.forwardResult.statusCode} (${req.forwardResult.durationMs}ms)`
        : 'Không bật chuyển tiếp');
  resSummary.innerHTML = [
    ['Status trả về', `HTTP ${stCode} (${req.responseSent?.contentType})`],
    ['Độ trễ giả lập', `${req.responseSent?.delayMs || 0} ms`],
    ['Proxy Forward', forwardInfo],
    ['Body trả về', (req.responseSent?.body || '').slice(0, 180)]
  ].map(([k, v]) => `<div class="kv-row"><span class="kv-key">${esc(k)}</span><span class="kv-val">${esc(v)}</span></div>`).join('');

  // Decoded JWT & Base64 Tokens
  const decodedEl = document.getElementById('det-decoded-tokens');
  const jwts = req.decodedItems?.jwts || [];
  const b64s = req.decodedItems?.base64 || [];

  if (jwts.length === 0 && b64s.length === 0) {
    decodedEl.innerHTML = `<p class="meta-hint">Không phát hiện chuỗi JWT hoặc Base64 nào trong Headers, Query hay Body của gói tin này.</p>`;
  } else {
    const blocks = [];
    for (const j of jwts) {
      const expBadge = j.expStatus
        ? (j.expStatus.expired
            ? `<span class="mini-tag hmac-bad">Đã hết hạn (${esc(j.expStatus.expiresAt)})</span>`
            : `<span class="mini-tag hmac-ok">Còn hiệu lực (${Math.round(j.expStatus.remainingSeconds / 60)} phút)</span>`)
        : '';
      blocks.push(`
        <div class="token-card">
          <div class="card-header-row" style="margin-bottom:6px;">
            <h5>🪪 Phát hiện JWT tại <code>${esc(j.location)}</code> ${expBadge}</h5>
            <button class="btn btn-accent btn-xs" onclick="openInJwtStudio('${esc(j.raw)}')">🔐 Mở trong JWT Studio</button>
          </div>
          <div class="split-code">
            <div>
              <div class="meta-hint">Header</div>
              <pre class="code-block compact-code">${esc(JSON.stringify(j.header, null, 2))}</pre>
            </div>
            <div>
              <div class="meta-hint">Payload</div>
              <pre class="code-block compact-code">${esc(JSON.stringify(j.payload, null, 2))}</pre>
            </div>
          </div>
        </div>
      `);
    }
    for (const b of b64s) {
      blocks.push(`
        <div class="token-card">
          <h5>📦 Giải mã Base64 tại <code>${esc(b.location)}</code></h5>
          <div class="kv-row"><span class="kv-key">Chuỗi gốc</span><span class="kv-val">${esc(b.original)}</span></div>
          <div class="kv-row"><span class="kv-key">Sau giải mã</span><span class="kv-val" style="color:#4ade80;">${esc(b.decoded)}</span></div>
        </div>
      `);
    }
    decodedEl.innerHTML = blocks.join('');
  }

  // Query & Headers Tables
  const queryEntries = Object.entries(req.query || {});
  document.getElementById('det-query-table').innerHTML = queryEntries.length
    ? `<div class="kv-list">${queryEntries.map(([k, v]) => `<div class="kv-row"><span class="kv-key">${esc(k)}</span><span class="kv-val">${esc(v)}</span></div>`).join('')}</div>`
    : `<p class="meta-hint">Không có Query Parameters</p>`;

  const headerEntries = Object.entries(req.headers || {});
  document.getElementById('det-headers-table').innerHTML = `<div class="kv-list">${headerEntries.map(([k, v]) => `<div class="kv-row"><span class="kv-key">${esc(k)}</span><span class="kv-val">${esc(v)}</span></div>`).join('')}</div>`;

  // Body & Hex
  document.getElementById('det-body-format').textContent = `Định dạng: ${(req.bodyFormat || 'text').toUpperCase()} (${formatBytes(req.sizeBytes)})`;
  document.getElementById('det-body-pretty').textContent = req.parsedBody
    ? JSON.stringify(req.parsedBody, null, 2)
    : (req.rawBody || '(Body rỗng)');
  document.getElementById('det-body-hex').textContent = req.hexPreview || '(Trống)';

  // HMAC Tab
  const ep = state.endpoints.find((e) => e.slug === req.slug);
  const secretInput = document.getElementById('hmac-secret-input');
  secretInput.value = req.signatureAnalysis?.computed?.secretUsed || ep?.secret || 'whsec_demo_secret_2026';
  renderHmacResult(req.signatureAnalysis);

  // Codegen Tab
  document.getElementById('det-codegen-output').textContent = generateCodeSnippet(req, state.selectedCodeLang);
}

function renderHmacResult(sigAnalysis) {
  const box = document.getElementById('hmac-result-box');
  if (!sigAnalysis) {
    box.innerHTML = '';
    return;
  }
  const detectedEntries = Object.entries(sigAnalysis.detectedHeaders || {});
  const statusBanner = sigAnalysis.verified === true
    ? `<div class="token-card" style="border-color:#22c55e;"><h5>✅ Chữ ký Webhook HỢP LỆ (${esc(sigAnalysis.matchedRule)})</h5></div>`
    : sigAnalysis.verified === false
      ? `<div class="token-card" style="border-color:#f43f5e;"><h5>❌ Chữ ký Webhook KHÔNG KHỚP với Secret đã nhập!</h5></div>`
      : `<div class="token-card"><h5>ℹ️ Gói tin không đính kèm Header chữ ký chuẩn hoặc chưa cấu hình Secret</h5></div>`;

  const comp = sigAnalysis.computed;
  const computedHtml = comp
    ? `
      <div class="info-card" style="margin-top:10px;">
        <h4>Bảng Chữ Ký Tính Toán Từ Raw Body (Secret: <code>${esc(comp.secretUsed)}</code>)</h4>
        <div class="kv-list">
          <div class="kv-row"><span class="kv-key">HMAC-SHA256 (Hex)</span><span class="kv-val">${esc(comp.sha256Hex)}</span></div>
          <div class="kv-row"><span class="kv-key">GitHub / Hub Style</span><span class="kv-val">${esc(comp.sha256GitHub)}</span></div>
          <div class="kv-row"><span class="kv-key">HMAC-SHA256 (Base64)</span><span class="kv-val">${esc(comp.sha256Base64)}</span></div>
          <div class="kv-row"><span class="kv-key">HMAC-SHA1 (Hex)</span><span class="kv-val">${esc(comp.sha1Hex)}</span></div>
          <div class="kv-row"><span class="kv-key">HMAC-SHA512 (Hex)</span><span class="kv-val">${esc(comp.sha512Hex)}</span></div>
        </div>
      </div>
    `
    : '';

  const detectedHtml = detectedEntries.length
    ? `
      <div class="info-card" style="margin-top:10px;">
        <h4>Header Chữ Ký Phát Hiện Trong Request</h4>
        <div class="kv-list">
          ${detectedEntries.map(([k, v]) => `<div class="kv-row"><span class="kv-key">${esc(k)}</span><span class="kv-val">${esc(v)}</span></div>`).join('')}
        </div>
      </div>
    `
    : '';

  box.innerHTML = statusBanner + detectedHtml + computedHtml;
}

window.selectRequest = function (id) {
  state.selectedRequestId = id;
  renderRequestList();
  renderRequestDetail();
};

window.editEndpoint = function (id) {
  const ep = state.endpoints.find((e) => e.id === id);
  if (!ep) return;
  document.getElementById('ep-id').value = ep.id;
  document.getElementById('ep-name').value = ep.name;
  document.getElementById('ep-slug').value = ep.slug;
  document.getElementById('ep-status').value = ep.statusCode;
  document.getElementById('ep-content-type').value = ep.contentType;
  document.getElementById('ep-delay').value = ep.delayMs || 0;
  document.getElementById('ep-secret').value = ep.secret || '';
  const reqHmacEl = document.getElementById('ep-require-hmac');
  if (reqHmacEl) reqHmacEl.checked = Boolean(ep.requireValidHmac);
  document.getElementById('ep-forward').value = ep.forwardUrl || '';
  const notifyUrlEl = document.getElementById('ep-notify-url');
  if (notifyUrlEl) notifyUrlEl.value = ep.notifyWebhookUrl || '';
  const notifyAnomEl = document.getElementById('ep-notify-anomaly-only');
  if (notifyAnomEl) notifyAnomEl.checked = Boolean(ep.notifyOnlyOnAnomaly);
  document.getElementById('ep-body').value = ep.responseBody || '';
  showToast(`Đang chỉnh sửa endpoint /hook/${ep.slug}`);
};

window.deleteEndpoint = async function (id) {
  const res = await fetch(`/api/endpoints/${encodeURIComponent(id)}`, { method: 'DELETE' });
  const data = await res.json();
  if (data.ok) {
    state.endpoints = data.endpoints;
    renderEndpoints();
    showToast('Đã xóa endpoint');
  }
};

function switchMainTab(tabName) {
  document.querySelectorAll('.tab-btn').forEach((b) => b.classList.toggle('active', b.dataset.tab === tabName));
  document.querySelectorAll('.tab-panel').forEach((p) => p.classList.toggle('active', p.id === `tab-${tabName}`));
}

window.switchMainTab = switchMainTab;

window.triggerGuideSim = async function (scenario = 'payment') {
  await fetch('/api/simulate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scenario })
  });
  switchMainTab('inspector');
  showToast('⚡ Đã bắn gói tin mẫu và chuyển sang màn hình Bắt Gói Tin!');
};

// Web API Hunter Helpers
function renderHunterEndpointsTable() {
  const filter = (document.getElementById('hunter-filter-input')?.value || '').toLowerCase().trim();
  const tbody = document.getElementById('hunter-endpoints-tbody');
  const countEl = document.getElementById('hunter-ep-count');

  const items = state.hunterEndpoints
    .map((ep, idx) => ({ ...ep, idx }))
    .filter((ep) => {
      if (!filter) return true;
      return `${ep.method} ${ep.fullUrl} ${ep.category} ${ep.source}`.toLowerCase().includes(filter);
    });

  countEl.textContent = String(items.length);

  if (items.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:18px;">Không tìm thấy đường dẫn API nào khớp bộ lọc.</td></tr>`;
    return;
  }

  tbody.innerHTML = items.map((ep) => `
    <tr>
      <td><span class="method-badge ${esc(ep.method === 'WS' ? 'PATCH' : ep.method)}">${esc(ep.method)}</span></td>
      <td><code style="color:#7dd3fc;">${esc(ep.fullUrl)}</code></td>
      <td><span class="meta-tag">${esc(ep.category)}</span></td>
      <td><span class="normal-badge">${esc(ep.source)}</span></td>
      <td>
        <div class="btn-row">
          ${ep.method !== 'WS' ? `<button class="btn btn-accent btn-xs" onclick="quickTestDiscoveredApi(${ep.idx})">🚀 Gọi thử</button>` : ''}
          <button class="btn btn-secondary btn-xs" onclick="sendDiscoveredToReplay(${ep.idx})">🔁 Replay</button>
          <button class="btn btn-warning btn-xs" onclick="sendDiscoveredToFuzz(${ep.idx})">⚡ Fuzz</button>
        </div>
      </td>
    </tr>
  `).join('');
}

window.fillHunterSample = function (type) {
  const input = document.getElementById('hunter-url');
  if (type === 'demo') {
    input.value = `${state.serverOrigin}/demo-webapp`;
  } else {
    input.value = 'https://jsonplaceholder.typicode.com';
  }
  document.getElementById('btn-run-hunter').click();
};

window.quickTestDiscoveredApi = async function (idx) {
  const ep = state.hunterEndpoints[idx];
  if (!ep) return;
  showToast(`🚀 Đang gọi thử ${ep.method} ${ep.fullUrl}...`);
  const res = await fetch('/api/replay', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      method: ep.method === 'WS' ? 'GET' : ep.method,
      targetUrl: ep.fullUrl,
      headers: { 'Accept': 'application/json, text/plain, */*' },
      body: ep.method === 'POST' ? JSON.stringify({ test: true }) : ''
    })
  });
  const entry = await res.json();
  const repRes = entry.response || {};

  const box = document.getElementById('hunter-quicktest-box');
  box.classList.remove('hidden');
  document.getElementById('hunter-quicktest-url').textContent = `${ep.method} ${ep.fullUrl} (${repRes.durationMs || 0}ms)`;

  const stEl = document.getElementById('hunter-quicktest-status');
  stEl.className = `status-pill ${statusClass(repRes.statusCode)}`;
  stEl.textContent = repRes.error ? `ERR: ${repRes.error}` : `HTTP ${repRes.statusCode}`;

  let pretty = repRes.body || '';
  try {
    pretty = JSON.stringify(JSON.parse(pretty), null, 2);
  } catch {
    // keep raw
  }
  document.getElementById('hunter-quicktest-body').textContent = pretty.slice(0, 3000) || '(Body rỗng)';
};

window.sendDiscoveredToReplay = function (idx) {
  const ep = state.hunterEndpoints[idx];
  if (!ep) return;
  document.getElementById('replay-method').value = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(ep.method) ? ep.method : 'GET';
  document.getElementById('replay-url').value = ep.fullUrl;
  if (ep.requestHeaders && Object.keys(ep.requestHeaders).length > 0) {
    document.getElementById('replay-headers').value = formatHeadersForTextarea(ep.requestHeaders);
  } else {
    document.getElementById('replay-headers').value = 'Accept: application/json\nContent-Type: application/json';
  }
  document.getElementById('replay-body').value = ep.postData || (ep.method === 'POST' ? '{\n  "sample": true\n}' : '');
  switchMainTab('replay');
  showToast('🔁 Đã nạp API (kèm Header & Body thực tế) sang Replay Studio');
};

window.sendDiscoveredToFuzz = function (idx) {
  const ep = state.hunterEndpoints[idx];
  if (!ep) return;
  document.getElementById('fuzz-method').value = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(ep.method) ? ep.method : 'GET';
  const hasQuery = ep.fullUrl.includes('?');
  document.getElementById('fuzz-url').value = hasQuery ? `${ep.fullUrl}&fuzz={{FUZZ}}` : `${ep.fullUrl}?id={{FUZZ}}`;
  switchMainTab('fuzzer');
  showToast('⚡ Đã nạp API sang Fuzzer kèm biến {{FUZZ}}');
};

// Open a JWT string in JWT Studio
window.openInJwtStudio = function (rawToken) {
  const cleaned = String(rawToken || '').replace(/^Bearer\s+/i, '').trim();
  document.getElementById('jwt-raw-input').value = cleaned;
  decodeJwtIntoStudio(cleaned);
  switchMainTab('jwt');
  showToast('🔐 Đã nạp Token vào JWT Studio!');
};

function decodeJwtIntoStudio(rawToken) {
  const cleaned = String(rawToken || '').replace(/^Bearer\s+/i, '').trim();
  const parts = cleaned.split('.');
  if (parts.length < 2) {
    showToast('Chuỗi JWT không đúng định dạng!');
    return;
  }
  try {
    const pad = (s) => s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4);
    const header = JSON.parse(decodeURIComponent(escape(atob(pad(parts[0])))));
    const payload = JSON.parse(decodeURIComponent(escape(atob(pad(parts[1])))));
    document.getElementById('jwt-header-input').value = JSON.stringify(header, null, 2);
    document.getElementById('jwt-payload-input').value = JSON.stringify(payload, null, 2);
  } catch {
    showToast('Không thể giải mã Header/Payload của JWT này.');
  }
}

// Export list of requests/endpoints to Postman Collection v2.1 JSON file
function exportPostmanCollection(items, collectionName, filename) {
  if (!items || items.length === 0) {
    showToast('Chưa có dữ liệu nào để xuất file Postman!');
    return;
  }
  const postmanItems = items.map((item, i) => {
    const method = (item.method && item.method !== 'WS') ? item.method.toUpperCase() : 'GET';
    const rawUrl = item.fullUrl || `${state.serverOrigin}${item.url || '/'}`;
    const headersObj = item.headers || item.requestHeaders || {};
    const headerArr = Object.entries(headersObj)
      .filter(([k]) => !['host', 'content-length', 'connection'].includes(k.toLowerCase()))
      .map(([key, value]) => ({ key, value: String(value) }));

    const bodyRaw = item.rawBody || item.postData || '';
    return {
      name: `${method} ${item.url || item.rawPath || `#${i + 1}`}`,
      request: {
        method,
        header: headerArr,
        url: { raw: rawUrl },
        ...(bodyRaw && !['GET', 'HEAD'].includes(method)
          ? { body: { mode: 'raw', raw: bodyRaw } }
          : {})
      }
    };
  });

  const collection = {
    info: {
      name: collectionName,
      description: 'Exported from NetPulse — Webhook Inspector & API Hunter',
      schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json'
    },
    item: postmanItems
  };

  const blob = new Blob([JSON.stringify(collection, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
  showToast(`📦 Đã tải xuống ${filename} (${postmanItems.length} requests)!`);
}

// ============================================================================
// REPLAY EXECUTION HISTORY & SIDE-BY-SIDE DIFF VIEWER HELPERS
// ============================================================================
function renderAssertionResults(assertionResults) {
  const box = document.getElementById('replay-assertions-box');
  if (!box) return;
  if (!assertionResults || !assertionResults.total) {
    box.classList.add('hidden');
    return;
  }
  box.classList.remove('hidden');
  const allOk = assertionResults.allPassed;
  box.style.borderColor = allOk ? '#22c55e' : '#f43f5e';

  box.innerHTML = `
    <div class="card-header-row" style="margin-bottom:6px;">
      <h4>${allOk ? '✅ Kiểm Chứng Tự Động: PASS' : '❌ Kiểm Chứng Tự Động: FAIL'}</h4>
      <span class="status-pill ${allOk ? 'status-2xx' : 'status-5xx'}">
        Đạt ${assertionResults.passed}/${assertionResults.total} điều kiện
      </span>
    </div>
    <div class="kv-list">
      ${(assertionResults.items || []).map((item) => `
        <div class="kv-row">
          <span class="kv-key" style="color:${item.passed ? '#4ade80' : '#fda4af'}; font-weight:700;">
            ${item.passed ? '✓ PASS' : '✗ FAIL'} • ${esc(item.rule)}
          </span>
          <span class="kv-val">Thực tế: <code>${esc(item.actual)}</code> (Kỳ vọng: <code>${esc(item.expected)}</code>)</span>
        </div>
      `).join('')}
    </div>
  `;
}

function renderReplayHistory() {
  const listEl = document.getElementById('replay-history-list');
  const countEl = document.getElementById('replay-history-count');
  if (!listEl || !countEl) return;

  countEl.textContent = String(state.replays.length);
  populateDiffSelectors();

  if (state.replays.length === 0) {
    listEl.innerHTML = `<div class="empty-state small" style="padding:12px;"><p>Chưa có lịch sử bắn Replay nào.</p></div>`;
    return;
  }

  listEl.innerHTML = state.replays.map((rep) => {
    const st = rep.response?.statusCode || 0;
    const dur = rep.response?.durationMs || 0;
    const ar = rep.assertionResults;
    const assertBadge = ar && ar.total > 0
      ? (ar.allPassed
          ? `<span class="mini-tag hmac-ok">✓ ${ar.passed}/${ar.total}</span>`
          : `<span class="mini-tag hmac-bad">✗ ${ar.passed}/${ar.total}</span>`)
      : '';
    return `
      <div class="req-item" onclick="loadReplayHistoryItem('${esc(rep.id)}')">
        <div class="req-item-top">
          <div style="display:flex; align-items:center; gap:6px; min-width:0;">
            <span class="method-badge ${esc(rep.method)}">${esc(rep.method)}</span>
            <span class="req-item-path" title="${esc(rep.targetUrl)}">${esc(rep.targetUrl)}</span>
          </div>
          <div style="display:flex; align-items:center; gap:4px;">
            ${assertBadge}
            <span class="status-pill ${statusClass(st)}">${st || 'ERR'}</span>
          </div>
        </div>
        <div class="req-item-bottom" style="margin-top:4px;">
          <span>${dur} ms • ${formatBytes(rep.response?.sizeBytes || 0)} • ${formatTime(rep.createdAt)}</span>
          <span class="btn-row" onclick="event.stopPropagation();">
            <button class="btn btn-secondary btn-xs" onclick="pinReplayToDiff('${esc(rep.id)}', 'A')" title="Ghim lần bắn này làm Gói A">⚖️ A</button>
            <button class="btn btn-secondary btn-xs" onclick="pinReplayToDiff('${esc(rep.id)}', 'B')" title="So sánh lần bắn này với Gói A">⚖️ B</button>
          </span>
        </div>
      </div>
    `;
  }).join('');
}

window.loadReplayHistoryItem = function (id) {
  const rep = state.replays.find((r) => r.id === id);
  if (!rep) return;
  document.getElementById('replay-method').value = rep.method || 'POST';
  document.getElementById('replay-url').value = rep.targetUrl || '';
  document.getElementById('replay-headers').value = formatHeadersForTextarea(rep.headers || {});
  document.getElementById('replay-body').value = rep.body || '';

  const repRes = rep.response || {};
  document.getElementById('replay-empty').classList.add('hidden');
  document.getElementById('replay-result').classList.remove('hidden');
  renderAssertionResults(rep.assertionResults);

  const stBadge = document.getElementById('rep-status-badge');
  stBadge.className = `status-pill ${statusClass(repRes.statusCode)}`;
  stBadge.textContent = repRes.error ? `ERR: ${repRes.error}` : `HTTP ${repRes.statusCode} ${repRes.statusMessage || ''}`;

  document.getElementById('rep-time-badge').textContent = `${repRes.durationMs || 0} ms`;
  document.getElementById('rep-size-badge').textContent = formatBytes(repRes.sizeBytes || 0);
  document.getElementById('rep-res-headers').textContent = JSON.stringify(repRes.headers || {}, null, 2);

  let formattedBody = repRes.body || '';
  try {
    formattedBody = JSON.stringify(JSON.parse(formattedBody), null, 2);
  } catch {
    // keep raw
  }
  document.getElementById('rep-res-body').textContent = formattedBody || '(Body trống)';
  showToast('📜 Đã nạp lại lần bắn từ Lịch sử Replay!');
};

window.pinReplayToDiff = function (id, slot) {
  if (slot === 'A') {
    state.diffPinA = id;
    populateDiffSelectors();
    showToast('⚖️ Đã ghim lần bắn Replay làm Gói A!');
  } else {
    state.diffPinB = id;
    populateDiffSelectors();
    switchMainTab('diff');
    runRequestDiff();
    showToast('⚖️ Đang so sánh lần bắn Replay (Gói B) với Gói A!');
  }
};

function getDiffComparableItems() {
  const webhookItems = state.requests.map((r, i) => ({
    ...r,
    _diffLabel: `[Webhook #${i + 1}] ${r.method} ${r.url} (${formatBytes(r.sizeBytes)} • ${formatTime(r.createdAt)})`
  }));

  const replayItems = state.replays.map((rep, i) => {
    const rawBody = rep.response?.body || rep.body || '';
    let parsedBody = null;
    try {
      parsedBody = JSON.parse(rawBody);
    } catch {
      parsedBody = null;
    }
    return {
      id: rep.id,
      method: rep.method,
      url: rep.targetUrl,
      sizeBytes: rep.response?.sizeBytes || 0,
      createdAt: rep.createdAt,
      clientIp: 'Replay Studio',
      responseSent: {
        statusCode: rep.response?.statusCode || 0,
        durationMs: rep.response?.durationMs || 0
      },
      headers: { ...(rep.headers || {}), ...(rep.response?.headers || {}) },
      query: {},
      rawBody,
      parsedBody,
      _diffLabel: `[Replay #${i + 1}] ${rep.method} ${rep.targetUrl} (HTTP ${rep.response?.statusCode || 0} • ${formatTime(rep.createdAt)})`
    };
  });

  return [...webhookItems, ...replayItems];
}

function populateDiffSelectors() {
  const selA = document.getElementById('diff-select-a');
  const selB = document.getElementById('diff-select-b');
  if (!selA || !selB) return;

  const allItems = getDiffComparableItems();
  const optsHtml = allItems.map((item) => {
    return `<option value="${esc(item.id)}">${esc(item._diffLabel)}</option>`;
  }).join('');

  selA.innerHTML = `<option value="">-- Chọn Gói tin A --</option>` + optsHtml;
  selB.innerHTML = `<option value="">-- Chọn Gói tin B --</option>` + optsHtml;

  if (state.diffPinA && allItems.some((r) => r.id === state.diffPinA)) {
    selA.value = state.diffPinA;
  } else if (allItems[1]) {
    selA.value = allItems[1].id;
    state.diffPinA = allItems[1].id;
  } else if (allItems[0]) {
    selA.value = allItems[0].id;
    state.diffPinA = allItems[0].id;
  }

  if (state.diffPinB && allItems.some((r) => r.id === state.diffPinB)) {
    selB.value = state.diffPinB;
  } else if (allItems[0]) {
    selB.value = allItems[0].id;
    state.diffPinB = allItems[0].id;
  }
}

function flattenJsonForDiff(obj, prefix = '', out = {}) {
  if (!obj || typeof obj !== 'object') return out;
  for (const [k, v] of Object.entries(obj)) {
    const pathKey = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      flattenJsonForDiff(v, pathKey, out);
    } else {
      out[pathKey] = JSON.stringify(v);
    }
  }
  return out;
}

function computeLineDiff(textA, textB) {
  const linesA = String(textA || '').split('\n');
  const linesB = String(textB || '').split('\n');
  const m = linesA.length;
  const n = linesB.length;

  // LCS matrix (capped at 400 lines for instant UI speed)
  if (m > 400 || n > 400) {
    return [
      ...linesA.map((l) => ({ type: 'del', text: `- ${l}` })),
      ...linesB.map((l) => ({ type: 'add', text: `+ ${l}` }))
    ];
  }

  const dp = Array.from({ length: m + 1 }, () => new Uint16Array(n + 1));
  for (let i = m - 1; i >= 0; i--) {
    for (let j = n - 1; j >= 0; j--) {
      if (linesA[i] === linesB[j]) {
        dp[i][j] = dp[i + 1][j + 1] + 1;
      } else {
        dp[i][j] = Math.max(dp[i + 1][j], dp[i][j + 1]);
      }
    }
  }

  const out = [];
  let i = 0;
  let j = 0;
  while (i < m && j < n) {
    if (linesA[i] === linesB[j]) {
      out.push({ type: 'same', text: `  ${linesA[i]}` });
      i++;
      j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      out.push({ type: 'del', text: `- ${linesA[i]}` });
      i++;
    } else {
      out.push({ type: 'add', text: `+ ${linesB[j]}` });
      j++;
    }
  }
  while (i < m) {
    out.push({ type: 'del', text: `- ${linesA[i++]}` });
  }
  while (j < n) {
    out.push({ type: 'add', text: `+ ${linesB[j++]}` });
  }
  return out;
}

function runRequestDiff() {
  const idA = document.getElementById('diff-select-a').value;
  const idB = document.getElementById('diff-select-b').value;
  state.diffPinA = idA;
  state.diffPinB = idB;

  const allItems = getDiffComparableItems();
  const reqA = allItems.find((r) => r.id === idA);
  const reqB = allItems.find((r) => r.id === idB);

  const emptyEl = document.getElementById('diff-empty-state');
  const resultsEl = document.getElementById('diff-results-area');

  if (!reqA || !reqB) {
    emptyEl.classList.remove('hidden');
    resultsEl.classList.add('hidden');
    return;
  }

  emptyEl.classList.add('hidden');
  resultsEl.classList.remove('hidden');

  // 1. Meta summary
  const sizeDelta = (reqB.sizeBytes || 0) - (reqA.sizeBytes || 0);
  const timeDelta = Math.round(((reqB.responseSent?.durationMs || 0) - (reqA.responseSent?.durationMs || 0)) * 100) / 100;

  document.getElementById('diff-meta-summary').innerHTML = [
    ['Method', `${reqA.method}  →  ${reqB.method}`],
    ['Đường dẫn URL', `${reqA.url}  →  ${reqB.url}`],
    ['HTTP Status', `${reqA.responseSent?.statusCode || 200}  →  ${reqB.responseSent?.statusCode || 200}`],
    ['Kích thước Body', `${reqA.sizeBytes} B  →  ${reqB.sizeBytes} B (${sizeDelta >= 0 ? '+' : ''}${sizeDelta} B)`],
    ['Thời gian xử lý', `${reqA.responseSent?.durationMs || 0} ms  →  ${reqB.responseSent?.durationMs || 0} ms (${timeDelta >= 0 ? '+' : ''}${timeDelta} ms)`],
    ['Client IP', `${reqA.clientIp}  →  ${reqB.clientIp}`]
  ].map(([k, v]) => `<div class="kv-row"><span class="kv-key">${esc(k)}</span><span class="kv-val">${esc(v)}</span></div>`).join('');

  // 2. JSON Fields Diff
  const flatA = reqA.parsedBody && typeof reqA.parsedBody === 'object' ? flattenJsonForDiff(reqA.parsedBody) : {};
  const flatB = reqB.parsedBody && typeof reqB.parsedBody === 'object' ? flattenJsonForDiff(reqB.parsedBody) : {};
  const allJsonKeys = Array.from(new Set([...Object.keys(flatA), ...Object.keys(flatB)]));
  const jsonChanges = [];

  for (const k of allJsonKeys) {
    if (!(k in flatA)) {
      jsonChanges.push({ key: k, status: 'add', text: `Thêm mới: ${flatB[k]}` });
    } else if (!(k in flatB)) {
      jsonChanges.push({ key: k, status: 'del', text: `Đã xóa (A: ${flatA[k]})` });
    } else if (flatA[k] !== flatB[k]) {
      jsonChanges.push({ key: k, status: 'mod', text: `${flatA[k]}  →  ${flatB[k]}` });
    }
  }

  document.getElementById('diff-json-fields').innerHTML = jsonChanges.length
    ? jsonChanges.map((c) => {
        const color = c.status === 'add' ? '#4ade80' : c.status === 'del' ? '#fda4af' : '#fbbf24';
        return `<div class="kv-row"><span class="kv-key">${esc(c.key)}</span><span class="kv-val" style="color:${color};">${esc(c.text)}</span></div>`;
      }).join('')
    : `<p class="meta-hint">Không có trường JSON nào bị thay đổi giữa Gói A và Gói B.</p>`;

  // 3. Headers & Query Diff
  const hA = { ...(reqA.headers || {}) };
  const hB = { ...(reqB.headers || {}) };
  for (const [qk, qv] of Object.entries(reqA.query || {})) hA[`?${qk}`] = qv;
  for (const [qk, qv] of Object.entries(reqB.query || {})) hB[`?${qk}`] = qv;

  const allHKeys = Array.from(new Set([...Object.keys(hA), ...Object.keys(hB)]));
  const hDiffs = [];
  for (const k of allHKeys) {
    if (['content-length', 'connection'].includes(k.toLowerCase())) continue;
    if (!(k in hA)) {
      hDiffs.push(`<div class="kv-row"><span class="kv-key" style="color:#4ade80;">+ ${esc(k)}</span><span class="kv-val" style="color:#4ade80;">${esc(hB[k])}</span></div>`);
    } else if (!(k in hB)) {
      hDiffs.push(`<div class="kv-row"><span class="kv-key" style="color:#fda4af;">- ${esc(k)}</span><span class="kv-val" style="color:#fda4af;">${esc(hA[k])}</span></div>`);
    } else if (String(hA[k]) !== String(hB[k])) {
      hDiffs.push(`<div class="kv-row"><span class="kv-key" style="color:#fbbf24;">~ ${esc(k)}</span><span class="kv-val"><span style="color:#fda4af;">${esc(hA[k])}</span>  →  <span style="color:#4ade80;">${esc(hB[k])}</span></span></div>`);
    }
  }
  document.getElementById('diff-headers-count').textContent = String(hDiffs.length);
  document.getElementById('diff-headers-box').innerHTML = hDiffs.length
    ? hDiffs.join('')
    : `<p class="meta-hint">Toàn bộ Headers và Query Parameters giống hệt nhau.</p>`;

  // 4. Line-by-Line Body Diff
  const bodyStrA = reqA.parsedBody ? JSON.stringify(reqA.parsedBody, null, 2) : (reqA.rawBody || '');
  const bodyStrB = reqB.parsedBody ? JSON.stringify(reqB.parsedBody, null, 2) : (reqB.rawBody || '');

  document.getElementById('diff-body-a').textContent = bodyStrA || '(Rỗng)';

  const diffLines = computeLineDiff(bodyStrA, bodyStrB);
  document.getElementById('diff-body-unified').innerHTML = diffLines
    .map((line) => `<div class="diff-line ${line.type}">${esc(line.text)}</div>`)
    .join('');
}

// Initialize Fuzz Presets
function loadFuzzPreset(presetKey) {
  const preset = state.fuzzPresets[presetKey];
  if (!preset) return;
  document.getElementById('fuzz-payload-list').value = preset.payloads.join('\n');
}

// Setup Event Listeners
function setupEventListeners() {
  // Main tabs
  document.querySelectorAll('.tab-btn').forEach((btn) => {
    btn.addEventListener('click', () => switchMainTab(btn.dataset.tab));
  });

  // Sub-tabs in Inspector
  document.querySelectorAll('.sub-tab-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const target = btn.dataset.subtab;
      document.querySelectorAll('.sub-tab-btn').forEach((b) => b.classList.toggle('active', b.dataset.subtab === target));
      document.querySelectorAll('.sub-tab-content').forEach((c) => c.classList.toggle('active', c.id === `subtab-${target}`));
    });
  });

  // Active endpoint selector
  document.getElementById('active-endpoint-select').addEventListener('change', (e) => {
    state.activeEndpointSlug = e.target.value;
    updateActiveEndpointBanner();
    renderRequestList();
  });

  // Copy active webhook URL
  document.getElementById('btn-copy-url').addEventListener('click', () => {
    const url = document.getElementById('active-webhook-url').textContent;
    navigator.clipboard.writeText(url);
    showToast('📋 Đã copy Local URL!');
  });

  // Copy Public Tunnel URL
  document.getElementById('btn-copy-public-url').addEventListener('click', () => {
    const url = document.getElementById('active-public-webhook-url').textContent;
    navigator.clipboard.writeText(url);
    showToast('🌍 Đã copy Public Internet Webhook URL!');
  });

  // Toggle Public Tunnel On/Off
  document.getElementById('btn-toggle-tunnel').addEventListener('click', async () => {
    const btn = document.getElementById('btn-toggle-tunnel');
    if (state.tunnel && state.tunnel.active) {
      btn.disabled = true;
      await fetch('/api/tunnel/stop', { method: 'POST' });
      state.tunnel = { active: false, status: 'stopped', publicBaseUrl: null };
      updateActiveEndpointBanner();
      btn.disabled = false;
      showToast('🛑 Đã đóng đường hầm Public Tunnel');
      return;
    }

    const provider = document.getElementById('tunnel-provider-select').value || 'ngrok';
    btn.disabled = true;
    btn.textContent = `⏳ Đang bật ${provider}...`;
    try {
      const res = await fetch('/api/tunnel/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider })
      }).then((r) => r.json());

      state.tunnel = res.tunnel || { active: false, status: 'error' };
      updateActiveEndpointBanner();
      if (state.tunnel.active && state.tunnel.publicBaseUrl) {
        showToast(`🌍 Đã mở Public Tunnel: ${state.tunnel.publicBaseUrl}`);
      } else {
        showToast(`⚠️ ${state.tunnel.error || 'Không thể mở Tunnel. Hãy thử đổi sang localhost.run!'}`);
      }
    } finally {
      btn.disabled = false;
    }
  });

  // Pin Diff A & B from Inspector Detail
  document.getElementById('btn-pin-diff-a').addEventListener('click', () => {
    if (!state.selectedRequestId) return;
    state.diffPinA = state.selectedRequestId;
    populateDiffSelectors();
    showToast('⚖️ Đã chọn gói tin này làm Gói A (Gốc)!');
  });

  document.getElementById('btn-pin-diff-b').addEventListener('click', () => {
    if (!state.selectedRequestId) return;
    state.diffPinB = state.selectedRequestId;
    populateDiffSelectors();
    switchMainTab('diff');
    runRequestDiff();
    showToast('⚖️ Đang so sánh Gói A và Gói B!');
  });

  // Diff Viewer tab controls
  document.getElementById('diff-select-a').addEventListener('change', runRequestDiff);
  document.getElementById('diff-select-b').addEventListener('change', runRequestDiff);
  document.getElementById('btn-diff-run').addEventListener('click', runRequestDiff);
  document.getElementById('btn-diff-swap').addEventListener('click', () => {
    const selA = document.getElementById('diff-select-a');
    const selB = document.getElementById('diff-select-b');
    const tmp = selA.value;
    selA.value = selB.value;
    selB.value = tmp;
    runRequestDiff();
    showToast('🔄 Đã đảo chiều Gói A ↔ Gói B');
  });

  // Simulation buttons
  document.querySelectorAll('.btn-sim').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const scenario = btn.dataset.sim;
      btn.disabled = true;
      try {
        await fetch('/api/simulate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ scenario })
        });
        switchMainTab('inspector');
        showToast('⚡ Đã bắn gói tin mẫu thành công!');
      } finally {
        btn.disabled = false;
      }
    });
  });

  // Pause/Resume Live Stream
  document.getElementById('btn-toggle-pause').addEventListener('click', () => {
    state.streamPaused = !state.streamPaused;
    const badge = document.getElementById('sse-indicator');
    const text = document.getElementById('sse-text');
    const btn = document.getElementById('btn-toggle-pause');
    if (state.streamPaused) {
      badge.classList.add('paused');
      text.textContent = 'Đã tạm dừng';
      btn.textContent = '▶ Tiếp tục';
    } else {
      badge.classList.remove('paused');
      text.textContent = 'Live Stream';
      btn.textContent = '⏸ Tạm dừng';
    }
  });

  // Search & filter requests
  document.getElementById('search-requests').addEventListener('input', renderRequestList);
  document.getElementById('filter-method').addEventListener('change', renderRequestList);

  // Clear requests
  document.getElementById('btn-clear-requests').addEventListener('click', async () => {
    const slugQuery = state.activeEndpointSlug ? `?slug=${encodeURIComponent(state.activeEndpointSlug)}` : '';
    const res = await fetch(`/api/requests${slugQuery}`, { method: 'DELETE' });
    const data = await res.json();
    state.requests = data.requests || [];
    state.selectedRequestId = state.requests[0]?.id || null;
    renderRequestList();
    renderRequestDetail();
    showToast('🗑️ Đã xóa danh sách gói tin');
  });

  // Delete single request
  document.getElementById('btn-delete-req').addEventListener('click', async () => {
    if (!state.selectedRequestId) return;
    const id = state.selectedRequestId;
    await fetch(`/api/requests/${encodeURIComponent(id)}`, { method: 'DELETE' });
    state.requests = state.requests.filter((r) => r.id !== id);
    state.selectedRequestId = state.requests[0]?.id || null;
    renderRequestList();
    renderRequestDetail();
    showToast('Đã xóa gói tin');
  });

  // Copy raw body
  document.getElementById('btn-copy-body').addEventListener('click', () => {
    const req = state.requests.find((r) => r.id === state.selectedRequestId);
    if (!req) return;
    navigator.clipboard.writeText(req.rawBody || '');
    showToast('📋 Đã copy Raw Body!');
  });

  // Verify HMAC with custom secret
  document.getElementById('btn-verify-hmac').addEventListener('click', async () => {
    const req = state.requests.find((r) => r.id === state.selectedRequestId);
    if (!req) return;
    const secret = document.getElementById('hmac-secret-input').value.trim();
    const res = await fetch('/api/hmac-verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        rawBody: req.rawBody || '',
        secret,
        headers: req.headers || {}
      })
    });
    const result = await res.json();
    req.signatureAnalysis = result;
    renderHmacResult(result);
    renderRequestList();
    showToast('🔐 Đã cập nhật kết quả kiểm tra HMAC');
  });

  // Codegen language switch
  document.querySelectorAll('[data-lang]').forEach((btn) => {
    btn.addEventListener('click', () => {
      state.selectedCodeLang = btn.dataset.lang;
      document.querySelectorAll('[data-lang]').forEach((b) => b.classList.toggle('active', b.dataset.lang === state.selectedCodeLang));
      const req = state.requests.find((r) => r.id === state.selectedRequestId);
      if (req) {
        document.getElementById('det-codegen-output').textContent = generateCodeSnippet(req, state.selectedCodeLang);
      }
    });
  });

  document.getElementById('btn-copy-codegen').addEventListener('click', () => {
    const code = document.getElementById('det-codegen-output').textContent;
    navigator.clipboard.writeText(code);
    showToast('📋 Đã copy đoạn code!');
  });

  // Push selected request to Replay Studio
  document.getElementById('btn-send-to-replay').addEventListener('click', () => {
    const req = state.requests.find((r) => r.id === state.selectedRequestId);
    if (!req) return;
    document.getElementById('replay-method').value = req.method || 'POST';
    document.getElementById('replay-url').value = req.fullUrl || `${state.serverOrigin}${req.url}`;
    document.getElementById('replay-headers').value = formatHeadersForTextarea(req.headers);
    document.getElementById('replay-body').value = req.parsedBody
      ? JSON.stringify(req.parsedBody, null, 2)
      : (req.rawBody || '');
    switchMainTab('replay');
    showToast('🔁 Đã nạp gói tin sang Replay Studio');
  });

  // Push selected request to API Fuzzer
  document.getElementById('btn-send-to-fuzzer').addEventListener('click', () => {
    const req = state.requests.find((r) => r.id === state.selectedRequestId);
    if (!req) return;
    document.getElementById('fuzz-method').value = req.method || 'POST';
    document.getElementById('fuzz-url').value = req.fullUrl || `${state.serverOrigin}${req.url}`;
    document.getElementById('fuzz-headers').value = formatHeadersForTextarea(req.headers);
    if (req.parsedBody && typeof req.parsedBody === 'object') {
      const clone = JSON.parse(JSON.stringify(req.parsedBody));
      const keys = Object.keys(clone);
      if (keys.length > 0) {
        clone[keys[0]] = '{{FUZZ}}';
      }
      document.getElementById('fuzz-body').value = JSON.stringify(clone, null, 2);
    } else {
      document.getElementById('fuzz-body').value = (req.rawBody || '') + '{{FUZZ}}';
    }
    switchMainTab('fuzzer');
    showToast('⚡ Đã nạp gói tin sang API Fuzzer (chèn sẵn {{FUZZ}})');
  });

  // Replay Studio Controls
  document.getElementById('btn-replay-fill-local').addEventListener('click', () => {
    document.getElementById('replay-url').value = document.getElementById('active-webhook-url').textContent;
  });

  // 1-Click Import cURL into Replay or Fuzzer
  async function parseCurlAndFill(targetMode) {
    const rawCurl = document.getElementById('curl-import-input').value.trim();
    if (!rawCurl) {
      showToast('Vui lòng dán lệnh cURL vào ô trước!');
      return;
    }
    const res = await fetch('/api/parse-curl', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ curl: rawCurl })
    }).then((r) => r.json());

    if (!res.ok) {
      showToast(`❌ ${res.error || 'Không thể phân tích lệnh cURL'}`);
      return;
    }

    const method = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(res.method) ? res.method : 'POST';
    if (targetMode === 'replay') {
      document.getElementById('replay-method').value = method;
      document.getElementById('replay-url').value = res.targetUrl;
      document.getElementById('replay-headers').value = formatHeadersForTextarea(res.headers || {});
      let bodyText = res.body || '';
      try {
        bodyText = JSON.stringify(JSON.parse(bodyText), null, 2);
      } catch {
        // keep raw
      }
      document.getElementById('replay-body').value = bodyText;
      showToast(`📥 Đã bóc tách lệnh cURL (${method} ${res.targetUrl}) vào Replay Studio!`);
    } else {
      document.getElementById('fuzz-method').value = method;
      const hasQuery = res.targetUrl.includes('?');
      document.getElementById('fuzz-url').value = hasQuery && !res.body ? `${res.targetUrl}&fuzz={{FUZZ}}` : res.targetUrl;
      document.getElementById('fuzz-headers').value = formatHeadersForTextarea(res.headers || {});
      if (res.body) {
        try {
          const parsed = JSON.parse(res.body);
          const keys = Object.keys(parsed);
          if (keys.length > 0) parsed[keys[0]] = '{{FUZZ}}';
          document.getElementById('fuzz-body').value = JSON.stringify(parsed, null, 2);
        } catch {
          document.getElementById('fuzz-body').value = `${res.body}{{FUZZ}}`;
        }
      }
      switchMainTab('fuzzer');
      showToast('⚡ Đã bóc tách lệnh cURL sang API Fuzzer (kèm biến {{FUZZ}})!');
    }
  }

  document.getElementById('btn-parse-curl-replay').addEventListener('click', () => parseCurlAndFill('replay'));
  document.getElementById('btn-parse-curl-fuzzer').addEventListener('click', () => parseCurlAndFill('fuzzer'));

  // Clear Replay History
  document.getElementById('btn-clear-replays').addEventListener('click', async () => {
    await fetch('/api/replays', { method: 'DELETE' });
    state.replays = [];
    renderReplayHistory();
    showToast('🗑️ Đã xóa lịch sử bắn Replay');
  });

  // Security & CORS Auditor in Replay Studio
  document.getElementById('btn-audit-security').addEventListener('click', async () => {
    const btn = document.getElementById('btn-audit-security');
    const method = document.getElementById('replay-method').value;
    const targetUrl = document.getElementById('replay-url').value.trim();
    const headers = parseHeadersInput(document.getElementById('replay-headers').value);
    const body = document.getElementById('replay-body').value;

    if (!targetUrl) {
      showToast('Vui lòng nhập URL đích trước khi quét bảo mật!');
      return;
    }

    btn.disabled = true;
    btn.textContent = '⏳ Đang quét...';
    try {
      const res = await fetch('/api/security-audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ method, targetUrl, headers, body })
      }).then((r) => r.json());

      const box = document.getElementById('replay-security-box');
      document.getElementById('replay-empty').classList.add('hidden');
      box.classList.remove('hidden');

      if (!res.ok) {
        box.innerHTML = `<p style="color:#fda4af;">❌ Lỗi quét bảo mật: ${esc(res.error)}</p>`;
        return;
      }

      const gradeColor = res.score >= 80 ? '#4ade80' : res.score >= 60 ? '#fbbf24' : '#f43f5e';
      const sevColors = {
        critical: '#f43f5e',
        high: '#fb7185',
        medium: '#fbbf24',
        low: '#38bdf8',
        pass: '#4ade80',
        ok: '#4ade80'
      };

      box.innerHTML = `
        <div class="card-header-row" style="margin-bottom:8px;">
          <h4>🛡️ Báo Cáo Kiểm Toán Bảo Mật &amp; CORS</h4>
          <span class="status-pill" style="background:rgba(15,23,42,0.9); color:${gradeColor}; border:1px solid ${gradeColor}; font-size:13px;">
            Điểm: ${res.score}/100 (Hạng ${esc(res.grade)})
          </span>
        </div>
        <div class="kv-list" style="margin-bottom:10px;">
          <div class="kv-row"><span class="kv-key">Access-Control-Allow-Origin</span><span class="kv-val">${esc(res.corsHeaders?.allowOrigin || '(Không trả về)')}</span></div>
          <div class="kv-row"><span class="kv-key">Access-Control-Allow-Credentials</span><span class="kv-val">${esc(res.corsHeaders?.allowCredentials || '(Không trả về)')}</span></div>
        </div>
        <div style="display:flex; flex-direction:column; gap:6px;">
          ${(res.findings || []).map((f) => {
            const sevKey = String(f.severity || '').toLowerCase();
            return `
            <div style="padding:8px 10px; border-radius:6px; background:#090e1a; border-left:3px solid ${sevColors[sevKey] || '#94a3b8'};">
              <div style="font-weight:700; font-size:12.5px; color:${sevColors[sevKey] || '#e2e8f0'};">[${esc(String(f.severity || '').toUpperCase())}] ${esc(f.title)}</div>
              <div style="font-size:12px; color:var(--text-muted); margin-top:2px;">${esc(f.detail)}</div>
            </div>
          `;
          }).join('')}
        </div>
      `;
      showToast(`🛡️ Hoàn tất quét Bảo mật & CORS: ${res.score}/100 (Hạng ${res.grade})`);
    } finally {
      btn.disabled = false;
      btn.textContent = '🛡️ Quét Bảo Mật & CORS';
    }
  });

  document.getElementById('btn-format-replay-json').addEventListener('click', () => {
    const el = document.getElementById('replay-body');
    try {
      el.value = JSON.stringify(JSON.parse(el.value), null, 2);
    } catch {
      showToast('Nội dung Body không phải JSON hợp lệ');
    }
  });

  // Save Environment Variables ({{BASE_URL}}, {{API_TOKEN}})
  document.getElementById('btn-save-env-vars').addEventListener('click', async () => {
    const envVars = parseEnvVarsInput(document.getElementById('env-vars-input').value);
    const res = await fetch('/api/env', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ envVars })
    }).then((r) => r.json());
    if (res.ok) {
      state.envVars = res.envVars || {};
      document.getElementById('env-vars-input').value = formatEnvVarsForTextarea(state.envVars);
      showToast(`🌐 Đã lưu ${Object.keys(state.envVars).length} biến môi trường vào data/store.json!`);
    }
  });

  document.getElementById('btn-use-env-url').addEventListener('click', () => {
    document.getElementById('replay-url').value = '{{BASE_URL}}/hook/{{WEBHOOK_SLUG}}';
    showToast('🔗 Đã chèn mẫu {{BASE_URL}}/hook/{{WEBHOOK_SLUG}} vào URL Replay!');
  });

  document.getElementById('btn-execute-replay').addEventListener('click', async () => {
    const btn = document.getElementById('btn-execute-replay');
    const method = document.getElementById('replay-method').value;
    const targetUrl = document.getElementById('replay-url').value.trim();
    const headers = parseHeadersInput(document.getElementById('replay-headers').value);
    const body = document.getElementById('replay-body').value;
    const assertions = (document.getElementById('replay-assertions')?.value || '')
      .split('\n')
      .map((s) => s.trim())
      .filter(Boolean);

    if (!targetUrl) {
      showToast('Vui lòng nhập URL đích!');
      return;
    }

    btn.disabled = true;
    btn.textContent = '⏳ Đang bắn...';
    try {
      const res = await fetch('/api/replay', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ method, targetUrl, headers, body, assertions })
      });
      const entry = await res.json();
      const repRes = entry.response || {};

      state.replays.unshift(entry);
      if (state.replays.length > 50) state.replays.length = 50;
      renderReplayHistory();
      renderAssertionResults(entry.assertionResults);

      document.getElementById('replay-empty').classList.add('hidden');
      document.getElementById('replay-result').classList.remove('hidden');

      const stBadge = document.getElementById('rep-status-badge');
      stBadge.className = `status-pill ${statusClass(repRes.statusCode)}`;
      stBadge.textContent = repRes.error ? `ERR: ${repRes.error}` : `HTTP ${repRes.statusCode} ${repRes.statusMessage || ''}`;

      document.getElementById('rep-time-badge').textContent = `${repRes.durationMs || 0} ms`;
      document.getElementById('rep-size-badge').textContent = formatBytes(repRes.sizeBytes || 0);
      document.getElementById('rep-res-headers').textContent = JSON.stringify(repRes.headers || {}, null, 2);

      let formattedBody = repRes.body || '';
      try {
        formattedBody = JSON.stringify(JSON.parse(formattedBody), null, 2);
      } catch {
        // leave as raw text
      }
      document.getElementById('rep-res-body').textContent = formattedBody || '(Body trống)';
      showToast('🚀 Đã nhận phản hồi Replay!');
    } finally {
      btn.disabled = false;
      btn.textContent = '🚀 Bắn Request';
    }
  });

  // Fuzzer Controls
  document.getElementById('fuzz-preset-select').addEventListener('change', (e) => {
    loadFuzzPreset(e.target.value);
  });

  document.getElementById('btn-start-fuzz').addEventListener('click', async () => {
    const btn = document.getElementById('btn-start-fuzz');
    const method = document.getElementById('fuzz-method').value;
    const targetUrl = document.getElementById('fuzz-url').value.trim();
    const headers = parseHeadersInput(document.getElementById('fuzz-headers').value);
    const body = document.getElementById('fuzz-body').value;
    const concurrency = Number(document.getElementById('fuzz-concurrency').value) || 4;
    const delayMs = Number(document.getElementById('fuzz-delay').value) || 0;
    const payloads = document.getElementById('fuzz-payload-list').value
      .split('\n')
      .filter((line) => line.length > 0);

    if (!targetUrl) {
      showToast('Vui lòng nhập URL mục tiêu cho Fuzzer!');
      return;
    }

    btn.disabled = true;
    btn.textContent = '⏳ Đang chạy chiến dịch Fuzzing...';
    try {
      const res = await fetch('/api/fuzz', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ method, targetUrl, headers, body, payloads, concurrency, delayMs })
      });
      const data = await res.json();
      if (data.error) {
        showToast(data.error);
        return;
      }

      document.getElementById('fuzz-empty').classList.add('hidden');
      document.getElementById('fuzz-results-wrap').classList.remove('hidden');

      document.getElementById('fuzz-summary-badges').innerHTML = `
        <span class="meta-tag">Baseline: HTTP ${data.baseline.statusCode} (${data.baseline.sizeBytes}B, ${data.baseline.durationMs}ms)</span>
        <span class="status-pill ${data.anomalyCount > 0 ? 'status-5xx' : 'status-2xx'}">
          Phát hiện ${data.anomalyCount}/${data.total} dị thường
        </span>
      `;

      const tbody = document.getElementById('fuzz-results-tbody');
      tbody.innerHTML = data.results.map((r, idx) => `
        <tr class="${r.isAnomaly ? 'anomaly-row' : ''}" data-idx="${idx}">
          <td>${r.index}</td>
          <td><code>${esc(r.payload)}</code></td>
          <td><span class="status-pill ${statusClass(r.statusCode)}">${r.statusCode || 'ERR'}</span></td>
          <td>${r.durationMs} ms</td>
          <td>${r.sizeBytes} B</td>
          <td>
            ${r.isAnomaly
              ? r.anomalies.map((a) => `<span class="anomaly-badge">⚠️ ${esc(a)}</span>`).join('')
              : `<span class="normal-badge">Bình thường</span>`
            }
          </td>
        </tr>
      `).join('');

      tbody.querySelectorAll('tr').forEach((row) => {
        row.addEventListener('click', () => {
          const item = data.results[Number(row.dataset.idx)];
          if (!item) return;
          document.getElementById('fuzz-inspect-box').classList.remove('hidden');
          document.getElementById('fuzz-inspect-payload').textContent = item.payload;
          document.getElementById('fuzz-inspect-body').textContent = item.responseBodyPreview || item.error || '(Trống)';
        });
      });

      showToast(`⚡ Hoàn tất Fuzzing ${data.total} payloads!`);
    } finally {
      btn.disabled = false;
      btn.textContent = '⚡ Chạy Fuzzing & Phân Tích Dị Thường';
    }
  });

  // Save Endpoint
  document.getElementById('btn-save-endpoint').addEventListener('click', async () => {
    const payload = {
      id: document.getElementById('ep-id').value.trim() || undefined,
      name: document.getElementById('ep-name').value.trim(),
      slug: document.getElementById('ep-slug').value.trim(),
      statusCode: Number(document.getElementById('ep-status').value) || 200,
      contentType: document.getElementById('ep-content-type').value.trim() || 'application/json',
      delayMs: Number(document.getElementById('ep-delay').value) || 0,
      secret: document.getElementById('ep-secret').value.trim(),
      requireValidHmac: Boolean(document.getElementById('ep-require-hmac')?.checked),
      forwardUrl: document.getElementById('ep-forward').value.trim(),
      notifyWebhookUrl: document.getElementById('ep-notify-url')?.value.trim() || '',
      notifyOnlyOnAnomaly: Boolean(document.getElementById('ep-notify-anomaly-only')?.checked),
      responseBody: document.getElementById('ep-body').value
    };
    const res = await fetch('/api/endpoints', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (data.ok) {
      state.endpoints = data.endpoints;
      renderEndpoints();
      showToast(`💾 Đã lưu endpoint /hook/${data.endpoint.slug}`);
    }
  });

  document.getElementById('btn-test-ep-notify').addEventListener('click', async () => {
    const notifyWebhookUrl = document.getElementById('ep-notify-url').value.trim();
    const slug = document.getElementById('ep-slug').value.trim() || 'payment-webhook';
    const name = document.getElementById('ep-name').value.trim() || 'NetPulse Endpoint';
    if (!notifyWebhookUrl) {
      showToast('Vui lòng nhập URL Telegram / Discord / Webhook nhận thông báo trước!');
      return;
    }
    const res = await fetch('/api/endpoints/test-notify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ notifyWebhookUrl, slug, name })
    }).then((r) => r.json());
    if (res.ok) {
      showToast(`🔔 Đã bắn thử cảnh báo thành công (HTTP ${res.result?.statusCode || 200})!`);
    } else {
      showToast(`⚠️ Không thể gửi cảnh báo: ${res.error || `HTTP ${res.result?.statusCode || 0}`}`);
    }
  });

  document.getElementById('btn-export-backup').addEventListener('click', async () => {
    const res = await fetch('/api/backup').then((r) => r.json());
    const blob = new Blob([JSON.stringify(res, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `netpulse-backup-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
    showToast('📥 Đã xuất file Backup toàn bộ dự án NetPulse!');
  });

  document.getElementById('btn-import-backup').addEventListener('click', () => {
    document.getElementById('backup-file-input').click();
  });

  document.getElementById('backup-file-input').addEventListener('change', async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      const res = await fetch('/api/restore', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(parsed)
      }).then((r) => r.json());
      if (res.ok) {
        await fetchInitialState();
        showToast('📤 Đã khôi phục toàn bộ dữ liệu từ file Backup!');
      } else {
        showToast(`❌ Lỗi khôi phục: ${res.error}`);
      }
    } catch {
      showToast('❌ File JSON không hợp lệ!');
    } finally {
      e.target.value = '';
    }
  });

  document.getElementById('btn-reset-endpoint-form').addEventListener('click', () => {
    document.getElementById('ep-id').value = '';
    document.getElementById('ep-name').value = '';
    document.getElementById('ep-slug').value = '';
    document.getElementById('ep-status').value = '200';
    document.getElementById('ep-content-type').value = 'application/json';
    document.getElementById('ep-delay').value = '0';
    document.getElementById('ep-secret').value = '';
    const reqHmacEl = document.getElementById('ep-require-hmac');
    if (reqHmacEl) reqHmacEl.checked = false;
    document.getElementById('ep-forward').value = '';
    const notifyUrlEl = document.getElementById('ep-notify-url');
    if (notifyUrlEl) notifyUrlEl.value = '';
    const notifyAnomEl = document.getElementById('ep-notify-anomaly-only');
    if (notifyAnomEl) notifyAnomEl.checked = false;
  });

  // Web API Hunter Controls
  document.getElementById('hunter-filter-input').addEventListener('input', renderHunterEndpointsTable);

  document.getElementById('btn-export-postman-reqs').addEventListener('click', () => {
    exportPostmanCollection(state.requests, 'NetPulse Captured Webhooks', 'netpulse-webhooks.postman_collection.json');
  });

  document.getElementById('btn-export-postman-hunter').addEventListener('click', () => {
    exportPostmanCollection(state.hunterEndpoints, 'NetPulse Discovered Website APIs', 'netpulse-website-apis.postman_collection.json');
  });

  document.getElementById('btn-run-hunter').addEventListener('click', async () => {
    const btn = document.getElementById('btn-run-hunter');
    const targetUrl = document.getElementById('hunter-url').value.trim();
    const probeCommonPaths = document.getElementById('hunter-probe-specs').checked;
    const useHeadless = document.getElementById('hunter-use-headless').checked;

    if (!targetUrl) {
      showToast('Vui lòng nhập địa chỉ trang web cần dò API!');
      return;
    }

    btn.disabled = true;
    btn.textContent = useHeadless ? '⏳ Đang mở Trình duyệt ngầm & Quét JS...' : '⏳ Đang quét HTML & JS...';
    try {
      const res = await fetch('/api/extract-apis', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetUrl, probeCommonPaths, useHeadless, maxScripts: 12 })
      });
      const data = await res.json();
      if (!data.ok) {
        showToast(`❌ Lỗi: ${data.error || 'Không thể quét trang web'}`);
        return;
      }

      document.getElementById('hunter-empty').classList.add('hidden');
      document.getElementById('hunter-results-area').classList.remove('hidden');
      document.getElementById('hunter-quicktest-box').classList.add('hidden');

      const info = data.pageInfo || {};
      const hl = info.headless || {};
      const headlessText = hl.enabled
        ? (hl.ok ? `✅ Đã bắt sống ${hl.capturedCount} XHR/Fetch bằng ${hl.browserUsed}` : `⚠️ ${hl.browserUsed || 'Không khả dụng'}`)
        : 'Đang tắt';

      document.getElementById('hunter-page-meta').innerHTML = [
        ['URL sau chuyển hướng', data.targetUrl],
        ['HTTP Status', `HTTP ${info.statusCode} (${info.durationMs}ms)`],
        ['Trình duyệt ngầm (CDP)', headlessText],
        ['Server / Hạ tầng', info.server],
        ['Chính sách CORS', info.cors],
        ['File JS đã phân tích', `${info.scriptsScanned} / ${info.scriptsFound} file JS bundles`]
      ].map(([k, v]) => `<div class="kv-row"><span class="kv-key">${esc(k)}</span><span class="kv-val">${esc(v)}</span></div>`).join('');

      const configs = data.configs || [];
      document.getElementById('hunter-configs-list').innerHTML = configs.length
        ? configs.map((c) => `<div class="kv-row"><span class="kv-key">${esc(c.key)}</span><span class="kv-val" style="color:#4ade80;">${esc(c.value)} <small style="color:var(--text-muted)">(${esc(c.source)})</small></span></div>`).join('')
        : `<p class="meta-hint">Không phát hiện biến cấu hình công khai (baseURL, NEXT_PUBLIC_*, VITE_*...)</p>`;

      state.hunterEndpoints = data.endpoints || [];
      renderHunterEndpointsTable();
      showToast(`🕵️‍♂️ Đã tìm thấy ${state.hunterEndpoints.length} đường dẫn API!`);
    } finally {
      btn.disabled = false;
      btn.textContent = '🔍 Quét & Lấy API';
    }
  });

  // JWT Studio Controls
  document.getElementById('btn-jwt-load-sample').addEventListener('click', async () => {
    const sampleHeader = { alg: 'HS256', typ: 'JWT' };
    const samplePayload = {
      iss: 'vietqr-gateway.vn',
      sub: 'user_8829',
      role: 'user',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600
    };
    const res = await fetch('/api/jwt/encode', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        header: sampleHeader,
        payload: samplePayload,
        secret: 'whsec_demo_secret_2026',
        mode: 'sign'
      })
    }).then((r) => r.json());
    if (res.token) {
      document.getElementById('jwt-raw-input').value = res.token;
      document.getElementById('jwt-header-input').value = JSON.stringify(sampleHeader, null, 2);
      document.getElementById('jwt-payload-input').value = JSON.stringify(samplePayload, null, 2);
      document.getElementById('jwt-output-token').value = res.token;
      showToast('🧪 Đã tạo JWT mẫu thành công!');
    }
  });

  document.getElementById('btn-jwt-decode').addEventListener('click', () => {
    decodeJwtIntoStudio(document.getElementById('jwt-raw-input').value);
    showToast('🔍 Đã giải mã xuống khung chỉnh sửa!');
  });

  document.getElementById('btn-jwt-set-admin').addEventListener('click', () => {
    try {
      const p = JSON.parse(document.getElementById('jwt-payload-input').value || '{}');
      p.role = 'admin';
      p.isAdmin = true;
      document.getElementById('jwt-payload-input').value = JSON.stringify(p, null, 2);
      showToast('👑 Đã cập nhật role = "admin" trong Payload!');
    } catch {
      showToast('Payload JSON không hợp lệ!');
    }
  });

  document.getElementById('btn-jwt-extend-exp').addEventListener('click', () => {
    try {
      const p = JSON.parse(document.getElementById('jwt-payload-input').value || '{}');
      p.exp = Math.floor(Date.now() / 1000) + 86400;
      document.getElementById('jwt-payload-input').value = JSON.stringify(p, null, 2);
      showToast('⏰ Đã gia hạn exp thêm +24 giờ!');
    } catch {
      showToast('Payload JSON không hợp lệ!');
    }
  });

  document.getElementById('btn-jwt-generate').addEventListener('click', async () => {
    let header;
    let payload;
    try {
      header = JSON.parse(document.getElementById('jwt-header-input').value || '{}');
      payload = JSON.parse(document.getElementById('jwt-payload-input').value || '{}');
    } catch {
      showToast('Header hoặc Payload không phải JSON hợp lệ!');
      return;
    }
    const secret = document.getElementById('jwt-secret-input').value;
    const mode = document.getElementById('jwt-sign-mode').value;
    const res = await fetch('/api/jwt/encode', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ header, payload, secret, mode })
    }).then((r) => r.json());

    if (res.token) {
      document.getElementById('jwt-output-token').value = res.token;
      document.getElementById('jwt-header-input').value = JSON.stringify(res.header, null, 2);
      showToast(mode === 'alg_none' ? '⚡ Đã tạo Token alg: none (không chữ ký)!' : '⚡ Đã ký Token mới thành công!');
    }
  });

  document.getElementById('btn-jwt-copy-output').addEventListener('click', () => {
    const out = document.getElementById('jwt-output-token').value || document.getElementById('jwt-raw-input').value;
    if (!out) return;
    navigator.clipboard.writeText(out);
    showToast('📋 Đã copy JWT Token!');
  });

  document.getElementById('btn-jwt-push-replay').addEventListener('click', () => {
    const token = document.getElementById('jwt-output-token').value.trim() || document.getElementById('jwt-raw-input').value.trim();
    if (!token) {
      showToast('Chưa có Token để đẩy sang Replay!');
      return;
    }
    const headersObj = parseHeadersInput(document.getElementById('replay-headers').value);
    headersObj['Authorization'] = `Bearer ${token}`;
    document.getElementById('replay-headers').value = formatHeadersForTextarea(headersObj);
    switchMainTab('replay');
    showToast('🔁 Đã gắn Authorization: Bearer <token> vào Replay Studio!');
  });

  document.getElementById('btn-jwt-audit-secret').addEventListener('click', async () => {
    const rawToken = document.getElementById('jwt-raw-input').value.trim() || document.getElementById('jwt-output-token').value.trim();
    if (!rawToken) {
      showToast('Vui lòng nhập hoặc nạp một chuỗi JWT vào ô bên trái trước!');
      return;
    }
    const customSecrets = document.getElementById('jwt-custom-wordlist').value
      .split('\n')
      .map((s) => s.trim())
      .filter(Boolean);

    const res = await fetch('/api/jwt/audit-secret', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: rawToken, customSecrets })
    }).then((r) => r.json());

    const box = document.getElementById('jwt-audit-result');
    if (!res.ok) {
      box.innerHTML = `<p style="color:#fda4af;">❌ ${esc(res.error)}</p>`;
      return;
    }
    if (res.found) {
      document.getElementById('jwt-secret-input').value = res.matchedSecret;
      box.innerHTML = `
        <h4 style="color:#4ade80;">🎉 ĐÃ TÌM THẤY SECRET KEY HỢP LỆ!</h4>
        <div class="kv-list">
          <div class="kv-row"><span class="kv-key">Secret tìm được</span><span class="kv-val" style="color:#4ade80; font-weight:700;">${esc(res.matchedSecret || '(Chuỗi rỗng)')}</span></div>
          <div class="kv-row"><span class="kv-key">Thuật toán</span><span class="kv-val">${esc(res.algorithm)}</span></div>
          <div class="kv-row"><span class="kv-key">Số khóa đã thử</span><span class="kv-val">${res.testedCount} khóa (${res.durationMs} ms)</span></div>
        </div>
        <p class="meta-hint" style="margin-top:8px;">Đã tự động điền khóa này vào ô <strong>"Secret Key để ký lại"</strong> bên trái!</p>
      `;
      showToast(`🔥 Tìm thấy JWT Secret: "${res.matchedSecret}"`);
    } else {
      box.innerHTML = `
        <h4 style="color:#fbbf24;">⚠️ Không khớp với từ điển hiện tại</h4>
        <p class="meta-hint">Đã thử ${res.testedCount} khóa (${res.durationMs} ms) nhưng chưa tìm thấy Secret khớp. Bạn có thể bổ sung thêm từ khóa nghi ngờ vào ô phía trên.</p>
      `;
    }
  });
}

// Connect Server-Sent Events (SSE)
function connectLiveStream() {
  const es = new EventSource('/api/stream');

  es.addEventListener('request_captured', (e) => {
    if (state.streamPaused) return;
    const record = JSON.parse(e.data);
    state.requests.unshift(record);
    if (!state.selectedRequestId) {
      state.selectedRequestId = record.id;
    }
    // Ensure auto-created endpoints show up
    if (!state.endpoints.some((ep) => ep.slug === record.slug)) {
      fetchInitialState();
    }
    renderRequestList();
    if (state.selectedRequestId === record.id) {
      renderRequestDetail();
    }
  });

  es.addEventListener('endpoints_updated', (e) => {
    state.endpoints = JSON.parse(e.data);
    renderEndpoints();
  });

  es.addEventListener('tunnel_updated', (e) => {
    state.tunnel = JSON.parse(e.data);
    updateActiveEndpointBanner();
  });

  es.addEventListener('requests_cleared', () => {
    fetchInitialState();
  });
}

async function fetchInitialState() {
  const res = await fetch('/api/state');
  const data = await res.json();
  state.serverOrigin = data.serverOrigin || window.location.origin;
  state.endpoints = data.endpoints || [];
  state.envVars = data.envVars || {};
  state.requests = data.requests || [];
  state.replays = data.replays || [];
  state.fuzzPresets = data.fuzzPresets || {};
  state.tunnel = data.tunnel || { active: false, status: 'stopped', publicBaseUrl: null };

  const envInput = document.getElementById('env-vars-input');
  if (envInput && !envInput.value) {
    envInput.value = formatEnvVarsForTextarea(state.envVars);
  }

  if (!state.selectedRequestId && state.requests.length > 0) {
    state.selectedRequestId = state.requests[0].id;
  }

  // Default URLs in Replay & Fuzzer
  const defaultHookUrl = `${state.serverOrigin}/hook/${state.endpoints[0]?.slug || 'payment-webhook'}`;
  if (!document.getElementById('replay-url').value) {
    document.getElementById('replay-url').value = defaultHookUrl;
    document.getElementById('replay-headers').value = 'Content-Type: application/json\nX-Custom-Source: NetPulse-Replay';
    document.getElementById('replay-body').value = JSON.stringify({
      event: 'order.paid',
      orderId: 'DH99999',
      amount: 250000
    }, null, 2);
  }
  if (!document.getElementById('fuzz-url').value) {
    document.getElementById('fuzz-url').value = `${defaultHookUrl}?probe={{FUZZ}}`;
  }

  loadFuzzPreset('boundary');
  renderEndpoints();
  renderRequestList();
  renderReplayHistory();
  renderRequestDetail();
}

window.addEventListener('DOMContentLoaded', async () => {
  setupEventListeners();
  await fetchInitialState();
  connectLiveStream();
});

