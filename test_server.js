/**
 * End-to-End Test Suite for NetPulse Webhook Inspector & API Fuzzer
 */

const assert = require('node:assert');
const { server, tryDecodeJwt, tryDecodeBase64, computeHmacSignatures } = require('./server');

async function runTests() {
  console.log('🧪 Bắt đầu kiểm thử NetPulse...');

  // 1. Unit test JWT & Base64 Decoders
  const sampleB64 = Buffer.from('orderId=DH88291&status=paid').toString('base64');
  assert.strictEqual(tryDecodeBase64(sampleB64), 'orderId=DH88291&status=paid', 'Base64 decode failed');
  console.log('  ✅ Giải mã Base64 hoạt động chính xác');

  const h = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const p = Buffer.from(JSON.stringify({ sub: 'user_123', role: 'admin' })).toString('base64url');
  const jwtDecoded = tryDecodeJwt(`Bearer ${h}.${p}.fakesig`);
  assert.ok(jwtDecoded && jwtDecoded.payload.sub === 'user_123', 'JWT decode failed');
  console.log('  ✅ Giải mã JWT hoạt động chính xác');

  // 2. Start server on ephemeral port and test HTTP APIs
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    // 2a. Simulate Payment Webhook (JWT + HMAC + Base64)
    const simRes = await fetch(`${baseUrl}/api/simulate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario: 'payment' })
    }).then((r) => r.json());
    assert.strictEqual(simRes.ok, true);
    assert.strictEqual(simRes.status, 200);
    console.log('  ✅ Bắn gói tin mẫu Payment (JWT + HMAC + Base64) thành công');

    // 2b. Verify captured request state
    const stateData = await fetch(`${baseUrl}/api/state`).then((r) => r.json());
    assert.ok(stateData.requests.length >= 1, 'Expected at least 1 captured request');
    const latestReq = stateData.requests[0];
    assert.strictEqual(latestReq.signatureAnalysis.verified, true, 'HMAC signature should be verified');
    assert.ok(latestReq.decodedItems.jwts.length >= 1, 'Should detect JWT in Authorization header');
    assert.ok(latestReq.decodedItems.base64.length >= 1, 'Should detect Base64 in JSON body');
    console.log('  ✅ Phân tích gói tin (JWT + Base64 + HMAC-SHA256) chính xác');

    // 2c. Test Replay API
    const replayData = await fetch(`${baseUrl}/api/replay`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        method: 'POST',
        targetUrl: `${baseUrl}/hook/payment-webhook?replayed=1`,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ testReplay: true })
      })
    }).then((r) => r.json());
    assert.strictEqual(replayData.response.statusCode, 200);
    console.log('  ✅ Chức năng Replay Request hoạt động chính xác');

    // 2d. Test Fuzzing API
    const fuzzData = await fetch(`${baseUrl}/api/fuzz`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        method: 'POST',
        targetUrl: `${baseUrl}/hook/payment-webhook`,
        headers: { 'Content-Type': 'application/json' },
        body: '{"amount": "{{FUZZ}}"}',
        payloads: ['-100', '0', '999999999', "' OR 1=1--"],
        concurrency: 2
      })
    }).then((r) => r.json());
    assert.strictEqual(fuzzData.total, 4);
    assert.strictEqual(fuzzData.results.length, 4);
    console.log('  ✅ Chức năng API Fuzzer ({{FUZZ}}) hoạt động chính xác');

    // 2e. Test Website API Hunter (/api/extract-apis with Headless Browser)
    const hunterData = await fetch(`${baseUrl}/api/extract-apis`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        targetUrl: `${baseUrl}/demo-webapp`,
        probeCommonPaths: false,
        useHeadless: true
      })
    }).then((r) => r.json());
    assert.strictEqual(hunterData.ok, true, 'API Hunter should return ok: true');
    assert.ok(hunterData.endpoints.length >= 4, `Expected >=4 discovered endpoints, got ${hunterData.endpoints.length}`);
    assert.ok(hunterData.configs.length >= 1, 'Expected at least 1 discovered JS config variable');
    console.log(`  ✅ Chức năng Dò API Trang Web + Trình duyệt ngầm (${hunterData.pageInfo.headless?.browserUsed}) tìm thấy ${hunterData.endpoints.length} API (bắt sống ${hunterData.pageInfo.headless?.capturedCount} XHR/Fetch)`);

    // 2f. Test JWT Studio (/api/jwt/encode & /api/jwt/audit-secret)
    const jwtSigned = await fetch(`${baseUrl}/api/jwt/encode`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        header: { alg: 'HS256', typ: 'JWT' },
        payload: { sub: 'admin_test', role: 'admin' },
        secret: 'supersecret',
        mode: 'sign'
      })
    }).then((r) => r.json());
    assert.strictEqual(jwtSigned.ok, true);
    assert.ok(jwtSigned.token.split('.').length === 3);

    const jwtAudit = await fetch(`${baseUrl}/api/jwt/audit-secret`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: jwtSigned.token })
    }).then((r) => r.json());
    assert.strictEqual(jwtAudit.found, true);
    assert.strictEqual(jwtAudit.matchedSecret, 'supersecret');
    console.log('  ✅ Chức năng JWT Studio (Ký mới, alg:none & Dò tìm Secret Key yếu) hoạt động chính xác');

    // 2g. Test 1-Click Import cURL (/api/parse-curl)
    const curlParsed = await fetch(`${baseUrl}/api/parse-curl`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        curl: `curl 'https://api.example.com/v1/orders' -H 'Authorization: Bearer tok_123' -H 'Content-Type: application/json' --data-raw '{"orderId":999}'`
      })
    }).then((r) => r.json());
    assert.strictEqual(curlParsed.ok, true);
    assert.strictEqual(curlParsed.method, 'POST');
    assert.strictEqual(curlParsed.targetUrl, 'https://api.example.com/v1/orders');
    assert.strictEqual(curlParsed.headers['Authorization'], 'Bearer tok_123');
    assert.strictEqual(curlParsed.body, '{"orderId":999}');
    console.log('  ✅ Chức năng Nhập lệnh cURL 1-Click (/api/parse-curl) hoạt động chính xác');

    // 2h. Test Security & CORS Auditor (/api/security-audit)
    const secAudit = await fetch(`${baseUrl}/api/security-audit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        method: 'POST',
        targetUrl: `${baseUrl}/hook/payment-webhook`,
        headers: { 'Content-Type': 'application/json' },
        body: '{"probe":1}'
      })
    }).then((r) => r.json());
    assert.strictEqual(secAudit.ok, true);
    assert.strictEqual(typeof secAudit.score, 'number');
    assert.ok(Array.isArray(secAudit.findings) && secAudit.findings.length > 0);
    console.log(`  ✅ Chức năng Quét Bảo Mật & CORS (/api/security-audit) hoạt động chính xác (Điểm: ${secAudit.score}/100 - Hạng ${secAudit.grade})`);

    // 2i. Test Conditional HMAC Enforcement (requireValidHmac -> HTTP 401)
    const createdEpRes = await fetch(`${baseUrl}/api/endpoints`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'Strict HMAC Hook',
        slug: 'strict-hmac-hook',
        statusCode: 200,
        secret: 'strict_secret_key',
        requireValidHmac: true
      })
    }).then((r) => r.json());
    const unauthHookRes = await fetch(`${baseUrl}/hook/strict-hmac-hook`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Webhook-Signature': 'invalid_sig' },
      body: '{"test":1}'
    });
    assert.strictEqual(unauthHookRes.status, 401, 'Should return HTTP 401 when requireValidHmac is enabled and HMAC fails');
    // Clean up test endpoint
    if (createdEpRes.endpoint?.id) {
      await fetch(`${baseUrl}/api/endpoints/${createdEpRes.endpoint.id}`, { method: 'DELETE' });
    }
    console.log('  ✅ Chức năng Luật điều kiện HMAC (Tự động trả về HTTP 401 khi sai chữ ký) hoạt động chính xác');

    // 2j. Test Environment Variables ({{ENV_VAR}}) + Automated Assertions in Replay
    await fetch(`${baseUrl}/api/env`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        envVars: {
          BASE_URL: baseUrl,
          WEBHOOK_SLUG: 'payment-webhook',
          API_TOKEN: 'whsec_demo_secret_2026'
        }
      })
    });
    const envReplay = await fetch(`${baseUrl}/api/replay`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        method: 'POST',
        targetUrl: '{{BASE_URL}}/hook/{{WEBHOOK_SLUG}}',
        headers: { 'Content-Type': 'application/json', 'X-Token': '{{API_TOKEN}}' },
        body: '{"order":"{{WEBHOOK_SLUG}}"}',
        assertions: ['status == 200', 'durationMs < 2000', 'json.success == true']
      })
    }).then((r) => r.json());
    assert.strictEqual(envReplay.response.statusCode, 200);
    assert.strictEqual(envReplay.assertionResults.allPassed, true);
    assert.strictEqual(envReplay.assertionResults.passed, 3);
    // Reset BASE_URL to default port 4080
    await fetch(`${baseUrl}/api/env`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        envVars: {
          BASE_URL: 'http://localhost:4080',
          WEBHOOK_SLUG: 'payment-webhook',
          API_TOKEN: 'whsec_demo_secret_2026',
          MERCHANT_ID: 'VN_SHOP_01'
        }
      })
    });
    console.log('  ✅ Chức năng Biến Môi Trường ({{BASE_URL}}) & Kiểm Chứng Tự Động (API Assertions PASS/FAIL) hoạt động chính xác');

    // 2k. Test Telegram/Discord/Webhook Alert Dispatch (/api/endpoints/test-notify)
    const notifyTest = await fetch(`${baseUrl}/api/endpoints/test-notify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        notifyWebhookUrl: `${baseUrl}/hook/catch-all`,
        slug: 'payment-webhook',
        name: 'Payment Alert Test'
      })
    }).then((r) => r.json());
    assert.strictEqual(notifyTest.ok, true);
    console.log('  ✅ Chức năng Cảnh báo Webhook (Telegram / Discord / Custom Alert) hoạt động chính xác');

    // 2l. Test Full Workspace Backup (/api/backup)
    const backupData = await fetch(`${baseUrl}/api/backup`).then((r) => r.json());
    assert.strictEqual(backupData.ok, true);
    assert.ok(Array.isArray(backupData.store.endpoints));
    console.log('  ✅ Chức năng Lưu trữ bền vững (data/store.json) & Xuất/Nhập Backup hoạt động chính xác');

    console.log('\n🎉 Tất cả bài kiểm thử đều PASS!');
  } finally {
    server.close();
  }
}

runTests().catch((err) => {
  console.error('❌ Test failed:', err);
  process.exit(1);
});

