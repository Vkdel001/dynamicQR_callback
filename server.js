import 'dotenv/config';
import express from 'express';
import crypto from 'crypto';

// ── Load env vars (Railway sets these, or use .env locally) ────────
const PORT           = process.env.PORT || 3000;
const WEBHOOK_AES_KEY = process.env.WEBHOOK_AES_KEY || '';
const WEBHOOK_AES_IV  = process.env.WEBHOOK_AES_IV  || '';

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.raw({ type: '*/*', limit: '1mb' }));

// ── Log EVERY request ──────────────────────────────────────────────
app.use((req, res, next) => {
  console.log(`[REQUEST] ${req.method} ${req.url} from ${req.headers['x-forwarded-for'] || req.socket.remoteAddress}`);
  console.log(`[REQUEST] Content-Type: ${req.headers['content-type']}`);
  console.log(`[REQUEST] Body type: ${typeof req.body}, length: ${req.body ? (Buffer.isBuffer(req.body) ? req.body.length : JSON.stringify(req.body).length) : 0}`);
  next();
});

// ── In-memory log of received webhooks ─────────────────────────────
const webhookLog = [];
const MAX_LOG = 200;

// ── AES-256-CBC decrypt ────────────────────────────────────────────
function aesDecrypt(base64Data) {
  if (!WEBHOOK_AES_KEY || !WEBHOOK_AES_IV) {
    return { error: 'Webhook AES key/IV not configured' };
  }
  try {
    const decoded = Buffer.from(base64Data, 'base64');
    const decipher = crypto.createDecipheriv(
      'aes-256-cbc',
      Buffer.from(WEBHOOK_AES_KEY, 'utf8'),
      Buffer.from(WEBHOOK_AES_IV, 'utf8')
    );
    let decrypted = Buffer.concat([decipher.update(decoded), decipher.final()]);
    let str = decrypted.toString('utf8').trim().replace(/\0/g, '');

    // Handle wrapped JSON string
    if (str.length >= 2 && str[0] === '"' && str[str.length - 1] === '"') {
      str = str.slice(1, -1).replace(/\\"/g, '"');
    }

    const parsed = JSON.parse(str);
    return { success: true, data: parsed };
  } catch (err) {
    return { error: err.message };
  }
}

// ═══════════════════════════════════════════════════════════════════
//  POST /webhook — receives Blink payment callbacks
// ═══════════════════════════════════════════════════════════════════
app.post('/webhook', (req, res) => {
  const timestamp = new Date().toISOString();
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  // Parse body — could be JSON object, Buffer, or string
  let body = req.body;
  if (Buffer.isBuffer(body)) {
    const str = body.toString('utf8');
    try { body = JSON.parse(str); } catch { body = str; }
  } else if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch { /* keep as string */ }
  }

  const entry = {
    id: Date.now(),
    timestamp,
    ip,
    method: req.method,
    headers: {
      'content-type': req.headers['content-type'],
      'user-agent': req.headers['user-agent'],
    },
    rawBody: typeof body === 'string' ? body : JSON.stringify(body),
    envelope: typeof body === 'object' ? body : null,
    decrypted: null,
    status: 'received',
  };

  console.log(`\n${'═'.repeat(60)}`);
  console.log(`[WEBHOOK] ${timestamp}`);
  console.log(`[WEBHOOK] IP: ${ip}`);
  console.log(`[WEBHOOK] Content-Type: ${req.headers['content-type']}`);
  console.log(`[WEBHOOK] AES Key: ${WEBHOOK_AES_KEY.length} bytes, IV: ${WEBHOOK_AES_IV.length} bytes`);
  console.log(`[WEBHOOK] Raw body: ${entry.rawBody.substring(0, 300)}`);

  // Try to find encrypted data
  let encryptedData = null;
  if (typeof body === 'object' && body !== null) {
    encryptedData = body.Body || body.body || body.data || null;
    console.log(`[WEBHOOK] Envelope keys: ${Object.keys(body).join(', ')}`);
  }

  if (encryptedData && typeof encryptedData === 'string') {
    console.log(`[WEBHOOK] Encrypted data length: ${encryptedData.length}`);
    console.log(`[WEBHOOK] Encrypted data: ${encryptedData.substring(0, 80)}...`);

    const result = aesDecrypt(encryptedData);
    entry.decrypted = result;

    if (result.success) {
      console.log(`[WEBHOOK] ✓ Decrypted successfully`);
      console.log(`[WEBHOOK] Payload: ${JSON.stringify(result.data, null, 2)}`);
      entry.status = 'decrypted';

      // Extract key fields
      const d = result.data;
      entry.requestUUID = d.RequestUUID || d.requestUUID || '';
      entry.transactionId = d.TransactionId || d.transactionId || '';
      entry.statusCode = d.TransactionStatusCode || d.transactionStatusCode || '';
      entry.transactionResponse = d.TransactionResponse || d.transactionResponse || '';

      console.log(`[WEBHOOK] RequestUUID: ${entry.requestUUID}`);
      console.log(`[WEBHOOK] StatusCode: ${entry.statusCode}`);
      console.log(`[WEBHOOK] Response: ${entry.transactionResponse}`);
    } else {
      console.log(`[WEBHOOK] ✕ Decryption failed: ${result.error}`);
      entry.status = 'decrypt_failed';
    }
  } else {
    console.log(`[WEBHOOK] No encrypted data found in payload`);
    entry.status = 'no_encrypted_data';
  }

  console.log(`${'═'.repeat(60)}\n`);

  // Store in log
  webhookLog.unshift(entry);
  if (webhookLog.length > MAX_LOG) webhookLog.pop();

  // Respond to Blink — exact format matching PHP stdClass output
  res.setHeader('Content-Type', 'application/json');
  res.status(200).send(JSON.stringify({
    Data: {},
    Status: { i: true, m: 'OK', s: '200' }
  }));
});

// ═══════════════════════════════════════════════════════════════════
//  GET /logs — view received webhooks (browser-friendly)
// ═══════════════════════════════════════════════════════════════════
app.get('/logs', (req, res) => {
  res.json({
    total: webhookLog.length,
    webhooks: webhookLog,
  });
});

// ═══════════════════════════════════════════════════════════════════
//  GET / — health check + quick status
// ═══════════════════════════════════════════════════════════════════
app.get('/', (req, res) => {
  res.send(`
    <html>
    <head>
      <title>Blink Webhook Receiver</title>
      <style>
        body { font-family: monospace; background: #0f1117; color: #eee; padding: 40px; }
        h1 { color: #00c853; }
        a { color: #4f8cff; }
        .stat { color: #8b90a5; }
        pre { background: #1a1d27; padding: 16px; border-radius: 8px; overflow-x: auto; }
      </style>
    </head>
    <body>
      <h1>✓ Blink Webhook Receiver</h1>
      <p class="stat">Status: Running</p>
      <p class="stat">Webhooks received: ${webhookLog.length}</p>
      <p class="stat">AES Key configured: ${WEBHOOK_AES_KEY ? 'Yes (' + WEBHOOK_AES_KEY.length + ' bytes)' : 'No'}</p>
      <p class="stat">AES IV configured: ${WEBHOOK_AES_IV ? 'Yes (' + WEBHOOK_AES_IV.length + ' bytes)' : 'No'}</p>
      <hr style="border-color:#333">
      <p>Webhook endpoint: <code>POST /webhook</code></p>
      <p>View logs: <a href="/logs">/logs</a></p>
      ${webhookLog.length > 0 ? `
        <h3>Latest webhook:</h3>
        <pre>${JSON.stringify(webhookLog[0], null, 2)}</pre>
      ` : '<p class="stat">No webhooks received yet.</p>'}
    </body>
    </html>
  `);
});

// ── Catch-all: log any unmatched routes ────────────────────────────
app.all('*', (req, res) => {
  console.log(`[404] Unmatched: ${req.method} ${req.url}`);
  console.log(`[404] Headers: ${JSON.stringify(req.headers)}`);
  res.status(200).send(JSON.stringify({
    Data: {},
    Status: { i: true, m: 'OK', s: '200' }
  }));
});

app.listen(PORT, () => {
  console.log(`Webhook receiver running on port ${PORT}`);
  console.log(`AES Key: ${WEBHOOK_AES_KEY ? 'configured (' + WEBHOOK_AES_KEY.length + ' bytes)' : 'NOT SET'}`);
  console.log(`AES IV:  ${WEBHOOK_AES_IV ? 'configured (' + WEBHOOK_AES_IV.length + ' bytes)' : 'NOT SET'}`);
  console.log(`\nEndpoints:`);
  console.log(`  POST /webhook  — receives Blink callbacks`);
  console.log(`  GET  /logs     — view received webhooks (JSON)`);
  console.log(`  GET  /         — status page`);
});
