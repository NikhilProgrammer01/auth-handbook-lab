// ─────────────────────────────────────────────────────────────────────────────
// Lesson 1.1 — Identity, Trust and the Three Questions
// Demo server: six broken/secure pairs, one per lesson concept.
// Run: node server.js  →  http://localhost:3001
// ─────────────────────────────────────────────────────────────────────────────

import express from 'express';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { users, orders, sellers, blacklist, resetData } from './data.js';
import { requireAuth } from './middleware/auth.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();

app.use(express.json());
app.use(express.static(join(__dirname, 'public')));

// ─── Demo 6: Audit middleware ─────────────────────────────────────────────
// Lesson 1.1 — Auditing: "What happened, and who did it?"
// Logs every /api request: principal, method, path, decision, timestamp.
// req.user is set by requireAuth, so it's available when 'finish' fires.
app.use('/api', (req, res, next) => {
  res.on('finish', () => {
    const principal = req.user ? `user=${req.user.id}(${req.user.role})` : 'ANON';
    const decision  = res.statusCode < 400 ? 'ALLOW' : `DENY(${res.statusCode})`;
    console.log(`[AUDIT] ${new Date().toISOString()} | ${principal} | ${req.method} ${req.path} | ${decision}`);
  });
  next();
});

// ─── Utility: Reset ───────────────────────────────────────────────────────
// Restores sellers and clears blacklist — run between demos to avoid bleed-over.
app.post('/api/reset', (_req, res) => {
  resetData();
  res.json({ message: 'Reset complete. Sellers restored, blacklist cleared.' });
});

// ─── Utility: State snapshot ──────────────────────────────────────────────
// Shows current in-memory state — useful when demoing via the UI.
app.get('/api/state', (_req, res) => {
  res.json({
    sellers:   [...sellers],
    blacklist: [...blacklist],
    orders:    orders.map(o => ({ ...o })),
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// DEMO 1 — Identity from Request Body
// Concept: "Identity comes only from the verified credential" — Lesson 1.1
// ═════════════════════════════════════════════════════════════════════════════

// BROKEN: reads userId from the request body — attacker controls this field
app.post('/api/broken/transfer', requireAuth, (req, res) => {
  // Lesson 1.1 — WRONG: identity from client-supplied field.
  // The body arrives from the untrusted client. Anyone can set userId to 2
  // and the server will treat the request as if Bob made it.
  const actingUserId = req.body.userId;
  const actor = users.find(u => u.id === actingUserId);

  res.json({
    demo:       'Demo 1 — BROKEN',
    warning:    'Identity read from req.body.userId — attacker set this field',
    actingAs:   actor ? `${actor.name} (id=${actor.id})` : `unknown user (userId=${actingUserId})`,
    transfer:   { from: req.body.from, to: req.body.to, amount: req.body.amount },
    realToken:  `The token belongs to user ${req.user.id} — but the server ignored it`,
  });
});

// SECURE: identity comes only from req.user — set by requireAuth from the token
app.post('/api/secure/transfer', requireAuth, (req, res) => {
  // Lesson 1.1 — CORRECT: identity from verified credential only.
  // req.body.userId is ignored entirely. The server sets req.user from the token.
  const actor = users.find(u => u.id === req.user.id);

  res.json({
    demo:      'Demo 1 — SECURE',
    actingAs:  `${actor.name} (id=${actor.id}, role=${actor.role})`,
    transfer:  { from: req.body.from, to: req.body.to, amount: req.body.amount },
    note:      'req.body.userId was ignored — only the token identity is used',
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// DEMO 2 — IDOR / Broken Access Control
// Concept: "Authorization is a decision made on every request" — Lesson 1.1
// ═════════════════════════════════════════════════════════════════════════════

// BROKEN: returns any order as long as the token is valid — no ownership check
app.get('/api/broken/orders/:id', requireAuth, (req, res) => {
  // Lesson 1.1 — WRONG: authenticated ≠ authorized.
  // Any logged-in user can read any order just by changing the ID.
  // This is IDOR (Insecure Direct Object Reference) / BOLA — OWASP A01:2025.
  const order = orders.find(o => o.id === parseInt(req.params.id));
  if (!order) return res.status(404).json({ error: 'Order not found' });

  res.json({
    demo:    'Demo 2 — BROKEN',
    warning: 'No ownership check — any authenticated user can read any order',
    order,
  });
});

// SECURE: checks ownership on every request — also used by Demo 4 (401 vs 403)
app.get('/api/secure/orders/:id', requireAuth, (req, res) => {
  // Lesson 1.1 — CORRECT: authorization decision per resource, per request.
  // "Authentication is an event. Authorization is a decision made on every request."
  const order = orders.find(o => o.id === parseInt(req.params.id));
  if (!order) return res.status(404).json({ error: 'Order not found' });

  const isOwner = order.userId === req.user.id;
  const isAdmin = req.user.role === 'admin';

  if (!isOwner && !isAdmin) {
    // Demo 4 — 403 vs 404 tradeoff (Lesson 1.1 assessment Scenario 4).
    // ?mode=hide returns 404 to conceal resource existence.
    // Default returns 403: "I know who you are, and the answer is no."
    if (req.query.mode === 'hide') {
      return res.status(404).json({
        error: 'Order not found',
        note:  '404 chosen to hide resource existence (mode=hide)',
        lesson: 'Demo 4 — 403 vs 404 tradeoff',
      });
    }
    // Lesson 1.1 — 403 = authenticated but not authorized
    return res.status(403).json({
      error:  'You do not own this order',
      you:    `user ${req.user.id}`,
      owner:  `user ${order.userId}`,
      lesson: 'Demo 4 — 403 means "I know who you are, and the answer is no"',
    });
  }

  res.json({ demo: 'Demo 2 & 4 — SECURE', order });
});

// ═════════════════════════════════════════════════════════════════════════════
// DEMO 3 — UI-Only Gating / Hidden Button
// Concept: "UI gating for UX, server check for security" — Lesson 1.1
// ═════════════════════════════════════════════════════════════════════════════

// BROKEN: only checks "is there a valid token" — ignores role
app.delete('/api/broken/sellers/:id', requireAuth, (req, res) => {
  // Lesson 1.1 — WRONG: the React UI hides "Delete Seller" for non-admins,
  // but this endpoint doesn't enforce the same rule. Any authenticated user
  // can call it directly with curl and bypass the UI entirely.
  const idx = sellers.findIndex(s => s.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'Seller not found' });

  const removed = sellers.splice(idx, 1)[0];
  res.json({
    demo:      'Demo 3 — BROKEN',
    warning:   'No role check — any authenticated user deleted this seller',
    deleted:   removed,
    deletedBy: req.user,
    reminder:  'Run POST /api/reset to restore sellers',
  });
});

// SECURE: role is enforced on the server, independent of what the UI shows
app.delete('/api/secure/sellers/:id', requireAuth, (req, res) => {
  // Lesson 1.1 — CORRECT: server enforces the policy, not the UI.
  // "Logged in" does not mean "allowed."
  if (req.user.role !== 'admin') {
    return res.status(403).json({
      error:    'Admin role required',
      yourRole: req.user.role,
      lesson:   'Demo 3 — 403: authenticated but not authorised',
    });
  }

  const idx = sellers.findIndex(s => s.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'Seller not found' });

  const removed = sellers.splice(idx, 1)[0];
  res.json({
    demo:      'Demo 3 — SECURE',
    deleted:   removed,
    deletedBy: req.user,
    reminder:  'Run POST /api/reset to restore sellers',
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// DEMO 4 — 401 vs 403 (covered inline on /api/secure/orders/:id above)
// Extra endpoint: no-auth test against a known resource
// ═════════════════════════════════════════════════════════════════════════════

// Status-code reference endpoint (no auth) — used in Demo 4 no-credential test
app.get('/api/demo4/check', requireAuth, (req, res) => {
  res.json({
    demo:    'Demo 4',
    message: 'You are authenticated',
    user:    req.user,
    lesson:  '200 = authenticated and reached this endpoint',
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// DEMO 5 — Stale Proof / Revocation
// Concept: "Whoever holds the card is you" — bearer credentials & revocation
// ═════════════════════════════════════════════════════════════════════════════

// BROKEN logout: says "logged out" but does nothing server-side
app.post('/api/broken/logout', requireAuth, (_req, res) => {
  // Lesson 1.1 — WRONG: logout is a lie.
  // The token is not added to any blacklist. The attacker's copy still works.
  res.json({
    demo:    'Demo 5 — BROKEN',
    message: 'Logged out (but the token was NOT revoked — try /api/profile)',
  });
});

// SECURE logout: adds the token to the blacklist — requireAuth checks it next time
app.post('/api/secure/logout', requireAuth, (req, res) => {
  // Lesson 1.1 — CORRECT: revoke the bearer credential server-side.
  // "A lost card must be invalidated" — the revocation problem.
  const token = req.headers['authorization'].slice(7);
  blacklist.add(token);
  res.json({
    demo:    'Demo 5 — SECURE',
    message: 'Token revoked. Try /api/profile with this token now — you will get 401.',
  });
});

// Profile endpoint — used by Demo 5 to verify whether a token still works
app.get('/api/profile', requireAuth, (req, res) => {
  res.json({
    message: 'Token is still valid — you are still authenticated',
    user:    req.user,
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Start
// ═════════════════════════════════════════════════════════════════════════════

app.listen(3001, () => {
  console.log('');
  console.log('╔══════════════════════════════════════════════════╗');
  console.log('║   Lesson 1.1 — Identity, Trust & the            ║');
  console.log('║   Three Questions — Demo Server                  ║');
  console.log('╠══════════════════════════════════════════════════╣');
  console.log('║   http://localhost:3001                          ║');
  console.log('╠══════════════════════════════════════════════════╣');
  console.log('║   Tokens (use in Authorization: Bearer <token>)  ║');
  console.log('║   token-alice  →  Alice  (role: user)            ║');
  console.log('║   token-bob    →  Bob    (role: admin)           ║');
  console.log('╠══════════════════════════════════════════════════╣');
  console.log('║   AUDIT LOG appears below as requests arrive     ║');
  console.log('╚══════════════════════════════════════════════════╝');
  console.log('');
});
