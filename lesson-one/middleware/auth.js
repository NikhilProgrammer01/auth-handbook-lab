// ─────────────────────────────────────────────────────────────────────────────
// requireAuth — authentication middleware
//
// Lesson 1.1: "The client is a suggestion. The server is the law."
// This middleware is the trust boundary. Everything inside it runs on the server.
// Everything that arrives from the client (headers, body) is untrusted input.
// ─────────────────────────────────────────────────────────────────────────────

import { tokenStore, blacklist } from '../data.js';

export function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'];

  // Lesson 1.1 — 401 means unauthenticated ("I don't know who you are").
  // Not "unauthorized" — the HTTP spec named it poorly; the lesson is explicit.
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'No credential provided',
      hint:  'Send: Authorization: Bearer <token>',
      lesson: '401 = unauthenticated (Lesson 1.1)',
    });
  }

  const token = authHeader.slice(7); // strip "Bearer "

  // Lesson 1.1 — Demo 5 (stale proof): revoked tokens are rejected here,
  // before we even look up who the token belongs to.
  if (blacklist.has(token)) {
    return res.status(401).json({
      error:  'Token has been revoked',
      lesson: 'Stale proof — Demo 5. The bearer credential was invalidated server-side.',
    });
  }

  const payload = tokenStore[token];
  if (!payload) {
    return res.status(401).json({
      error:  'Invalid token',
      lesson: '401 = unauthenticated — token not recognised',
    });
  }

  // Lesson 1.1 — Identity is established HERE from the verified credential.
  // req.user is set by us on the server — the client cannot supply or change it.
  // This is what "identity comes from the verified credential" means in practice.
  req.user = { id: payload.userId, role: payload.role };
  next();
}
