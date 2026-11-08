# Lesson 1.1 — Identity, Trust and the Three Questions

**Auth Engineering Handbook · Phase 1 · Lesson 1.1**

This project makes every concept from Lesson 1.1 runnable. Each demo has a **BROKEN** endpoint and a **SECURE** endpoint. You experience the attack first, then understand why it works, then see it blocked.

---

## Quick Start

```bash
cd lesson-one
npm install
node server.js
```

Open **http://localhost:3001** in your browser for the interactive UI.

> **curl quoting note:** All curl commands use Unix-style single quotes.
> Run them in **Git Bash**, **WSL**, or any Unix terminal on Windows.
> PowerShell users: replace `'...'` with `"..."` and escape inner quotes as `\"`.

---

## Tokens (your credentials for every test)

| Token | Identity | Role |
|-------|----------|------|
| `token-alice` | Alice (id=1) | user |
| `token-bob` | Bob (id=2) | admin |
| *(no header)* | — | unauthenticated |
| `bad-token` | — | invalid |

```bash
# Alice
-H "Authorization: Bearer token-alice"

# Bob (admin)
-H "Authorization: Bearer token-bob"
```

---

## Seed Data

| Resource | ID | Owner |
|----------|----|-------|
| Order — Laptop | 101 | Alice (user 1) |
| Order — Phone | 102 | Bob (user 2) |
| Order — Keyboard | 103 | Alice (user 1) |
| Seller — TechShop | 10 | (admin-managed) |
| Seller — GadgetWorld | 11 | (admin-managed) |

---

## Reset

Run this any time to restore deleted sellers and clear the token blacklist (after Demo 3 or Demo 5):

```bash
curl -X POST http://localhost:3001/api/reset
```

---

---

## Demo 1 — Identity from Request Body

### From the lesson

> *"Identity comes only from the verified credential, never from client-supplied fields."*
>
> *"Server reads `userId` or `role` from the request body → Attacker changes the field and becomes someone else."*

### The concept

The server receives bytes from an unknown source. If it trusts a `userId` field in the request body — which the client controls — an attacker can set that field to any value and impersonate any user. Identity must come from the verified credential (the token), not from the payload the client supplies.

---

### Step 1: Perform the attack (BROKEN endpoint)

Send a request as **Alice** (token-alice), but set `userId: 2` in the body to impersonate **Bob**:

```bash
curl -X POST http://localhost:3001/api/broken/transfer \
  -H "Authorization: Bearer token-alice" \
  -H "Content-Type: application/json" \
  -d '{"from": "ACC-1001", "to": "ACC-9999", "amount": 50000, "userId": 2}'
```

**You should see:** `HTTP 200` — `actingAs: "Bob (id=2)"`

Alice's token was valid (authenticated), but the server used the body's `userId` to decide who was acting. Alice just impersonated Bob.

### What just happened?

The broken endpoint does this:

```js
// WRONG — attacker controls this field
const actingUserId = req.body.userId;
```

The body comes from the untrusted client. Anyone can set `userId` to any value. The server authenticated the request (confirmed the token is real) but then threw away the token's identity and used the client's claim instead.

---

### Step 2: Same request on the SECURE endpoint

```bash
curl -X POST http://localhost:3001/api/secure/transfer \
  -H "Authorization: Bearer token-alice" \
  -H "Content-Type: application/json" \
  -d '{"from": "ACC-1001", "to": "ACC-9999", "amount": 50000, "userId": 2}'
```

**You should see:** `HTTP 200` — `actingAs: "Alice (id=1)"` — `body.userId was ignored`

### Why this works

The secure endpoint does this:

```js
// CORRECT — identity from verified credential only
const actor = users.find(u => u.id === req.user.id); // req.user set by requireAuth
```

`req.user` is set by the `requireAuth` middleware after verifying the token. The client cannot supply or modify `req.user` — it lives on the server. The body's `userId` field is completely ignored.

---

### Bonus — Testing habit: Tamper test

> *"Tamper test: change every ID, user field and role in the request."* — Lesson 1.1

Try changing `userId` to values that don't exist:

```bash
# userId of a non-existent user
curl -X POST http://localhost:3001/api/broken/transfer \
  -H "Authorization: Bearer token-alice" \
  -H "Content-Type: application/json" \
  -d '{"from": "ACC-1001", "to": "ACC-9999", "amount": 50000, "userId": 999}'
```

The broken endpoint still acts — it just can't find the user name. Identity from the body is always broken, even when the value is invalid.

---

---

## Demo 2 — IDOR / Broken Access Control

### From the lesson

> *"Any logged-in user can fetch any `/orders/:id` → Customers iterate IDs and read everyone's orders (IDOR/BOLA)."*
>
> *"FAILURE MODE: In 2019, First American Financial exposed hundreds of millions of documents because document URLs used sequential IDs and anyone with one link could change the number. Broken Access Control is ranked A01 in OWASP Top 10:2025."*

### The concept

Authentication confirms who you are. It says nothing about what you are allowed to access. A logged-in user is not automatically allowed to access every resource. Each resource request needs its own authorization check: does this user own this resource, or have a role that grants access?

---

### Step 1: Perform the attack (BROKEN endpoint)

Alice owns orders 101 and 103. Bob owns order 102. Use **Alice's token** to fetch **Bob's order**:

```bash
curl http://localhost:3001/api/broken/orders/102 \
  -H "Authorization: Bearer token-alice"
```

**You should see:** `HTTP 200` — Bob's order data returned to Alice

Alice is authenticated. The broken endpoint stops there — it doesn't ask "does Alice own order 102?"

### What just happened?

```js
// WRONG — no ownership check
const order = orders.find(o => o.id === parseInt(req.params.id));
if (!order) return res.status(404).json(...);
res.json({ order }); // returned to anyone with any valid token
```

An attacker with any valid account can iterate order IDs (101, 102, 103 …) and read every order in the system. This is **Insecure Direct Object Reference (IDOR)**, also called Broken Object Level Authorization (BOLA).

---

### Step 2: Same request on the SECURE endpoint

```bash
curl http://localhost:3001/api/secure/orders/102 \
  -H "Authorization: Bearer token-alice"
```

**You should see:** `HTTP 403` — `"You do not own this order"`

### Why this works

```js
// CORRECT — ownership checked on every request
const isOwner = order.userId === req.user.id;
const isAdmin = req.user.role === 'admin';
if (!isOwner && !isAdmin) return res.status(403).json(...);
```

Authorization is checked **per request**, **per resource**. Alice's token is valid, but the server verifies she owns order 102 before returning it. She doesn't — so 403.

---

### Bonus — Two-account test

> *"Two-account test: as User B, request every resource User A created. All must fail."* — Lesson 1.1

```bash
# Alice tries to read Bob's order (should fail on SECURE)
curl http://localhost:3001/api/secure/orders/102 -H "Authorization: Bearer token-alice"
# → 403

# Bob tries to read Alice's order (admin role — should succeed)
curl http://localhost:3001/api/secure/orders/101 -H "Authorization: Bearer token-bob"
# → 200 (admin can access any order)

# Alice reads her own order (should succeed)
curl http://localhost:3001/api/secure/orders/101 -H "Authorization: Bearer token-alice"
# → 200
```

---

---

## Demo 3 — Hidden Button / UI-Only Gating

### From the lesson

> *"'Refund' button hidden in React for non-managers; endpoint unchecked → Support agent calls the endpoint with curl."*
>
> *"UI gating for UX, server check for security."*
>
> *"The client is a suggestion. The server is the law."*

### The concept

The React UI shows "Delete Seller" only to admins. But the UI is in the **untrusted zone** — the client. The server must enforce the same policy independently. Any user can skip the UI entirely and call the endpoint directly with curl.

---

### Step 1: Perform the attack (BROKEN endpoint)

Use **Alice's token** (role: user, non-admin) to delete a seller — bypassing the UI that would have hidden the button:

```bash
curl -X DELETE http://localhost:3001/api/broken/sellers/10 \
  -H "Authorization: Bearer token-alice"
```

**You should see:** `HTTP 200` — seller deleted. Alice is not an admin.

The UI would never have shown Alice the button. But the endpoint didn't check — and curl doesn't use the UI.

### What just happened?

```js
// WRONG — only checks "is there a valid token"
app.delete('/api/broken/sellers/:id', requireAuth, (req, res) => {
  // No role check — any authenticated user gets through
  sellers.splice(idx, 1);
  res.json({ deleted: removed });
});
```

Authentication happened (token is valid). Authorization did not. The server trusted the UI to enforce access control — which it cannot, because the client is untrusted.

---

### Step 2: Same attack on the SECURE endpoint

```bash
curl -X DELETE http://localhost:3001/api/secure/sellers/10 \
  -H "Authorization: Bearer token-alice"
```

**You should see:** `HTTP 403` — `"Admin role required"` — `yourRole: "user"`

### Why this works

```js
// CORRECT — role enforced on the server
if (req.user.role !== 'admin') {
  return res.status(403).json({ error: 'Admin role required' });
}
```

The server checks `req.user.role` — set from the verified token, not from anything the client sent. Even if the attacker modifies their token's role claim, the token is looked up in `tokenStore` on the server, so the role is authoritative.

---

### Bonus — Admin can still delete (correct behaviour)

```bash
curl -X DELETE http://localhost:3001/api/secure/sellers/11 \
  -H "Authorization: Bearer token-bob"
```

**You should see:** `HTTP 200` — Bob (admin) deleted the seller correctly.

```bash
# Restore sellers after this
curl -X POST http://localhost:3001/api/reset
```

---

### Bonus — Bypass-the-client test

> *"Bypass-the-client test: call the endpoint with curl. Any protection that disappears was never a protection."* — Lesson 1.1

This whole demo IS the bypass-the-client test. The UI hides the button — but curl ignores the UI.

---

---

## Demo 4 — 401 vs 403 Status Codes

### From the lesson

> *"HTTP 401 Unauthorized really means unauthenticated; 403 Forbidden means 'I know who you are, and the answer is no.'"*
>
> *"Debug by status code: 401 points to authentication (missing/expired credential, cookie not sent, clock skew); 403 points to the authorization policy."*

### The concept

These two status codes signal completely different problems. 401 means "prove who you are first." 403 means "I know who you are — you're not allowed." Mixing them up makes debugging much harder and leaks information about which problem you're hitting.

---

### Scenario A — No credential → expect 401

```bash
curl http://localhost:3001/api/secure/orders/101
```

**You should see:** `HTTP 401` — `"No credential provided"`

No `Authorization` header. The server doesn't know who is asking. 401 = unauthenticated.

---

### Scenario B — Bad/invalid token → expect 401

```bash
curl http://localhost:3001/api/secure/orders/101 \
  -H "Authorization: Bearer bad-token"
```

**You should see:** `HTTP 401` — `"Invalid token"`

A token was sent, but it doesn't exist in the token store. The server still doesn't know who you are. 401 = unauthenticated.

---

### Scenario C — Valid token, wrong owner → expect 403

```bash
curl http://localhost:3001/api/secure/orders/102 \
  -H "Authorization: Bearer token-alice"
```

**You should see:** `HTTP 403` — `"You do not own this order"` — `you: "user 1"` — `owner: "user 2"`

Alice is authenticated (the server knows she is Alice). But she doesn't own order 102. 403 = authenticated, not authorized.

---

### Scenario D — Valid token, own resource → expect 200

```bash
curl http://localhost:3001/api/secure/orders/101 \
  -H "Authorization: Bearer token-alice"
```

**You should see:** `HTTP 200` — Alice's order returned.

Authenticated AND authorized. Both checks passed.

---

### Scenario E — 403 vs 404 tradeoff

> *"User 55 requests GET /orders/9812, owned by user 77, and gets 403. A reviewer suggests 404."* — Lesson 1.1 Assessment Scenario 4

Should you return 403 (reveals the resource exists) or 404 (hides existence)?

```bash
# Default — 403 (reveals existence to Alice)
curl http://localhost:3001/api/secure/orders/102 \
  -H "Authorization: Bearer token-alice"
# → 403 "You do not own this order"

# mode=hide — 404 (hides existence)
curl 'http://localhost:3001/api/secure/orders/102?mode=hide' \
  -H "Authorization: Bearer token-alice"
# → 404 "Order not found"
```

**When to use each:**
- **403** — when the existence of the resource is not sensitive (most orders/invoices). Clearer for debugging, honest with the user.
- **404** — when the existence itself is sensitive (medical records, private messages, confidential documents). Hiding whether resource 9812 exists prevents enumeration attacks.

For most order systems, 403 is the right call. If existence itself is a secret, use 404 — but document the decision.

---

---

## Demo 5 — Stale Proof / Token Revocation

### From the lesson

> *"A customer changes a leaked password on the web. Their phone app stays logged in, and so does the attacker's session. Is this a bug?"*
>
> *"Credentials valid for 30 days with no revocation → Suspended fraudster stays logged in."*
>
> *"Whoever holds the card is you (a bearer credential); a lost card must be invalidated (the revocation problem)."*

### The concept

A bearer token is like a hotel keycard: whoever holds it is treated as the rightful user. If you log out but the server doesn't invalidate the token, the attacker who stole it can keep using it indefinitely.

**Recommended test flow:** run steps in order. Reset between broken and secure tests.

---

### Step 1: Broken logout — the token survives

```bash
# Step 1a — "Log out" on the broken endpoint
curl -X POST http://localhost:3001/api/broken/logout \
  -H "Authorization: Bearer token-alice"
# → 200 "Logged out (but the token was NOT revoked)"

# Step 1b — Use the same token again immediately
curl http://localhost:3001/api/profile \
  -H "Authorization: Bearer token-alice"
# → 200 "Token is still valid"
```

**You should see:** `HTTP 200` on the profile check — the logout did nothing. An attacker holding Alice's token stays logged in after she "logged out."

### What just happened?

```js
// WRONG — returns 200 but does nothing server-side
app.post('/api/broken/logout', requireAuth, (_req, res) => {
  res.json({ message: 'Logged out' }); // token is still alive
});
```

The token is a bearer credential. The server has no memory of "this token is now invalid" — so every request with the token still passes.

---

### Step 2: Reset, then secure logout — token is revoked

```bash
# Reset first (clear blacklist from any previous demo)
curl -X POST http://localhost:3001/api/reset

# Step 2a — Log out on the secure endpoint
curl -X POST http://localhost:3001/api/secure/logout \
  -H "Authorization: Bearer token-alice"
# → 200 "Token revoked. Try using it again."

# Step 2b — Try the same token again
curl http://localhost:3001/api/profile \
  -H "Authorization: Bearer token-alice"
# → 401 "Token has been revoked"
```

**You should see:** `HTTP 401` — the token is dead even though it was once valid.

### Why this works

```js
// CORRECT — adds token to server-side blacklist
app.post('/api/secure/logout', requireAuth, (req, res) => {
  const token = req.headers['authorization'].slice(7);
  blacklist.add(token); // server remembers this token is invalid
  res.json({ message: 'Token revoked.' });
});
```

`requireAuth` checks `blacklist.has(token)` on every request. The token is now rejected regardless of whether it would otherwise be valid.

---

### Reset when done

```bash
curl -X POST http://localhost:3001/api/reset
```

This clears the blacklist so Alice's token works again in other demos.

---

---

## Demo 6 — Auditing

### From the lesson

> *"Auditing (Accounting): 'What happened, and who did it?' The record that lets you investigate later."*
>
> *"Together these are often called 'AAA': Authentication, Authorization, Auditing."*

### The concept

Every request is logged with the principal (who), the action (what), the resource (on what), and the decision (allow/deny). Without this, you cannot answer "did user X access resource Y?" after a breach.

---

### How to observe it

Watch the terminal where `node server.js` is running as you interact with any demo. You will see lines like:

```
[AUDIT] 2026-11-08T10:00:01Z | user=1(user)  | GET /orders/101  | ALLOW
[AUDIT] 2026-11-08T10:00:03Z | user=1(user)  | GET /orders/102  | DENY(403)
[AUDIT] 2026-11-08T10:00:05Z | ANON          | GET /orders/101  | DENY(401)
[AUDIT] 2026-11-08T10:00:07Z | user=1(user)  | DELETE /sellers/10 | DENY(403)
[AUDIT] 2026-11-08T10:00:09Z | user=2(admin) | DELETE /sellers/10 | ALLOW
```

**What each field means:**
- `user=1(user)` — principal: user id=1, role=user
- `ANON` — no credential was provided
- `ALLOW` — request was served (2xx)
- `DENY(403)` — authenticated but not authorized
- `DENY(401)` — unauthenticated

---

### Reproduce the audit log in one shot

Run these commands and watch the terminal:

```bash
# 1. Alice reads her own order → ALLOW
curl http://localhost:3001/api/secure/orders/101 -H "Authorization: Bearer token-alice"

# 2. Alice reads Bob's order → DENY(403)
curl http://localhost:3001/api/secure/orders/102 -H "Authorization: Bearer token-alice"

# 3. No token → DENY(401)
curl http://localhost:3001/api/secure/orders/101

# 4. Alice tries to delete a seller → DENY(403)
curl -X DELETE http://localhost:3001/api/secure/sellers/10 -H "Authorization: Bearer token-alice"

# 5. Bob (admin) deletes a seller → ALLOW
curl -X DELETE http://localhost:3001/api/secure/sellers/10 -H "Authorization: Bearer token-bob"

# Reset
curl -X POST http://localhost:3001/api/reset
```

---

---

## Full Testing Checklist (from Lesson 1.1 testing habits)

> *"Two-account test, No-credential test, Tamper test, Bypass-the-client test"* — Lesson 1.1

| Test | Command | Expected |
|------|---------|----------|
| No credential | `curl /api/secure/orders/101` | 401 |
| Bad token | `curl /api/secure/orders/101 -H "Authorization: Bearer bad-token"` | 401 |
| Valid token, own resource | `curl /api/secure/orders/101 -H "Authorization: Bearer token-alice"` | 200 |
| Two-account: User A reads User B's resource | `curl /api/secure/orders/102 -H "Authorization: Bearer token-alice"` | 403 |
| Tamper: change userId in body | `POST /api/secure/transfer` with `userId: 2` and token-alice | Ignored, acts as Alice |
| Bypass-the-client: non-admin calls admin endpoint | `DELETE /api/broken/sellers/10 -H "Authorization: Bearer token-alice"` | 200 (broken!) |
| Same bypass on secure | `DELETE /api/secure/sellers/10 -H "Authorization: Bearer token-alice"` | 403 |
| Stale proof: use token after logout | logout then `GET /api/profile` | 401 (secure), 200 (broken) |

---

## Concept Map — Lesson to Demo

| Lesson 1.1 concept | Demo |
|--------------------|------|
| Identification / AuthN / AuthZ / Auditing (the Four Questions) | Demo 6 — Auditing; Demo 4 — 401 vs 403 |
| "Authentication is an event; Authorization is a decision on every request" | Demo 2 — IDOR |
| "The client is a suggestion. The server is the law." | Demo 3 — Hidden Button |
| "Identity comes only from the verified credential" | Demo 1 — Identity from Body |
| IDOR / BOLA — OWASP A01:2025 | Demo 2 — IDOR |
| "UI gating for UX, server check for security" | Demo 3 — Hidden Button |
| Bearer credential — "whoever holds the card is you" | Demo 5 — Stale Proof |
| Revocation — "a lost card must be invalidated" | Demo 5 — Stale Proof |
| "401 = unauthenticated; 403 = known, but no" | Demo 4 — 401 vs 403 |
| 403 vs 404 tradeoff | Demo 4 — Scenario E |
| "What happened, and who did it?" — Auditing | Demo 6 — Auditing |
| Testing habits: two-account, no-credential, tamper, bypass-the-client | Full checklist above |
