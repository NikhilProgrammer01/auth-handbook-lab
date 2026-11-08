// ─────────────────────────────────────────────────────────────────────────────
// In-memory data store for Lesson 1.1 demos.
// No database — intentionally simple. The lesson is about concepts, not storage.
// ─────────────────────────────────────────────────────────────────────────────

export const users = [
  { id: 1, name: "Alice", email: "alice@example.com", role: "user"  },
  { id: 2, name: "Bob",   email: "bob@example.com",   role: "admin" },
];

// Orders belong to specific users — used for IDOR demo (Demo 2).
// Alice (id=1) owns orders 101 and 103. Bob (id=2) owns order 102.
const _seedOrders = () => [
  { id: 101, userId: 1, item: "Laptop",   amount: 85000 },
  { id: 102, userId: 2, item: "Phone",    amount: 42000 },
  { id: 103, userId: 1, item: "Keyboard", amount:  4500 },
];

// Sellers — used for hidden-button demo (Demo 3).
// resetData() restores this list after a deletion.
const _seedSellers = () => [
  { id: 10, name: "TechShop",    ownerId: 1 },
  { id: 11, name: "GadgetWorld", ownerId: 2 },
];

export const orders  = _seedOrders();
export const sellers = _seedSellers();

// ─── Tokens ───────────────────────────────────────────────────────────────
// Lesson 1.1 — Tokens are intentionally simple named strings.
// Real tokens are cryptographically signed — see Lesson 2.4 (JWTs).
// Format here: just a readable name that maps to a user payload.
export const tokenStore = {
  "token-alice": { userId: 1, role: "user"  },
  "token-bob":   { userId: 2, role: "admin" },
};

// ─── Token blacklist ───────────────────────────────────────────────────────
// Lesson 1.1 — Used by Demo 5 (stale proof / revocation).
// SECURE logout adds the token here; requireAuth checks it on every request.
// BROKEN logout does NOT add to this set — demonstrating the gap.
export const blacklist = new Set();

// ─── Reset ────────────────────────────────────────────────────────────────
// Restores data to its seed state. Not a lesson concept — just a demo utility
// so demos don't permanently interfere with each other.
export function resetData() {
  sellers.splice(0, sellers.length, ..._seedSellers());
  orders.splice(0, orders.length, ..._seedOrders());
  blacklist.clear();
}
