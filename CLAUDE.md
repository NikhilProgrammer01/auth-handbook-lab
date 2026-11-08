# Auth Engineering Handbook — Learning Project

## What this repo is
Hands-on demos for each lesson of the Auth Engineering Handbook (November 2026 edition).
One folder per lesson: `lesson-one/`, `lesson-two/`, etc.
Each folder is a **standalone** Node.js + Express project — no shared code between lessons.

## Stack decisions (apply until a lesson explicitly changes them)
- Runtime: Node.js + Express, ES modules (`"type": "module"`)
- No build step — runs with `node server.js`
- Frontend: single plain HTML file with vanilla `fetch()` — no React until a lesson introduces it
- Data: in-memory only — no real database until a lesson introduces one
- Tokens: complexity scales with the lesson (see ladder below)

## Token complexity ladder
- **Lessons 1.x** — fake named string tokens (e.g. `token-alice`) — clearly commented as conceptual
- **Lesson 2.4+** — real JWTs with `jsonwebtoken`
- **Lesson 2.2+** — server-side sessions with `express-session`
- **Do NOT** use future concepts in earlier lessons — the gap between concept and implementation IS the lesson

## Demo pattern — apply to every lesson folder
Every demo has:
1. A `BROKEN` route (`/api/broken/...`) — the wrong implementation
2. A `SECURE` route (`/api/secure/...`) — the correct implementation
3. A README section that leads with the attack, then the fix

## README rules for every lesson
- Every section must open with an **exact quote** from the lesson PDF
- Flow: concept → Step 1 (attack on BROKEN, observe) → "What just happened?" → Step 2 (blocked on SECURE, observe) → "Why this works"
- Include `curl` commands for every test — no test should require a browser
- Map testing habits from the lesson (two-account, tamper, bypass-the-client) to explicit curl steps

## Comments in this project
Comments ARE encouraged here — this is educational code.
- Explain WHY and connect to the lesson concept
- Reference the lesson section: `// Lesson 1.1 — identity comes from token, never from body`
- Do NOT explain WHAT the code does (variable names do that) — explain the AUTH CONCEPT

## Naming and port conventions
- Broken routes: `/api/broken/...`
- Secure routes: `/api/secure/...`
- Ports: lesson-one=3001, lesson-two=3002, ... (no conflicts when running multiple simultaneously)
