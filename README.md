# Servsly Showcase

A documentation-style walkthrough of selected slices from **Servsly** (hosting platform/survey/lead intake).  
This repo intentionally shares **cleaned and simplified** snippets — not full production code — to demonstrate design, security posture, and development practices.

> ⚠️ **Note:** The production applications are private. This showcase omits secrets, infrastructure details, and proprietary logic.  
> Code snippets are trimmed for clarity and are **not** drop-in complete.

---

## What’s Inside

- **`user_auth.md`** — Email-based authentication flow (models → forms → views) with verification tokens and “remember me” sessions.  
- **`customer_forms.md`** — Minimal contact/lead intake (model + form + view) with server-side validation and anti-bot honeypot.  
- **`hosting_pipeline.md`** *(advanced appendix)* — Sanitized lifecycle for **Validate → Preview → Publish** of static site revisions (DB-centric, no infra exposure).

Each document is a one-pager with:
- A short overview of intent and constraints  
- Curated code blocks (models, forms, views/services)  
- Notes on security and reasoning

---

## Tech Stack (Representative)

- **Language:** Python  
- **Framework:** Django (auth, forms, class-based views)  
- **Data:** Django ORM, JSON fields for reports/metadata  
- **Auth:** Email-based login, verification tokens, session control  
- **Ops/Patterns:** Idempotent actions, transactional updates, per-site revision numbering  
- **Anti-abuse:** Honeypot inputs (no external CAPTCHA in showcase)  
- **Testing Style (implied):** Unit/feature tests around validation, permissions, and flows

> This showcase avoids production infrastructure (Nginx, systemd, storage layout, DNS providers, Cloudflare, etc.) on purpose.

---

## Architecture (Conceptual)

```text
Browser
  │  (forms: signup, login, contact)
  ▼
Django Views (Auth / Forms / Hosting Services)
  │  validate input, issue tokens, enforce permissions
  ▼
Django Models (User / EmailVerification / Site / SiteRevision / Domain)
  │  persist state, version content, enforce invariants
  ▼
Database (relational)
'''
'''text
Hosting
Upload ZIP → Validate (stats, has index.html?) → [Preview (token+ttl)] → Publish (mark rev, set current)
```
