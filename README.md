
# Auth Service – Production‑Grade Authentication & Authorization Platform


![Python](https://img.shields.io/badge/python-3.13-blue)
![Django](https://img.shields.io/badge/django-5.x-success)
![Auth](https://img.shields.io/badge/auth-production--grade-green)
![RBAC](https://img.shields.io/badge/RBAC-enabled-purple)

> A production-grade authentication & authorization platform for modern SaaS backends.

This repository provides a **standalone, reusable authentication and authorization service**
built with **Django + Django REST Framework**, designed for **real SaaS products**.

It supports:
- Email/password auth
- SSO (Google, GitHub)
- Multi‑tenant organisations
- Role‑based & permission‑based access control
- Active sessions
- Audit logs
- Abuse protection

This is **not a demo**. It is intended to be used as a **core platform service**.

---

## Table of Contents

1. Architecture Overview  
2. Tech Stack  
3. Core Concepts  
4. Authentication Flows  
5. Single Sign‑On (SSO)  
6. Organisations & Memberships  
7. Authorization Model  
8. Active Sessions  
9. Audit Logs  
10. Rate Limiting & Abuse Protection  
11. Admin Panel  
12. Project Structure  
13. Environment Variables  
14. Local Development  
15. Extending the System  

---

## 1. Architecture Overview

```
Clients (Web / Mobile / API)
        ↓
Auth APIs (DRF)
        ↓
Authorization Layer
  ├─ User‑level RBAC (global)
  └─ Org‑level RBAC (scoped)
        ↓
PostgreSQL + Redis
```

**Separation of concerns is strict:**
- Authentication ≠ Authorization
- User scope ≠ Organisation scope

---

## 2. Tech Stack

- Python 3.13
- Django 5.1+
- Django REST Framework
- PostgreSQL
- Redis
- JWT (SimpleJWT)
- Docker & Docker Compose
- Nginx

---

## 3. Core Concepts

### User
- Identified **only by email**
- Password optional (SSO users)
- Global `role` defines system‑level access

### Organisation
- Multi‑tenant boundary
- Identified by **slug**
- Owned by a user

### Membership
- Connects user ↔ organisation
- Holds org‑level role

---

## 4. Authentication Flows

### Register
```
POST /api/v1/auth/register/
```

- Creates user
- Email verification required

### Login
```
POST /api/v1/auth/login/
```

- Returns JWT access + refresh
- Creates server‑side session

### Logout
```
POST /api/v1/auth/logout/
POST /api/v1/auth/logout-all/
```

---

## 5. Single Sign‑On (SSO)

Supported providers:
- Google
- GitHub

### Flow
1. Client requests SSO start
2. Backend generates OAuth URL + signed `state`
3. Provider redirects to unified callback
4. User is logged in

### Endpoints
```
POST /api/v1/auth/sso/<provider>/
GET  /api/v1/auth/sso/callback/
```

- Unified callback
- Signed & time‑limited state
- One user per email
- SSO users can later set a password

---

## 6. Organisations & Memberships

### Create Org
```
POST /api/v1/orgs/create/
```

### List My Orgs
```
GET /api/v1/orgs/
```

### Membership Roles
- OWNER
- ADMIN
- MEMBER

Memberships define **org‑level access only**.

---

## 7. Authorization Model

### User‑Level (Global)

Used for:
- Internal dashboards
- Admin APIs
- System tools

Roles:
- END_USER (default)
- STAFF
- DATA_ADMIN
- SYSTEM_ADMIN

Permissions example:
```
internal.dashboard.view
internal.users.read
internal.audit.read
```

### Org‑Level (Scoped)

Used for:
- Org actions
- Member management

Permissions example:
```
org.view
member.invite
member.role.change
```

### Enforcement

All access checks go through **single guard functions**:
- `require_user_permission(...)`
- `require_permission(membership, ...)`

---

## 8. Active Sessions

Each login creates a `UserSession`:
- Refresh token JTI tracked
- Per‑device logout supported
- Logout‑all supported

Access tokens remain stateless.

---

## 9. Audit Logs

Audit logs are:
- Append‑only
- Immutable
- Compliance‑ready

Logged events include:
- Login / logout
- Registration
- Password changes
- Org creation
- Membership changes
- Role changes

---

## 10. Rate Limiting & Abuse Protection

Redis‑backed throttling protects:
- Login
- Forgot password
- SSO start
- Org invites

Endpoint‑specific limits are enforced via DRF throttles.

---

## 11. Admin Panel

Django admin provides:
- User management (with global roles)
- Organisations & members
- Active sessions
- Audit logs (read‑only)
- SSO identities
- Permission mappings

Django’s default permission system is intentionally **not used**.

---

## 12. Project Structure

```
config/
  settings/
  urls.py
users/
  models.py
  views.py
  permissions.py
  throttles.py
  audit.py
orgs/
  models.py
  views.py
  permissions.py
docker/
docker-compose.yml
```

---

## 13. Environment Variables

```
DATABASE_URL
REDIS_URL
SECRET_KEY
JWT_SECRET_KEY

GOOGLE_CLIENT_ID
GOOGLE_CLIENT_SECRET

GITHUB_CLIENT_ID
GITHUB_CLIENT_SECRET

FRONTEND_URL
EMAIL_HOST_USER
EMAIL_HOST_PASSWORD
```

---

## 14. Local Development

```bash
docker compose up --build
uv run python manage.py migrate
uv run python manage.py seed_permissions
```

Admin:
```
http://localhost/admin/
```

---

## 15. Extending the System

Recommended extensions:
- HttpOnly cookie token delivery
- Webhooks / event stream
- ABAC or policy engine
- Multi‑region session revocation

Avoid premature complexity.

---

## Philosophy

> Authentication proves identity.  
> Authorization proves intent.  
> Scopes must never bleed.

This service is designed to be **boring, predictable, and secure** —
exactly what authentication should be.
