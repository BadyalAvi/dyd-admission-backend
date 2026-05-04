# NovaCrest Admission Portal
### Production-ready Full-Stack University Admission System

---

## Tech Stack
- **Backend**: Node.js + Express
- **Database**: LowDB (JSON file-based, zero native deps — works everywhere)
- **Auth**: JWT (students + admin with bcrypt hashed passwords)
- **Storage**: Local filesystem (uploaded docs stored in `data/uploads/`)
- **Frontend**: Vanilla HTML/CSS/JS (no build step required)

---

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Start the server
node server.js

# 3. Open in browser
# Student form:  http://localhost:3000
# Admin panel:   http://localhost:3000/admin.html
```

---

## Default Credentials
| Role  | Username | Password |
|-------|----------|----------|
| Admin | admin    | admin123 |

> Change password in production by updating the hash in `data/db.json`

---

## API Reference

### Auth
| Method | Route | Description |
|--------|-------|-------------|
| POST | `/api/auth/register` | Student registration |
| POST | `/api/auth/login` | Student login |
| POST | `/api/auth/admin-login` | Admin login |

### Applications
| Method | Route | Auth | Description |
|--------|-------|------|-------------|
| POST | `/api/applications/start` | None | Start new application, get App ID |
| PUT | `/api/applications/:appId` | None | Save/update any section |
| GET | `/api/applications/:appId` | Student/Admin | Get application details |
| POST | `/api/applications/:appId/submit` | Student | Final submission |
| POST | `/api/applications/:appId/upload` | None | Upload document file |

### Admin
| Method | Route | Auth | Description |
|--------|-------|------|-------------|
| GET | `/api/admin/applications` | Admin | List all (paginated, filterable) |
| GET | `/api/admin/applications/:appId` | Admin | Get full detail |
| PATCH | `/api/admin/applications/:appId` | Admin | Update status/remarks/admNo |
| DELETE | `/api/admin/applications/:appId` | Admin | Delete application |

---

## Data Storage
All data is stored in `data/db.json` — JSON format, human-readable, zero config.
Uploaded files are stored in `data/uploads/<appId>/`.

## Deploy to Production
1. Set environment variable: `JWT_SECRET=your-strong-secret-here`
2. Set `PORT=80` or use a reverse proxy (Nginx/Apache)
3. For production, consider migrating to SQLite or PostgreSQL by replacing the `db.js` module

---

## Features
- ✅ Multi-step form with real-time auto-save to backend
- ✅ File upload (photo, signature, 8 document types)
- ✅ JWT authentication for both students and admin
- ✅ Admin panel: list, search, filter, detail view, status updates
- ✅ Application status: Draft → Pending → Approved/Rejected/On Hold
- ✅ Auto-generated Application IDs (NCU-2025-XXXXX)
- ✅ Password hashing with bcrypt
- ✅ Rate-limiting ready (add express-rate-limit)
- ✅ Zero database setup — works out of the box
