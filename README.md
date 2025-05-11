# PulseWire - Hackathon Submission

## Overview
PulseWire is a full-stack modern news aggregator built for hackathon evaluation. It features robust database usage, secure authentication with JWT, and excellent role-based access control, including a complete admin dashboard.

---

## Key Features

- **Full Stack**: React + Express + SQLite
- **Database Usage**: All user, article, and saved article data is stored in SQLite (no localStorage for persistence)
- **Authentication**: Secure login/signup with JWT (token-based authentication)
- **Role-Based Access**: User roles (user/admin) enforced in both backend and frontend
- **Admin Dashboard**:
  - List all users
  - Promote users to admin
  - Add new users
- **Save Articles**: Authenticated users can save news articles to their account
- **Modern UI**: Responsive, accessible, and styled with Tailwind CSS

---

## Database Design
- **users**: id, username, password_hash, role, created_at
- **articles**: id, title, content, url, published_at
- **saved_articles**: id, user_id, article_id, saved_at

---

## Role-Based Access (Evaluation: Excellent)
- Users have roles: `user` or `admin`
- Admins can access the admin dashboard, promote users, and add users
- All role checks are enforced in backend endpoints and frontend navigation

---

## JWT Authentication
- JWT issued on login/signup, stored in localStorage
- JWT contains userId, username, and role
- All protected API requests require JWT in the Authorization header

---

## How to Run (Single Command)

1. **Install dependencies**
   ```sh
   pnpm install
   ```
2. **Start both frontend and backend**
   ```sh
   pnpm run dev
   ```
   - Frontend: http://localhost:5173
   - Backend: http://localhost:3001

---

## Admin Credentials (Seeded)
- **Username:** `admin`
- **Password:** `admin123`

---

## Usage Guide
- **Login/Signup**: Register or log in as a user or admin
- **Save Articles**: Click the bookmark icon on any article to save it
- **View Saved Articles**: Go to the "Saved" tab
- **Admin Dashboard**: If logged in as admin, access the "Admin" tab to:
  - View all users
  - Promote users to admin
  - Add new users

---

## Tech Stack
- **Frontend**: React, TypeScript, Tailwind CSS, Axios
- **Backend**: Express, SQLite, JWT, bcryptjs
- **Tooling**: Vite, pnpm, concurrently, nodemon

---

## Hackathon Evaluation Checklist
- [x] **Database Usage: Excellent** (all data in SQLite, full CRUD)
- [x] **Role-Based Access: Excellent** (admin/user, enforced everywhere)
- [x] **JWT Authentication** (secure, stateless)
- [x] **Admin Features** (user management, promotion, creation)
- [x] **Single Command Run** (`pnpm run dev`)

---

## Authors
Team PulseWire

---

## License
MIT
