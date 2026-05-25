# Google Authentication System (Employee Management System SaaS)

A fully functional, highly secure, and visually stunning Google Authentication and Session management system for the Employee Management System website. Built on modern backend architectures using Node.js, Express, and MongoDB Mongoose, and secured through Passport.js Google OAuth 2.0 with session storage.

---

## 🚀 Quick Local Installation Guide

### Prerequisites
- [Node.js](https://nodejs.org/) installed (v16+ recommended).
- [MongoDB Atlas](https://www.mongodb.com/cloud/atlas) account and database instance running (or a local MongoDB instance).

### 1. Install Project Dependencies
Navigate to the project root directory in your terminal and install all required modules:
```bash
cd google-auth-ems
npm install
```

### 2. Configure Environment Secrets
1. Copy the `.env.example` file to create a working `.env` configuration file:
   ```bash
   cp .env.example .env
   ```
2. Open `.env` in your editor and input your real credentials:
   - **`MONGO_URI`**: Paste your secure MongoDB connection string.
   - **`SESSION_SECRET`**: Replace with a secure random 32-character key.
   - **`GOOGLE_CLIENT_ID`** & **`GOOGLE_CLIENT_SECRET`**: Generate these inside the Google Cloud Console (instructions below).
   - **`GOOGLE_CALLBACK_URL`**: Keep as `http://localhost:5000/auth/google/callback` for local development.

### 3. Bootstrap & Run Local Development Server
Boot up the development environment using `nodemon` (auto-reloads upon code modifications):
```bash
npm run dev
```
Alternatively, execute standard startup commands:
```bash
npm start
```
The server will bind, verify Mongoose connections, and output startup metrics:
```txt
MongoDB Connected: cluster0.v8h6j.mongodb.net
Server bootstrap running in development mode on port 5000
```
Open your browser and visit: `http://localhost:5000/`

### 🌟 Local Developer Sandbox Mode (Zero-Config Testing)
**No Google OAuth Credentials? No problem!** 
If the `GOOGLE_CLIENT_ID` or `GOOGLE_CLIENT_SECRET` environment variables are not configured in your `.env` file (or left as their default placeholder values), the system automatically activates **Local Developer Sandbox Mode**:
- Clicking **"Continue with Google"** will immediately bypass the Google consent page and log you into a beautifully simulated **Admin Developer Profile**.
- All session-based cookies, route guards, and MongoDB database storage triggers function exactly as they would in production, enabling you to test the complete dark/light theme, profile dropdowns, responsive layouts, and session locks out-of-the-box!

---

## 🛠️ Google Cloud Console Credentials Setup Instructions

Follow this checklist to generate your secure Client ID and Client Secret:

1. **Visit the Developer Console**:
   Go to the [Google Cloud Console](https://console.cloud.google.com/) and authenticate with your standard Google Account.

2. **Establish a New Project**:
   - Click the project selector dropdown at the top navigation bar and select **New Project**.
   - Input your project metadata name (e.g. `EMS-SaaS-Auth`) and click **Create**.

3. **Configure the OAuth Consent Screen**:
   - Navigate to the **OAuth consent screen** section on the left-side navigation drawer.
   - Select **External** as your User Type (allowing any corporate Gmail account to login) and click **Create**.
   - **App Information**:
     - Input your App name (e.g. `EMS Dashboard Portal`).
     - Pick a support email from the dropdown.
   - **Developer Contact Information**:
     - Input your notification email address.
   - Click **Save and Continue**.

4. **Assign API Permissions (Scopes)**:
   - In the **Scopes** stage, click **Add or Remove Scopes**.
   - Under standard scopes list, toggle:
     - `.../auth/userinfo.profile` (Accesses avatar picture and user display name)
     - `.../auth/userinfo.email` (Accesses primary email address)
   - Click **Update**, then **Save and Continue**.

5. **Generate Credentials Keys**:
   - Navigate to the **Credentials** page in the left drawer.
   - Click the **+ Create Credentials** button at the top bar and select **OAuth client ID**.
   - **Application Type**: Select **Web application** from the dropdown.
   - **Authorized JavaScript origins**:
     - Add: `http://localhost:5000`
   - **Authorized redirect URIs** (CRITICAL):
     - Add: `http://localhost:5000/auth/google/callback`
   - Click **Create**.

6. **Bind Secrets to environment variables**:
   - A modal will present your unique **Your Client ID** and **Your Client Secret** keys.
   - Copy these parameters and paste them directly into your local `google-auth-ems/.env` file:
     ```env
     GOOGLE_CLIENT_ID=your_copied_client_id.apps.googleusercontent.com
     GOOGLE_CLIENT_SECRET=GOCSPX-your_copied_client_secret
     ```

---

## 🛡️ Security Architecture Checklist

This repository implements industry-standard safety practices to protect user sessions and database credentials:

- **Mongoose User Profiler**: Automatically validates and sanitizes input data.
- **Session-Based Authentication Gates**: Standard page and API endpoints are protected using robust custom middleware selectors (`ensureAuth` and `ensureGuest`), completely blocking unauthorized session bypass attempts.
- **Passport Google OAuth 2.0 State Verification**: Safely verifies Google profiles, updates login metrics inside MongoDB collection, and serializes only the unique MongoDB user `_id` into session cookies (`connect.sid`), keeping credentials completely hidden.
- **Database Cascade Syncs**: Deployed index protections ensure no email duplication across different Google profiles can trigger write exceptions.
