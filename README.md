# MERN Auth Project

A full-stack authentication system built with the MERN stack (MongoDB, Express.js, React, Node.js).

## Features
- User registration and login with JWT authentication
- Email verification with OTP
- Password reset via email OTP
- Secure HTTP-only cookies for authentication
- Responsive React frontend with protected routes
- Toast notifications for user feedback

## Folder Structure

```
Mern auth/
├── client/           # React frontend
│   ├── public/
│   └── src/
│       ├── assets/
│       ├── components/
│       ├── context/
│       ├── pages/
│       ├── App.jsx
│       ├── main.jsx
│       └── index.css
├── server/           # Node.js/Express backend
│   ├── config/
│   ├── controllers/
│   ├── middleware/
│   ├── models/
│   ├── routes/
│   ├── server.js
│   └── .env
```

## Getting Started

### Prerequisites
- Node.js (v18+ recommended)
- MongoDB (local or Atlas)

### Backend Setup
1. Go to the `server` folder:
   ```bash
   cd server
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Create a `.env` file with the following variables:
   ```env
   PORT=4000
   MONGODB_URI=your_mongodb_connection_string
   JWT_SECRET=your_jwt_secret
   SENDER_EMAIL=your_email@example.com
   SENDER_PASSWORD=your_email_password
   NODE_ENV=development
   ```
4. Start the backend:
   ```bash
   npm start
   ```

### Frontend Setup
1. Go to the `client` folder:
   ```bash
   cd client
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Create a `.env` file with the following variable:
   ```env
   VITE_BACKEND_URL=http://localhost:4000
   ```
4. Start the frontend:
   ```bash
   npm run dev
   ```

### Usage
- Visit `http://localhost:5173` in your browser.
- Register a new account, verify your email, and log in.
- Try password reset and protected routes.

## Notes
- For email features, use a real email and app password (e.g., Gmail App Password).
- For local development, cookies are set with `SameSite=Lax` and `secure: false`.
- Update CORS and environment variables as needed for production.

## License
MIT
