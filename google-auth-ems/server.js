const express = require('express');
const cors = require('cors');
const session = require('express-session');
const passport = require('passport');
const path = require('path');
const dotenv = require('dotenv');
const connectDB = require('./config/db');

// Load environment variables from .env
dotenv.config();

// Initialize MongoDB Connection
connectDB();

const app = express();

// Load Passport Configuration Strategy
require('./config/passport')(passport);

// Middlewares
app.use(cors({
  origin: process.env.CORS_ORIGINS || '*',
  credentials: true
}));

// Body parsers
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Express Session Configuration
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'a82bf9df1782bb31c9a4192b49c71e2c9060b9bc2f6c91a0c8d1976a11cbe2d3',
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 24 * 60 * 60 * 1000, // 24 Hours duration
      secure: process.env.NODE_ENV === 'production', // true in HTTPS production environments
      sameSite: 'lax'
    }
  })
);

// Bind Passport Session Initialization
app.use(passport.initialize());
app.use(passport.session());

// Mount Static Directories
app.use(express.static(path.join(__dirname, 'public')));

// Mount Endpoint Routing Paths
app.use('/auth', require('./routes/authRoutes'));
app.use('/api', require('./routes/dashboardRoutes'));

// Default Root Redirector
app.get('/', (req, res) => {
  if (req.isAuthenticated()) {
    res.redirect('/dashboard.html');
  } else {
    res.redirect('/login.html');
  }
});

// Safe Fallback Custom 404 handler
app.use((req, res, next) => {
  res.status(404).sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Centralized Error-handling Middleware
app.use((err, req, res, next) => {
  console.error('Unhandled Application Exception Context:', err);
  res.status(500).json({
    success: false,
    message: 'A critical backend application crash occurred.',
    error: process.env.NODE_ENV === 'development' ? err.message : {}
  });
});

const PORT = process.env.PORT || 5000;

const server = app.listen(PORT, () => {
  console.log(`Server bootstrap running in ${process.env.NODE_ENV || 'development'} mode on port ${PORT}`);
});

// Graceful Terminations listeners
process.on('unhandledRejection', (err) => {
  console.error(`Unhandled Server rejection error context: ${err.message}`);
  server.close(() => process.exit(1));
});
