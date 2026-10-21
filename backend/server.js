
/**
 * CyberShield Backend: server.js
 * Express server with MongoDB connection, authentication,
 * security and admin routes.
 */

require("dotenv").config();

const express = require("express");
const cors = require("cors");

const connectDB = require("./src/config/db");

const authRoutes = require("./src/routes/authRoutes");
const adminRoutes = require("./src/routes/adminRoutes");
const securityRoutes = require("./src/routes/securityRoutes");

const app = express();

// --------------------------------------------------------------------------
// Middleware
// --------------------------------------------------------------------------

app.use(cors());
app.use(express.json());

// --------------------------------------------------------------------------
// Health check
// --------------------------------------------------------------------------

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "CyberShield Backend is running 🚀",
    version: "1.0.0",
  });
});

// --------------------------------------------------------------------------
// Authentication API
// --------------------------------------------------------------------------

app.use("/api/auth", authRoutes);

// --------------------------------------------------------------------------
// Security API
// --------------------------------------------------------------------------

app.use("/api/security", securityRoutes);

// --------------------------------------------------------------------------
// Admin API
// --------------------------------------------------------------------------

app.use("/api/admin", adminRoutes);

// --------------------------------------------------------------------------
// Database connection and Vercel export
// --------------------------------------------------------------------------

const dbConnection = connectDB();

app.locals.dbConnection = dbConnection;

// Export the Express app for Vercel's serverless handler.
module.exports = app;
