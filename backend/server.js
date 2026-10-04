// ==========================================================================
// CyberShield Backend: server.js
// Express server with MongoDB connection, authentication, security and admin routes
// ==========================================================================

require("dotenv").config();

const express = require("express");
const cors = require("cors");

const connectDB = require("./src/config/db");

const authRoutes = require("./src/routes/authRoutes");
const adminRoutes = require("./src/routes/adminRoutes");
const securityRoutes = require("./src/routes/securityRoutes");

const app = express();
const PORT = process.env.PORT || 5000;

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
//
// POST /api/auth/register
// POST /api/auth/login
// GET  /api/auth/me
//

app.use("/api/auth", authRoutes);

// --------------------------------------------------------------------------
// Security API
// --------------------------------------------------------------------------
//
// GET /api/security/dashboard
// GET /api/security/events
// GET /api/security/alerts
//

app.use("/api/security", securityRoutes);

// --------------------------------------------------------------------------
// Admin API
// --------------------------------------------------------------------------
//
// GET   /api/admin/dashboard
// GET   /api/admin/security-events
// etc.
//

app.use("/api/admin", adminRoutes);

// --------------------------------------------------------------------------
// Database connection, then server startup
// --------------------------------------------------------------------------

const startServer = async () => {
  try {
    await connectDB();

    app.listen(PORT, () => {
      console.log(
        `CyberShield backend running on http://localhost:${PORT}`
      );
    });
  } catch (error) {
    console.error(
      "Failed to start CyberShield backend:",
      error.message
    );

    process.exit(1);
  }
};

startServer();