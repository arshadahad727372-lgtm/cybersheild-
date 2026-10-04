// ==========================================================================
// CyberShield Backend: src/routes/authRoutes.js
// Authentication routes (mounted at /api/auth in server.js)
// ==========================================================================

const express = require("express");

const { register, login, getMe } = require("../controllers/authController");

// auth.js exports the middleware function directly (module.exports = auth),
// so it is imported without curly braces.
const auth = require("../middleware/auth");

const router = express.Router();

// --------------------------------------------------------------------------
// PUBLIC ROUTES: no authentication required
// --------------------------------------------------------------------------

// POST /register: create a new user account
router.post("/register", register);

// POST /login: verify credentials and receive a JWT
router.post("/login", login);

// --------------------------------------------------------------------------
// PROTECTED ROUTES: valid JWT required (Authorization: Bearer <token>)
// The auth middleware runs first, then the controller.
// --------------------------------------------------------------------------

// GET /me: return the currently authenticated user
router.get("/me", auth, getMe);

module.exports = router;