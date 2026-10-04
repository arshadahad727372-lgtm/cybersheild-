// ==========================================================================
// CyberShield Backend: src/middleware/auth.js
// JWT authentication middleware
// Required env var: JWT_SECRET
// ==========================================================================

const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");

const unauthorized = (res) =>
  res.status(401).json({
    success: false,
    message: "Not authorized",
  });

const auth = (req, res, next) => {
  try {
    // 1. Read and validate the Authorization header: "Bearer <token>"
    const authHeader = req.headers.authorization;

    if (!authHeader || typeof authHeader !== "string") {
      return unauthorized(res);
    }

    const parts = authHeader.trim().split(/\s+/);

    if (parts.length !== 2 || parts[0].toLowerCase() !== "bearer") {
      return unauthorized(res);
    }

    const token = parts[1];

    if (!token) {
      return unauthorized(res);
    }

    // 2. Make sure the server is configured correctly
    const secret = process.env.JWT_SECRET;

    if (!secret) {
      console.error("[auth middleware] Server configuration error: JWT secret is not set");
      return res.status(500).json({
        success: false,
        message: "Internal server error",
      });
    }

    // 3. Verify the token (signature + expiry). Pin the algorithm to HS256,
    //    which is what jsonwebtoken uses by default for string secrets.
    const decoded = jwt.verify(token, secret, { algorithms: ["HS256"] });

    // 4. Validate the payload before trusting it
    if (
      !decoded ||
      typeof decoded !== "object" ||
      typeof decoded.id !== "string" ||
      !mongoose.isValidObjectId(decoded.id)
    ) {
      return unauthorized(res);
    }

    // 5. Attach only the necessary information to the request
    req.user = {
      id: decoded.id,
      role: decoded.role,
    };

    return next();
  } catch (error) {
    // Expired, invalid, or malformed tokens all get the same safe response.
    if (
      error instanceof jwt.TokenExpiredError ||
      error instanceof jwt.JsonWebTokenError ||
      error instanceof jwt.NotBeforeError
    ) {
      return unauthorized(res);
    }

    // Anything else is unexpected: log only the message, never tokens or headers.
    console.error("[auth middleware] Unexpected error:", error.message);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

module.exports = auth;