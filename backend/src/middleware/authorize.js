// ==========================================================================
// CyberShield Backend: src/middleware/authorize.js
// Role-based authorization middleware factory
//
// Usage (always place after the auth middleware):
//   router.get("/admin-only", auth, authorize("admin"), handler);
//   router.get("/shared", auth, authorize("admin", "user"), handler);
// ==========================================================================

const authorize = (...allowedRoles) => {
  // Developer configuration checks: fail fast when the route is defined,
  // not later when a request arrives.
  if (allowedRoles.length === 0) {
    throw new Error("authorize() requires at least one allowed role");
  }

  if (allowedRoles.some((role) => typeof role !== "string" || role.trim() === "")) {
    throw new Error("authorize() roles must be non-empty strings");
  }

  const roles = new Set(allowedRoles.map((role) => role.trim()));

  return (req, res, next) => {
    // req.user is set only by the auth middleware after JWT verification.
    if (!req.user || typeof req.user.role !== "string") {
      return res.status(401).json({
        success: false,
        message: "Not authorized",
      });
    }

    if (!roles.has(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: "Forbidden",
      });
    }

    return next();
  };
};

module.exports = authorize;