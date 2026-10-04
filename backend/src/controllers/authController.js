// ==========================================================================
// CyberShield Backend: src/controllers/authController.js
// Authentication controller: register, login, getMe
//
// Includes:
// - User registration
// - Secure login
// - JWT generation
// - Failed-login security logging
// - Suspicious login activity detection
// - Suspicious alert deduplication
// - Current-user retrieval
//
// Requires: npm install zod
// Required env vars: JWT_SECRET
// Optional env vars: JWT_EXPIRES_IN (default "1d")
// ==========================================================================

const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const { z } = require("zod");

const User = require("../models/User");
const SecurityEvent = require("../models/SecurityEvent");
const { logSecurityEvent } = require("../services/securityService");

// --------------------------------------------------------------------------
// Constants
// --------------------------------------------------------------------------

const SALT_ROUNDS = 12;
const DEFAULT_JWT_EXPIRES_IN = "1d";
const MAX_PASSWORD_LENGTH = 72;

// Suspicious activity detection
const FAILED_LOGIN_THRESHOLD = 5;
const FAILED_LOGIN_WINDOW_MINUTES = 15;

// Dummy hash used for unknown emails so login timing is more consistent.
const DUMMY_HASH = bcrypt.hashSync(
  "cybershield-dummy-password",
  SALT_ROUNDS
);

// --------------------------------------------------------------------------
// Validation schemas
// --------------------------------------------------------------------------

const registerSchema = z.object({
  name: z
    .string({ required_error: "Name is required" })
    .trim()
    .min(1, "Name is required")
    .max(100, "Name must be at most 100 characters"),

  email: z
    .string({ required_error: "Email is required" })
    .trim()
    .toLowerCase()
    .email("Please provide a valid email address")
    .max(254, "Email is too long"),

  password: z
    .string({ required_error: "Password is required" })
    .min(6, "Password must be at least 6 characters")
    .max(
      MAX_PASSWORD_LENGTH,
      `Password must be at most ${MAX_PASSWORD_LENGTH} characters`
    ),
});

const loginSchema = z.object({
  email: z
    .string({ required_error: "Email is required" })
    .trim()
    .toLowerCase()
    .email("Please provide a valid email address"),

  password: z
    .string({ required_error: "Password is required" })
    .min(1, "Password is required")
    .max(MAX_PASSWORD_LENGTH, "Invalid email or password"),
});

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

const toSafeUser = (user) => ({
  id: user._id,
  name: user.name,
  email: user.email,
  role: user.role,
  isActive: user.isActive,
  createdAt: user.createdAt,
  updatedAt: user.updatedAt,
});

const formatValidationErrors = (zodError) =>
  zodError.issues.map((issue) => ({
    field: issue.path.join("."),
    message: issue.message,
  }));

const sendValidationError = (res, zodError) =>
  res.status(400).json({
    success: false,
    message: "Validation failed",
    errors: formatValidationErrors(zodError),
  });

const sendServerError = (res, label, error) => {
  console.error(`[auth] ${label}:`, error.message);

  return res.status(500).json({
    success: false,
    message: "Internal server error",
  });
};

// --------------------------------------------------------------------------
// Security event helper
// --------------------------------------------------------------------------

const safeLogSecurityEvent = async (eventData) => {
  try {
    await logSecurityEvent(eventData);
  } catch (error) {
    // Security logging must never break the authentication request.
    // Only safe diagnostic information is logged.
    console.error(
      "[auth] Security event logging failed:",
      error.name,
      error.message
    );
  }
};

// --------------------------------------------------------------------------
// Suspicious login activity detection
// --------------------------------------------------------------------------

const detectSuspiciousLoginActivity = async ({
  email,
  ipAddress,
  user,
  userAgent,
}) => {
  try {
    // Do not attempt detection without an IP address.
    if (
      typeof ipAddress !== "string" ||
      ipAddress.trim() === ""
    ) {
      return;
    }

    const windowStart = new Date(
      Date.now() -
        FAILED_LOGIN_WINDOW_MINUTES * 60 * 1000
    );

    // Count failed login attempts from this IP
    // within the detection window.
    const failedLoginCount =
      await SecurityEvent.countDocuments({
        type: "login_failed",
        ipAddress,
        createdAt: {
          $gte: windowStart,
        },
      });

    // Threshold has not been reached yet.
    if (failedLoginCount < FAILED_LOGIN_THRESHOLD) {
      return;
    }

    // Check whether an unresolved suspicious-activity
    // alert already exists for this IP within the same window.
    const existingAlert =
      await SecurityEvent.exists({
        type: "suspicious_activity",
        ipAddress,
        status: {
          $in: ["open", "investigating"],
        },
        createdAt: {
          $gte: windowStart,
        },
      });

    // An alert already exists, so do not create another one.
    if (existingAlert) {
      return;
    }

    // Create one high-severity suspicious-activity alert.
    await safeLogSecurityEvent({
      type: "suspicious_activity",
      severity: "high",
      user: user || null,
      email: email || null,
      ipAddress,
      userAgent,
      message:
        "Repeated failed login attempts detected",
      metadata: {
        failedLoginCount,
        threshold: FAILED_LOGIN_THRESHOLD,
        windowMinutes:
          FAILED_LOGIN_WINDOW_MINUTES,
      },
    });
  } catch (error) {
    // Detection must never break the login request.
    console.error(
      "[auth] Suspicious activity detection failed:",
      error.name,
      error.message
    );
  }
};

// --------------------------------------------------------------------------
// JWT
// --------------------------------------------------------------------------

const generateToken = (user) => {
  const secret = process.env.JWT_SECRET;

  if (!secret) {
    throw new Error("JWT_SECRET is not configured");
  }

  return jwt.sign(
    {
      id: user._id.toString(),
      role: user.role,
    },
    secret,
    {
      expiresIn:
        process.env.JWT_EXPIRES_IN ||
        DEFAULT_JWT_EXPIRES_IN,
    }
  );
};

// --------------------------------------------------------------------------
// POST /register
// --------------------------------------------------------------------------

const register = async (req, res) => {
  try {
    const parsed = registerSchema.safeParse(req.body);

    if (!parsed.success) {
      return sendValidationError(res, parsed.error);
    }

    const { name, email, password } = parsed.data;

    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message:
          "An account with this email already exists",
      });
    }

    const hashedPassword = await bcrypt.hash(
      password,
      SALT_ROUNDS
    );

    // Role is intentionally NOT taken from req.body.
    // New accounts always use the User model default: "user".
    const user = await User.create({
      name,
      email,
      password: hashedPassword,
    });

    return res.status(201).json({
      success: true,
      message: "Registration successful",
      data: {
        user: toSafeUser(user),
      },
    });
  } catch (error) {
    // Handle MongoDB duplicate-key race condition.
    if (error && error.code === 11000) {
      return res.status(409).json({
        success: false,
        message:
          "An account with this email already exists",
      });
    }

    return sendServerError(
      res,
      "register failed",
      error
    );
  }
};

// --------------------------------------------------------------------------
// POST /login
// --------------------------------------------------------------------------

const login = async (req, res) => {
  try {
    const parsed = loginSchema.safeParse(req.body);

    if (!parsed.success) {
      return sendValidationError(res, parsed.error);
    }

    const { email, password } = parsed.data;

    const user = await User.findOne({ email }).select(
      "+password"
    );

    // Always perform bcrypt comparison, even if the email
    // doesn't exist, to reduce timing-based account discovery.
    const hashToCheck = user
      ? user.password
      : DUMMY_HASH;

    const passwordMatches = await bcrypt.compare(
      password,
      hashToCheck
    );

    // ----------------------------------------------------------------------
    // FAILED LOGIN
    // ----------------------------------------------------------------------

    if (!user || !passwordMatches) {
      const ipAddress = req.ip;
      const userAgent = req.get("user-agent");

      // Log the individual failed login.
      await safeLogSecurityEvent({
        type: "login_failed",
        severity: "medium",
        user: user ? user._id : null,
        email,
        ipAddress,
        userAgent,
        message: "Failed login attempt",
      });

      // Check whether repeated failed attempts from this
      // IP address have reached the suspicious-activity threshold.
      await detectSuspiciousLoginActivity({
        email,
        ipAddress,
        user: user ? user._id : null,
        userAgent,
      });

      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    // ----------------------------------------------------------------------
    // INACTIVE ACCOUNT
    // ----------------------------------------------------------------------

    if (!user.isActive) {
      return res.status(403).json({
        success: false,
        message:
          "This account has been deactivated. Please contact support.",
      });
    }

    // ----------------------------------------------------------------------
    // SUCCESSFUL LOGIN
    // ----------------------------------------------------------------------

    const token = generateToken(user);

    await safeLogSecurityEvent({
      type: "login_success",
      severity: "low",
      user: user._id,
      email: user.email,
      ipAddress: req.ip,
      userAgent: req.get("user-agent"),
      message: "Successful login",
    });

    return res.status(200).json({
      success: true,
      message: "Login successful",
      data: {
        token,
        user: toSafeUser(user),
      },
    });
  } catch (error) {
    return sendServerError(
      res,
      "login failed",
      error
    );
  }
};

// --------------------------------------------------------------------------
// GET /me
// --------------------------------------------------------------------------

const getMe = async (req, res) => {
  try {
    const userId = req.user && req.user.id;

    if (
      !userId ||
      !mongoose.isValidObjectId(userId)
    ) {
      return res.status(401).json({
        success: false,
        message: "Not authorized",
      });
    }

    const user = await User.findById(userId).select(
      "-password"
    );

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    if (!user.isActive) {
      return res.status(403).json({
        success: false,
        message:
          "This account has been deactivated. Please contact support.",
      });
    }

    return res.status(200).json({
      success: true,
      data: {
        user: toSafeUser(user),
      },
    });
  } catch (error) {
    return sendServerError(
      res,
      "getMe failed",
      error
    );
  }
};

// --------------------------------------------------------------------------
// Exports
// --------------------------------------------------------------------------

module.exports = {
  register,
  login,
  getMe,
};