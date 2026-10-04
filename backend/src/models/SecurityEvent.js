// ==========================================================================
// CyberShield Backend: src/models/SecurityEvent.js
// Mongoose SecurityEvent model
//
// Stores security-related events (logins, lockouts, admin actions, etc.)
// so they can be reviewed in the dashboard.
//
// SECURITY: never store passwords, JWT tokens, API keys or other secrets
// in any field of this model, including the free-form `metadata` object.
// ==========================================================================

const mongoose = require("mongoose");

const securityEventSchema = new mongoose.Schema(
  {
    // What kind of event happened
    type: {
      type: String,
      required: [true, "Event type is required"],
      enum: [
        "login_success",
        "login_failed",
        "logout",
        "suspicious_activity",
        "account_locked",
        "admin_action",
      ],
      trim: true,
    },

    // How serious the event is
    severity: {
      type: String,
      enum: ["low", "medium", "high", "critical"],
      default: "low",
    },

    // The user involved, if known (null for failed logins with unknown accounts)
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },

    // Email involved in the event (useful when no matching user exists)
    email: {
      type: String,
      lowercase: true,
      trim: true,
      default: null,
    },

    // Network and client details of the request
    ipAddress: {
      type: String,
      trim: true,
      default: null,
    },
    userAgent: {
      type: String,
      trim: true,
      default: null,
    },

    // Short human-readable description of the event
    message: {
      type: String,
      required: [true, "Event message is required"],
      trim: true,
      maxlength: [500, "Message must be at most 500 characters"],
    },

    // Extra non-sensitive details (never put secrets or tokens here)
    metadata: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },

    // Review workflow state
    status: {
      type: String,
      enum: ["open", "investigating", "resolved"],
      default: "open",
    },
  },
  {
    timestamps: true, // adds createdAt and updatedAt automatically
  }
);

// --------------------------------------------------------------------------
// Indexes (speed up the most common dashboard queries)
// --------------------------------------------------------------------------

// Newest events first
securityEventSchema.index({ createdAt: -1 });

// Filter by severity and status (e.g. all open critical events)
securityEventSchema.index({ severity: 1, status: 1 });

// Filter by event type, newest first (e.g. recent failed logins)
securityEventSchema.index({ type: 1, createdAt: -1 });

// Activity history of one user, newest first
securityEventSchema.index({ user: 1, createdAt: -1 });

module.exports = mongoose.model("SecurityEvent", securityEventSchema);