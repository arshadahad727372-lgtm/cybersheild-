// ==========================================================================
// CyberShield Backend: src/services/securityService.js
// Central service for creating security events
//
// Use this from controllers, middleware and future security modules instead
// of calling SecurityEvent.create() directly, so every event is validated,
// limited to known fields, and stripped of secrets in one place.
//
// Example:
//   await logSecurityEvent({
//     type: "login_failed",
//     severity: "medium",
//     email: "user@example.com",
//     ipAddress: req.ip,
//     userAgent: req.get("user-agent"),
//     message: "Failed login attempt",
//   });
// ==========================================================================

const SecurityEvent = require("../models/SecurityEvent");

// --------------------------------------------------------------------------
// Secret protection for the free-form `metadata` object
// --------------------------------------------------------------------------

// Any metadata key containing one of these fragments is removed.
// Keys are lowercased and stripped of symbols first, so "accessToken",
// "access_token" and "Access-Token" are all caught by "token".
const SENSITIVE_KEY_FRAGMENTS = [
  "password",
  "passwd",
  "token", // accessToken, refreshToken, csrfToken, ...
  "jwt",
  "secret",
  "apikey",
  "authorization",
  "cookie",
  "credential",
  "privatekey",
];

// Prevents huge or circular objects from being processed forever.
const MAX_METADATA_DEPTH = 5;

const isSensitiveKey = (key) => {
  const normalized = String(key).toLowerCase().replace(/[^a-z0-9]/g, "");
  return SENSITIVE_KEY_FRAGMENTS.some((fragment) => normalized.includes(fragment));
};

const isPlainObject = (value) => {
  if (Object.prototype.toString.call(value) !== "[object Object]") {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
};

// Recursively copy a value, dropping sensitive keys.
// Returns undefined for values that should be discarded.
const sanitizeValue = (value, depth) => {
  if (depth > MAX_METADATA_DEPTH) {
    return undefined;
  }

  if (typeof value === "function" || typeof value === "symbol") {
    return undefined;
  }

  if (Array.isArray(value)) {
    return value
      .map((item) => sanitizeValue(item, depth + 1))
      .filter((item) => item !== undefined);
  }

  if (isPlainObject(value)) {
    const clean = {};
    for (const [key, nested] of Object.entries(value)) {
      if (isSensitiveKey(key)) {
        continue;
      }
      const cleanNested = sanitizeValue(nested, depth + 1);
      if (cleanNested !== undefined) {
        clean[key] = cleanNested;
      }
    }
    return clean;
  }

  // Primitives, Dates, ObjectIds, etc. are kept as they are.
  return value;
};

const sanitizeMetadata = (metadata) => {
  if (!isPlainObject(metadata)) {
    return {};
  }
  return sanitizeValue(metadata, 0) || {};
};

// --------------------------------------------------------------------------
// logSecurityEvent
// --------------------------------------------------------------------------

/**
 * Create and save a security event.
 *
 * Only the fields listed below are read from the input. Anything else
 * (for example password, accessToken or authorization) is ignored, and
 * sensitive keys inside `metadata` are removed.
 *
 * @param {object} eventData
 * @param {string} eventData.type        Required. One of the SecurityEvent types.
 * @param {string} eventData.message     Required. Short description (max 500 chars).
 * @param {string} [eventData.severity]  Defaults to "low".
 * @param {*}      [eventData.user]      User ObjectId or null.
 * @param {string} [eventData.email]     Defaults to null.
 * @param {string} [eventData.ipAddress] Defaults to null.
 * @param {string} [eventData.userAgent] Defaults to null.
 * @param {object} [eventData.metadata]  Non-sensitive extra details. Defaults to {}.
 * @param {string} [eventData.status]    Defaults to "open".
 * @returns {Promise<object>} The created SecurityEvent document.
 * @throws {Error} If type or message is missing, or the event cannot be saved.
 */
const logSecurityEvent = async (eventData = {}) => {
  // Whitelist: pick only the allowed fields; everything else is ignored.
  const {
    type,
    severity = "low",
    user = null,
    email = null,
    ipAddress = null,
    userAgent = null,
    message,
    metadata = {},
    status = "open",
  } = eventData && typeof eventData === "object" ? eventData : {};

  // Required fields
  if (typeof type !== "string" || type.trim() === "") {
    throw new Error("logSecurityEvent: 'type' is required");
  }

  if (typeof message !== "string" || message.trim() === "") {
    throw new Error("logSecurityEvent: 'message' is required");
  }

  try {
    return await SecurityEvent.create({
      type,
      severity,
      user: user || null,
      email: email || null,
      ipAddress: ipAddress || null,
      userAgent: userAgent || null,
      message,
      metadata: sanitizeMetadata(metadata),
      status,
    });
  } catch (error) {
    // Invalid values (for example an unknown type or severity): report only
    // which fields failed, never the values that were submitted.
    if (error && error.name === "ValidationError") {
      const fields = Object.keys(error.errors || {}).join(", ");
      throw new Error(`logSecurityEvent: invalid event data (${fields})`);
    }

    // Anything else (for example a database problem): log only a safe label.
    // The raw error is not logged because it may contain connection details
    // or submitted data.
    console.error("[security] Failed to save security event");
    throw new Error("logSecurityEvent: failed to save security event");
  }
};

module.exports = {
  logSecurityEvent,
};