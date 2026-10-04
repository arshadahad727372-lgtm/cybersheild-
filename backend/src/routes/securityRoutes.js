const express = require("express");

const {
  getDashboard,
  getSecurityEvents,
  getSecurityAlerts,
} = require("../controllers/securityController");

const auth = require("../middleware/auth");

const router = express.Router();

router.get("/dashboard", auth, getDashboard);

router.get("/events", auth, getSecurityEvents);

router.get("/alerts", auth, getSecurityAlerts);

module.exports = router;