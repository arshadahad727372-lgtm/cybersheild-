const SecurityEvent = require("../models/SecurityEvent");

// GET /api/security/dashboard
const getDashboard = async (req, res) => {
  try {
    const [
      totalEvents,
      openEvents,
      investigatingEvents,
      resolvedEvents,
      criticalEvents,
      highEvents,
      failedLogins,
      successfulLogins,
    ] = await Promise.all([
      SecurityEvent.countDocuments(),
      SecurityEvent.countDocuments({ status: "open" }),
      SecurityEvent.countDocuments({ status: "investigating" }),
      SecurityEvent.countDocuments({ status: "resolved" }),
      SecurityEvent.countDocuments({ severity: "critical" }),
      SecurityEvent.countDocuments({ severity: "high" }),
      SecurityEvent.countDocuments({ type: "login_failed" }),
      SecurityEvent.countDocuments({ type: "login_success" }),
    ]);

    const recentEvents = await SecurityEvent.find()
      .sort({ createdAt: -1 })
      .limit(10)
      .populate("user", "name email")
      .lean();

    const alerts = await SecurityEvent.find({
      type: "suspicious_activity",
    })
      .sort({ createdAt: -1 })
      .limit(10)
      .populate("user", "name email")
      .lean();

    res.json({
      success: true,
      data: {
        stats: {
          totalEvents,
          openEvents,
          investigatingEvents,
          resolvedEvents,
          criticalEvents,
          highEvents,
          failedLogins,
          successfulLogins,
        },
        recentEvents,
        alerts,
      },
    });
  } catch (error) {
    console.error("getDashboard error:", error);

    res.status(500).json({
      success: false,
      message: "Failed to load security dashboard",
    });
  }
};


// GET /api/security/events
const getSecurityEvents = async (req, res) => {
  try {
    const events = await SecurityEvent.find()
      .sort({ createdAt: -1 })
      .limit(100)
      .populate("user", "name email")
      .lean();

    res.json({
      success: true,
      data: {
        events,
      },
    });
  } catch (error) {
    console.error("getSecurityEvents error:", error);

    res.status(500).json({
      success: false,
      message: "Failed to load security events",
    });
  }
};


// GET /api/security/alerts
const getSecurityAlerts = async (req, res) => {
  try {
    const alerts = await SecurityEvent.find({
      type: "suspicious_activity",
    })
      .sort({ createdAt: -1 })
      .limit(100)
      .populate("user", "name email")
      .lean();

    res.json({
      success: true,
      data: {
        alerts,
      },
    });
  } catch (error) {
    console.error("getSecurityAlerts error:", error);

    res.status(500).json({
      success: false,
      message: "Failed to load security alerts",
    });
  }
};


module.exports = {
  getDashboard,
  getSecurityEvents,
  getSecurityAlerts,
};