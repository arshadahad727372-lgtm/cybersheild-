const express = require("express");

const auth = require("../middleware/auth");
const authorize = require("../middleware/authorize");
const SecurityEvent = require("../models/SecurityEvent");

const router = express.Router();

/*
|--------------------------------------------------------------------------
| ADMIN DASHBOARD
| GET /api/admin/dashboard
|--------------------------------------------------------------------------
*/

router.get(
  "/dashboard",
  auth,
  authorize("admin"),
  async (req, res) => {
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

      res.status(200).json({
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
          user: {
            id: req.user.id,
            role: req.user.role,
          },
        },
      });
    } catch (error) {
      console.error("Admin dashboard error:", error);

      res.status(500).json({
        success: false,
        message: "Failed to load admin dashboard",
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| SECURITY STATISTICS
| GET /api/admin/security-stats
|--------------------------------------------------------------------------
*/

router.get(
  "/security-stats",
  auth,
  authorize("admin"),
  async (req, res) => {
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

      res.status(200).json({
        success: true,
        data: {
          totalEvents,
          openEvents,
          investigatingEvents,
          resolvedEvents,
          criticalEvents,
          highEvents,
          failedLogins,
          successfulLogins,
        },
      });
    } catch (error) {
      console.error("Security stats error:", error);

      res.status(500).json({
        success: false,
        message: "Failed to load security statistics",
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| ALL SECURITY EVENTS
| GET /api/admin/security-events
|--------------------------------------------------------------------------
*/

router.get(
  "/security-events",
  auth,
  authorize("admin"),
  async (req, res) => {
    try {
      const events = await SecurityEvent.find()
        .sort({ createdAt: -1 })
        .limit(100)
        .populate("user", "name email")
        .lean();

      res.status(200).json({
        success: true,
        data: {
          events,
        },
      });
    } catch (error) {
      console.error("Get security events error:", error);

      res.status(500).json({
        success: false,
        message: "Failed to load security events",
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| RECENT SECURITY EVENTS
| GET /api/admin/security-events/recent
|--------------------------------------------------------------------------
*/

router.get(
  "/security-events/recent",
  auth,
  authorize("admin"),
  async (req, res) => {
    try {
      const events = await SecurityEvent.find()
        .sort({ createdAt: -1 })
        .limit(10)
        .populate("user", "name email")
        .lean();

      res.status(200).json({
        success: true,
        data: {
          events,
        },
      });
    } catch (error) {
      console.error("Recent security events error:", error);

      res.status(500).json({
        success: false,
        message: "Failed to load recent security events",
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| SINGLE SECURITY EVENT
| GET /api/admin/security-events/:id
|--------------------------------------------------------------------------
*/

router.get(
  "/security-events/:id",
  auth,
  authorize("admin"),
  async (req, res) => {
    try {
      const event = await SecurityEvent.findById(req.params.id)
        .populate("user", "name email")
        .lean();

      if (!event) {
        return res.status(404).json({
          success: false,
          message: "Security event not found",
        });
      }

      res.status(200).json({
        success: true,
        data: {
          event,
        },
      });
    } catch (error) {
      console.error("Get security event error:", error);

      res.status(500).json({
        success: false,
        message: "Failed to load security event",
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| UPDATE SECURITY EVENT STATUS
| PATCH /api/admin/security-events/:id/status
|--------------------------------------------------------------------------
*/

router.patch(
  "/security-events/:id/status",
  auth,
  authorize("admin"),
  async (req, res) => {
    try {
      const { status } = req.body;

      const allowedStatuses = [
        "open",
        "investigating",
        "resolved",
      ];

      if (!allowedStatuses.includes(status)) {
        return res.status(400).json({
          success: false,
          message:
            "Invalid status. Use open, investigating, or resolved.",
        });
      }

      const event = await SecurityEvent.findById(
        req.params.id
      );

      if (!event) {
        return res.status(404).json({
          success: false,
          message: "Security event not found",
        });
      }

      event.status = status;

      await event.save();

      res.status(200).json({
        success: true,
        message: "Security event status updated successfully",
        data: {
          event,
        },
      });
    } catch (error) {
      console.error("Update security event status error:", error);

      res.status(500).json({
        success: false,
        message: "Failed to update security event status",
      });
    }
  }
);

module.exports = router;