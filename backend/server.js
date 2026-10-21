
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const connectDB = require("./src/config/db");

const authRoutes = require("./src/routes/authRoutes");
const adminRoutes = require("./src/routes/adminRoutes");
const securityRoutes = require("./src/routes/securityRoutes");

const app = express();

app.use(cors({
  origin: [
    "https://cybersheild-theta.vercel.app",
    "http://localhost:5173"
  ],
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json());

app.get("/", (req, res) => {
  res.status(200).json({
    success: true,
    message: "CyberShield Backend is running",
    version: "1.0.0"
  });
});

app.use("/api/auth", authRoutes);
app.use("/api/security", securityRoutes);
app.use("/api/admin", adminRoutes);

// Connect once and expose the connection promise for serverless requests.
const dbConnection = connectDB();
app.locals.dbConnection = dbConnection;

module.exports = app;
