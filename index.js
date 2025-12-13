// server.js
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");

const app = express();

// ---------------- Config ----------------
const PORT = Number(process.env.PORT) || 5000;
const DB_NAME = process.env.DB_NAME || "responseTeamDB";

let MONGO_URI = process.env.MONGO_URI || null;
if (!MONGO_URI && process.env.DB_USER && process.env.DB_PASS && process.env.DB_HOST) {
  MONGO_URI = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@${process.env.DB_HOST}`;
}
if (!MONGO_URI && process.env.DB_USER && process.env.DB_PASS) {
  MONGO_URI = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@flash0.v0bnf8w.mongodb.net/?appName=flash0`;
}
if (!MONGO_URI) console.warn("WARNING: MONGO_URI not set. Configure .env properly.");

// CORS origins: comma‑separated list in env, fallback to localhost
const CORS_ORIGINS = (process.env.CORS_ORIGINS ||
  "http://localhost:5173,http://localhost:3000")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// ---------------- Middlewares ----------------
app.use(helmet());            // basic security headers
app.use(morgan("dev"));       // HTTP logging
app.use(express.json({ limit: "1mb" })); // parse JSON body

// Fine‑grained CORS handling
const corsOptions = {
  origin: (origin, cb) => {
    if (!origin) return cb(null, true); // allow tools like Postman
    if (CORS_ORIGINS.includes(origin)) return cb(null, true);
    return cb(new Error("CORS policy: origin not allowed"), false);
  },
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  credentials: true,
};
app.use(cors(corsOptions));

// simple test route
app.get("/", (req, res) => res.send("Middleware setup complete"));

const PORT = Number(process.env.PORT) || 5000;
module.exports = { app };

if (require.main === module) {
  app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
}