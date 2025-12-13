// server.js
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const { MongoClient, ServerApiVersion } = require("mongodb");

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
if (!MONGO_URI) console.warn("WARNING: MONGO_URI not set. Configure .env correctly.");

// ---------------- Middleware ----------------
const CORS_ORIGINS = (process.env.CORS_ORIGINS ||
  "http://localhost:5173,http://localhost:3000")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

app.use(helmet());
app.use(morgan("dev"));
app.use(express.json({ limit: "1mb" }));

const corsOptions = {
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (CORS_ORIGINS.includes(origin)) return cb(null, true);
    return cb(new Error("CORS policy: origin not allowed"), false);
  },
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  credentials: true,
};
app.use(cors(corsOptions));

// ---------------- MongoDB (cached) ----------------
let cachedClient = null;
let cachedDb = null;

async function connectDB() {
  if (cachedDb && cachedClient) return { client: cachedClient, db: cachedDb };
  if (!MONGO_URI) throw new Error("MONGO_URI not configured");

  const client = new MongoClient(MONGO_URI, {
    serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
  });

  await client.connect();
  const db = client.db(DB_NAME);

  cachedClient = client;
  cachedDb = db;

  console.log("✅ MongoDB connected and cached");
  return { client, db };
}

async function closeDb() {
  if (cachedClient) {
    await cachedClient.close();
    cachedClient = null;
    cachedDb = null;
    console.log("MongoDB connection closed.");
  }
}

// ------------- Test route -------------
app.get("/", (req, res) => res.send("Database connection utilities ready"));

// Exports & start
module.exports = { app, connectDB, closeDb };

if (require.main === module) {
  app.listen(PORT, () => console.log(`✅ Server listening on port ${PORT}`));
}