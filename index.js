// server.js
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const { MongoClient, ServerApiVersion } = require("mongodb");
const stripe = require("stripe")(process.env.STRIPE_SECRET);   // <-- Stripe SDK

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

// ---------------- Helpers ----------------
const wrap = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

// ---------------- Stripe: create PaymentIntent ----------------
app.post(
  "/payments/create-payment-intent",
  wrap(async (req, res) => {
    const { amount, currency = "usd", userEmail, description = "" } = req.body || {};
    if (!amount || !userEmail)
      return res.status(400).send({ ok: false, message: "amount and userEmail required" });

    const amt = Number(amount);
    if (Number.isNaN(amt) || amt <= 0)
      return res.status(400).send({ ok: false, message: "Invalid amount" });

    const amountInCents = Math.round(amt * 100);
    try {
      const paymentIntent = await stripe.paymentIntents.create({
        amount: amountInCents,
        currency,
        receipt_email: userEmail,
        description,
        metadata: { userEmail },
      });
      res.send({ ok: true, clientSecret: paymentIntent.client_secret });
    } catch (err) {
      console.error("Stripe PaymentIntent error:", err);
      res.status(500).send({ ok: false, message: "Could not create payment intent" });
    }
  })
);

// ------------- Test route -------------
app.get("/", (req, res) => res.send("Stripe PaymentIntent endpoint active"));

// Exports & start
module.exports = { app, connectDB, closeDb };

if (require.main === module) {
  app.listen(PORT, () => console.log(`✅ Server listening on port ${PORT}`));
}