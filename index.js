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

// ---------------- Stripe: create Checkout Session ----------------
app.post(
  "/create-checkout-session",
  wrap(async (req, res) => {
    const { amount, currency = "usd", userEmail, name = "Donation" } = req.body || {};
    if (!amount || !userEmail)
      return res.status(400).send({ ok: false, message: "amount and userEmail required" });

    const amt = Number(amount);
    if (Number.isNaN(amt) || amt <= 0)
      return res.status(400).send({ ok: false, message: "Invalid amount" });

    const amountCents = Math.round(amt * 100);

    try {
      const session = await stripe.checkout.sessions.create({
        mode: "payment",
        line_items: [
          {
            price_data: {
              currency,
              product_data: { name },
              unit_amount: amountCents,
            },
            quantity: 1,
          },
        ],
        customer_email: userEmail,
        metadata: { userEmail },
        success_url: `${process.env.CLIENT_URL || "http://localhost:5173"}/dashboard/funding-success`,
        cancel_url: `${process.env.CLIENT_URL || "http://localhost:5173"}/funding-cancel`,
      });

      res.send({ ok: true, url: session.url, id: session.id });
    } catch (err) {
      console.error("create-checkout-session error:", err);
      res.status(500).send({ ok: false, message: "Could not create checkout session" });
    }
  })
);

// ---------------- Stripe: retrieve Checkout Session ----------------
app.get(
  "/checkout-session",
  wrap(async (req, res) => {
    const sessionId = req.query.session_id || req.headers["x-session-id"];
    if (!sessionId)
      return res.status(400).send({ ok: false, message: "session_id query required" });

    try {
      const session = await stripe.checkout.sessions.retrieve(sessionId, { expand: ["payment_intent"] });

      const userEmail = session.customer_email || session.metadata?.userEmail || null;
      const amountCents = session.amount_total ?? session.payment_intent?.amount ?? 0;
      const currency = session.currency || session.payment_intent?.currency || "usd";
      const paymentIntentId = session.payment_intent?.id || session.payment_intent || null;
      const checkoutSessionId = session.id;

      const { db } = await connectDB();
      const funds = db.collection("funds");

      // Ensure idempotency — no duplicate records
      const existing = await funds.findOne({
        $or: [
          { stripeCheckoutSession: checkoutSessionId },
          { stripePaymentIntent: paymentIntentId },
        ],
      });

      if (existing)
        return res.send({ ok: true, recorded: false, message: "Already recorded", data: existing });

      const doc = {
        userEmail,
        amount: Number(amountCents) / 100,
        currency,
        transactionId: paymentIntentId || checkoutSessionId,
        stripeCheckoutSession: checkoutSessionId,
        stripePaymentIntent: paymentIntentId,
        createdAt: new Date(),
        meta: { stripe: true, source: "checkout-session-reconcile" },
      };

      const result = await funds.insertOne(doc);
      res.send({ ok: true, recorded: true, data: result });
    } catch (err) {
      console.error("Error retrieving checkout-session:", err);
      res.status(500).send({ ok: false, message: "Failed to retrieve or record session", error: err.message });
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