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
const bodyParser = require("body-parser"); // needed for raw body verification

// ---------------- Stripe: webhook (raw body) ----------------
app.post(
  "/payments/webhook",
  bodyParser.raw({ type: "application/json" }),
  async (req, res) => {
    const sig = req.headers["stripe-signature"];
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

    let event;
    try {
      if (webhookSecret) {
        // Verify webhook signature
        event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
      } else {
        // Fallback: no verification in dev
        event = JSON.parse(req.body.toString());
      }
    } catch (err) {
      console.error("⚠️ Webhook verification failed:", err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    try {
      switch (event.type) {
        // When a PaymentIntent succeeds
        case "payment_intent.succeeded": {
          const pi = event.data.object;
          const userEmail = pi.metadata?.userEmail || pi.receipt_email || null;
          const { amount, currency, id: transactionId } = pi;
          const { db } = await connectDB();
          const funds = db.collection("funds");

          const existing = await funds.findOne({ stripePaymentIntent: transactionId });
          if (!existing) {
            await funds.insertOne({
              userEmail,
              amount: amount / 100,
              currency,
              transactionId,
              stripePaymentIntent: transactionId,
              createdAt: new Date(),
              meta: { stripe: true, source: "payment_intent.succeeded" },
            });
            console.log("✅ Recorded fund for PaymentIntent", transactionId);
          } else {
            console.log("Skipped duplicate fund for", transactionId);
          }
          break;
        }

        // When a Checkout Session completes
        case "checkout.session.completed": {
          const session = event.data.object;
          try {
            // Retrieve complete session details including payment_intent
            const fullSession = await stripe.checkout.sessions.retrieve(session.id, { expand: ["payment_intent"] });
            const userEmail = fullSession.customer_email || fullSession.metadata?.userEmail || null;
            const amountCents = fullSession.amount_total ?? fullSession.payment_intent?.amount ?? 0;
            const currency = fullSession.currency || fullSession.payment_intent?.currency || "usd";
            const paymentIntentId = fullSession.payment_intent?.id || fullSession.payment_intent || null;

            const { db } = await connectDB();
            const funds = db.collection("funds");

            const existing = await funds.findOne({
              $or: [
                { stripePaymentIntent: paymentIntentId },
                { stripeCheckoutSession: session.id },
              ],
            });

            if (!existing) {
              await funds.insertOne({
                userEmail,
                amount: Number(amountCents) / 100,
                currency,
                transactionId: paymentIntentId || session.id,
                stripeCheckoutSession: session.id,
                stripePaymentIntent: paymentIntentId,
                createdAt: new Date(),
                meta: { stripe: true, source: "checkout.session.completed" },
              });
              console.log("✅ Recorded fund for Checkout Session", session.id);
            } else {
              console.log("Skipped duplicate session", session.id);
            }
          } catch (err) {
            console.error("Failed to handle checkout.session.completed:", err);
          }
          break;
        }

        case "payment_intent.payment_failed": {
          const pi = event.data.object;
          console.warn(" Payment failed:", pi.last_payment_error?.message || "unknown reason");
          break;
        }

        default:
          console.log(`Unhandled Stripe event type: ${event.type}`);
      }

      res.json({ received: true });
    } catch (err) {
      console.error("Webhook processing error:", err);
      res.status(500).send({ ok: false, message: "Webhook processing failed" });
    }
  }
);
// ---------------- Helpers for user management ----------------
const { ObjectId } = require("mongodb");

// small helper to wrap async routes (added before, reused here)
const isValidObjectId = (id) => {
  try {
    return new ObjectId(id).toString() === id.toString();
  } catch {
    return false;
  }
};

function buildSetOnInsert(defaults, toSet) {
  const out = {};
  for (const k of Object.keys(defaults)) {
    if (toSet[k] === undefined) out[k] = defaults[k];
  }
  return out;
}

// ---------------- Routes: User Auth Sync ----------------
/**
 * POST /api/auth/sync
 * Accepts a user profile or idToken; upserts user by email.
 */
app.post(
  "/api/auth/sync",
  wrap(async (req, res) => {
    const payload = req.body || {};
    if (!payload.email) {
      return res.status(400).send({ ok: false, message: "email required" });
    }

    const { db } = await connectDB();
    const users = db.collection("users");

    // only allow safe fields for upsert
    const safeFields = [
      "email",
      "name",
      "avatar",
      "bloodGroup",
      "district",
      "upazila",
      "role",
      "status",
    ];

    const toSet = {};
    for (const field of safeFields) {
      if (payload[field] !== undefined) toSet[field] = payload[field];
    }

    toSet.updatedAt = new Date();
    if (payload.idToken) toSet.idToken = payload.idToken;

    const defaults = { createdAt: new Date(), role: "donor", status: "active" };
    const setOnInsert = buildSetOnInsert(defaults, toSet);

    const result = await users.updateOne(
      { email: payload.email },
      { $set: toSet, ...(Object.keys(setOnInsert).length ? { $setOnInsert: setOnInsert } : {}) },
      { upsert: true }
    );

    res.send({ ok: true, message: "Auth sync upserted", data: result });
  })
);

// ------------- Test route -------------
app.get("/", (req, res) => res.send("Stripe PaymentIntent endpoint active"));

// Exports & start
module.exports = { app, connectDB, closeDb };

if (require.main === module) {
  app.listen(PORT, () => console.log(`✅ Server listening on port ${PORT}`));
}