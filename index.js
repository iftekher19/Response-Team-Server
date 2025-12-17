require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const bodyParser = require("body-parser"); // used for raw webhook body
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const stripe = require('stripe')(process.env.STRIPE_SECRET);

const app = express();

// ---------------- Config ----------------
const PORT = Number(process.env.PORT) || 5000;
const DB_NAME = process.env.DB_NAME || "responseTeamDB";

// Build MONGO_URI 
let MONGO_URI = process.env.MONGO_URI || null;
if (!MONGO_URI && process.env.DB_USER && process.env.DB_PASS && process.env.DB_HOST) {
  MONGO_URI = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@flash0.v0bnf8w.mongodb.net/?appName=flash0`;
}
if (!MONGO_URI && process.env.DB_USER && process.env.DB_PASS) {
  MONGO_URI = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@flash0.v0bnf8w.mongodb.net/?appName=flash0`;
}

if (!MONGO_URI) {
  console.warn("WARNING: MONGO_URI not set. Set MONGO_URI or DB_USER & DB_PASS & DB_HOST in your .env");
}

// CORS origins
const CORS_ORIGINS = (process.env.CORS_ORIGINS || "http://localhost:5173,http://localhost:3000")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// ---------------- Middlewares ----------------
app.use(helmet()); 
app.use(express.json({ limit: "1mb" })); 
app.use(morgan("dev")); 

const corsOptions = {
  origin: (origin, cb) => {
    // allow server-to-server or tools without origin
    if (!origin) return cb(null, true);
    if (CORS_ORIGINS.indexOf(origin) !== -1) return cb(null, true);
    return cb(new Error("CORS policy: This origin is not allowed"), false);
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

  if (!MONGO_URI) {
    throw new Error("MONGO_URI is not set. Set MONGO_URI or DB_USER & DB_PASS & DB_HOST env vars.");
  }

  const client = new MongoClient(MONGO_URI, {
    serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
  });

  await client.connect();
  const db = client.db(DB_NAME);

  cachedClient = client;
  cachedDb = db;

  console.log("MongoDB connected (cached)");
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

/// ---------------- Helpers ----------------
const wrap = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

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

// ---------------- Stripe: create PaymentIntent  ----------------
app.post(
  "/payments/create-payment-intent",
  wrap(async (req, res) => {
    const { amount, currency = "usd", userEmail, description = "" } = req.body || {};
    if (!amount || !userEmail) return res.status(400).send({ ok: false, message: "amount and userEmail required" });

    const amountNumber = Number(amount);
    if (Number.isNaN(amountNumber) || amountNumber <= 0) {
      return res.status(400).send({ ok: false, message: "Invalid amount" });
    }
    const amountInCents = Math.round(amountNumber * 100);

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
      console.error("Stripe create PaymentIntent error:", err);
      res.status(500).send({ ok: false, message: "Could not create payment intent" });
    }
  })
);

// ---------------- Stripe: create Checkout Session (new) ----------------
app.post(
  "/create-checkout-session",
  wrap(async (req, res) => {
    try {
      const { amount, userEmail, name = "Donation" } = req.body;

      if (!amount || !userEmail) {
        return res.status(400).send({ ok: false, message: "amount and userEmail required" });
      }

      const amountNumber = Number(amount);
      if (Number.isNaN(amountNumber) || amountNumber <= 0) {
        return res.status(400).send({ ok: false, message: "Invalid amount" });
      }

      const amountInCents = Math.round(amountNumber * 100);

      console.log("Creating checkout:", {
        amountInCents,
        userEmail,
        name,
      });

      const session = await stripe.checkout.sessions.create({
        mode: "payment",
        payment_method_types: ["card"],
        line_items: [
          {
            price_data: {
              currency: "usd",
              product_data: { name },
              unit_amount: amountInCents,
            },
            quantity: 1,
          },
        ],
        customer_email: userEmail,
        success_url: `${process.env.CLIENT_URL}/dashboard/funding-success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${process.env.CLIENT_URL}/funding-cancel`,
      });

      return res.send({ ok: true, url: session.url, id: session.id });
    } catch (err) {
      console.error("Stripe checkout error:", err);
      return res.status(500).send({
        ok: false,
        message: "Stripe checkout failed",
        error: err.message,
      });
    }
  })
);


app.get(
  "/checkout-session",
  wrap(async (req, res) => {
    const sessionId = req.query.session_id || req.headers["x-session-id"];
    if (!sessionId) return res.status(400).send({ ok: false, message: "session_id query required" });

    try {
      const session = await stripe.checkout.sessions.retrieve(sessionId, { expand: ["payment_intent"] });

      const userEmail = session.customer_email || session.metadata?.userEmail || null;
      // amount_total is in cents
      const amountCents = session.amount_total ?? session.payment_intent?.amount ?? null;
      const currency = session.currency || session.payment_intent?.currency || null;
      const paymentIntentId = session.payment_intent?.id || session.payment_intent || null;
      const checkoutSessionId = session.id;

      const { db } = await connectDB();
      const funds = db.collection("funds");

      // Check for existing record by checkoutSession or paymentIntent
      const existing = await funds.findOne({
        $or: [
          { stripeCheckoutSession: checkoutSessionId },
          { stripePaymentIntent: paymentIntentId }
        ]
      });

      if (existing) {
        return res.send({ ok: true, recorded: false, message: "Already recorded", data: existing });
      }

      // Insert new fund
      const doc = {
        userEmail,
        donorName: session.customer_details?.name || session.metadata?.donorName || null,
        amount: amountCents != null ? Number(amountCents) / 100 : 0,
        currency,
        transactionId: paymentIntentId || checkoutSessionId,
        stripeCheckoutSession: checkoutSessionId,
        stripePaymentIntent: paymentIntentId,
        createdAt: new Date(),
        meta: { stripe: true, source: "checkout-session-reconcile" }
      };

      const result = await funds.insertOne(doc);
        return res.send({
          ok: true,
          donation: {
            amount: doc.amount,
            currency: doc.currency,
            userEmail: doc.userEmail,
            transactionId: doc.transactionId,
            createdAt: doc.createdAt,
          },
      });
    } catch (err) {
      console.error("Error in GET /checkout-session:", err);
      return res.status(500).send({ ok: false, message: "Failed to retrieve or record session", error: err.message });
    }
  })
);

// ---------------- Stripe: webhook ) ----------------
app.post(
  "/payments/webhook",
  bodyParser.raw({ type: "application/json" }),
  async (req, res) => {
    const sig = req.headers["stripe-signature"];
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

    let event;
    try {
      if (webhookSecret) {
        event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
      } else {
        event = JSON.parse(req.body.toString());
      }
    } catch (err) {
      console.error("⚠️  Webhook signature verification failed.", err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    try {
      // handle relevant events
      switch (event.type) {
        case "payment_intent.succeeded": {
          const pi = event.data.object;
          const userEmail = pi.metadata?.userEmail || pi.receipt_email || null;
          const amountCents = pi.amount;
          const currency = pi.currency;
          const transactionId = pi.id;

          try {
            const { db } = await connectDB();
            const funds = db.collection("funds");

            //  check existing by stripePaymentIntent
            const existing = await funds.findOne({ stripePaymentIntent: transactionId });
            if (!existing) {
              await funds.insertOne({
                userEmail,
                amount: Number(amountCents) / 100,
                currency,
                transactionId,
                stripePaymentIntent: transactionId,
                createdAt: new Date(),
                meta: { stripe: true, source: "payment_intent.succeeded" },
              });
              console.log("Recorded fund for PI", transactionId);
            } else {
              console.log("Fund already recorded for PI", transactionId);
            }
          } catch (dbErr) {
            console.error("Failed to record fund in DB:", dbErr);
          }
          break;
        }

        case "checkout.session.completed": {
          const session = event.data.object;
          try {
            // fetch full session with payment_intent expanded for reliable fields
            const fullSession = await stripe.checkout.sessions.retrieve(session.id, { expand: ["payment_intent"] });

            const userEmail = fullSession.customer_email || fullSession.metadata?.userEmail || null;
            const amountCents = fullSession.amount_total ?? (fullSession.payment_intent?.amount ?? null);
            const currency = fullSession.currency || (fullSession.payment_intent?.currency || null);
            const paymentIntentId = fullSession.payment_intent?.id || fullSession.payment_intent || null;
            const checkoutSessionId = fullSession.id;

            const { db } = await connectDB();
            const funds = db.collection("funds");

            // Avoid duplicates check by paymentIntentId or checkoutSessionId
            const existing = await funds.findOne({
              $or: [
                { stripePaymentIntent: paymentIntentId },
                { stripeCheckoutSession: checkoutSessionId }
              ]
            });

            if (!existing) {
              await funds.insertOne({
                userEmail,
                amount: amountCents != null ? Number(amountCents) / 100 : 0,
                currency,
                transactionId: paymentIntentId || checkoutSessionId,
                stripeCheckoutSession: checkoutSessionId,
                stripePaymentIntent: paymentIntentId,
                createdAt: new Date(),
                meta: { stripe: true, source: "checkout.session.completed", rawSession: fullSession }
              });
              console.log("Recorded fund (checkout.session.completed):", checkoutSessionId);
            } else {
              console.log("Fund already recorded for session:", checkoutSessionId);
            }
          } catch (err) {
            console.error("Failed to handle checkout.session.completed:", err);
          }
          break;
        }

        case "payment_intent.payment_failed": {
          const pi = event.data.object;
          console.warn("Payment failed:", pi.last_payment_error?.message || "unknown reason");
          break;
        }

        default:
          console.log(`Unhandled Stripe event type: ${event.type}`);
      }

      res.json({ received: true });
    } catch (err) {
      console.error("Error handling webhook event:", err);
      res.status(500).send({ ok: false, message: "Webhook handler error" });
    }
  }
);

// POST /api/auth/sync (compatibility with frontend)
app.post(
  "/api/auth/sync",
  wrap(async (req, res) => {
    const payload = req.body || {};
    if (!payload.email) return res.status(400).send({ ok: false, message: "email required" });

    const { db } = await connectDB();
    const users = db.collection("users");

    // Only allow safe profile fields
    const allowedProfileFields = ["email", "name", "avatar", "bloodGroup", "district", "upazila", "role", "status"];
    const toSet = {};
    for (const k of allowedProfileFields) {
      if (payload[k] !== undefined) toSet[k] = payload[k];
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

// POST /users - upsert by email 
app.post(
  "/users",
  wrap(async (req, res) => {
    const user = req.body || {};
    if (!user.email) return res.status(400).send({ ok: false, message: "Email is required" });

    const { db } = await connectDB();
    const users = db.collection("users");

    const allowed = ["email", "name", "avatar", "bloodGroup", "district", "upazila", "role", "status", "idToken"];
    const toSet = {};
    for (const k of allowed) {
      if (user[k] !== undefined) toSet[k] = user[k];
    }
    toSet.updatedAt = new Date();

    const defaults = { createdAt: new Date(), role: "donor", status: "active" };
    const setOnInsert = buildSetOnInsert(defaults, toSet);

    const result = await users.updateOne(
      { email: toSet.email },
      { $set: toSet, ...(Object.keys(setOnInsert).length ? { $setOnInsert: setOnInsert } : {}) },
      { upsert: true }
    );

    res.status(200).send({ ok: true, message: "User upserted", data: result });
  })
);

// GET /users - list or query
app.get(
  "/users",
  wrap(async (req, res) => {
    const { db } = await connectDB();
    const users = db.collection("users");

    const filter = {};
    if (req.query.email) filter.email = req.query.email;
    if (req.query.role) filter.role = req.query.role;
    if (req.query.status) filter.status = req.query.status;

    const docs = await users.find(filter).toArray();
    res.send({ ok: true, data: docs });
  })
);

// PATCH /users/:id - partial update
app.patch(
  "/users/:id",
  wrap(async (req, res) => {
    const id = req.params.id;
    if (!isValidObjectId(id)) return res.status(400).send({ ok: false, message: "Invalid user id" });

    const updates = { ...req.body };
    delete updates.email; 
    updates.updatedAt = new Date();

    const { db } = await connectDB();
    const users = db.collection("users");

    const result = await users.updateOne({ _id: new ObjectId(id) }, { $set: updates });
    res.send({ ok: true, message: "User updated", data: result });
  })
);

// PUT /users/:id/profile - convenience route, keep email immutable
app.put(
  "/users/:id/profile",
  wrap(async (req, res) => {
    const id = req.params.id;
    if (!isValidObjectId(id)) return res.status(400).send({ ok: false, message: "Invalid user id" });

    const payload = { ...req.body };
    delete payload.email;

    const allowed = ["name", "avatar", "bloodGroup", "district", "upazila", "role", "status"];
    const toSet = {};
    for (const k of allowed) {
      if (payload[k] !== undefined) toSet[k] = payload[k];
    }
    toSet.updatedAt = new Date();

    const { db } = await connectDB();
    const users = db.collection("users");
    const result = await users.updateOne({ _id: new ObjectId(id) }, { $set: toSet });

    res.send({ ok: true, message: "Profile updated", data: result });
  })
);

// PATCH role/status convenience
app.patch(
  "/users/:id/role",
  wrap(async (req, res) => {
    const id = req.params.id;
    if (!isValidObjectId(id)) return res.status(400).send({ ok: false, message: "Invalid user id" });

    const { role } = req.body;
    if (!role) return res.status(400).send({ ok: false, message: "role required" });

    const { db } = await connectDB();
    const users = db.collection("users");
    const result = await users.updateOne({ _id: new ObjectId(id) }, { $set: { role, updatedAt: new Date() } });
    res.send({ ok: true, message: "Role updated", data: result });
  })
);

app.patch(
  "/users/:id/status",
  wrap(async (req, res) => {
    const id = req.params.id;
    if (!isValidObjectId(id)) return res.status(400).send({ ok: false, message: "Invalid user id" });

    const { status } = req.body;
    if (!status) return res.status(400).send({ ok: false, message: "status required" });

    const { db } = await connectDB();
    const users = db.collection("users");
    const result = await users.updateOne({ _id: new ObjectId(id) }, { $set: { status, updatedAt: new Date() } });
    res.send({ ok: true, message: "Status updated", data: result });
  })
);

// Create donation request (canonical)
app.post(
  "/donation-requests",
  wrap(async (req, res) => {
    const payload = req.body || {};
    if (!payload.requesterEmail) return res.status(400).send({ ok: false, message: "requesterEmail is required" });

    const { db } = await connectDB();
    const users = db.collection("users");
    const requests = db.collection("donationRequests");

    const requester = await users.findOne({ email: payload.requesterEmail });
    if (!requester) return res.status(400).send({ ok: false, message: "Requester profile not found" });
    if (requester.status === "blocked") return res.status(403).send({ ok: false, message: "User is blocked" });

    const newReq = {
      requesterEmail: payload.requesterEmail,
      requesterName: payload.requesterName || requester.name || "",
      recipientName: payload.recipientName || "",
      recipientDistrict: payload.recipientDistrict || "",
      recipientUpazila: payload.recipientUpazila || "",
      hospitalName: payload.hospitalName || "",
      fullAddress: payload.fullAddress || "",
      bloodGroup: payload.bloodGroup || "",
      donationDate: payload.donationDate || "",
      donationTime: payload.donationTime || "",
      requestMessage: payload.requestMessage || "",
      status: payload.status || "pending",
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await requests.insertOne(newReq);
    res.status(201).send({ ok: true, message: "Donation request created", data: result });
  })
);

// Compatibility: POST /requests -> create
app.post(
  "/requests",
  wrap(async (req, res) => {
    const payload = req.body || {};
    if (!payload.requesterEmail) return res.status(400).send({ ok: false, message: "requesterEmail is required" });

    const { db } = await connectDB();
    const users = db.collection("users");
    const requests = db.collection("donationRequests");

    const requester = await users.findOne({ email: payload.requesterEmail });
    if (!requester) return res.status(400).send({ ok: false, message: "Requester profile not found" });
    if (requester.status === "blocked") return res.status(403).send({ ok: false, message: "User is blocked" });

    const newReq = {
      requesterEmail: payload.requesterEmail,
      requesterName: payload.requesterName || requester.name || "",
      recipientName: payload.recipientName || "",
      recipientDistrict: payload.recipientDistrict || "",
      recipientUpazila: payload.recipientUpazila || "",
      hospitalName: payload.hospitalName || "",
      fullAddress: payload.fullAddress || "",
      bloodGroup: payload.bloodGroup || "",
      donationDate: payload.donationDate || "",
      donationTime: payload.donationTime || "",
      requestMessage: payload.requestMessage || "",
      status: payload.status || "pending",
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await requests.insertOne(newReq);
    res.status(201).send({ ok: true, message: "Donation request created", data: result });
  })
);

// Get donation requests 
app.get(
  "/donation-requests",
  wrap(async (req, res) => {
    const { db } = await connectDB();
    const requests = db.collection("donationRequests");

    const filter = {};
    const { status, bloodGroup, district, upazila, requesterEmail, page = 1, limit = 50 } = req.query;

    if (status) filter.status = status;
    if (bloodGroup) filter.bloodGroup = bloodGroup;
    if (district) filter.recipientDistrict = district;
    if (upazila) filter.recipientUpazila = upazila;
    if (requesterEmail) filter.requesterEmail = requesterEmail;

    const skip = (Number(page) - 1) * Number(limit);
    const cursor = requests.find(filter).sort({ createdAt: -1 }).skip(skip).limit(Number(limit));
    const docs = await cursor.toArray();
    res.send({ ok: true, data: docs });
  })
);

// Compatibility GET /requests -> list donation-requests 
app.get(
  "/requests",
  wrap(async (req, res) => {
    const { db } = await connectDB();
    const requests = db.collection("donationRequests");

    const filter = {};
    const { status, bloodGroup, district, upazila, requesterEmail, page = 1, limit = 50 } = req.query;

    if (status) filter.status = status;
    if (bloodGroup) filter.bloodGroup = bloodGroup;
    if (district) filter.recipientDistrict = district;
    if (upazila) filter.recipientUpazila = upazila;
    if (requesterEmail) filter.requesterEmail = requesterEmail;

    const skip = (Number(page) - 1) * Number(limit);
    const cursor = requests.find(filter).sort({ createdAt: -1 }).skip(skip).limit(Number(limit));
    const docs = await cursor.toArray();
    res.send({ ok: true, data: docs });
  })
);

// Backwards-compatible GET /requests/my?email=<email>
app.get(
  "/requests/my",
  wrap(async (req, res) => {
    const email = req.query.email;
    if (!email) return res.status(400).send({ ok: false, message: "email query required" });

    const limit = Number(req.query.limit) || 3;
    const { db } = await connectDB();
    const requests = db.collection("donationRequests");

    const docs = await requests.find({ requesterEmail: email }).sort({ createdAt: -1 }).limit(limit).toArray();
    res.send({ ok: true, data: docs });
  })
);

// Get single request 
app.get(
  "/donation-requests/:id",
  wrap(async (req, res) => {
    const id = req.params.id;
    if (!isValidObjectId(id)) return res.status(400).send({ ok: false, message: "Invalid request id" });

    const { db } = await connectDB();
    const requests = db.collection("donationRequests");
    const doc = await requests.findOne({ _id: new ObjectId(id) });
    if (!doc) return res.status(404).send({ ok: false, message: "Request not found" });
    res.send({ ok: true, data: doc });
  })
);

//GET /requests/:id
app.get(
  "/requests/:id",
  wrap(async (req, res) => {
    const id = req.params.id;
    if (!isValidObjectId(id)) return res.status(400).send({ ok: false, message: "Invalid request id" });

    const { db } = await connectDB();
    const requests = db.collection("donationRequests");
    const doc = await requests.findOne({ _id: new ObjectId(id) });
    if (!doc) return res.status(404).send({ ok: false, message: "Request not found" });
    res.send({ ok: true, data: doc });
  })
);

// Update request 
app.patch(
  "/donation-requests/:id",
  wrap(async (req, res) => {
    const id = req.params.id;
    if (!isValidObjectId(id)) return res.status(400).send({ ok: false, message: "Invalid request id" });

    const updates = req.body || {};
    const allowed = ["status", "donorName", "donorEmail", "donationDate", "donationTime", "requestMessage"];
    const toSet = {};
    for (const key of allowed) {
      if (updates[key] !== undefined) toSet[key] = updates[key];
    }
    toSet.updatedAt = new Date();

    const { db } = await connectDB();
    const requests = db.collection("donationRequests");
    const result = await requests.updateOne({ _id: new ObjectId(id) }, { $set: toSet });
    res.send({ ok: true, message: "Request updated", data: result });
  })
);

// PATCH /requests/:id/status for UI convenience
app.patch(
  "/requests/:id",
  wrap(async (req, res) => {
    const id = req.params.id;
    if (!isValidObjectId(id)) return res.status(400).send({ ok: false, message: "Invalid request id" });

    const updates = req.body || {};
    const allowed = ["status", "donorName", "donorEmail", "donationDate", "donationTime", "requestMessage"];
    const toSet = {};
    for (const key of allowed) {
      if (updates[key] !== undefined) toSet[key] = updates[key];
    }
    toSet.updatedAt = new Date();

    const { db } = await connectDB();
    const requests = db.collection("donationRequests");
    const result = await requests.updateOne({ _id: new ObjectId(id) }, { $set: toSet });
    res.send({ ok: true, message: "Request updated", data: result });
  })
);

// PATCH /requests/:id/status -> convenience for RequestCard change status button
app.patch(
  "/requests/:id/status",
  wrap(async (req, res) => {
    const id = req.params.id;
    if (!isValidObjectId(id)) return res.status(400).send({ ok: false, message: "Invalid request id" });

    const { status } = req.body;
    if (!status) return res.status(400).send({ ok: false, message: "status required" });

    const { db } = await connectDB();
    const requests = db.collection("donationRequests");
    const result = await requests.updateOne({ _id: new ObjectId(id) }, { $set: { status, updatedAt: new Date() } });
    res.send({ ok: true, message: "Status updated", data: result });
  })
);

// Delete request canonical & compatibility
app.delete(
  "/donation-requests/:id",
  wrap(async (req, res) => {
    const id = req.params.id;
    if (!isValidObjectId(id)) return res.status(400).send({ ok: false, message: "Invalid request id" });

    const { db } = await connectDB();
    const requests = db.collection("donationRequests");
    const result = await requests.deleteOne({ _id: new ObjectId(id) });
    if (!result.deletedCount) return res.status(404).send({ ok: false, message: "Request not found" });
    res.send({ ok: true, message: "Request deleted" });
  })
);

app.delete(
  "/requests/:id",
  wrap(async (req, res) => {
    const id = req.params.id;
    if (!isValidObjectId(id)) return res.status(400).send({ ok: false, message: "Invalid request id" });

    const { db } = await connectDB();
    const requests = db.collection("donationRequests");
    const result = await requests.deleteOne({ _id: new ObjectId(id) });
    if (!result.deletedCount) return res.status(404).send({ ok: false, message: "Request not found" });
    res.send({ ok: true, message: "Request deleted" });
  })
);

// GET /my-donation-requests?email= -> list requests by requesterEmail
app.get(
  "/my-donation-requests",
  wrap(async (req, res) => {
    const { email } = req.query;
    if (!email) return res.status(400).send({ ok: false, message: "Email query required" });

    const { db } = await connectDB();
    const requests = db.collection("donationRequests");
    const docs = await requests.find({ requesterEmail: email }).sort({ createdAt: -1 }).toArray();
    res.send({ ok: true, data: docs });
  })
);

// GET /admin/stats  -> returns counts used by DashboardHome
app.get(
  "/admin/stats",
  wrap(async (req, res) => {
    const { db } = await connectDB();
    const usersC = db.collection("users");
    const fundsC = db.collection("funds");
    const requestsC = db.collection("donationRequests");

    // Perform counts and aggregation in parallel
    const [usersCount, fundsAgg, requestsCount] = await Promise.all([
      usersC.countDocuments({}),
      fundsC.aggregate([{ $group: { _id: null, total: { $sum: "$amount" } } }]).toArray(),
      requestsC.countDocuments({}),
    ]);

    const totalFunds = (fundsAgg[0] && fundsAgg[0].total) || 0;

    res.send({ ok: true, data: { users: usersCount, funds: totalFunds, requests: requestsCount } });
  })
);

// ---------------- Search donors (public) ----------------
app.get(
  "/search-donors",
  wrap(async (req, res) => {
    const { db } = await connectDB();
    const users = db.collection("users");

    const { bloodGroup, district, upazila, page = 1, limit = 50 } = req.query;
    const filter = { status: "active" };

    if (bloodGroup) filter.bloodGroup = bloodGroup;
    if (district) filter.district = district;
    if (upazila) filter.upazila = upazila;

    const skip = (Number(page) - 1) * Number(limit);
    const docs = await users.find(filter).skip(skip).limit(Number(limit)).toArray();

    const safe = docs.map((u) => ({
      _id: u._id,
      name: u.name,
      email: u.email,
      avatar: u.avatar,
      bloodGroup: u.bloodGroup,
      district: u.district,
      upazila: u.upazila,
      role: u.role,
      status: u.status,
    }));

    res.send({ ok: true, data: safe });
  })
);
// ---------------- Funds listing & summary ----------------
app.get(
  "/funds",
  wrap(async (req, res) => {
    const { db } = await connectDB();
    const funds = db.collection("funds");
    const docs = await funds.find({}).sort({ createdAt: -1 }).toArray();
    res.send({ ok: true, data: docs });
  })
);

app.get(
  "/funds/summary",
  wrap(async (req, res) => {
    const { db } = await connectDB();
    const funds = db.collection("funds");
    const agg = await funds.aggregate([{ $group: { _id: null, total: { $sum: "$amount" }, count: { $sum: 1 } } }]).toArray();
    const summary = agg[0] || { total: 0, count: 0 };
    res.send({ ok: true, data: { total: summary.total, count: summary.count } });
  })
);

// ---------------- Basic routes & health ----------------
app.get("/", (req, res) => res.send("Response Team - Blood Donation API is running"));
app.get("/healthz", (req, res) => res.status(200).json({ ok: true, uptime: process.uptime() }));

// ---------------- Error handler ----------------
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err && err.stack ? err.stack : err);
  if (err?.message?.includes("CORS policy")) {
    return res.status(403).send({ ok: false, message: err.message });
  }
  const payload = process.env.NODE_ENV === "production"
    ? { message: "Internal Server Error" }
    : { message: err?.message || "Internal Server Error", stack: err?.stack };
  res.status(500).send({ ok: false, ...payload });
});

// ---------------- Export & start ----------------
module.exports = { app, closeDb };

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`✅ Server listening on port ${PORT}`);
  });
}