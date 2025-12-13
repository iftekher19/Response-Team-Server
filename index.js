
require("dotenv").config();
const express = require("express");

const app = express();

// ---------------- Config ----------------
const PORT = Number(process.env.PORT) || 5000;
const DB_NAME = process.env.DB_NAME || "responseTeamDB";

// Build MONGO_URI robustly from environment variables
let MONGO_URI = process.env.MONGO_URI || null;
if (!MONGO_URI && process.env.DB_USER && process.env.DB_PASS && process.env.DB_HOST) {
  MONGO_URI = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@${process.env.DB_HOST}`;
}
if (!MONGO_URI && process.env.DB_USER && process.env.DB_PASS) {
  MONGO_URI = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@flash0.v0bnf8w.mongodb.net/?appName=flash0`;
}

if (!MONGO_URI) {
  console.warn("WARNING: MONGO_URI not set. Configure .env correctly.");
}

app.get("/", (req, res) => res.send("Server initialized"));

module.exports = { app };

if (require.main === module) {
  app.listen(PORT, () => console.log(`✅ Server listening on port ${PORT}`));
}