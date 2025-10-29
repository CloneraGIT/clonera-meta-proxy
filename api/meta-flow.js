import express from "express";
import serverless from "serverless-http";

const app = express();
app.use(express.json({ limit: "2mb" }));

// Simple POST route just to prove it works
app.post("/", (req, res) => {
  console.log("Ping received:", req.body);
  return res.status(200).json({ ok: true, echo: req.body || null });
});

// Export for Vercel (no app.listen()!)
export default serverless(app);
