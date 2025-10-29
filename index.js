app.post("/meta-flow", async (req, res) => {
  try {
    console.log("Incoming test payload:", req.body);

    // TEMPORARY BYPASS – skip decryption
    const payload = req.body;

    // Forward directly to n8n
    const n8nResponse = await fetch(N8N_WEBHOOK, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    const result = await n8nResponse.json();

    // Respond directly with n8n's response (no encryption)
    return res.status(200).json(result);
  } catch (err) {
    console.error("Bypass forwarding error:", err);
    return res.status(500).json({ error: "Bypass failed" });
  }
});
