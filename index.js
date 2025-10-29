import express from "express";
import crypto from "crypto";
import fetch from "node-fetch";
import serverless from "serverless-http";

const app = express();
app.use(express.json({ limit: "2mb" }));

// --- CONFIG ---
const PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----
YOUR_PRIVATE_KEY_HERE
-----END RSA PRIVATE KEY-----`;

const N8N_WEBHOOK = "https://cloneratriage.app.n8n.cloud/webhook/meta-flow";

// --- HELPERS ---
function decryptAESKey(encryptedAESKey64) {
  const encryptedAESKey = Buffer.from(encryptedAESKey64, "base64");
  return crypto.privateDecrypt(
    { key: PRIVATE_KEY, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    encryptedAESKey
  );
}

function decryptData(aesKey, iv64, encryptedData64) {
  const iv = Buffer.from(iv64, "base64");
  const data = Buffer.from(encryptedData64, "base64");
  const decipher = crypto.createDecipheriv("aes-128-cbc", aesKey, iv);
  let decrypted = decipher.update(data);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return JSON.parse(decrypted.toString("utf8"));
}

// --- ROUTE ---
app.post("/meta-flow", async (req, res) => {
  try {
    const { encrypted_flow_data, encrypted_aes_key, initial_vector } = req.body;

    // Step 1. Decrypt Meta payload
    const aesKey = decryptAESKey(encrypted_aes_key);
    const payload = decryptData(aesKey, initial_vector, encrypted_flow_data);
    console.log("Decrypted Meta Payload:", payload);

    // Step 2. Forward decrypted payload to n8n
    const n8nResponse = await fetch(N8N_WEBHOOK, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    const result = await n8nResponse.json();

    // Step 3. Encrypt response back to Meta
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-128-cbc", aesKey, iv);
    let encrypted = cipher.update(JSON.stringify(result));
    encrypted = Buffer.concat([encrypted, cipher.final()]);

    const encryptedResponse = {
      encrypted_flow_data: encrypted.toString("base64"),
      encrypted_aes_key,
      initial_vector: iv.toString("base64"),
    };

    return res.status(200).json(encryptedResponse);
  } catch (err) {
    console.error("Decryption/Forwarding error:", err);
    return res.status(421).json({ error: "Decryption failed" });
  }
});

// --- EXPORT FOR VERCEL ---
export default serverless(app);
