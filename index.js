import express from "express";
import crypto from "crypto";
import fetch from "node-fetch";

const app = express();
app.use(express.json({ limit: "2mb" }));

// === CONFIG ===
const PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
YOUR_PRIVATE_KEY_HERE
-----END PRIVATE KEY-----`;

const N8N_WEBHOOK = "https://cloneratriage.app.n8n.cloud/webhook/lookup-vehicle";

// === HELPERS ===
function decryptAESKey(encryptedKeyB64) {
  const privateKey = crypto.createPrivateKey(PRIVATE_KEY);
  const encryptedKey = Buffer.from(encryptedKeyB64, "base64");
  return crypto.privateDecrypt(
    { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    encryptedKey
  );
}

function decryptData(aesKey, ivB64, encryptedDataB64) {
  const iv = Buffer.from(ivB64, "base64");
  const cipherData = Buffer.from(encryptedDataB64, "base64");
  const decipher = crypto.createDecipheriv("aes-128-cbc", aesKey, iv);
  let decrypted = decipher.update(cipherData);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return JSON.parse(decrypted.toString("utf8").trim());
}

function encryptData(aesKey, ivB64, data) {
  const iv = Buffer.from(ivB64, "base64");
  const json = JSON.stringify(data);
  const pad = 16 - (json.length % 16);
  const padded = Buffer.concat([Buffer.from(json), Buffer.alloc(pad, 0)]);
  const cipher = crypto.createCipheriv("aes-128-cbc", aesKey, iv);
  let encrypted = cipher.update(padded);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return encrypted.toString("base64");
}

// === META FLOW HANDLER ===
app.post("/meta-flow", async (req, res) => {
  try {
    const { encrypted_aes_key, encrypted_flow_data, initial_vector } = req.body;

    // 1. Decrypt AES key and data
    const aesKey = decryptAESKey(encrypted_aes_key);
    const data = decryptData(aesKey, initial_vector, encrypted_flow_data);

    // 2. Forward decrypted JSON to n8n
    const forward = await fetch(N8N_WEBHOOK, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data)
    });
    const responseData = await forward.json();

    // 3. Encrypt response again for Meta
    const encryptedResponse = encryptData(aesKey, initial_vector, responseData);

    res.status(200).json({
      encrypted_flow_data: encryptedResponse,
      encrypted_aes_key,
      initial_vector
    });
  } catch (err) {
    console.error(err);
    res.status(421).send("Decryption failed");
  }
});

app.listen(3000, () => console.log("Clonera Meta proxy running on port 3000"));
