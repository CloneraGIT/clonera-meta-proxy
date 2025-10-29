import express from "express";
import crypto from "crypto";
import fetch from "node-fetch";

const app = express();
app.use(express.json({ limit: "2mb" }));

// --- CONFIG ---
const PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAsGZd7eG9SNbzBX6kUYrbai4QI0rSWKAYyayBHQ3haJg5kbGj
wVbsZsshR/pm8Qs+krLE5IH+hdrdwB0wwoSvHkuJadBICBoOfHi3aurQy8YGW3QA
Ln2OvCEKP1CtILsOlLrwnOrNitCEw5rnDJYd5Eu0H4NteOaum/5XpTa2O6bhqsV6
9FxGdaBX+BHH0qULfTh6ndHazpEhBshSF8AfQtYbQIIZy8QBDh9et3XE2B3AtZeN
kbXN6ebEuEak3miXPb9cL5+Q7gLNb4N+GXqyXAhZSRRzYOfRTS803BEPXLD6badL
RO5Q6QmuwImhH1e+HS2k6YGYep5QprkJeXMUfQIDAQABAoIBAQCVaqA1VvjWMfw3
s0XMLCoejlXtDvuNRk64xP24doFv70EUP7vNkKs9huHx7hA0LKob6IEObW4CQ5mB
mTgsC+epaaJDlsDs2+VZWYdDcRLbCClqXZ+pwYCdqf7cEqITD18SbCZTRDBGXMmY
RiVfa+h18Anqh5C6z+snBxGGSAmkDBXw00LoZVYgZXhiSMBFvj3uqa2gXd+33DBx
DyP241POfNoallYCSg6PZnEIu1O8rMRXyJarUK3IYmcQcZM2QCo7+pxFmQGTuiyC
d8wl1tK7YtrPwre6u8lovK16/aWXshYnstyhz6TEo82M3Gg7UizuX6WPePi0sP15
B3+qMA+hAoGBAObAFRZ5QcVOXo5fIXBB2uE60Zw1dZ/iQLy1h04WPZ7dTmhjb+qW
L6rkYmSwtckS2TtHGXKvFKsAzz9lr0zBUjW6VevzhBGAuLGmTyI9t9acnJ05EVDs
iMnmgjOYtw4D75j0sUh072Fo06MHK5d0Io8rDd3qM66rJH62nEi7MfUbAoGBAMOz
yWzzCpLV5DkzG/ANDUsSS5XK/u11WmzjpaLpriIp6HdSKsoLx4o/xu+Ndnjf3Xl+
hK3ZQvsGPIblWSmqjmQv+YEOmBbG2SQtFzhEhfuAmnMKFXkEYo0w25viA30ZCvSE
+78ONuiede8qeNXfU4uLZKNmUPAOXtdjhwBWu+5HAoGAN2w5ZG15c6eQJIgK4wie
Ruy2vdtFRkK0o97CAeproIWtOHtxvRmXl2dFjsO21fXWAVvha99LiosmPCbzRO9G
DKuVyZdyyDVvpxO3/BRw3HY/U7AKTbKSZFQeP8BVb2NYoBddoXacrHveIVEukjEN
v+9qZDvFcBWhLWI1BW8Y37MCgYAwU92SAhLCX/+UAIMNrKtztnjj7NU3XpuN+EmX
CY3u8dpuXOQkMPR9t3IxBgYTo3TV4+Bv7g8UXl3kEg8KswumwhIjRK9aMJC+1kO9
qW5MxV1eu0bCM8sCguY4gH/MDLsf1xcz/xagK0GEZkCg0B2ZgDrB/ypNnb7eAb38
325ZUQKBgQDlQ5bJ2KvwUaQHnyMZOfc6KABBZ+OtHEivNdWsk63VrOF45F93DNCq
cv5KljwngtH6630vCiFe5Lb3FVcGuLGN8RaDQn2PYwmFfc28mxUQE9vCLryECH+A
YFkQhsMcqx9mlV6gvbsOXlZEELjuU7EzAzzCnGSyxofq4/VDTSNfBA==
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

    // Step 2. Forward decrypted JSON to n8n
    const n8nResponse = await fetch(N8N_WEBHOOK, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    const result = await n8nResponse.json();

    // Step 3. Encrypt response back for Meta
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-128-cbc", aesKey, iv);
    let encrypted = cipher.update(JSON.stringify(result));
    encrypted = Buffer.concat([encrypted, cipher.final()]);

    const encryptedResponse = {
      encrypted_flow_data: encrypted.toString("base64"),
      encrypted_aes_key, // Meta expects same key
      initial_vector: iv.toString("base64"),
    };

    return res.status(200).json(encryptedResponse);
  } catch (err) {
    console.error("Decryption/Forwarding error:", err);
    return res.status(421).json({ error: "Decryption failed" });
  }
});

// --- START ---
app.listen(3000, () => console.log("Meta Proxy running"));
