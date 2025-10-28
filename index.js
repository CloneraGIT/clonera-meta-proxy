import express from "express";
import crypto from "crypto";
import fetch from "node-fetch";

const app = express();
app.use(express.json({ limit: "2mb" }));

// === CONFIG ===
const PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIIEogIBAAKCAQEArZnV0b6f89bsCkFScnKCPIdUBjYBTE4VqbFbBlB4UQgOhcTT
oYow59BCJCu9pH+83C6aiyZKz6YF6BJ0+kT5t42H1ov4oveYlIfYsQzYfQgD6gEu
kxtbpLQkYpVgDHbJ+cVRl0QM+8aWhWtk+67bZDWn+p3iEwBnKqCVhwuSZSjE78t0
CwTgy/FLWef4M3g5EPxvsjCbNI0G7BAvtTIOd6Obo16JqXxndQZrOtTa11DbYYax
mTEtgGZKsCkO2b2YZ/RZyxXf47WQ9DEOMCzuwsd4mItpC194KcGY95KsaGTUmpgY
OpBq7GsQFa+NKXf1BOvVoEnwHs1Qk43ixXnOdwIDAQABAoIBACEswLuwXgjPDZR4
HzVXxKOkiN4W+/CFC4a+KdLvFc8GZyARGRBJxEbIeZtH8Jm6/3BkR4xH6Qv9gitz
O3+IJuB433iUjxM1labsvvA2sDhUi8rwJuJd3AmBk2JzgUNggACHQKxTiNekf6dH
eqjOJYbk6hDukwFmllCDF5ATGgrSix1IBjze5WwP8ipbhmvaDLIFSZEbchO8Hkxs
281HGYz5hYz9kz9hTDy+4gIlLwu7x5axmrI49atjl1cmL6ubrH9xqId4A1J+3n5o
GSueg67Ol9KfscBgXQCvNBgQZ3qbmBtPTtaklC/P7u6PQMse8zUkqW0WDk8Qroqf
TzI5GsECgYEA0xptU9JXYGULcgpiVrsjxjBgBaZdozeZmgCgQFSM72qkgihGdYdb
7DnKfZQb0kwsE4mdw5zbC4tfqciI+QciEe0DpzEvWRRcW2SFdI4CNPmGOr+bIZck
mXJ6tY9s4Nz++04XptFN0nIAOgRgfTgm4LDByGAy4oJUo8aZc3LI+rkCgYEA0oWV
pxyxDWH2z17G8YddWYeH0YJcGhma1aWg/Pz/kzwHeDFcl1fqcZ+TRtVtDRp/jSsz
tuGGdPCAzvaOh8N+qSpw/ABWpf39iFxvBbrdozFK6uozUS6wK/XnNazmcCdWv7q6
8QDcVYGcKjuJIJLiu8cLQZ/tSN3SF0UwvSFMuq8CgYAWKiMqdt5Ht7RA8AgtNQ7n
gzLBxRr1xSOygLhSqM33YUoOhG4JbwHexp6VGtTk+qxyDLPs0u5IwwRzTiPbib0x
BqKojkh7YODlk6NTfomKyFwolO+T0ku8dMGfiISVA38eIa/oCvfRzbhqXwVGgHvM
gaKHCFqvX6HFZFe+QGILuQKBgGs6eXhuB8yeOl1zk/eQED865jYTpR/yLMhnnbFe
mDsBV3ikA9pegF6xfg2VRf9noNJhz+x1wMuteJ5yPTTvoYM+x9/DuF7CGTIsiqwr
exrVT6iJ8+uE0V0C2mqfj5xOnUP5M6Dv5Ep1QvrL6lO6HVyxzIz3jaAQxCLwLhwX
awKnAoGARRldRtE3yzAhPs8SuSRmCeHAbjzPOH6kEa8VZTM/BKfOJLcrzWvljgfh
3JBnlCEzLACxvOJmAloL/lpubbnl2rgHUZZ7CMiBJvoZCpBzaKrUVqj6lCoHsOFL
C9v3zDBTLhYDIbhuQkxUALlqQf7YvJSC8bkUw1Qeg/rMznHpWVs=
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
