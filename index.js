const crypto = require("crypto");
const axios = require("axios");
const dotenv = require("dotenv");
const express = require("express");
const fs = require("fs");
const https = require("https");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();

dotenv.config({ path: path.join(__dirname, ".env.server") });

function writeCertFromEnv(certEnvKey, keyEnvKey, certPath, keyPath) {
  const certValue = process.env[certEnvKey];
  const keyValue = process.env[keyEnvKey];

  if (!certValue || !keyValue || !certPath || !keyPath) return;

  const resolvedCertPath = path.resolve(__dirname, certPath);
  const resolvedKeyPath = path.resolve(__dirname, keyPath);
  const certDir = path.dirname(resolvedCertPath);
  const keyDir = path.dirname(resolvedKeyPath);

  if (!fs.existsSync(certDir)) {
    fs.mkdirSync(certDir, { recursive: true });
  }
  if (!fs.existsSync(keyDir)) {
    fs.mkdirSync(keyDir, { recursive: true });
  }

  if (!fs.existsSync(resolvedCertPath)) {
    fs.writeFileSync(resolvedCertPath, certValue.replace(/\\n/g, "\n"));
  }

  if (!fs.existsSync(resolvedKeyPath)) {
    fs.writeFileSync(resolvedKeyPath, keyValue.replace(/\\n/g, "\n"));
  }
}

const app = express();
const PORT = Number(process.env.PORT) || 4000;
const dbPath = path.join(__dirname, "records.sqlite");
const db = new sqlite3.Database(dbPath);
const TOSS_API_BASE_URL =
  process.env.TOSS_API_BASE_URL || "https://apps-in-toss-api.toss.im";
const AUTH_API_BASE =
  process.env.AUTH_API_BASE ||
  `${TOSS_API_BASE_URL}/api-partner/v1/apps-in-toss/user/oauth2`;
const CLIENT_CERT_PATH = process.env.CLIENT_CERT_PATH;
const CLIENT_KEY_PATH = process.env.CLIENT_KEY_PATH;
const AAD = process.env.AAD_STRING || "TOSS";
const DECRYPTION_KEY_BASE64 = process.env.DECRYPTION_KEY_BASE64;

writeCertFromEnv(
  "TOSS_CLIENT_CERT",
  "TOSS_CLIENT_KEY",
  CLIENT_CERT_PATH,
  CLIENT_KEY_PATH
);

const tossApi = axios.create({
  baseURL: AUTH_API_BASE,
  timeout: 6000,
  httpsAgent: new https.Agent({
    cert: CLIENT_CERT_PATH
      ? fs.readFileSync(path.resolve(__dirname, CLIENT_CERT_PATH))
      : undefined,
    key: CLIENT_KEY_PATH
      ? fs.readFileSync(path.resolve(__dirname, CLIENT_KEY_PATH))
      : undefined,
    rejectUnauthorized: true,
  }),
});

db.serialize(() => {
  db.run(
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      toss_user_key TEXT UNIQUE NOT NULL,
      name TEXT,
      birth_year INTEGER,
      created_at TEXT NOT NULL
    )`
  );
  db.run(
    `CREATE TABLE IF NOT EXISTS records (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      time REAL NOT NULL,
      user_id INTEGER,
      created_at TEXT NOT NULL
    )`
  );

  db.all("PRAGMA table_info(records)", (err, columns) => {
    if (err || !Array.isArray(columns)) return;
    const hasUserId = columns.some((column) => column.name === "user_id");
    if (!hasUserId) {
      db.run("ALTER TABLE records ADD COLUMN user_id INTEGER");
    }
  });
});

app.use(express.json());
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, X-User-Id, Authorization"
  );
  res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");

  if (req.method === "OPTIONS") {
    res.sendStatus(204);
    return;
  }

  next();
});

function decryptField(encryptedText) {
  if (!encryptedText || !DECRYPTION_KEY_BASE64) return null;

  const key = Buffer.from(DECRYPTION_KEY_BASE64, "base64");
  const decoded = Buffer.from(encryptedText, "base64");
  if (decoded.length <= 28) return null;

  const iv = decoded.subarray(0, 12);
  const cipherTextWithTag = decoded.subarray(12);
  const tag = cipherTextWithTag.subarray(cipherTextWithTag.length - 16);
  const cipherText = cipherTextWithTag.subarray(0, cipherTextWithTag.length - 16);

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAAD(Buffer.from(AAD, "utf8"));
  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([decipher.update(cipherText), decipher.final()]);
  return decrypted.toString("utf8");
}

function parseBirthYear(birthday) {
  if (!birthday) return null;
  const digits = String(birthday).replace(/[^0-9]/g, "");
  if (digits.length < 4) return null;
  const year = Number(digits.slice(0, 4));
  return Number.isFinite(year) ? year : null;
}

function getUserId(req) {
  const headerValue = req.get("x-user-id");
  const bodyValue = req.body?.userId;
  const candidate = headerValue ?? bodyValue;
  if (candidate === undefined || candidate === null) return null;
  const parsed = Number(candidate);
  if (!Number.isFinite(parsed) || parsed <= 0) return null;
  return Math.trunc(parsed);
}

function getBirthYearRange(ageGroup, currentYear) {
  switch (ageGroup) {
    case "10s":
      return { minYear: currentYear - 19, maxYear: currentYear - 10 };
    case "20s":
      return { minYear: currentYear - 29, maxYear: currentYear - 20 };
    case "30s":
      return { minYear: currentYear - 39, maxYear: currentYear - 30 };
    case "40s":
      return { minYear: 0, maxYear: currentYear - 40 };
    default:
      return null;
  }
}

function buildDistribution(times, bucketCount) {
  const distribution = Array(bucketCount).fill(0);
  if (!times.length) return distribution;

  const sorted = [...times].sort((a, b) => a - b);
  const bucketSize = 100 / bucketCount;

  sorted.forEach((_, index) => {
    const percentile = (index / sorted.length) * 100;
    const bucket = Math.min(
      bucketCount - 1,
      Math.floor(percentile / bucketSize)
    );
    distribution[bucket] += 1;
  });

  return distribution;
}

app.post("/auth/toss/login", async (req, res) => {
  const authorizationCode = req.body?.authorizationCode;
  const referrer = req.body?.referrer;

  if (!authorizationCode || !referrer) {
    res.status(400).json({ message: "Missing authorizationCode/referrer" });
    return;
  }

  if (!CLIENT_CERT_PATH || !CLIENT_KEY_PATH || !DECRYPTION_KEY_BASE64) {
    res.status(500).json({ message: "Missing server auth config" });
    return;
  }

  try {
    console.info("[toss-login] generate-token request");
    const tokenResponse = await tossApi.post(
      "/generate-token",
      { authorizationCode, referrer },
      { headers: { "Content-Type": "application/json" } }
    );

    console.info(
      "[toss-login] generate-token result",
      tokenResponse.data?.resultType
    );
    if (tokenResponse.data?.resultType !== "SUCCESS") {
      res.status(502).json({ message: "Failed to get access token" });
      return;
    }

    const accessToken = tokenResponse.data?.success?.accessToken;
    if (!accessToken) {
      res.status(502).json({ message: "Missing access token" });
      return;
    }

    console.info("[toss-login] login-me request");
    const meResponse = await tossApi.get("/login-me", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    console.info("[toss-login] login-me result", meResponse.data?.resultType);
    if (meResponse.data?.resultType !== "SUCCESS") {
      res.status(502).json({ message: "Failed to load user info" });
      return;
    }

    const success = meResponse.data?.success || {};
    const userKey = success.userKey;
    if (!userKey) {
      res.status(400).json({ message: "Missing userKey" });
      return;
    }

    const name = decryptField(success.name);
    const birthYear = parseBirthYear(decryptField(success.birthday));
    const createdAt = new Date().toISOString();

    db.get(
      "SELECT id FROM users WHERE toss_user_key = ?",
      [String(userKey)],
      (selectErr, row) => {
        if (selectErr) {
          res.status(500).json({ message: "Failed to load user" });
          return;
        }

        if (row?.id) {
          console.info("[toss-login] user found", row.id);
          res.json({ userId: row.id });
          return;
        }

        db.run(
          "INSERT INTO users (toss_user_key, name, birth_year, created_at) VALUES (?, ?, ?, ?)",
          [String(userKey), name, birthYear, createdAt],
          function onInsert(insertErr) {
            if (insertErr) {
              res.status(500).json({ message: "Failed to save user" });
              return;
            }

            console.info("[toss-login] user created", this.lastID);
            res.json({ userId: this.lastID });
          }
        );
      }
    );
  } catch (error) {
    const status = error?.response?.status;
    const data = error?.response?.data;
    console.error("토스 로그인 처리에 실패했어요.", status, data || error);
    res.status(502).json({ message: "Login failed" });
  }
});

app.post("/auth/toss/disconnect", (req, res) => {
  console.info("[toss-disconnect] payload", req.body);
  // TODO: handle user unlink (e.g., deactivate user, revoke tokens) if needed.
  res.sendStatus(200);
});

app.get("/api/stats", (req, res) => {
  const ageGroup = String(req.query?.ageGroup ?? "all");
  const allowedGroups = new Set(["all", "10s", "20s", "30s", "40s"]);

  if (!allowedGroups.has(ageGroup)) {
    res.status(400).json({ message: "Invalid ageGroup" });
    return;
  }

  const currentYear = new Date().getFullYear();
  const range = getBirthYearRange(ageGroup, currentYear);
  const userId = getUserId(req);

  let whereClause = "";
  let params = [];

  if (ageGroup !== "all" && range) {
    if (ageGroup === "40s") {
      whereClause = "WHERE u.birth_year IS NOT NULL AND u.birth_year <= ?";
      params = [range.maxYear];
    } else {
      whereClause =
        "WHERE u.birth_year IS NOT NULL AND u.birth_year BETWEEN ? AND ?";
      params = [range.minYear, range.maxYear];
    }
  }

  db.all(
    `SELECT r.time AS time
     FROM records r
     LEFT JOIN users u ON r.user_id = u.id
     ${whereClause}`,
    params,
    (err, rows) => {
      if (err) {
        res.status(500).json({ message: "Failed to load stats" });
        return;
      }

      const times = rows
        .map((row) => Number(row?.time))
        .filter((value) => Number.isFinite(value));
      const sampleCount = times.length;
      const averageTime =
        sampleCount > 0
          ? times.reduce((sum, value) => sum + value, 0) / sampleCount
          : null;
      const distribution = buildDistribution(times, 11);

      const respondWithUserTime = (myTime) => {
        const validMyTime = Number.isFinite(myTime) ? myTime : null;
        const fasterCount =
          validMyTime !== null
            ? times.filter((value) => value < validMyTime).length
            : 0;
        const percentile =
          validMyTime !== null && sampleCount > 0
            ? Math.round((fasterCount / sampleCount) * 100)
            : null;

        res.json({
          ageGroup,
          myTime: validMyTime !== null ? Number(validMyTime.toFixed(2)) : null,
          averageTime:
            averageTime !== null ? Number(averageTime.toFixed(2)) : null,
          percentile,
          distribution,
          sampleCount,
        });
      };

      if (!userId) {
        respondWithUserTime(null);
        return;
      }

      db.get(
        "SELECT MIN(time) AS bestTime FROM records WHERE user_id = ?",
        [userId],
        (bestErr, row) => {
          if (bestErr) {
            res.status(500).json({ message: "Failed to load user record" });
            return;
          }
          const bestTime = Number(row?.bestTime);
          respondWithUserTime(bestTime);
        }
      );
    }
  );
});

app.get("/auth/me", (req, res) => {
  const userId = getUserId(req);

  if (!userId) {
    res.status(401).json({ loggedIn: false });
    return;
  }

  db.get(
    "SELECT name, birth_year FROM users WHERE id = ?",
    [userId],
    (selectErr, row) => {
      if (selectErr) {
        res.status(503).json({ loggedIn: false });
        return;
      }
      if (!row) {
        res.status(401).json({ loggedIn: false });
        return;
      }

      res.json({
        loggedIn: true,
        user: {
          name: row.name ?? null,
          birthYear: row.birth_year ?? null,
        },
      });
    }
  );
});

app.post("/result", (req, res) => {
  const time = Number(req.body?.time);
  const userId = getUserId(req);

  if (!Number.isFinite(time) || time <= 0) {
    res.status(400).json({ message: "Invalid time" });
    return;
  }

  if (!userId) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const createdAt = new Date().toISOString();

  db.run(
    "INSERT INTO records (time, user_id, created_at) VALUES (?, ?, ?)",
    [time, userId, createdAt],
    (insertErr) => {
      if (insertErr) {
        res.status(500).json({ message: "Failed to save record" });
        return;
      }

      const isLoggedIn = true;

      const computeStats = (effectiveTime) => {
        db.get(
          `SELECT
            AVG(time) AS averageTime,
            SUM(CASE WHEN time < ? THEN 1 ELSE 0 END) AS fasterCount,
            COUNT(*) AS totalCount
          FROM records`,
          [effectiveTime],
          (statsErr, row) => {
            if (statsErr) {
              res.status(500).json({ message: "Failed to compute stats" });
              return;
            }

            const totalCount = row?.totalCount ?? 1;
            const fasterCount = row?.fasterCount ?? 0;
            const averageTime = row?.averageTime ?? effectiveTime;
            const rankPercent = Math.round((fasterCount / totalCount) * 100);

            res.json({
              myTime: Number(effectiveTime.toFixed(2)),
              averageTime: Number(averageTime.toFixed(2)),
              rankPercent,
              isLoggedIn,
            });
          }
        );
      };

      if (isLoggedIn) {
        db.get(
          "SELECT MIN(time) AS bestTime FROM records WHERE user_id = ?",
          [userId],
          (bestErr, row) => {
            if (bestErr) {
              res.status(500).json({ message: "Failed to compute best time" });
              return;
            }

            const bestTime = row?.bestTime ?? time;
            computeStats(bestTime);
          }
        );
      } else {
        computeStats(time);
      }
    }
  );
});

app.listen(PORT, () => {
  console.log(`1to50 server listening on http://localhost:${PORT}`);
});
