const express = require("express");
const fs = require("fs");
const path = require("path");

const app = express();

const logFilePath = path.join(__dirname, "visits.log");

app.use((req, res, next) => {
  const now = new Date().toISOString();
  const ip =
    req.headers["x-forwarded-for"]?.toString().split(",")[0].trim() ||
    req.socket.remoteAddress ||
    "";
  const userAgent = req.headers["user-agent"] || "";
  const acceptLanguage = req.headers["accept-language"] || "";
  const url = req.originalUrl || req.url || "";

  const entry = {
    time: now,
    ip,
    userAgent,
    acceptLanguage,
    url
  };

  try {
    fs.appendFileSync(logFilePath, JSON.stringify(entry) + "\n", { encoding: "utf8" });
  } catch (e) {
  }

  next();
});

const publicDir = path.join(__dirname, "public");
app.use(express.static(publicDir));

app.get("*", (_req, res) => {
  res.sendFile(path.join(publicDir, "index.html"));
});

const port = process.env.PORT || 3000;

app.listen(port, () => {
  console.log(`Scam info web listening on http://localhost:${port}/`);
});

