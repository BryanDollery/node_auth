"use strict";

// Basic jwt authentication demo
// For demo reasons, this assumes that if the user is in the db and doesn't have a password, then this is a registration event and the given password should be stored

const http = require("http");
const https = require("https");
const express = require("express");
const fs = require("fs");
const bodyParser = require("body-parser");
const pino = require("pino");
const expressPino = require("express-pino-logger");
const db = require("./db");
const jwt = require("jsonwebtoken");
const eJwt = require("express-jwt");
const bcrypt = require("bcrypt");
const { check, validationResult } = require("express-validator");
const log = pino({ level: process.env.LOG_LEVEL || "debug", redact: ["password", "newPassword", "req.headers.authorization"], censor: ["**secret**"] });
const { StatusCodes } = require("http-status-codes");

const PORT = process.env.PORT || 9000;
const exposedPort = process.env.EXPOSED_PORT || PORT;
const ENV = process.env.ENV || dev;
const SSL_KEY_FILE = process.env.SSL_KEY_FILE;
const SSL_CRT_FILE = process.env.SSL_CRT_FILE;
const SSL_CHN_FILE = process.env.SSL_CHN_FILE;
const expressLogger = expressPino({ logger: log });
const salt = bcrypt.genSaltSync(12); // the cost is about a second on my machine, running in docker
const JWT_SECRET = process.env.JWT_KEY || "secret-password";
const ALGORITHM = "HS512";

const azureCreds = {
  region: "westeurope",
  translation: {
    key: "...",
    endpoint: "https://api.cognitive.microsofttranslator.com/"
  },
  transcription: {
    key: "..."
  }
};

const app = express();

app.use((req, res, next) => {
  log.info(`Req-URL: ${req.url}`);
  next();
});

app.use(eJwt({ secret: JWT_SECRET, algorithms: [ALGORITHM] }).unless({ path: ["/auth", "/health"] }));
app.use(expressLogger);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.disable("x-powered-by");

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "*");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");

  if (req.method === "OPTIONS") return res.status(StatusCodes.OK).json({});

  next();
});

app.get("/health", async (req, res) => {
  return res.sendStatus(StatusCodes.OK);
});

app.get("/auth/validate", async (req, res) => {
  return res.sendStatus(StatusCodes.OK);
});

app.put(
  "/auth/changepassword",
  [
    check("username").trim().isAlphanumeric().isLength({ min: 3, max: 16 }).withMessage("username should be between 3 and 16 chars long and may only contain letters and numbers"), //
    check("newPassword").trim().isLength({ min: 4 }).withMessage("password must be at least 4 characters long") //
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);

      if (!errors.isEmpty()) {
        return res.status(StatusCodes.UNPROCESSABLE_ENTITY).json({ errors: errors.array() });
      }

      const username = await req.body.username;
      log.info(`Login attempt for: ${username}`);
      const newPassword = bcrypt.hashSync(req.body.newPassword, salt);
      await db.updatePassword(username, newPassword);
      res.sendStatus(StatusCodes.NO_CONTENT);
    } catch (err) {
      res.status(StatusCodes.INTERNAL_SERVER_ERROR).send(JSON.stringify(err));
    }
  }
);

app.post(
  "/auth",
  [
    check("username").trim().isLength({ min: 3, max: 16 }).withMessage("username should be between 3 and 16 chars long and may only contain letters and numbers"), //
    check("password").trim().isLength({ min: 4 }).withMessage("password must be at least 4 characters long") //
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);

      if (!errors.isEmpty()) {
        log.info(`Resource could not be processed -- see returned error. Given username: ${req.body.username}`);
        return res.status(StatusCodes.UNPROCESSABLE_ENTITY).json({ errors: errors.array() });
      }

      const username = await req.body.username;
      log.info(`Login attempt for: ${username}`);
      const authenticated = await db.authenticate(username, req.body.password);

      if (!authenticated) {
        if (await db.isUser(username)) {
          log.info(`User ${username} did not authenticate due to incorrect password`);
          return res.sendStatus(StatusCodes.UNAUTHORIZED);
        }

        if (!(await db.isAllowed(username))) {
          log.info(`User ${username} did not authenticate due to not being allowed`);
          return res.sendStatus(StatusCodes.FORBIDDEN);
        }

        // Register the user with the hashed password and allow to authenticate
        log.info(`Registering new user ${username}`);
        const hashedPassword = bcrypt.hashSync(req.body.password, salt);
        db.save({ username: username, password: hashedPassword });
      }

      // Authenticated (or newly registered) user
      // Generate and return a 6-hour token

      const id = await db.getUserId(username);
      if (!id) {
        log.error(`Cannot get user id for this username ${username}`);
        return res.sendStatus(StatusCodes.INTERNAL_SERVER_ERROR);
      }

      var token = jwt.sign(
        {
          id: id,
          username: username,
          azureCreds: {
            ...azureCreds
          }
        },
        JWT_SECRET,
        {
          algorithm: ALGORITHM,
          expiresIn: "12h"
        }
      );

      res.send(JSON.stringify({ token: token }));
    } catch (err) {
      res.status(StatusCodes.INTERNAL_SERVER_ERROR).send(JSON.stringify(err));
    }
  }
);

if (ENV === "prod") {
  const privateKey = fs.readFileSync(SSL_KEY_FILE, "utf8");
  const certificate = fs.readFileSync(SSL_CRT_FILE, "utf8");
  const ca = fs.readFileSync(SSL_CHN_FILE, "utf8");

  const creds = {
    key: privateKey,
    cert: certificate,
    ca: ca
  };

  https.createServer(creds, app).listen(PORT, async () => {
    log.info(`CORS Auth service starting...`);
    await db.connect();
    log.info(`CORS Auth service started on port ${exposedPort} in prod with tls (https)`);
  });
} else {
  http.createServer(app).listen(PORT, async () => {
    log.info(`CORS Auth service starting...`);
    await db.connect();
    log.info(`CORS Auth service started on port ${exposedPort} in dev`);
  });
}
