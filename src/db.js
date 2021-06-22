"use strict";

const pino = require("pino");
const { MongoClient: mongo, ObjectId } = require("mongodb");
const bcrypt = require("bcrypt");

const MongoConnectionString = process.env.MONGO;
const log = pino({ level: process.env.LOG_LEVEL || "debug" });

const db = {
  connection: null,
  database: null,
  allowedUsers: null,
  users: null,

  connect: async () => {
    if (!!db.connection) return;
    log.info("Connecting to azure cosmos...");

    try {
      db.connection = await mongo.connect(MongoConnectionString, {
        useUnifiedTopology: true
      });

      db.database = db.connection.db("user_db"); // fake name
      db.users = db.database.collection("users");
      db.allowedUsers = db.database.collection("allowed-users");
      log.info("Connected");
    } catch (err) {
      log.error(`Cannot connect`);
      throw { message: "Cannot connect to database", cause: { ...err } };
    }
  },

  save: async user => {
    try {
      await db.connect();
      return await db.users.insertOne(user);
    } catch (err) {
      log.error(err);
      throw { message: `Cannot save user: ${JSON.stringify(user, null, 4)}`, cause: { ...err } };
    }
  },

  isAllowed: async username => {
    try {
      await db.connect();
      const allowedUser = await db.allowedUsers.findOne({ username: username });
      return !!allowedUser;
    } catch (err) {
      log.error(err);
      throw { message: `Cannot determine isAllowed for ${username}`, cause: { ...err } };
    }
  },

  isUser: async username => {
    try {
      await db.connect();
      const user = await db.users.findOne({ username: username });
      return !!user;
    } catch (err) {
      log.error(err);
      throw { message: `Cannot determine isUser for ${username}`, cause: { ...err } };
    }
  },

  authenticate: async (username, password) => {
    try {
      await db.connect();
      const user = await db.users.findOne({ username: username });
      if (!user) return false;
      return bcrypt.compareSync(password, user.password);
    } catch (err) {
      log.error(err);
      throw { message: `Cannot determine isValidUser for ${username}`, cause: { ...err } };
    }
  },

  getUser: async username => {
    try {
      await db.connect();
      const user = await db.users.findOne({ username: username });
      return user;
    } catch (err) {
      log.error(err);
      throw { message: `Cannot getUser: ${username}`, cause: { ...err } };
    }
  },

  getUserId: async username => {
    try {
      await db.connect();
      const user = await db.users.findOne({ username: username });
      if (!user) return false;
      return user._id;
    } catch (err) {
      log.error(err);
      throw { message: `Cannot getUserId: ${username}`, cause: { ...err } };
    }
  },

  updatePassword: async (username, password) => {
    try {
      await db.connect();
      const id = await db.getUserId(username);
      await db.users.updateOne({ _id: new ObjectId(id) }, { $set: { username: username, password: password } }, { upsert: true });
    } catch (err) {
      log.error(err);
      throw { message: `Cannot update password for: ${username}`, cause: { ...err } };
    }
  }
};

module.exports = db;
