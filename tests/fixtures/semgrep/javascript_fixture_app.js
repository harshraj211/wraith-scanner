const express = require("express");
const axios = require("axios");
const fs = require("fs");

const app = express();

app.get("/reflect", (req, res) => {
  res.send(req.query.name);
});

app.get("/redirect", (req, res) => {
  res.redirect(req.query.next);
});

app.get("/fetch", async (req, res) => {
  const response = await axios.get(req.query.url);
  res.json(response.data);
});

app.get("/file", (req, res) => {
  const filePath = req.query.path;
  fs.readFile(filePath, "utf8", () => {});
  res.end("ok");
});

app.get("/user", async (req, res) => {
  const id = req.query.id;
  const rows = await db.query(`SELECT * FROM users WHERE id = ${id}`);
  res.json(rows);
});

module.exports = app;
