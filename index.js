require("dotenv").config();
const express = require("express");
const nunjucks = require("nunjucks");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const { MongoClient, ObjectId } = require("mongodb");
const helmet = require("helmet");
const csurf = require("csurf");
const rateLimit = require("express-rate-limit");
const { body, validationResult } = require("express-validator");
const marked = require("marked");

const app = express();

nunjucks.configure("views", {
  autoescape: true,
  express: app,
});


app.set("view engine", "njk");

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static("public"));
app.use(helmet());
const csrfProtection = csurf({ cookie: true });

// ограничение частоты запросов аутентификации
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 минут
  max: 100,
});
// ограничение частоты запросов мутаций API
const apiMutationsLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 1000 });

// CSRF токен
app.get("/api/csrf-token", csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

function getCookieOptions() {
  const isProd = process.env.NODE_ENV === "production";
  return {
    httpOnly: true,
    sameSite: isProd ? "lax" : undefined,
    secure: isProd ? true : undefined,
  };
}

// хеширование паролей
async function hashPassword(password) {
  const saltRounds = 10;
  return bcrypt.hash(String(password), saltRounds);
}

// подключение к MongoDB
const clientPromise = MongoClient.connect(process.env.DB_URI);

app.use(async (req, res, next) => {
  try {
    const client = await clientPromise;
    const dbName = process.env.DB_NAME || "notes";
    req.db = client.db(dbName);
    next();
  } catch (err) {
    next(err);
  }
});

// аутентификация
async function getAuthentication(req, res, next) {
  try {
    const cookies = req.cookies || {};
    const sessionId = cookies.sessionId;
    if (!sessionId) {
      req.user = null;
      return next();
    }
    const db = req.db;
    if (!db) {
      req.user = null;
      return next();
    }
    const session = await db.collection("sessions").findOne({ _id: new ObjectId(sessionId) });
    if (!session) {
      req.user = null;
      return next();
    }
    const user = await db.collection("users").findOne({ _id: new ObjectId(session.user_id) });
    req.user = user ? { id: user._id, username: user.username } : null;
    return next();
  } catch (err) {
    console.error(err);
    req.user = null;
    return next();
  }
}

// маршруты
app.get("/", getAuthentication, (req, res) => {
  if (req.user) {
    return res.redirect("/dashboard");
  }
  return res.render("index", {
    authError: req.query.authError,
  });
});

app.get("/dashboard", getAuthentication, (req, res) => {
  if (!req.user) {
    return res.redirect("/");
  }
  return res.render("dashboard", {
    username: req.user.username,
  });
});

// health-check
app.get("/api/health", (req, res) => {
  res.json({ ok: true, uptime: process.uptime(), now: new Date().toISOString() });
});

// регистрация
app.post(
  "/signup",
  authLimiter,
  [
    body("username")
      .trim()
      .toLowerCase()
      .notEmpty().withMessage("Укажите имя пользователя")
      .isLength({ min: 3, max: 32 }).withMessage("Имя: 3–32 символа"),
    body("password")
      .isLength({ min: 6 }).withMessage("Пароль: минимум 6 символов"),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        const msg = errors.array()[0]?.msg || "Неверные данные";
        return res.redirect("/?authError=" + encodeURIComponent(msg));
      }
      const db = req.db;
      const { username, password } = req.body;
      const existing = await db.collection("users").findOne({ username });
      if (existing) {
        return res.redirect("/?authError=" + encodeURIComponent("Пользователь уже существует"));
      }
      const passwordHash = await hashPassword(String(password));
      const result = await db.collection("users").insertOne({ username, passwordHash, createdAt: new Date() });
      const userId = result.insertedId;
      const session = await db.collection("sessions").insertOne({ user_id: userId, createdAt: new Date() });
      res.cookie("sessionId", session.insertedId.toString(), getCookieOptions());
      return res.redirect("/dashboard");
    } catch (err) {
      console.error(err);
      return res.redirect("/?authError=" + encodeURIComponent("Ошибка регистрации"));
    }
  }
);

// логин
app.post("/login", authLimiter, async (req, res) => {
  try {
    const db = req.db;
    let { username, password } = req.body || {};
    username = String(username || "").trim();
    password = String(password || "");
    const user = await db.collection("users").findOne({ username });
    if (!user) {
      return res.redirect("/?authError=" + encodeURIComponent("Неверное имя пользователя"));
    }
    const ok = await bcrypt.compare(String(password || ""), user.passwordHash);
    if (!ok) {
      return res.redirect("/?authError=" + encodeURIComponent("Неверный пароль"));
    }
    const session = await db.collection("sessions").insertOne({ user_id: user._id, createdAt: new Date() });
    res.cookie("sessionId", session.insertedId.toString(), getCookieOptions());
    return res.redirect("/dashboard");
  } catch (err) {
    console.error(err);
    return res.redirect("/?authError=" + encodeURIComponent("Ошибка аутентификации"));
  }
});

// логаут
app.get("/logout", async (req, res) => {
  try {
    const db = req.db;
    const sessionId = req.cookies.sessionId;
    if (sessionId) await db.collection("sessions").deleteOne({ _id: new ObjectId(sessionId) });
    res.clearCookie("sessionId");
  } catch (err) {
    console.error(err);
  }
  return res.redirect("/");
});

// получение списка заметок с фильтрацией по периоду/архиву
app.get("/api/notes", getAuthentication, async (req, res) => {
  if (!req.user) {
    return res.status(401).send("Unauthorized");
  }

  let { age = "1week", search = "", page = "1" } = req.query;
  const allowedAges = new Set(["1week", "1month", "3months", "alltime", "archive"]);
  if (!allowedAges.has(String(age))) age = "1week";
  search = String(search || "").slice(0, 100);
  const now = Date.now();

  let cutoff = null;
  if (age === "1week") {
    cutoff = now - 7 * 24 * 60 * 60 * 1000;
  } else if (age === "1month") {
    cutoff = now - 30 * 24 * 60 * 60 * 1000;
  } else if (age === "3months") {
    cutoff = now - 90 * 24 * 60 * 60 * 1000;
  } else if (age === "alltime" || age === "archive") {
    cutoff = null;
  }

  const db = req.db;
  const notesCol = db.collection("notes");
  const userId = typeof req.user.id === "string" ? new ObjectId(req.user.id) : req.user.id;

  // фильтрация
  const filter = { user_id: userId };
  if (age === "archive") {
    filter.archived = true;
  } else {
    filter.archived = { $ne: true };
  }
  if (cutoff) {
    filter.createdAt = { $gte: new Date(cutoff) };
  }

  // поиск по заголовку
  const q = String(search || "").trim().toLowerCase();

  function escapeHtml(str = "") {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function highlightTitle(title, q) {
    if (!q) return null;
    const idx = title.toLowerCase().indexOf(q);
    if (idx === -1) return null;
    const before = escapeHtml(title.slice(0, idx));
    const match = escapeHtml(title.slice(idx, idx + q.length));
    const after = escapeHtml(title.slice(idx + q.length));
    return `${before}<mark>${match}</mark>${after}`;
  }

  if (q) {
    filter.title = { $regex: q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), $options: "i" };
  }

  const pageNum = Math.max(parseInt(page, 10) || 1, 1);
  const pageSize = 20;
  const skip = (pageNum - 1) * pageSize;

  const cursor = notesCol
    .find(filter)
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(pageSize);

  const [items, total] = await Promise.all([
    cursor.toArray(),
    notesCol.countDocuments(filter),
  ]);

  const allMatched = items.map((n) => ({
    _id: n._id.toString(),
    title: n.title,
    text: n.text,
    created: n.createdAt?.toISOString?.() || n.createdAt,
    isArchived: !!n.archived,
    highlights: highlightTitle(n.title || "", q) || undefined,
  }));

  // пагинация
  const end = skip + pageSize;
  const hasMore = total > end;
  res.json({ data: allMatched, hasMore });
});

// получение одной заметки
app.get("/api/notes/:id", getAuthentication, async (req, res) => {
  if (!req.user) return res.status(401).send("Unauthorized");
  const db = req.db;
  const notesCol = db.collection("notes");
  const userId = typeof req.user.id === "string" ? new ObjectId(req.user.id) : req.user.id;
  const id = req.params.id;
  if (!ObjectId.isValid(id)) return res.status(400).send("Bad id");
  const note = await notesCol.findOne({ _id: new ObjectId(id), user_id: userId });
  if (!note) return res.status(404).send("Not found");

  const text = String(note.text || "");
  const html = typeof marked.parse === "function" ? marked.parse(text) : marked(text);

  return res.json({
    _id: note._id.toString(),
    title: note.title,
    text: note.text,
    created: note.createdAt?.toISOString?.() || note.createdAt,
    isArchived: !!note.archived,
    html,
  });
});

// удаление всех заархивированных заметок
app.delete("/api/notes/archived", getAuthentication, apiMutationsLimiter, csrfProtection, async (req, res) => {
  if (!req.user) return res.status(401).send("Unauthorized");
  const db = req.db;
  const notesCol = db.collection("notes");
  const userId = typeof req.user.id === "string" ? new ObjectId(req.user.id) : req.user.id;
  await notesCol.deleteMany({ user_id: userId, archived: true });
  return res.json({ ok: true });
});

// удаление одной архивной заметки
app.delete("/api/notes/:id", getAuthentication, apiMutationsLimiter, csrfProtection, async (req, res) => {
  if (!req.user) return res.status(401).send("Unauthorized");
  const db = req.db;
  const notesCol = db.collection("notes");
  const userId = typeof req.user.id === "string" ? new ObjectId(req.user.id) : req.user.id;
  const id = req.params.id;
  if (!ObjectId.isValid(id)) return res.status(400).send("Bad id");
  const result = await notesCol.deleteOne({ _id: new ObjectId(id), user_id: userId, archived: true });
  if (!result.deletedCount) return res.status(404).send("Not found or not archived");
  return res.json({ ok: true });
});

// редактирование заметки
app.put("/api/notes/:id", getAuthentication, apiMutationsLimiter, csrfProtection, async (req, res) => {
  if (!req.user) return res.status(401).send("Unauthorized");
  const db = req.db;
  const notesCol = db.collection("notes");
  const userId = typeof req.user.id === "string" ? new ObjectId(req.user.id) : req.user.id;
  const id = req.params.id;
  if (!ObjectId.isValid(id)) return res.status(400).send("Bad id");
  let { title = "", text = "" } = req.body || {};
  title = String(title || "").trim();
  text = String(text || "");
  if (title.length > 200) return res.status(400).send("Title too long");
  if (text.length > 20000) return res.status(400).send("Text too long");
  const result = await notesCol.updateOne(
    { _id: new ObjectId(id), user_id: userId },
    { $set: { title: String(title || ""), text: String(text || "") } }
  );
  if (!result.matchedCount) return res.status(404).send("Not found");
  return res.json({ ok: true });
});

// архивирование
app.post("/api/notes/:id/archive", getAuthentication, apiMutationsLimiter, csrfProtection, async (req, res) => {
  if (!req.user) return res.status(401).send("Unauthorized");
  const db = req.db;
  const notesCol = db.collection("notes");
  const userId = typeof req.user.id === "string" ? new ObjectId(req.user.id) : req.user.id;
  const id = req.params.id;
  if (!ObjectId.isValid(id)) return res.status(400).send("Bad id");
  const result = await notesCol.updateOne(
    { _id: new ObjectId(id), user_id: userId },
    { $set: { archived: true } }
  );
  if (!result.matchedCount) return res.status(404).send("Not found");
  return res.json({ ok: true });
});

// разархивирование
app.post("/api/notes/:id/unarchive", getAuthentication, apiMutationsLimiter, csrfProtection, async (req, res) => {
  if (!req.user) return res.status(401).send("Unauthorized");
  const db = req.db;
  const notesCol = db.collection("notes");
  const userId = typeof req.user.id === "string" ? new ObjectId(req.user.id) : req.user.id;
  const id = req.params.id;
  if (!ObjectId.isValid(id)) return res.status(400).send("Bad id");
  const result = await notesCol.updateOne(
    { _id: new ObjectId(id), user_id: userId },
    { $set: { archived: false } }
  );
  if (!result.matchedCount) return res.status(404).send("Not found");
  return res.json({ ok: true });
});

// создание новой заметки
app.post("/api/notes", getAuthentication, apiMutationsLimiter, csrfProtection, async (req, res) => {
  if (!req.user) {
    return res.status(401).send("Unauthorized");
  }

  let { title = "", text = "" } = req.body || {};
  title = String(title || "").trim();
  text = String(text || "");
  if (!title && !text) {
    return res.status(400).send("Title or text is required");
  }
  if (title.length > 200) return res.status(400).send("Title too long");
  if (text.length > 20000) return res.status(400).send("Text too long");

  const db = req.db;
  const notesCol = db.collection("notes");
  const userId = typeof req.user.id === "string" ? new ObjectId(req.user.id) : req.user.id;

  const doc = {
    user_id: userId,
    title: String(title || ""),
    text: String(text || ""),
    createdAt: new Date(),
    archived: false,
  };
  const result = await notesCol.insertOne(doc);
  const note = {
    _id: result.insertedId.toString(),
    title: doc.title,
    text: doc.text,
    createdAt: doc.createdAt.toISOString(),
    archived: doc.archived,
  };
  return res.json(note);
});

// обработчик ошибок
app.use((err, req, res) => {
  console.error(err);
  if (req.path && req.path.startsWith("/api/")) {
    return res.status(500).json({ error: "Internal Server Error" });
  }
  res.status(500).send("Internal Server Error");
});

app.use((req, res) => {
  res.status(404);
  return res.render("404");
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Listening on http://localhost:${port}`);
});
