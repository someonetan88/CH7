require("dotenv").config();
require("./instrument");

const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const Sentry = require("@sentry/node");
const { Server } = require("socket.io");
const http = require("http");
const { users, findUserByEmail, hashPassword } = require("./models/user");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.set("view engine", "ejs");

// Setup mailer
const transporter = nodemailer.createTransport({
  service: "gmail",
  host: "smtp.gmail.com",
  port: 587,
  secure: false,
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS,
  },
  tls: {
    rejectUnauthorized: false,
  },
});

// Routes
app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  if (findUserByEmail(email)) {
    Sentry.captureException(`User ${email} already exists`);
    return res.status(400).send("User already exists");
  }
  const hashedPassword = await hashPassword(password);
  users.push({ email, password: hashedPassword });
  io.emit("notification", { message: `User ${email} registered!` });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = findUserByEmail(email);
  if (user) {
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (passwordMatch) {
      const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET, { expiresIn: "1h" });
      io.emit("notification", { message: `Welcome ${email} this is your token ${token}` });
      // res.json({ token });
    } else {
      io.emit("notification", { message: `Invalid credentials` });
    }
  } else {
    io.emit("notification", { message: `Invalid credentials` });
  }
});

app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  const user = findUserByEmail(email);
  if (user) {
    const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET, { expiresIn: "15m" });
    const resetLink = `http://localhost:${process.env.PORT}/reset-password?token=${token}`;

    transporter.sendMail(
      {
        from: process.env.MAILER_USER,
        to: user.email,
        subject: "Password Reset",
        text: `Click here to reset your password: ${resetLink}`,
      },
      (err) => {
        if (err) {
          console.log(err);
          Sentry.captureException(err);
          return io.emit("notification", { message: "Error sending password reset link" });
        }
        io.emit("notification", { message: "Password reset link sent" });
      }
    );
  } else {
    io.emit("notification", { message: "User not found" });
    Sentry.captureException("User not found");
  }
});

app.get("/reset-password", (req, res) => {
  const { token } = req.query;
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    res.render("reset-password", { email: decoded.email });
  } catch (err) {
    Sentry.captureException(err);
    res.status(400).send("Invalid token");
  }
});

app.post("/reset-password", async (req, res) => {
  const { email, password } = req.body;
  const user = findUserByEmail(email);
  if (user) {
    user.password = await hashPassword(password);
    io.emit("notification", { message: `Password updated for ${email}` });
  } else {
    res.status(404).send("User not found");
  }
});

// Optional fallthrough error handler
app.use(function onError(err, req, res, next) {
  Sentry.captureException(err);
  res.statusCode = 500;
  res.end(res.sentry + "\n");
});

// Start server
const port = process.env.PORT || 3000;
server.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

// Socket.io connection
io.on("connection", (socket) => {
  console.log("A user connected");
});

// Route to test Sentry error reporting
app.get("/debug-sentry", function mainHandler(req, res) {
  throw new Error("My first Sentry error!");
});

// Route to display login page
app.get("/", (_, res) => {
  res.render("login");
});
app.get("/login", (_, res) => {
  res.render("login");
});
app.get("/forgot-password", (_, res) => {
  res.render("forgot-password");
});
app.get("/register", (_, res) => {
  res.render("register");
});
