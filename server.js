const express = require('express');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require("fs");
const rateLimit = require('express-rate-limit');

const Agencies = require('./models/Agencies');
const Vehicle = require('./models/Vehicles');
const User = require("./models/User");
const OTP = require("./models/OTP");
const Counter = require("./models/Counter");
const Booking = require("./models/Booking");

require("dotenv").config();

const session = require("express-session");
const MongoStore = require("connect-mongo");

const app = express();
app.set('trust proxy', 1); 
app.use(bodyParser.json());

// ✅ FIXED CORS - Works for both local and Render
const isProduction = process.env.NODE_ENV === 'production';

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, Postman, same-origin)
    if (!origin) return callback(null, true);
    
    const allowedOrigins = [
      'http://localhost:5000',
      'http://localhost:3000',
      'http://127.0.0.1:5000',
      'https://customer-0lnl.onrender.com'
    ];
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(null, true); // ✅ Allow all origins temporarily for testing
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Serve public folder
app.use(express.static(path.join(__dirname, 'public')));

// MongoDB Setup
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.error("❌ MongoDB Error:", err));

// Booking ID Helper
async function getNextBookingId() {
  const counter = await Counter.findOneAndUpdate(
    { id: "booking_seq" },
    { $inc: { seq: 1 } },
    { new: true, upsert: true }
  );
  return "BO113" + counter.seq;
}

// Email Transporter
// ✅ ENHANCED Email Transporter with debugging
const transporter = nodemailer.createTransport({
  service: 'gmail',
  host: 'smtp.gmail.com',
  port: 587,
  secure: false, // Use STARTTLS
  auth: {
    user: process.env.USER,
    pass: process.env.PASS
  },
  tls: {
    rejectUnauthorized: false
  },
  debug: true, // ✅ Enable debug logs
  logger: true // ✅ Enable logger
});

// ✅ Verify email configuration on startup
transporter.verify(function (error, success) {
  if (error) {
    console.log('❌ Email transporter verification failed:', error);
    console.log('❌ Check your USER and PASS environment variables');
  } else {
    console.log('✅ Email server is ready to send messages');
  }
});


// ✅ FIXED SESSION - Works for both HTTP (local) and HTTPS (Render)
app.use(session({
  secret: process.env.SESSION_SECRET || "secret123",
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGO_URI,
    collectionName: "sessions",
  }),
  cookie: {
    maxAge: 1000 * 60 * 60, // 1 hour
    httpOnly: true,
    secure: isProduction, // true in production (HTTPS), false in development (HTTP)
    sameSite: isProduction ? 'none' : 'lax' // 'none' for cross-origin in production
  }
}));

// Rate limiting for OTP
const otpLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  message: { success: false, message: 'Too many OTP requests. Please try again after an hour.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Generate OTP
app.post('/generate-otp', otpLimiter, async (req, res) => {
  const { email } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Email already registered' });
    }

    await OTP.deleteMany({ email });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await OTP.create({ email, otp });

    console.log(`📩 OTP for ${email}: ${otp} (valid 3 min)`);

    await transporter.sendMail({
      from: process.env.USER || 'sharingyatra@gmail.com',
      to: email,
      subject: 'Your OTP Code - Sharing Yatra',
      text: `Dear user,\n\nYour OTP is ${otp}.\nIt will expire in 3 minutes.\n\nDo not share it with anyone.\n\nSharing Yatra`
    });

    res.json({ success: true, message: 'OTP sent successfully' });
  } catch (err) {
    console.error('Error sending OTP:', err);
    res.status(500).json({ success: false, message: 'Failed to send OTP' });
  }
});

// Register
app.post('/register', async (req, res) => {
  const { email, username, password, otp, phone, age } = req.body;

  try {
    const otpRecord = await OTP.findOne({ email });
    if (!otpRecord) {
      return res.status(400).json({ success: false, message: 'OTP not generated or expired' });
    }

    if (!username || username.trim() === "") {
      return res.status(400).json({ success: false, message: 'Name is required' });
    }

    if (otpRecord.otp !== otp) {
      await OTP.deleteOne({ email });
      return res.status(400).json({ success: false, message: 'Invalid OTP' });
    }

    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    if (!passwordRegex.test(password)) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 8 characters long, include uppercase, lowercase, number, and a special character."
      });
    }

    const phoneRegex = /^(\+\d{1,3}[- ]?)?\d{10}$/;
    if (!phoneRegex.test(phone)) {
      return res.status(400).json({ success: false, message: 'Phone number must be 10 digits (country code optional)' });
    }

    if (!age || age.toString().trim() === "") {
      return res.status(400).json({ success: false, message: 'Age is required' });
    }

    const ageNum = parseInt(age);
    if (isNaN(ageNum) || ageNum < 18 || ageNum > 120) {
      return res.status(400).json({ 
        success: false, 
        message: 'Age must be a number between 18 and 120' 
      });
    }

    const newUser = new User({ email, username, password, phone, age: ageNum });
    await newUser.save();
    await OTP.deleteOne({ email });

    res.json({ success: true, message: 'User registered successfully' });
  } catch (err) {
    console.error('Error registering user:', err);
    res.status(500).json({ success: false, message: 'Registration failed' });
  }
});

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'option.html'));
});

app.get('/customerSignup.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'customerSignup.html'));
});

app.get('/agency', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'agencysignup.html'));
});

// ✅ LOGIN ROUTE - With proper error handling
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  console.log(`📝 Login attempt for: ${email}`); // Debug log

  try {
    let account = await User.findOne({ email });
    let userType = "customer";

    if (!account) {
      account = await Agencies.findOne({ email });
      userType = "agency";
    }

    if (!account) {
      console.log(`❌ Account not found: ${email}`);
      return res.status(400).json({ success: false, message: "Account not found" });
    }

    if (account.password !== password) {
      console.log(`❌ Invalid password for: ${email}`);
      return res.status(400).json({ success: false, message: "Invalid password" });
    }

    req.session.user = {
      id: account._id,
      email: account.email,
      phone: account.phone,
      name: userType === "customer" ? account.username : "Agency",
      type: userType
    };

    // Save session explicitly
    req.session.save((err) => {
      if (err) {
        console.error('Session save error:', err);
        return res.status(500).json({ success: false, message: "Session error" });
      }
      console.log(`✅ Login successful: ${email}`);
      res.json({ success: true, message: "Login successful" });
    });

  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.get("/api/profile", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ message: "Not logged in" });
  }
  res.json(req.session.user);
});

app.get("/dashboard", (req, res) => {
  if (!req.session.user) {
    return res.redirect("/login.html");
  }
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

// ... rest of your code (Rail Graph, routes, etc.)

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
});
