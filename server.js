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

// ✅ FIX: Removed duplicate bodyParser.json()
app.use(bodyParser.json());

// ✅ FIX: Updated CORS to only include frontend origins
// ✅ FIX: Add back your actual frontend URL
app.use(cors({
  origin: [
    "http://localhost:5000",  // If your HTML files are served from this port
    "http://127.0.0.1:5000",  // Alternative localhost
    "https://customer-0lnl.onrender.com"  // Production frontend
  ],
  methods: "GET,POST,PUT,DELETE,OPTIONS",
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization']
}));


// Serve public folder
app.use(express.static(path.join(__dirname, 'public')));

// ====== MongoDB Setup ======
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.error("❌ MongoDB Error:", err));

// ====== Booking ID Helper ======
async function getNextBookingId() {
  const counter = await Counter.findOneAndUpdate(
    { id: "booking_seq" },
    { $inc: { seq: 1 } },
    { new: true, upsert: true }
  );
  return "BO113" + counter.seq;
}

// ====== Email Transporter ======
// ✅ FIX: Removed commented-out hardcoded credentials
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.USER,
    pass: process.env.PASS
  }
});

// ====== Session Setup ======
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
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "lax"
  }
}));

// ✅ FIX: Added rate limiting for OTP generation
const otpLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // Max 5 OTP requests per hour per IP
  message: { success: false, message: 'Too many OTP requests. Please try again after an hour.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ====== Generate OTP ======
app.post('/generate-otp', otpLimiter, async (req, res) => {
  const { email } = req.body;

  try {
    // Check if user already exists
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

// ====== Register (Validate OTP + Save User) ======
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

    // ✅ FIX: Delete OTP after invalid attempt to prevent brute force
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

    // ✅ FIX: Updated phone validation to accept country codes
    const phoneRegex = /^(\+\d{1,3}[- ]?)?\d{10}$/;
    if (!phoneRegex.test(phone)) {
      return res.status(400).json({ success: false, message: 'Phone number must be 10 digits (country code optional)' });
    }

    // ✅ FIX: Added proper age validation with range check
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

// ====== Routes ======
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'option.html'));
});

app.get('/customerSignup.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'customerSignup.html'));
});

app.get('/agency', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'agencysignup.html'));
});

// ====== Login Route ======
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    let account = await User.findOne({ email });
    let userType = "customer";

    if (!account) {
      account = await Agencies.findOne({ email });
      userType = "agency";
    }

    if (!account) {
      return res.status(400).json({ success: false, message: "Account not found" });
    }

    if (account.password !== password) {
      return res.status(400).json({ success: false, message: "Invalid password" });
    }

    req.session.user = {
      id: account._id,
      email: account.email,
      phone: account.phone,
      name: userType === "customer" ? account.username : "Agency",
      type: userType
    };

    res.json({ success: true, message: "Login successful" });
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

// --- START: RAIL GRAPH IMPLEMENTATION ---

const mumbaiNetwork = JSON.parse(
  fs.readFileSync(path.join(__dirname, "public", "stationdata.json"), "utf-8")
);

class RailGraph {
  constructor({ transferPenalty = 0.5, defaultEdgeWeight = 1 } = {}) {
    this.transferPenalty = transferPenalty;
    this.defaultEdgeWeight = defaultEdgeWeight;
    this.adj = new Map();
    this.nodeInfo = new Map();
    this.stationLines = new Map();
  }

  static nodeId(stationName, lineName) {
    return `${stationName}@@${lineName}`;
  }

  _ensureNode(nodeId, info) {
    if (!this.adj.has(nodeId)) {
      this.adj.set(nodeId, []);
      this.nodeInfo.set(nodeId, info);
      const { stationName, lineName } = info;
      if (!this.stationLines.has(stationName)) this.stationLines.set(stationName, new Set());
      this.stationLines.get(stationName).add(lineName);
    }
  }

  _addEdge(a, b, w, meta = {}) {
    if (!this.adj.has(a) || !this.adj.has(b)) return;
    this.adj.get(a).push({ to: b, weight: w, meta });
    this.adj.get(b).push({ to: a, weight: w, meta });
  }

  buildFromNetwork(network) {
    const stationDistanceLookup = new Map();
    for (const line of network.lines) {
      for (const route of line.routes) {
        for (const st of route.stations) {
          const name = st.station_name;
          if (st.distance_km !== null && st.distance_km !== undefined) {
            if (!stationDistanceLookup.has(name)) stationDistanceLookup.set(name, st.distance_km);
          }
        }
      }
    }

    for (const line of network.lines) {
      const lineName = line.line_name;
      for (const route of line.routes) {
        const stations = route.stations || [];
        for (let i = 0; i < stations.length; i++) {
          const s = stations[i];
          const name = s.station_name;
          const dist = (s.distance_km !== null && s.distance_km !== undefined)
            ? s.distance_km
            : (stationDistanceLookup.has(name) ? stationDistanceLookup.get(name) : null);

          const id = RailGraph.nodeId(name, lineName);
          this._ensureNode(id, { stationName: name, lineName, distance: dist });
        }

        for (let i = 0; i < stations.length - 1; i++) {
          const s1 = stations[i], s2 = stations[i + 1];
          const id1 = RailGraph.nodeId(s1.station_name, lineName);
          const id2 = RailGraph.nodeId(s2.station_name, lineName);

          const d1 = this.nodeInfo.get(id1)?.distance;
          const d2 = this.nodeInfo.get(id2)?.distance;
          let weight;
          if (typeof d1 === 'number' && typeof d2 === 'number') {
            weight = Math.abs(d2 - d1);
            if (weight === 0) weight = 0.0001;
          } else {
            weight = this.defaultEdgeWeight;
          }

          this._addEdge(id1, id2, weight, { type: 'track', routeName: route.route_name, lineName });
        }
      }
    }

    for (const [stationName, lineSet] of this.stationLines.entries()) {
      const lines = Array.from(lineSet);
      if (lines.length <= 1) continue;
      for (let i = 0; i < lines.length; i++) {
        for (let j = i + 1; j < lines.length; j++) {
          const a = RailGraph.nodeId(stationName, lines[i]);
          const b = RailGraph.nodeId(stationName, lines[j]);
          this._addEdge(a, b, this.transferPenalty, { type: 'transfer', stationName });
        }
      }
    }
  }

  findNodesForStation(stationName) {
    const nodes = [];
    for (const [nodeId, info] of this.nodeInfo.entries()) {
      if (info.stationName === stationName) nodes.push(nodeId);
    }
    return nodes;
  }

  shortestPath(startStationName, endStationName) {
    const startNodes = this.findNodesForStation(startStationName);
    const endNodes = new Set(this.findNodesForStation(endStationName));
    if (startNodes.length === 0) return { found: false };
    if (endNodes.size === 0) return { found: false };

    const distances = new Map();
    const prev = new Map();
    const visited = new Set();
    for (const nodeId of this.adj.keys()) {
      distances.set(nodeId, Infinity);
      prev.set(nodeId, null);
    }
    for (const s of startNodes) distances.set(s, 0);

    while (true) {
      let u = null;
      let bestDist = Infinity;
      for (const [nodeId, dist] of distances.entries()) {
        if (!visited.has(nodeId) && dist < bestDist) {
          bestDist = dist;
          u = nodeId;
        }
      }
      if (u === null) break;
      visited.add(u);

      for (const edge of this.adj.get(u)) {
        const v = edge.to;
        if (visited.has(v)) continue;
        const alt = distances.get(u) + edge.weight;
        if (alt < distances.get(v)) {
          distances.set(v, alt);
          prev.set(v, u);
        }
      }
    }

    let bestEnd = null;
    let bestDistance = Infinity;
    for (const e of endNodes) {
      const d = distances.get(e);
      if (typeof d === 'number' && d < bestDistance) {
        bestDistance = d;
        bestEnd = e;
      }
    }
    if (bestEnd === null) return { found: false };

    const nodePath = [];
    let cur = bestEnd;
    while (cur) {
      nodePath.push(cur);
      cur = prev.get(cur);
    }
    nodePath.reverse();

    const path = nodePath.map(nodeId => {
      const info = this.nodeInfo.get(nodeId);
      return { stationName: info.stationName, lineName: info.lineName };
    });

    return {
      found: true,
      totalWeightedDistance: bestDistance,
      path
    };
  }
}

const railGraph = new RailGraph({ transferPenalty: 0.5 });
railGraph.buildFromNetwork(mumbaiNetwork);
console.log("✅ Rail Graph Built (Transfer Penalty: 0.5 km)");

// ✅ FIX: Added date validation in parseTime function
function parseTime(date, timeString) {
  if (!timeString) {
    throw new Error("Booking time is missing");
  }

  // Validate date
  const dateObj = new Date(date);
  if (!date || isNaN(dateObj.getTime())) {
    throw new Error("Invalid date provided");
  }

  if (/^\d{1,2}:\d{2}$/.test(timeString)) {
    const [hours, minutes] = timeString.split(":").map(Number);
    const d = new Date(date);
    d.setHours(hours, minutes, 0, 0);
    return d;
  }

  const parts = timeString.split(" ");
  if (parts.length !== 2) {
    throw new Error("Invalid time format, must be 'h:mm AM/PM' or 'HH:mm'");
  }

  const [time, modifier] = parts;
  let [hours, minutes] = time.split(":").map(Number);

  if (modifier.toUpperCase() === "PM" && hours < 12) hours += 12;
  if (modifier.toUpperCase() === "AM" && hours === 12) hours = 0;

  const d = new Date(date);
  d.setHours(hours, minutes, 0, 0);
  return d;
}

function formatTime(date) {
  let hours = date.getHours();
  let minutes = date.getMinutes();
  const ampm = hours >= 12 ? 'PM' : 'AM';
  hours = hours % 12;
  hours = hours ? hours : 12;
  minutes = minutes < 10 ? '0' + minutes : minutes;
  return hours + ':' + minutes + ' ' + ampm;
}

function calculateArrivalTimes(path, startTime, travelDate) {
  const journeyStart = parseTime(travelDate, startTime);
  const stationsInPath = [];
  let currentTime = journeyStart;
  let totalPhysicalDistance = 0;

  for (let i = 0; i < path.length; i++) {
    const { stationName, lineName } = path[i];

    let prevStation = i > 0 ? path[i - 1].stationName : null;
    let prevLine = i > 0 ? path[i - 1].lineName : null;

    if (i > 0) {
      const prevNodeId = RailGraph.nodeId(prevStation, prevLine);
      const currNodeId = RailGraph.nodeId(stationName, lineName);

      const edge = railGraph.adj.get(prevNodeId)?.find(e => e.to === currNodeId);

      if (edge) {
        if (edge.meta.type === 'track') {
          const distanceKm = edge.weight;
          const travelMinutes = distanceKm * 5;
          currentTime = new Date(currentTime.getTime() + travelMinutes * 60000);
          totalPhysicalDistance += distanceKm;
        } else if (edge.meta.type === 'transfer') {
          currentTime = new Date(currentTime.getTime() + 5 * 60000);
        }
      }
    }

    if (i === 0 || stationName !== stationsInPath[stationsInPath.length - 1].name) {
      stationsInPath.push({
        name: stationName,
        time: formatTime(currentTime),
        line: lineName
      });
    } else if (stationName === stationsInPath[stationsInPath.length - 1].name) {
      stationsInPath[stationsInPath.length - 1].time = formatTime(currentTime);
      stationsInPath[stationsInPath.length - 1].line = lineName;
    }
  }

  return {
    stations: stationsInPath,
    totalPhysicalDistance
  };
}

// ====== Shortest Distance API ======
app.get("/api/distance", (req, res) => {
  const { from, to } = req.query;

  if (!from || !to) {
    return res.status(400).json({ success: false, message: "Both 'from' and 'to' stations are required." });
  }

  try {
    const result = railGraph.shortestPath(from, to);

    if (!result.found) {
      return res.status(404).json({ success: false, message: "Route not found between these stations." });
    }

    let totalPhysicalDistance = 0;
    let transfers = 0;

    for (let i = 0; i < result.path.length - 1; i++) {
      const prevNodeId = RailGraph.nodeId(result.path[i].stationName, result.path[i].lineName);
      const currNodeId = RailGraph.nodeId(result.path[i + 1].stationName, result.path[i + 1].lineName);

      const edge = railGraph.adj.get(prevNodeId)?.find(e => e.to === currNodeId);

      if (edge) {
        if (edge.meta.type === 'track') {
          totalPhysicalDistance += edge.weight;
        } else if (edge.meta.type === 'transfer') {
          transfers += 1;
        }
      }
    }

    res.json({
      success: true,
      totalDistance: parseFloat(totalPhysicalDistance.toFixed(2)),
      weightedDistance: parseFloat(result.totalWeightedDistance.toFixed(2)),
      transfers: transfers,
      route: result.path.map(p => p.stationName)
    });

  } catch (error) {
    console.error("Distance API Error:", error.message, error.stack);
    res.status(500).json({ success: false, message: "Server error calculating distance." });
  }
});

// ✅ FIX: Escaped regex input to prevent injection
app.get("/api/search-rides", async (req, res) => {
  try {
    const { address } = req.query;
    let searchStation = address ? address.toLowerCase() : "";
    
    // ✅ SECURITY FIX: Escape special regex characters
    searchStation = searchStation.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    
    console.log("Searching agencies near:", searchStation);

    const agencies = await Agencies.find({
      $expr: {
        $regexMatch: {
          input: searchStation,
          regex: { $concat: ["\\b", "$oprateStation", "\\b"] },
          options: "i"
        }
      }
    });

    if (!agencies.length) {
      return res.status(404).json({ message: "No agencies found for this station." });
    }

    const agenciesWithVehicles = await Promise.all(
      agencies.map(async (agency) => {
        const vehicles = await Vehicle.find({ agencyId: agency._id });

        return {
          _id: agency._id,
          name: agency.agencyName,
          address: agency.oprateStation,
          vehicles: vehicles
        };
      })
    );

    console.log("✅ agenciesWithVehicles:", agenciesWithVehicles.length);
    res.json(agenciesWithVehicles);

  } catch (err) {
    console.error("❌ Error while searching rides:", err);
    res.status(500).json({ success: false, message: "Server error while searching rides." });
  }
});

// ====== Booking API ======
app.post("/api/bookings", async (req, res) => {
  try {
    // ✅ Authentication check enabled
    if (!req.session.user) {
      return res.status(401).json({ message: "Not logged in" });
    }

    let {
      from, to, pickupAddress, bookingType, date, time, area, city,
      agencyId, vehicleId, fare, totalDistance
    } = req.body;

    if (bookingType === 'express_connect') {
      const now = new Date();
      date = date || now.toISOString().split('T')[0];
      time = time || `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;
    }

    if (!from || !to || !pickupAddress || !date || !time || !area || !city || !agencyId || !vehicleId) {
      return res.status(400).json({ success: false, message: "Missing required booking details." });
    }

    const shortestPathResult = railGraph.shortestPath(from, to);
    if (!shortestPathResult.found) {
      return res.status(400).json({ success: false, message: "No route found." });
    }
    const { stations: stationsInPath, totalPhysicalDistance } = calculateArrivalTimes(
      shortestPathResult.path, time, date
    );

    const customerName = req.session.user.name;
    const customerEmail = req.session.user.email;
    const mobile = req.session.user.phone;
    const bookingId = await getNextBookingId();

    const booking = new Booking({
      bookingId,
      from,
      to,
      pickupAddress,
      bookingType,
      date,
      time,
      area,
      city,
      customerName,
      customerEmail,
      mobile,
      stations: stationsInPath,
      totalDistance: parseFloat(totalDistance) || parseFloat(totalPhysicalDistance.toFixed(2)),
      agencyId,
      vehicleId,
      fare,
      status: "pending"
    });

    await booking.save();

    res.status(201).json({
      success: true,
      bookingId: booking.bookingId,
      message: "Booking request sent successfully"
    });
  } catch (err) {
    console.error("Booking error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
});
