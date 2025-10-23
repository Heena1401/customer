const mongoose = require("mongoose");

const otpSchema = new mongoose.Schema({
  email: String,
  otp: String,
  createdAt: { type: Date, default: Date.now, expires: 180 } // auto-delete after 3 min
});

module.exports = mongoose.model("OTP", otpSchema);
