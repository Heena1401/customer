const mongoose = require("mongoose");

const counterSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  seq: { type: Number, default: 3221 }  // start from 1111
});

module.exports = mongoose.model("Counter", counterSchema);
