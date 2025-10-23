const mongoose = require("mongoose");

const agenciesSchema = new mongoose.Schema(
  {
    role: { type: String, default: "agency" },
    agencyName: { type: String, required: true },
    ownerName: { type: String },
    oprateStation: { type: String, required: true }, // <-- field used for search
    agencyEmail: { type: String, required: true, unique: true },
    agencyMobile: { type: String },
    password: { type: String, required: true },
    agencyLicense: { type: String },
    gstNumber: { type: String },
    panNumber: { type: String },
    gumastaLicenseUrl: { type: String },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Agencies", agenciesSchema);
