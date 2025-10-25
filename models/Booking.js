const mongoose = require("mongoose");

const bookingSchema = new mongoose.Schema({
  // ✅ Added index for better query performance
  bookingId: { 
    type: String, 
    required: true, 
    unique: true,
    index: true
  },
  customerName: { type: String, required: true }, // ✅ Added required
  customerEmail: { type: String, required: true }, // ✅ Added required
  mobile: { type: String, required: true }, // ✅ Added required
  from: { type: String, required: true },
  to: { type: String, required: true },
  pickupAddress: { type: String, required: true },
  area: { type: String, required: true }, // ✅ Added required
  city: { type: String, required: true }, // ✅ Added required
  bookingType: { 
    type: String, 
    required: true,
    enum: ['express_connect', 'scheduled'] // ✅ Added enum for validation
  },
  date: { type: String, required: true },  
  time: { type: String, required: true }, 
  
  // ✅ Enhanced stations schema with line information
  stations: [
    {
      name: { type: String, required: true },
      time: { type: String, required: true },
      line: { type: String } // ✅ Added line field (from updated calculateArrivalTimes)
    }
  ],
  
  totalDistance: { type: Number, required: true },
  
  // ✅ Properly formatted with consistent indentation
  agencyId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Agencies',
    required: true,
    index: true // ✅ Added index for faster lookups
  },
  
  vehicleId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Vehicle',
    required: true,
    index: true // ✅ Added index for faster lookups
  },
  
  // ✅ Fixed capitalization: 'Fare' -> 'fare' (consistent with backend)
  // ✅ Changed to Number for proper calculations
  fare: { 
    type: Number,
    required: true
  },
  
  // ✅ Added enum for status validation and fixed default capitalization
  status: { 
    type: String, 
    default: "pending",
    enum: ['pending', 'confirmed', 'cancelled', 'completed'],
    lowercase: true
  }
}, {
  // ✅ Added timestamps for createdAt and updatedAt
  timestamps: true
});

// ✅ Add compound index for common queries
bookingSchema.index({ customerEmail: 1, status: 1 });
bookingSchema.index({ agencyId: 1, status: 1 });
bookingSchema.index({ date: 1, status: 1 });

module.exports = mongoose.model("Booking", bookingSchema);
