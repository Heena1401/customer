const mongoose = require('mongoose');
const { Schema } = mongoose;

const vehicleSchema = new Schema({
    vehicle_name: {
        type: String,
        required: true,
        trim: true
    },
    model: {
        type: String,
        required: true,
        trim: true
    },
    number_plate: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    rc_number: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    insurance_number: {
        type: String,
        required: true,
        trim: true
    },
    owner_name: {
        type: String,
        required: true,
        trim: true
    },
    ac_type: {
        type: String,
        required: true,
        // You could make this an enum for better data control:
        // enum: ['AC', 'Non-AC', 'Both'] 
    },
    vehicle_type: {
        type: String,
        required: true,
        // You could make this an enum:
        // enum: ['Premium', 'Sedan', 'SUV', 'Hatchback']
    },
    max_capacity: {
        type: Number, // Changed from String to Number
        required: true
    },
    rate_per_km: {
        type: Number, // Changed from String to Number
        required: true
    },
    agencyId: {
        type: Schema.Types.ObjectId,
        ref: 'Agency', // This links to your 'Agency' model
        required: true
    },
    assignedDriver: {
        type: Schema.Types.ObjectId,
        ref: 'Driver', // Assumes you have a 'Driver' or 'User' model for drivers
        default: null
    }
}, {
    // This automatically adds 'createdAt' and 'updatedAt' fields
    timestamps: true 
});

// Mongoose will create a collection named 'vehicles' (pluralized) from this model
module.exports = mongoose.model('Vehicle', vehicleSchema);