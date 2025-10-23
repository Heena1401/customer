// This file loads your .env variables (like MONGO_URI)
require("dotenv").config(); 
const mongoose = require('mongoose');
const Vehicle = require('./models/Vehicles'); // Check this path!
const ObjectId = mongoose.Types.ObjectId;

// --- All IDs are 24 characters. Be careful on copy-paste! ---
const vehiclesToAdd = [
  {
    _id: new ObjectId('68f9498a42f23121a9772178'),
    vehicle_name: "maruti",
    model: "ST57521",
    number_plate: "MH01451226",
    rc_number: "MH5465421",
    insurance_number: "24545615",
    owner_name: "Santosh",
    ac_type: "AC",
    vehicle_type: "Premium",
    max_capacity: 4,   // Using Number
    rate_per_km: 15,  // Using Number
    agencyId: new ObjectId('68f9493242f23121a9772167'),
    assignedDriver: new ObjectId('68f9565df8fcc7ccd32b934c')
  },
  {
    _id: new ObjectId('68f75ca9159044fcbe1c30e5'),
    vehicle_name: "Tata Nexon",
    model: "XZ+",
    number_plate: "MH03PZ7766",
    rc_number: "RC66666",
    insurance_number: "INS66666",
    owner_name: "Dummy Owner",
    ac_type: "Non-AC",
    vehicle_type: "SUV",
    max_capacity: 5,
    rate_per_km: 14,
    agencyId: new ObjectId('68f75bf159c8f0c8ca4bdb3b') 
  },
  {
    _id: new ObjectId('68f75c9159044fcbe1c30e4'), 
    vehicle_name: "Hyundai Verna",
    model: "SX",
    number_plate: "MH03PZ9988",
    rc_number: "RC55555",
    insurance_number: "INS55555",
    owner_name: "Dummy Owner",
    ac_type: "AC",
    vehicle_type: "Sedan",
    max_capacity: 4,
    rate_per_km: 17,
    agencyId: new ObjectId('68f75bf159c8f0c8ca4bdb3b')
  }
];

// This async function connects, adds the data, and disconnects
async function addVehicles() {
  try {
    // 1. Connect to the database
    console.log("Connecting to MongoDB...");
    await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log("✅ MongoDB Connected");

    console.log("Adding/updating vehicles...");
    
    // 2. Loop and 'upsert' each vehicle
    // (Upsert = update if it exists, insert if it's new)
    for (const vehicle of vehiclesToAdd) {
      await Vehicle.updateOne(
        { _id: vehicle._id }, // Find by _id
        { $set: vehicle },     // Set all data
        { upsert: true }      // This creates it if it doesn't exist
      );
    }
    
    console.log(`✅ Successfully processed ${vehiclesToAdd.length} vehicles.`);

  } catch (error) {
    // If the error happens, it will be caught here
    console.error("❌ Error adding vehicles:", error.message);
  } finally {
    // 3. Always disconnect
    await mongoose.connection.close();
    console.log("Disconnected from MongoDB.");
  }
}

// Call the function to run the script
addVehicles();