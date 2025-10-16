// backend/config/db.js

const mongoose = require('mongoose');

// Asynchronous function to connect to the database
const connectDB = async () => {
  try {
    // Attempt to connect to MongoDB using the URI from environment variables
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('✅ MongoDB connected successfully.');
  } catch (error) {
    // Log any errors that occur during connection and exit the process
    console.error('❌ MongoDB connection error:', error.message);
    process.exit(1); // Exit with a failure code
  }
};

module.exports = connectDB;