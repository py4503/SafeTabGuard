// backend/models/BlockedUrl.js

const mongoose = require('mongoose');

// Define the schema for the 'blockedurls' collection
const BlockedUrlSchema = new mongoose.Schema({
  url: {
    type: String,
    required: true,
    trim: true,
  },
  reasons: {
    type: [String], // An array of strings explaining why it was blocked
    required: true,
  },
  timestamp: {
    type: Date,
    default: Date.now,
  },
});

// Create and export the Mongoose model
module.exports = mongoose.model('BlockedUrl', BlockedUrlSchema);