// backend/server.js

// Load environment variables from .env file
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const connectDB = require('./config/db');

// Initialize the Express application
const app = express();

// Connect to MongoDB
connectDB();

// --- Middleware ---
// Enable Cross-Origin Resource Sharing (CORS) for all routes
// This allows your Chrome extension to make requests to this backend
app.use(cors());

// Enable the Express app to parse JSON formatted request bodies
app.use(express.json());

// --- API Routes ---
// Mount the API routes from './routes/api.js' under the '/api' path
app.use('/api', require('./routes/api'));

// Define the port for the server to listen on
const PORT = process.env.PORT || 5000;

// Start the server and listen for incoming connections on the specified port
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));