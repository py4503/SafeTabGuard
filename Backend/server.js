
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const connectDB = require('./config/db');

const app = express();

// Connect to MongoDB
connectDB();

app.use(cors());

app.use(express.json({limit:'10mb'}));

app.use(express.urlencoded({ limit: '10mb', extended: true }));

// API Routes
app.use('/api', require('./routes/api'));

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));