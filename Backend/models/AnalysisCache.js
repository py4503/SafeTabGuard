
const mongoose = require('mongoose');

// schema for caching of analysis to speedup process

const AnalysisCacheSchema = new mongoose.Schema({
  url: {
    type: String,
    required: true,
    unique: true,
    index: true,   
  },
  

  result: {
    type: Object, 
    required: true,
  },

  
  createdAt: {
    type: Date,
    default: Date.now,
    expires: '24h', 
  },
});

module.exports = mongoose.model('AnalysisCache', AnalysisCacheSchema);