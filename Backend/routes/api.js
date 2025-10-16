// backend/routes/api.js

const express = require('express');
const router = express.Router();
const axios = require('axios');
const BlockedUrl = require('../models/BlockedUrl');

const domainBlacklist = [
  'malicious-example.com',
  'phishing-site.net',
  'scam-domain.org',
];
const suspiciousTokens = ['login', 'verify', 'update', 'secure', 'account', 'banking'];

/**
 * VirusTotal URL Scanner
 * @param {string} url The URL to check
 * @returns {Promise<boolean>} True if malicious, false otherwise
 */
const checkVirusTotal = async (url) => {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    console.warn('VirusTotal API key not found. Skipping check.');
    return false;
  }

  try {
    // Step 1: Encode URL for VirusTotal
    const encodedUrl = Buffer.from(url).toString('base64').replace(/=+$/, '');

    // Step 2: Submit URL to VirusTotal
    await axios.post('https://www.virustotal.com/api/v3/urls', 
      `url=${encodeURIComponent(url)}`,
      {
        headers: {
          'x-apikey': apiKey,
          'Content-Type': 'application/x-www-form-urlencoded',
        }
      }
    );

    // Step 3: Get report
    const response = await axios.get(`https://www.virustotal.com/api/v3/urls/${encodedUrl}`, {
      headers: {
        'x-apikey': apiKey,
      }
    });

    console.log("response : ",response);

    const analysis = response.data.data.attributes.last_analysis_stats;
    
    // Define as malicious if any engines flagged it
    const totalDetections = analysis.malicious + analysis.suspicious;

    if (totalDetections > 0) {
      console.log(`VirusTotal flagged URL as malicious/suspicious: ${url}`);
      return true;
    }

    return false;

  } catch (error) {
    console.error('Error with VirusTotal API:', error.response?.data || error.message);
    return false;
  }
};

router.post('/check-url', async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }

  let isSafe = true;
  const reasons = [];

  try {
    const [isVirusTotalPhish] = await Promise.all([
      checkVirusTotal(url)
    ]);

    if (isVirusTotalPhish) {
      isSafe = false;
      reasons.push('Flagged as malicious or suspicious by VirusTotal.');
    }

    const urlObject = new URL(url);

    // Local Blacklist
    if (domainBlacklist.includes(urlObject.hostname)) {
      isSafe = false;
      reasons.push('Domain is on a known local blacklist.');
    }

    // HTTPS check
    if (urlObject.protocol !== 'https:') {
      isSafe = false;
      reasons.push('Connection is not secure (uses HTTP).');
    }

    // Suspicious Tokens
    for (const token of suspiciousTokens) {
      if (url.toLowerCase().includes(token)) {
        isSafe = false;
        reasons.push(`URL contains suspicious keyword: "${token}".`);
        break;
      }
    }

    // Log and Save if unsafe
    if (!isSafe) {
      console.log(`Unsafe URL detected: ${url}. Reasons: ${reasons.join(', ')}`);
      const uniqueReasons = [...new Set(reasons)];
      const newBlockedUrl = new BlockedUrl({ url, reasons: uniqueReasons });
      await newBlockedUrl.save();
    }

    res.json({
      safe: isSafe,
      reasons: [...new Set(reasons)],
    });

  } catch (error) {
    if (error instanceof TypeError) {
      return res.status(400).json({ safe: false, reasons: ['Invalid URL format provided.'] });
    }
    console.error('Server Error:', error);
    res.status(500).json({ error: 'An internal server error occurred.' });
  }
});

module.exports = router;
