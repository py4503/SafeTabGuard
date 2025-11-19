// backend/routes/api.js

const express = require('express');
const router = express.Router();
const axios = require('axios');
const { BedrockRuntimeClient, InvokeModelCommand } = require("@aws-sdk/client-bedrock-runtime");
const BlockedUrl = require('../models/BlockedUrl.js');
const AnalysisCache = require('../models/AnalysisCache.js');

// Configuration 
const domainBlacklist = ['malicious-example.com', 'phishing-site.net'];
const suspiciousTokens = ['login', 'verify', 'update', 'secure', 'account', 'banking'];

//  AWS Bedrock Client Setup
const credentials = {
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
};

const bedrockClient = new BedrockRuntimeClient({ region: process.env.AWS_REGION || "us-east-1" }, credentials);

// Check 1: VirusTotal API
const checkVirusTotal = async (url) => {
    const apiKey = process.env.VIRUSTOTAL_API_KEY;
    if (!apiKey) return { isUnsafe: false, reason: null };

    try {
        const urlId = Buffer.from(url).toString('base64').replace(/=/g, '');
        const apiUrl = `https://www.virustotal.com/api/v3/urls/${urlId}`;
        const response = await axios.get(apiUrl, { headers: { 'x-apikey': apiKey } });
        const maliciousCount = response.data.data.attributes.last_analysis_stats.malicious;

        if (maliciousCount > 0) {
            return { isUnsafe: true, reason: `Flagged as malicious by ${maliciousCount} vendors on VirusTotal.` };
        }
        return { isUnsafe: false, reason: null };
    } catch (error) {
        if (error.response && error.response.status === 404) return { isUnsafe: false, reason: null };
        console.error(' [Backend] Error calling VirusTotal API:', error.message);
        return { isUnsafe: false, reason: null };
    }
};

// Check - 2: Rule based checking

const checkUrlHeuristics = (url) => {
    const reasons = [];
    let score = 0; // We can still use a simple score or just collect reasons

    try {
        const parsedUrl = new URL(url);
        const hostname = parsedUrl.hostname || '';
        const pathAndQuery = (parsedUrl.pathname + parsedUrl.search).toLowerCase();

        // --- Optimized Checks ---

        // 1. Extremely Long URL (less likely for legitimate root pages)
        if (url.length > 150) {
            score += 1;
            reasons.push("URL is unusually long (> 150 chars).");
        }

        // 2. Suspicious Keywords (only in path/query, multiple are worse)
        const suspiciousKeywords = ['login', 'verify', 'account', 'password', 'update', 'secure', 'signin', 'banking', 'confirm', 'credential'];
        let keywordCount = 0;
        suspiciousKeywords.forEach(keyword => {
            if (pathAndQuery.includes(keyword)) {
                keywordCount++;
            }
        });
        if (keywordCount > 1) {
            score += 2;
            reasons.push("URL path/parameters contain multiple suspicious keywords.");
        } else if (keywordCount === 1) {
            score += 1;
            reasons.push("URL path/parameters contain a suspicious keyword.");
        }

        // 3. Excessive Dots in Hostname (higher threshold)
        if ((hostname.match(/\./g) || []).length > 4) {
            score += 1;
            reasons.push("Excessive dots in domain name.");
        }

        // 4. Excessive Hyphens in Hostname (higher threshold)
        if ((hostname.match(/-/g) || []).length > 3) {
            score += 1;
            reasons.push("Excessive hyphens in domain name.");
        }

        // 5. Missing HTTPS (clear penalty)
        if (parsedUrl.protocol !== 'https:') {
            score += 2;
            reasons.push("Connection is not secure (No HTTPS).");
        }

        // 6. Contains '@' Symbol (Strong indicator)
        if (url.includes('@')) {
            score += 3;
            reasons.push("URL contains '@' symbol, often used to obscure the real domain.");
        }

        // 7. Hostname is an IP Address (Very strong indicator)
        const ipRegex = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
        if (ipRegex.test(hostname)) {
            score += 4;
            reasons.push("Domain is a raw IP address, uncommon for legitimate sites.");
        }
        
        // --- Decision ---
        // We can base the decision purely on accumulating reasons or a score threshold
        const isSuspicious = score >= 4; // Example threshold, adjust as needed

        return {
            isSuspicious: isSuspicious,
            reasons: isSuspicious ? reasons : []
        };

    } catch (error) {
        // If URL parsing fails, assume it's potentially suspicious but don't crash
        console.warn(`[Heuristic Check] Failed to parse URL: ${url}`, error.message);
        return { isSuspicious: false, reasons: [] }; // Fail relatively safe
    }
};

// Check-3 : AWS Bedrock AI Content Analysis
const analyzeContentWithBedrock = async (htmlContent) => {
    const messages = [{
        role: "user",
        content: `You are a senior cybersecurity analyst. Analyze the following HTML/JS code for security vulnerabilities.
        Provide a single JSON object with two keys:
        1. "score": An integer between 0 (safe) and 100 (malicious).
        2. "vulnerabilities": A JSON array of objects, where each object has "vulnerability", "confidence", "explanation", and "recommendation".
        If no vulnerabilities are found, return a score of 0 and an empty vulnerabilities array.

        Code to analyze: <code>${htmlContent}</code>`
    }];

    const params = {
        modelId: "anthropic.claude-3-sonnet-20240229-v1:0",
        contentType: "application/json",
        accept: "application/json",
        body: JSON.stringify({
            anthropic_version: "bedrock-2023-05-31",
            max_tokens: 4000,
            messages: messages,
        }),
    };

    try {
        const command = new InvokeModelCommand(params);
        const apiResponse = await bedrockClient.send(command);
        const decodedBody = new TextDecoder().decode(apiResponse.body);
        const responseBody = JSON.parse(decodedBody);

        // console.log("AI response:", responseBody);
        
        const rawText = responseBody.content[0].text;

        // Using a regular expression to find the JSON block, (as there might be some extra text).
        // The 's' flag allows '.' to match newline characters.
        const jsonMatch = rawText.match(/\{.*\}/s);
        
        // Check if a valid JSON block was found.
        if (jsonMatch && jsonMatch[0]) {
            // Parse only the extracted JSON string.
            return JSON.parse(jsonMatch[0]);
        } else {
            // If no JSON is found, return a safe default to prevent crashes.
            console.error("[Backend] AI did not return a valid JSON object. Raw response:", rawText);
            return { score: 0, vulnerabilities: [] };
        }

    } catch (error) {
        // This will now catch errors from both the API call and the JSON parsing.
        console.error("[Backend] Error in Bedrock analysis:", error);
        return { score: 0, vulnerabilities: [] }; // Fail safe
    }
};

// Instant Scan (VirusTotal + Heuristics + Blacklist)
router.post('/check-url-fast', async (req, res) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'URL is required.' });

    const simpleReasons = new Set();

    try {
        // Runs VirusTotal and heuristic check at the same time
        const [virusTotalResult, heuristicResult] = await Promise.all([
            checkVirusTotal(url),
            checkUrlHeuristics(url)
        ]);

        // __results__
        // A) Add VirusTotal reasons
        if (virusTotalResult.isUnsafe) {
            simpleReasons.add(virusTotalResult.reason);
        }

        // B) Add Heuristic reasons
        if (heuristicResult.isSuspicious) {
            heuristicResult.reasons.forEach(reason => simpleReasons.add(`[Heuristic] ${reason}`));
        }

        // C) Add Local Blacklist check
        try {
            const urlObject = new URL(url);
            if (domainBlacklist.includes(urlObject.hostname)) {
                simpleReasons.add('Domain is on a known local blacklist.');
            }
        } catch (e) { /* Ignore invalid URL format */ }

        // __Final Decision__       
        const reasonsArray = Array.from(simpleReasons);
        if (reasonsArray.length > 0) {
            console.log(`[Fast Check] Unsafe URL detected: ${url}. Reasons:`, reasonsArray);
            return res.json({ safe: false, simple_reasons: reasonsArray });
        }

        console.log(`[Fast Check] URL passed initial checks: ${url}`);
        return res.json({ safe: true, simple_reasons: [] });

    } catch (error) {
        console.error("[Backend] Error during fast check:", error);
        // Fail safe in case of unexpected errors during the fast check
        return res.status(500).json({ safe: true, simple_reasons: ["Fast analysis inconclusive due to server error."] });
    }
});

// Endpoint for ai

router.post('/analyze-content-ai', async (req, res) => {
    const { url, htmlContent } = req.body; // Pass URL for caching
    if (!url || !htmlContent) return res.status(400).json({ error: 'URL and htmlContent are required.' });

    // Check cache first for the full analysis
    const cachedResult = await AnalysisCache.findOne({ url });
    if (cachedResult) {
        return res.json(cachedResult.result);
    }

    const bedrockResult = await analyzeContentWithBedrock(htmlContent);
    const aiVulnerabilities = bedrockResult.vulnerabilities || [];
    const aiScore = bedrockResult.score || 0;
    const scoreThreshold = 50;
    
    let decision;
    if (aiVulnerabilities.length > 0 || aiScore >= scoreThreshold) {
        decision = {
            safe: false,
            ai_vulnerabilities: aiVulnerabilities,
            score: aiScore
        };
    } else {
        decision = { safe: true, ai_vulnerabilities: [], score: aiScore };
    }

    // Save to cache before returning
    const newCacheEntry = new AnalysisCache({ url, result: decision });
    await newCacheEntry.save();
    
    return res.json(decision);
});

module.exports = router;