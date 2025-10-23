// extension/background.js

const FAST_CHECK_URL = 'http://localhost:5000/api/check-url-fast';
const AI_ANALYSIS_URL = 'http://localhost:5000/api/analyze-content-ai';

// ✅ NEW: Message listener to handle the "Proceed Anyway" request from the warning page.
chrome.runtime.onMessage.addListener((message, sender) => {
    if (message.type === 'proceedToUrl' && message.url && sender.tab?.id) {
        // Step 1: Set the bypass flag in storage.
        chrome.storage.local.set({ bypassUrl: message.url }, () => {
            // Step 2: Navigate the tab AFTER the flag is set. This centralizes control.
            chrome.tabs.update(sender.tab.id, { url: message.url });
        });
    }
});

// --- Main Navigation Listener ---
chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId === 0 && details.url && (details.url.startsWith('http:') || details.url.startsWith('https:'))) {
    chrome.storage.local.get(['protectionEnabled', 'bypassUrl'], (result) => {
      const isEnabled = result.protectionEnabled !== false;

      // ✅ FIXED: Use a precise match and clear the bypass flag.
      if (result.bypassUrl && details.url === result.bypassUrl) {
        console.log(`[SafeTabGuard] Bypass activated for: ${details.url}`);
        chrome.storage.local.remove('bypassUrl');
        return; // Allow navigation to proceed.
      }

      if (isEnabled) {
        initiateSecurityCheck(details.url, details.tabId);
      }
    });
  }
});

// --- Orchestration Logic ---
async function initiateSecurityCheck(url, tabId) {
    try {
        chrome.action.setBadgeText({ text: 'SCAN', tabId: tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#FDBA74', tabId: tabId });

        const fastResponse = await fetch(FAST_CHECK_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url }),
        });
        const fastResult = await fastResponse.json();

        if (fastResult.safe === false) {
            updateBlockedStats();
            const dataToStore = {
                blockedUrl: url,
                simpleReasons: fastResult.simple_reasons || [],
                aiVulnerabilities: [],
                score: 0,
                isAiScanning: true,
                lastBlockedSite: { url: url, timestamp: new Date().toISOString() },
            };
            chrome.storage.local.set(dataToStore, () => {
                const warningPageUrl = chrome.runtime.getURL('warning.html');
                chrome.tabs.update(tabId, { url: warningPageUrl });
                performAiAnalysis(url, tabId);
            });
            return;
        }
        await performAiAnalysis(url, tabId);
    } catch (error) {
        console.error('[SafeTabGuard] Error during instant scan:', error);
        chrome.action.setBadgeText({ text: 'ERR', tabId: tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#F87171', tabId: tabId });
    }
}

async function performAiAnalysis(url, tabId) {
    try {
        const injectionResults = await chrome.scripting.executeScript({
            target: { tabId: tabId },
            func: () => document.documentElement.outerHTML,
        });
        const htmlContent = injectionResults?.[0]?.result;
        if (!htmlContent) {
            chrome.action.setBadgeText({ text: '', tabId: tabId });
            return;
        }

        const aiResponse = await fetch(AI_ANALYSIS_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url, htmlContent }),
        });
        const aiResult = await aiResponse.json();

        chrome.storage.local.get(null, (currentData) => {
            const dataToStore = {
                ...currentData,
                aiVulnerabilities: aiResult.ai_vulnerabilities || [],
                score: Math.max(currentData.score || 0, aiResult.score || 0),
                isAiScanning: false,
            };
            chrome.storage.local.set(dataToStore);
        });

        chrome.tabs.sendMessage(tabId, {
            type: 'aiAnalysisComplete',
            payload: aiResult
        }).catch(() => {});

        const tab = await chrome.tabs.get(tabId);
        const isTabOnWarningPage = tab.url.includes('warning.html');

        if (aiResult.safe === false && !isTabOnWarningPage) {
            updateBlockedStats(); // This was the missing call
            const warningPageUrl = chrome.runtime.getURL('warning.html');
            chrome.tabs.update(tabId, { url: warningPageUrl });
        } else {
            chrome.action.setBadgeText({ text: '', tabId: tabId });
        }
    } catch (error) {
        console.error('[SafeTabGuard] Error during AI scan:', error);
    }
}

function updateBlockedStats() {
  const today = new Date().toLocaleDateString();
  chrome.storage.local.get('blockedStats', (result) => {
    let stats = result.blockedStats || { count: 0, date: today };
    if (stats.date === today) {
      stats.count++;
    } else {
      stats = { count: 1, date: today };
    }
    chrome.storage.local.set({ blockedStats: stats });
  });
}