// extension/background.js

// IMPORTANT: Replace this with your actual deployed Render backend URL.
const BACKEND_URL = 'https://safetabguard-api.onrender.com/api/check-url'; 

/**
 * Listens for when the browser is about to navigate to a new page.
 * We use onCommitted because it's a reliable event that fires after a navigation 
 * has been initiated but before the page content has loaded.
 */
chrome.webNavigation.onCommitted.addListener(
  (details) => {
    // We only want to check the top-level page, not iframes or other resources.
    // The check for frameId === 0 ensures this.
    if (details.frameId === 0 && details.url) {
      // Ignore internal Chrome URLs and non-web pages
      if (details.url.startsWith('http:') || details.url.startsWith('https:')) {
        console.log(`[SafeTabGuard] Navigating to: ${details.url}`);
        checkUrlWithBackend(details.url, details.tabId);
      }
    }
  },
  // URL filters to apply this listener to all web pages.
  { url: [{ schemes: ['http', 'https'] }] }
);

/**
 * Sends a URL to the backend for analysis and handles the response.
 * @param {string} url The URL of the visited page.
 * @param {number} tabId The ID of the tab where the navigation is occurring.
 */
async function checkUrlWithBackend(url, tabId) {
  try {
    const response = await fetch(BACKEND_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url: url }),
    });

    const result = await response.json();

    // Check if the backend flagged the URL as unsafe.
    if (result && result.safe === false) {
      console.warn(`[SafeTabGuard] Unsafe URL detected: ${url}`, result.reasons);

      // Store the unsafe URL and reasons so the warning page can access it.
      // This is the standard way to pass data to an extension page.
      chrome.storage.local.set({
        blockedUrl: url,
        reasons: result.reasons || ['No specific reason provided.'],
      });

      // Get the URL for our local warning page.
      const warningPageUrl = chrome.runtime.getURL('warning.html');

      // Redirect the user's tab to our warning page.
      chrome.tabs.update(tabId, { url: warningPageUrl });
    } else {
      console.log(`[SafeTabGuard] URL is safe: ${url}`);
    }
  } catch (error) {
    // Log any errors that occur during the fetch operation.
    // This could happen if the backend is down or there's a network issue.
    console.error('[SafeTabGuard] Error checking URL:', error);
  }
}