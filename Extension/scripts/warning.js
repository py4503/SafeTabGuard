
document.addEventListener('DOMContentLoaded', () => {
    const goBackButton = document.getElementById('go-back');
    const proceedAnywayButton = document.getElementById('proceed-anyway');
    const blockedUrlElement = document.getElementById('blocked-url');
    const reasonsListElement = document.getElementById('reasons-list');
    const riskScoreElement = document.getElementById('risk-score');
    let blockedUrl = '';

    const setupEventListeners = () => {
        if (goBackButton) {
            goBackButton.addEventListener('click', () => {
                chrome.tabs.getCurrent((tab) => {
                    if (tab) chrome.tabs.remove(tab.id);
                });
            });
        }
        if (proceedAnywayButton) {
            proceedAnywayButton.addEventListener('click', () => {
                if (blockedUrl) {
                    chrome.runtime.sendMessage({ type: 'proceedToUrl', url: blockedUrl });
                }
            });
        }
    };

    const renderAiVulnerabilities = (vulnerabilities) => {
        const loadingState = document.getElementById('ai-loading-state');
        if (loadingState) loadingState.remove();

        vulnerabilities.forEach(vuln => {
            const confidenceColor = vuln.confidence === 'High' ? 'text-red-400' : vuln.confidence === 'Medium' ? 'text-yellow-400' : 'text-slate-400';
            const li = document.createElement('li');
            li.innerHTML = `
                <details class="group bg-slate-900/60 rounded-lg border border-slate-700 overflow-hidden">
                  <summary class="flex items-center justify-between p-3 cursor-pointer hover:bg-slate-700/50 transition-colors">
                    <div class="flex items-center gap-3">
                      <svg class="w-5 h-5 ${confidenceColor} flex-shrink-0" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.487 0l5.516 9.807c.75 1.33-.214 2.994-1.744 2.994H4.485c-1.53 0-2.494-1.664-1.744-2.994L8.257 3.1zM9 8a1 1 0 012 0v3a1 1 0 11-2 0V8zm1 6a1 1 0 100 2 1 1 0 000-2z" clip-rule="evenodd"/></svg>
                      <span class="font-semibold text-slate-300">${vuln.vulnerability}</span>
                    </div>
                    <div class="flex items-center gap-2">
                       <span class="text-xs font-bold ${confidenceColor} bg-slate-800 px-2 py-1 rounded-full">${vuln.confidence}</span>
                       <svg class="w-5 h-5 text-slate-500 group-open:rotate-90 transition-transform" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M7.21 14.77a.75.75 0 01.02-1.06L11.168 10 7.23 6.29a.75.75 0 111.04-1.08l4.5 4.25a.75.75 0 010 1.08l-4.5 4.25a.75.75 0 01-1.06-.02z" clip-rule="evenodd" /></svg>
                    </div>
                  </summary>
                  <div class="p-4 border-t border-slate-700 bg-slate-900">
                    <p class="text-slate-400">${vuln.explanation}</p>
                  </div>
                </details>
            `;
            reasonsListElement.appendChild(li);
        });
    };

    const renderSimpleReasons = (reasons) => {
        reasons.forEach(reason => {
            const li = document.createElement('li');
            li.className = 'bg-slate-900/60 p-3 rounded-md border border-slate-700 flex items-center gap-3';
            li.innerHTML = `
                <svg class="w-5 h-5 text-yellow-400 flex-shrink-0" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path d="M10.75 4.75a.75.75 0 00-1.5 0v4.5h-4.5a.75.75 0 000 1.5h4.5v4.5a.75.75 0 001.5 0v-4.5h4.5a.75.75 0 000-1.5h-4.5v-4.5z"/></svg>
                <span class="text-slate-300">${reason}</span>`;
            reasonsListElement.appendChild(li);
        });
    };

    const initializePage = () => {
        chrome.storage.local.get(['blockedUrl', 'simpleReasons', 'aiVulnerabilities', 'score', 'isAiScanning'], (data) => {
            blockedUrl = data.blockedUrl || '';
            blockedUrlElement.textContent = blockedUrl;
            if (data.score) riskScoreElement.textContent = data.score;
            
            reasonsListElement.innerHTML = '';
            if (data.simpleReasons?.length > 0) renderSimpleReasons(data.simpleReasons);
            if (data.aiVulnerabilities?.length > 0) renderAiVulnerabilities(data.aiVulnerabilities);

            if (data.isAiScanning) {
                const li = document.createElement('li');
                li.id = 'ai-loading-state';
                li.className = 'bg-slate-900/60 p-3 rounded-md border border-slate-700 flex items-center gap-3 animate-pulse';
                li.innerHTML = `
                    <svg class="w-5 h-5 text-blue-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path d="M10 3.5a1.5 1.5 0 01.52 2.924l4.202 2.101a4.5 4.5 0 010 2.95l-4.202 2.101A1.5 1.5 0 1110 16.5V3.5z"/></svg>
                    <span class="text-slate-300">Performing deep content analysis...</span>`;
                reasonsListElement.appendChild(li);
            }
        });
    };

    chrome.runtime.onMessage.addListener((message) => {
        if (message.type === 'aiAnalysisComplete') {
            const payload = message.payload;
            if (riskScoreElement && payload.score) riskScoreElement.textContent = payload.score;
            
            if (payload.safe === false && payload.ai_vulnerabilities?.length > 0) {
                renderAiVulnerabilities(payload.ai_vulnerabilities);
            } else {
                const loadingState = document.getElementById('ai-loading-state');
                if (loadingState) {
                    loadingState.className = 'bg-slate-900/60 p-3 rounded-md border border-slate-700 flex items-center gap-3';
                    loadingState.innerHTML = `
                        <svg class="w-5 h-5 text-green-400 flex-shrink-0" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.857-9.809a.75.75 0 00-1.214-.882l-3.483 4.79-1.88-1.88a.75.75 0 10-1.06 1.061l2.5 2.5a.75.75 0 001.137-.089l4-5.5z" clip-rule="evenodd" /></svg>
                        <span class="text-slate-300">Deep content scan complete. No additional threats found.</span>`;
                }
            }
        }
    });

    initializePage();
    setupEventListeners();
});