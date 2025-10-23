import React, { useState, useEffect } from 'react';
import { ShieldCheck, AlertTriangle, History, EyeOff } from 'lucide-react';

function App() {
  const [isEnabled, setIsEnabled] = useState(true);
  const [blockedCount, setBlockedCount] = useState(0);
  const [lastBlocked, setLastBlocked] = useState(null);

  useEffect(() => {
    if (chrome.storage && chrome.storage.local) {
      chrome.storage.local.get(
        ['protectionEnabled', 'blockedStats', 'lastBlockedSite'],
        (result) => {
          if (result.protectionEnabled !== undefined) {
            setIsEnabled(result.protectionEnabled);
          }

          const stats = result.blockedStats;
          const today = new Date().toLocaleDateString();
          if (stats && stats.date === today) {
            setBlockedCount(stats.count);
          }
          
          if (result.lastBlockedSite) {
            setLastBlocked(result.lastBlockedSite);
          }
        }
      );
    }
  }, []);

  const handleToggle = () => {
    const newState = !isEnabled;
    setIsEnabled(newState);
    if (chrome.storage && chrome.storage.local) {
      chrome.storage.local.set({ protectionEnabled: newState });
    }
  };

  const getDomain = (url) => {
    try {
      return new URL(url).hostname;
    } catch (e) {
      return url;
    }
  };

  return (
    <div className="w-80 p-4 bg-slate-900 text-slate-200">
      <div className="flex items-center justify-between mb-5">
        <h1 className="text-xl font-bold tracking-wider">SafeTabGuard</h1>
        <ShieldCheck className="w-7 h-7 text-emerald-400" />
      </div>
      <div className={`p-4 rounded-lg mb-4 border transition-all duration-300 ${
          isEnabled
            ? 'bg-slate-800 border-emerald-500/50 shadow-lg shadow-emerald-500/10'
            : 'bg-slate-800 border-slate-700'
        }`}
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            {isEnabled ? (
              <ShieldCheck className="w-8 h-8 text-emerald-400 animate-pulse" />
            ) : (
              <AlertTriangle className="w-8 h-8 text-yellow-400" />
            )}
            <div>
              <p className="text-sm text-slate-400">Real-Time Protection</p>
              <p className={`text-lg font-bold ${isEnabled ? 'text-emerald-400' : 'text-yellow-400'}`}>
                {isEnabled ? 'Active' : 'Disabled'}
              </p>
            </div>
          </div>
          <div
            onClick={handleToggle}
            className={`w-14 h-8 flex items-center rounded-full p-1 cursor-pointer transition-colors duration-300 ${
              isEnabled ? 'bg-emerald-500' : 'bg-slate-600'
            }`}
          >
            <div
              className={`bg-white w-6 h-6 rounded-full shadow-md transform transition-transform duration-300 ease-in-out ${
                isEnabled ? 'translate-x-6' : 'translate-x-0'
              }`}
            ></div>
          </div>
        </div>
      </div>

      {/* Stats */}
      <div className="bg-slate-800 border border-slate-700 p-4 rounded-lg mb-4">
        <div className="flex items-center space-x-3">
          <EyeOff className="w-6 h-6 text-cyan-400" />
          <div>
            <p className="text-sm font-semibold text-slate-400">Threats Blocked Today</p>
            <p className="text-3xl font-bold text-slate-100 mt-1">{blockedCount}</p>
          </div>
        </div>
      </div>

      {/* Last Blocked Site*/}
      <div className="bg-slate-800 border border-slate-700 p-4 rounded-lg">
        <div className="flex items-center space-x-3">
          <History className="w-6 h-6 text-red-400" />
          <div>
            <p className="text-sm font-semibold text-slate-400">Last Blocked Threat</p>
            {lastBlocked ? (
              <p className="text-md font-mono text-red-400 mt-1 truncate" title={lastBlocked.url}>
                {getDomain(lastBlocked.url)}
              </p>
            ) : (
              <p className="text-md text-slate-500 mt-1">No threats blocked yet.</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;