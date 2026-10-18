// VaultBase — Background Service Worker (MV3)
'use strict';

// ── Device Fingerprint via SubtleCrypto SHA-256 ───────────────────────────────
async function generateDeviceFingerprint() {
  const components = [
    navigator.userAgent,
    navigator.language,
    navigator.languages?.join(',') || '',
    navigator.platform,
    'sw-no-screen', // Fixes MV3 navigator screen bug 
    new Date().getTimezoneOffset().toString(),
    (navigator.hardwareConcurrency || 0).toString(),
    (navigator.deviceMemory || 0).toString(),
    navigator.maxTouchPoints?.toString() || '0',
    // We can't do canvas/webgl in background directly, so we use a fallback ID
    // or we could collect it from the popup/content script.
    // For now, let's add a random seed that persists.
  ];

  const encoder = new TextEncoder();
  const data = encoder.encode(components.join('||'));

  try {
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  } catch {
    return Math.random().toString(36).substring(2) + Date.now().toString(36);
  }
}

// In a real implementation, we would use a hidden offscreen document or 
// collect signals from the content script/popup to get Canvas/WebGL.
// For the demo, let's enhance the components with some more static signals.
async function getEnhancedFingerprint(tabId) {
  const basicFp = await generateDeviceFingerprint();
  
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => {
        const getCanvasHash = () => {
          const canvas = document.createElement('canvas');
          const ctx = canvas.getContext('2d');
          ctx.textBaseline = "top";
          ctx.font = "14px 'Arial'";
          ctx.textBaseline = "alphabetic";
          ctx.fillStyle = "#f60";
          ctx.fillRect(125,1,62,20);
          ctx.fillStyle = "#069";
          ctx.fillText("vaultbase-fp", 2, 15);
          ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
          ctx.fillText("vaultbase-fp", 4, 17);
          return canvas.toDataURL();
        };

        const getWebGLRenderer = () => {
          const canvas = document.createElement('canvas');
          const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
          if (!gl) return 'no-webgl';
          const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
          return debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 'no-renderer-info';
        };

        return {
          canvas: getCanvasHash(),
          webgl: getWebGLRenderer(),
          screen: `${window.screen.width}x${window.screen.height}x${window.screen.colorDepth}`,
          ua: navigator.userAgent
        };
      }
    });

    if (results && results[0] && results[0].result) {
      const { canvas, webgl, screen } = results[0].result;
      const combined = [basicFp, canvas, webgl, screen].join('||');
      const encoder = new TextEncoder();
      const data = encoder.encode(combined);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }
  } catch (err) {
    console.error('Failed to get enhanced fingerprint:', err);
  }
  
  return basicFp;
}

chrome.runtime.onInstalled.addListener(async () => {
  // Initial fingerprint (basic)
  const fp = await generateDeviceFingerprint();
  await chrome.storage.session.set({ deviceFingerprint: fp });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'GET_FINGERPRINT') {
    chrome.storage.session.get(['deviceFingerprint']).then(async (result) => {
      // If we have a tab, try to get an enhanced one
      const tabId = sender.tab?.id || message.tabId;
      if (tabId) {
        const enhancedFp = await getEnhancedFingerprint(tabId);
        await chrome.storage.session.set({ deviceFingerprint: enhancedFp });
        sendResponse({ fingerprint: enhancedFp });
      } else if (result.deviceFingerprint) {
        sendResponse({ fingerprint: result.deviceFingerprint });
      } else {
        const fp = await generateDeviceFingerprint();
        await chrome.storage.session.set({ deviceFingerprint: fp });
        sendResponse({ fingerprint: fp });
      }
    }).catch(() => sendResponse({ fingerprint: 'fallback-' + Date.now() }));
    return true;
  }

  if (message.type === 'INJECT_SESSION') {
    chrome.storage.session.get(['loginPageTabId']).then(async (sessionData) => {
      let targetTabId = null;
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true }).catch(() => []);
      if (tabs && tabs[0]) {
        targetTabId = tabs[0].id;
      } else if (sessionData && sessionData.loginPageTabId) {
        targetTabId = sessionData.loginPageTabId;
      }

      if (!targetTabId) {
        return sendResponse({ success: false, error: 'No active tab found' });
      }

      chrome.scripting.executeScript({
        target: { tabId: targetTabId },
        world: 'ISOLATED',
        func: (token, userId) => {
          window.__vaultbaseAuth = { token, userId, ts: Date.now() };
          const authEvent = new CustomEvent('vaultbase:authenticated', {
            detail: { token, userId },
            bubbles: true
          });
          window.dispatchEvent(authEvent);
          document.dispatchEvent(authEvent);

          // Direct session event to page DOM
          document.dispatchEvent(new CustomEvent('vaultbase:session', {
            detail: { token, userId },
            bubbles: true
          }));
        },
        args: [message.token || '', message.userId || '']
      })
        .then(() => sendResponse({ success: true }))
        .catch(err => sendResponse({ success: false, error: err.message }));
    });
    return true;
  }

  if (message.type === 'LOGIN_DETECTED') {
    chrome.storage.session.set({
      loginPageUrl: message.url,
      loginPageTabId: sender.tab?.id || null,
      prefillEmail: message.email || ''
    }).then(() => sendResponse({ acknowledged: true }));
    return true;
  }

  if (message.type === 'OPEN_POPUP') {
    chrome.storage.session.set({ prefillEmail: message.email || '' });
    sendResponse({ acknowledged: true });
    return true;
  }

  if (message.type === 'TRIGGER_POPUP') {
    if (chrome.action && chrome.action.openPopup) {
      chrome.action.openPopup()
        .then(() => sendResponse({ success: true }))
        .catch(err => sendResponse({ success: false, error: err.message }));
    } else {
      sendResponse({ success: false, error: 'chrome.action.openPopup not supported' });
    }
    return true;
  }

  if (message.type === 'CLEAR_SESSION') {
    chrome.storage.session.clear().then(() => sendResponse({ success: true }));
    return true;
  }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'complete') {
    chrome.scripting.executeScript({
      target: { tabId },
      world: 'ISOLATED',
      func: () => {
        window.dispatchEvent(new CustomEvent('vaultbase:rescan'));
      }
    }).catch(() => {});
  }
});
