// VaultBase — Content Script
'use strict';

(function () {
  if (window.__vaultbaseContentLoaded) return;
  window.__vaultbaseContentLoaded = true;

  const INJECTED_ATTR = 'data-vaultbase-injected';

  function isLoginForm(form) {
    if (!form) return false;
    const inputs = form.querySelectorAll('input');
    let hasPassword = false;
    let hasIdentifier = false;

    inputs.forEach(input => {
      const type = (input.type || '').toLowerCase();
      const name = (input.name || '').toLowerCase();
      const id   = (input.id   || '').toLowerCase();
      const ph   = (input.placeholder || '').toLowerCase();
      const ac   = (input.autocomplete || '').toLowerCase();

      if (type === 'password') hasPassword = true;
      if (
        type === 'email' ||
        ac.includes('email') ||
        ac.includes('username') ||
        name.includes('email') || name.includes('user') || name.includes('login') ||
        id.includes('email')   || id.includes('user')   || id.includes('login') ||
        ph.includes('email')   || ph.includes('user')   || ph.includes('username')
      ) hasIdentifier = true;
    });

    return hasPassword && hasIdentifier;
  }

  function findLoginForms(root) {
    const forms = [];
    const searchRoot = root || document;

    searchRoot.querySelectorAll('form').forEach(f => { if (isLoginForm(f)) forms.push(f); });
    
    // Also find formless containers
    if (forms.length === 0) {
      searchRoot.querySelectorAll('div, section').forEach(el => {
        if (el.querySelector('input[type="password"]') && !el.closest('form')) {
          if (isLoginForm(el)) forms.push(el);
        }
      });
    }

    searchRoot.querySelectorAll('*').forEach(el => {
      if (el.shadowRoot) findLoginForms(el.shadowRoot).forEach(f => forms.push(f));
    });
    return forms;
  }

  function injectButton(container) {
    if (container.querySelector('.vb-injected-wrap')) return;

    const wrap = document.createElement('div');
    wrap.className = 'vb-injected-wrap';
    wrap.style.marginTop = '12px';
    wrap.style.width = '100%';

    // Check for specific slot (DemoBank support)
    const slot = container.querySelector('#vaultbase-slot') || document.getElementById('vaultbase-slot');
    
    // Only add divider if NOT using a pre-defined slot (which likely has its own divider)
    if (!slot) {
      const divider = document.createElement('div');
      divider.className = 'vb-divider';
      divider.innerHTML = '<span>or</span>';
      wrap.appendChild(divider);
    }

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'vaultbase-btn';
    btn.innerHTML = `<span class="vb-lock">🔒</span><span class="vb-text">Login with VaultBase</span>`;

    btn.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();

      const emailInput = container.querySelector('input[type="email"], input[type="text"]');
      const email = emailInput?.value?.trim() || '';

      if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.id) {
        try {
          chrome.runtime.sendMessage({ type: 'LOGIN_DETECTED', url: window.location.href, email });
          chrome.runtime.sendMessage({ type: 'OPEN_POPUP', email });
          chrome.runtime.sendMessage({ type: 'TRIGGER_POPUP' });
        } catch (err) {
          console.warn("[VaultBase] Extension reloaded. Please refresh this page.");
        }
      } else {
        console.warn("[VaultBase] Extension context unavailable. Reload page.");
      }
    });

    wrap.appendChild(btn);

    if (slot) {
      slot.appendChild(wrap);
    } else {
      const submitBtn = container.querySelector('button[type="submit"], input[type="submit"]');
      if (submitBtn && submitBtn.parentNode) { 
        submitBtn.parentNode.insertBefore(wrap, submitBtn.nextSibling); 
      } else { 
        container.appendChild(wrap); 
      }
    }
  }

  function scanAndInject() { findLoginForms(document).forEach(injectButton); }

  const observer = new MutationObserver(() => { scanAndInject(); });
  if (document.body) { observer.observe(document.body, { childList: true, subtree: true }); scanAndInject(); }

  window.addEventListener('vaultbase:rescan', scanAndInject);

  window.addEventListener('vaultbase:authenticated', (e) => {
    document.dispatchEvent(new CustomEvent('vaultbase:session', { detail: e.detail, bubbles: true }));
  });
})();
