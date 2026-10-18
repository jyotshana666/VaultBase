// VaultBase — Fetch Patch for Chrome Extension MV3
// Wraps window.fetch BEFORE face-api.js/TF.js loads.
// TF.js internally uses fetch() to load model weight shards, but its
// internal fetch reference can fail for chrome-extension:// URLs in MV3.
// This patch intercepts those calls and falls back to XMLHttpRequest.
(function () {
  "use strict";
  const nativeFetch = window.fetch.bind(window);

  window.fetch = async function patchedFetch(input, init) {
    const url = typeof input === "string" ? input : input?.url || "";

    // Only intercept chrome-extension:// URLs (model files)
    if (url.startsWith("chrome-extension://")) {
      try {
        const res = await nativeFetch(input, init);
        if (res.ok) return res;
        throw new Error("HTTP " + res.status);
      } catch (_nativeErr) {
        // Native fetch failed — fall back to XMLHttpRequest
        console.log("[fetch-patch] XHR fallback for:", url.split("/").pop());
        return new Promise((resolve, reject) => {
          const xhr = new XMLHttpRequest();
          xhr.open("GET", url, true);
          xhr.responseType = "arraybuffer";
          xhr.onload = function () {
            if (xhr.status >= 200 && xhr.status < 300) {
              // Detect if this is JSON (manifest) or binary (shard)
              const contentType =
                xhr.getResponseHeader("content-type") || "";
              const isJson =
                url.endsWith(".json") || contentType.includes("json");

              const headers = new Headers();
              headers.set(
                "content-type",
                isJson ? "application/json" : "application/octet-stream"
              );

              resolve(
                new Response(xhr.response, {
                  status: xhr.status,
                  statusText: xhr.statusText || "OK",
                  headers,
                })
              );
            } else {
              reject(new TypeError("XHR failed: " + xhr.status));
            }
          };
          xhr.onerror = function () {
            reject(new TypeError("XHR network error for: " + url));
          };
          xhr.send();
        });
      }
    }

    // Non-extension URLs — pass through to native fetch unchanged
    return nativeFetch(input, init);
  };

  console.log("[fetch-patch] ✓ Chrome extension fetch patch installed");
})();
