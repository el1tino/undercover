"use strict";

// Sets a sensible default API URL on first install, so the popup has
// something to show before the user configures anything.
chrome.runtime.onInstalled.addListener(async () => {
  const stored = await chrome.storage.sync.get("apiUrl");
  if (!stored.apiUrl) {
    await chrome.storage.sync.set({ apiUrl: "http://127.0.0.1:8000" });
  }
});
