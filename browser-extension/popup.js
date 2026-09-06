"use strict";

const DEFAULT_API_URL = "http://127.0.0.1:8000";

const apiUrlInput = document.getElementById("api-url");
const settingsPanel = document.getElementById("settings");
const settingsToggle = document.getElementById("settings-toggle");
const settingsStatus = document.getElementById("settings-status");
const saveSettingsButton = document.getElementById("save-settings");
const emailText = document.getElementById("email-text");
const capturePageButton = document.getElementById("capture-page");
const reportButton = document.getElementById("report-button");
const resultEl = document.getElementById("result");
const resultLevel = document.getElementById("result-level");
const resultScore = document.getElementById("result-score");
const resultFactors = document.getElementById("result-factors");
const resultLink = document.getElementById("result-link");
const errorEl = document.getElementById("error");

function showError(message) {
  errorEl.textContent = message;
  errorEl.hidden = false;
}

function clearError() {
  errorEl.hidden = true;
  errorEl.textContent = "";
}

async function getApiUrl() {
  const stored = await chrome.storage.sync.get("apiUrl");
  return stored.apiUrl || DEFAULT_API_URL;
}

async function setApiUrl(url) {
  await chrome.storage.sync.set({ apiUrl: url });
}

function originPatternFor(url) {
  try {
    const parsed = new URL(url);
    return `${parsed.protocol}//${parsed.host}/*`;
  } catch {
    return null;
  }
}

async function ensureHostPermission(url) {
  const pattern = originPatternFor(url);
  if (!pattern) {
    throw new Error(`"${url}" is not a valid URL.`);
  }
  const has = await chrome.permissions.contains({ origins: [pattern] });
  if (has) return;

  const granted = await chrome.permissions.request({ origins: [pattern] });
  if (!granted) {
    throw new Error(
      `Permission to reach ${pattern} was not granted -- can't submit the report.`
    );
  }
}

settingsToggle.addEventListener("click", () => {
  settingsPanel.hidden = !settingsPanel.hidden;
});

saveSettingsButton.addEventListener("click", async () => {
  const url = apiUrlInput.value.trim() || DEFAULT_API_URL;
  try {
    await ensureHostPermission(url);
    await setApiUrl(url);
    settingsStatus.textContent = "Saved.";
  } catch (err) {
    settingsStatus.textContent = err.message;
  }
});

capturePageButton.addEventListener("click", async () => {
  clearError();
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.id) {
      showError("No active tab found.");
      return;
    }
    const [{ result }] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => document.body.innerText,
    });
    // This is a best-effort convenience, not real email parsing: page
    // text has no From/Subject/Authentication-Results headers, so
    // sender identification and header checks will come back empty.
    // Pasting the raw email source (Gmail: Show original; Outlook:
    // View message source) gives a real analysis instead.
    emailText.value = `Subject: ${tab.title || ""}\n\n${result || ""}`;
  } catch (err) {
    showError(`Could not capture page text: ${err.message}`);
  }
});

reportButton.addEventListener("click", async () => {
  clearError();
  resultEl.hidden = true;

  const rawEmail = emailText.value.trim();
  if (!rawEmail) {
    showError("Paste an email (or capture the page text) first.");
    return;
  }

  const apiUrl = await getApiUrl();
  reportButton.disabled = true;
  reportButton.textContent = "Reporting...";

  try {
    await ensureHostPermission(apiUrl);

    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const source = (tab && (tab.title || tab.url)) || "reported-via-extension";

    const response = await fetch(`${apiUrl}/report/email`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ source, raw_email: rawEmail }),
    });

    if (!response.ok) {
      const detail = await response.text();
      throw new Error(`API returned ${response.status}: ${detail.slice(0, 200)}`);
    }

    const body = await response.json();
    showResult(apiUrl, body);
  } catch (err) {
    showError(
      `Could not reach the undercover API at ${apiUrl}. Is it running? (${err.message})`
    );
  } finally {
    reportButton.disabled = false;
    reportButton.textContent = "Report to undercover";
  }
});

function showResult(apiUrl, assessment) {
  resultLevel.textContent = assessment.risk_level;
  resultLevel.className = `badge ${assessment.risk_level}`;
  resultScore.textContent = `score ${assessment.risk_score.toFixed(2)}`;

  resultFactors.innerHTML = "";
  for (const factor of assessment.factors || []) {
    const li = document.createElement("li");
    li.textContent = factor.detail;
    resultFactors.appendChild(li);
  }

  resultLink.href = `${apiUrl}/ui/cases/${assessment.id}`;
  resultEl.hidden = false;
}

(async function init() {
  const apiUrl = await getApiUrl();
  apiUrlInput.value = apiUrl;
})();
