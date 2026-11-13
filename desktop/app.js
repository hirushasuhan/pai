/**
 * PAI Studio Desktop UI Client Application.
 * Communicates with local loopback bridge server on http://127.0.0.1:8765.
 */

const API_BASE = "http://127.0.0.1:8765";

// State
let currentTab = "chat";
let activeModel = "llama3.2:3b";
let chatHistory = [];
let availableModels = [];

// DOM Elements
const navItems = document.querySelectorAll(".nav-item");
const tabViews = document.querySelectorAll(".tab-view");
const serverStatusDot = document.getElementById("server-status-dot");
const serverStatusText = document.getElementById("server-status-text");
const headerModelSelect = document.getElementById("header-model-select");
const toggleInternet = document.getElementById("toggle-internet");
const toggleFactcheck = document.getElementById("toggle-factcheck");

// Chat DOM
const messagesList = document.getElementById("messages-list");
const chatForm = document.getElementById("chat-form");
const chatInput = document.getElementById("chat-input");
const btnSend = document.getElementById("btn-send");

// Models DOM
const installedModelsList = document.getElementById("installed-models-list");
const btnRefreshModels = document.getElementById("btn-refresh-models");
const pullModelNameInput = document.getElementById("pull-model-name");
const btnPullModel = document.getElementById("btn-pull-model");
const pullProgressContainer = document.getElementById("pull-progress-container");
const pullProgressBar = document.getElementById("pull-progress-bar");
const pullStatusText = document.getElementById("pull-status-text");
const pullPercentText = document.getElementById("pull-percent-text");

// Cloud DOM
const btnSaveKeys = document.querySelectorAll(".btn-save-key");

// Antigravity DOM
const antigravityTaskInput = document.getElementById("antigravity-task-input");
const btnRunAntigravity = document.getElementById("btn-run-antigravity");
const antigravityLog = document.getElementById("antigravity-log");

// Tools DOM
const toolWeatherCity = document.getElementById("tool-weather-city");
const btnGetWeather = document.getElementById("btn-get-weather");
const weatherResultBox = document.getElementById("weather-result-box");
const toolSearchQuery = document.getElementById("tool-search-query");
const btnRunSearch = document.getElementById("btn-run-search");
const searchResultBox = document.getElementById("search-result-box");

// Initial Setup
document.addEventListener("DOMContentLoaded", () => {
  setupNavigation();
  setupChat();
  setupModels();
  setupCloudKeys();
  setupAntigravity();
  setupTools();
  checkServerHealth();
  setInterval(checkServerHealth, 5000);
});

// 1. Navigation
function setupNavigation() {
  navItems.forEach((btn) => {
    btn.addEventListener("click", () => {
      const tab = btn.getAttribute("data-tab");
      switchTab(tab);
    });
  });

  headerModelSelect.addEventListener("change", async (e) => {
    const selected = e.target.value;
    try {
      const res = await fetch(`${API_BASE}/api/models/switch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ model: selected }),
      });
      const data = await res.json();
      if (data.success) {
        activeModel = selected;
      }
    } catch (err) {
      console.error("Failed to switch model:", err);
    }
  });

  toggleInternet.addEventListener("change", async (e) => {
    await toggleFeature("internet", e.target.checked);
  });

  toggleFactcheck.addEventListener("change", async (e) => {
    await toggleFeature("factcheck", e.target.checked);
  });
}

function switchTab(tab) {
  currentTab = tab;
  navItems.forEach((btn) => {
    btn.classList.toggle("active", btn.getAttribute("data-tab") === tab);
  });
  tabViews.forEach((view) => {
    view.classList.toggle("active", view.id === `view-${tab}`);
  });

  if (tab === "models") loadModelsList();
  if (tab === "cloud") loadCloudConfig();
  if (tab === "tools") loadDoctorTelemetry();
}

async function toggleFeature(feature, val) {
  try {
    await fetch(`${API_BASE}/api/settings/toggle`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ feature, value: val }),
    });
  } catch (err) {
    console.error("Toggle error:", err);
  }
}

// 2. Health & Status
async function checkServerHealth() {
  try {
    const res = await fetch(`${API_BASE}/api/status`);
    if (res.ok) {
      const data = await res.json();
      serverStatusDot.classList.add("online");
      serverStatusText.textContent = `Online (${data.active_model})`;
      activeModel = data.active_model;
      toggleInternet.checked = data.internet_enabled;
      toggleFactcheck.checked = data.factcheck_enabled;
    } else {
      setOffline();
    }
  } catch (err) {
    setOffline();
  }
}

function setOffline() {
  serverStatusDot.classList.remove("online");
  serverStatusText.textContent = "Engine Offline (Start bridge)";
}

// 3. Chat System
function setupChat() {
  chatForm.addEventListener("submit", (e) => {
    e.preventDefault();
    sendMessage();
  });

  chatInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  });
}

async function sendMessage() {
  const text = chatInput.value.trim();
  if (!text) return;

  chatInput.value = "";
  appendMessage("user", text);

  // Assistant typing placeholder
  const placeholder = appendMessage("assistant", "Thinking...");
  const bodyDiv = placeholder.querySelector(".msg-body");

  try {
    const res = await fetch(`${API_BASE}/api/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        prompt: text,
        model: activeModel,
        history: chatHistory,
      }),
    });

    const data = await res.json();
    if (data.success) {
      renderAssistantResponse(placeholder, data.response, data.thinking, data.factcheck);
      chatHistory.push({ role: "user", content: text });
      chatHistory.push({ role: "assistant", content: data.response });
    } else {
      bodyDiv.innerHTML = `<span style="color:var(--accent-red)">Error: ${data.error || "Generation failed"}</span>`;
    }
  } catch (err) {
    bodyDiv.innerHTML = `<span style="color:var(--accent-red)">Connection error: ${err.message}</span>`;
  }
}

function appendMessage(role, text) {
  const msg = document.createElement("div");
  msg.className = `message ${role}`;

  const header = document.createElement("div");
  header.className = "msg-header";
  header.innerHTML = `
    <span class="avatar-badge">${role === "user" ? "YOU" : "PAI"}</span>
    <span class="msg-author">${role === "user" ? "User" : "PAI Assistant"}</span>
    <span class="msg-time">${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
  `;

  const body = document.createElement("div");
  body.className = "msg-body";
  body.textContent = text;

  msg.appendChild(header);
  msg.appendChild(body);
  messagesList.appendChild(msg);
  messagesList.scrollTop = messagesList.scrollHeight;

  return msg;
}

function renderAssistantResponse(msgElement, responseText, thinkingText, factcheckData) {
  const bodyDiv = msgElement.querySelector(".msg-body");
  bodyDiv.innerHTML = "";

  // 1. Thinking trace
  if (thinkingText) {
    const thinkBox = document.createElement("div");
    thinkBox.className = "thinking-box";
    thinkBox.innerHTML = `
      <div class="thinking-header">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"></path></svg>
        <span>Model Thinking Trace (Click to toggle)</span>
      </div>
      <div class="thinking-content">${escapeHtml(thinkingText)}</div>
    `;
    const header = thinkBox.querySelector(".thinking-header");
    const content = thinkBox.querySelector(".thinking-content");
    header.addEventListener("click", () => {
      content.style.display = content.style.display === "none" ? "block" : "none";
    });
    bodyDiv.appendChild(thinkBox);
  }

  // 2. Main formatted markdown content
  const contentDiv = document.createElement("div");
  contentDiv.innerHTML = formatMarkdown(responseText);
  bodyDiv.appendChild(contentDiv);

  // 3. Fact-checking card
  if (factcheckData && factcheckData.claims && factcheckData.claims.length > 0) {
    const fcCard = document.createElement("div");
    fcCard.className = "factcheck-card";
    
    let claimsHtml = "";
    factcheckData.claims.forEach((c) => {
      let badgeClass = "badge-unverified";
      let icon = "⚠️ UNVERIFIED";
      if (c.verdict === "VERIFIED") {
        badgeClass = "badge-verified";
        icon = "✅ VERIFIED";
      } else if (c.verdict === "CONTRADICTED") {
        badgeClass = "badge-contradicted";
        icon = "❌ CONTRADICTED";
      }

      let citationsHtml = "";
      if (c.citations && c.citations.length > 0) {
        citationsHtml = c.citations.map(cite => `<a class="cite-link" href="${cite.url}" target="_blank">${cite.title || 'Source'}</a>`).join(", ");
      }

      claimsHtml += `
        <div class="claim-row">
          <span class="${badgeClass}">[${icon}]</span> ${escapeHtml(c.statement)}
          ${citationsHtml ? `— Sources: ${citationsHtml}` : ''}
        </div>
      `;
    });

    fcCard.innerHTML = `
      <div class="factcheck-header">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
        <span>Live Web Grounding & Fact-Check Audit:</span>
      </div>
      <div class="factcheck-claims-list">${claimsHtml}</div>
    `;
    bodyDiv.appendChild(fcCard);
  }

  messagesList.scrollTop = messagesList.scrollHeight;
}

// 4. Model Manager
function setupModels() {
  btnRefreshModels.addEventListener("click", loadModelsList);

  btnPullModel.addEventListener("click", () => {
    const name = pullModelNameInput.value.trim();
    if (!name) return;
    pullModel(name);
  });
}

async function loadModelsList() {
  installedModelsList.innerHTML = '<div class="loading-spinner">Loading models...</div>';
  try {
    const res = await fetch(`${API_BASE}/api/models`);
    const data = await res.json();
    
    // Update select in navbar
    headerModelSelect.innerHTML = "";
    
    // Local models
    const localGroup = document.createElement("optgroup");
    localGroup.label = "Local Models (Ollama)";
    data.local_models.forEach((m) => {
      const opt = document.createElement("option");
      opt.value = m.name;
      opt.textContent = `${m.name} (${m.size_gb} GB)`;
      if (m.name === data.active_model) opt.selected = true;
      localGroup.appendChild(opt);
    });
    headerModelSelect.appendChild(localGroup);

    // Cloud models
    const cloudGroup = document.createElement("optgroup");
    cloudGroup.label = "3rd-Party Cloud AI";
    data.cloud_models.forEach((cm) => {
      const opt = document.createElement("option");
      opt.value = cm.model;
      opt.textContent = `${cm.model} (${cm.display_provider})`;
      if (cm.model === data.active_model) opt.selected = true;
      cloudGroup.appendChild(opt);
    });
    headerModelSelect.appendChild(cloudGroup);

    // Render installed cards
    if (data.local_models.length === 0) {
      installedModelsList.innerHTML = '<div class="text-muted">No local models found. Pull one above!</div>';
      return;
    }

    installedModelsList.innerHTML = "";
    data.local_models.forEach((m) => {
      const card = document.createElement("div");
      card.className = `model-item-card ${m.is_active ? 'active' : ''}`;
      card.innerHTML = `
        <div class="flex-between">
          <span class="model-item-title">${m.name}</span>
          ${m.is_active ? '<span class="avatar-badge">Active</span>' : ''}
        </div>
        <div class="model-item-meta">Size: ${m.size_gb} GB</div>
        <button class="btn btn-secondary btn-sm btn-activate-model" data-model="${m.name}">
          ${m.is_active ? 'Current Model' : 'Switch to this model'}
        </button>
      `;
      card.querySelector(".btn-activate-model").addEventListener("click", () => {
        headerModelSelect.value = m.name;
        headerModelSelect.dispatchEvent(new Event("change"));
        loadModelsList();
      });
      installedModelsList.appendChild(card);
    });
  } catch (err) {
    installedModelsList.innerHTML = `<div style="color:var(--accent-red)">Error loading models: ${err.message}</div>`;
  }
}

function pullModel(name) {
  pullProgressContainer.classList.remove("hidden");
  pullProgressBar.style.width = "0%";
  pullStatusText.textContent = `Initializing download for ${name}...`;
  pullPercentText.textContent = "0%";
  btnPullModel.disabled = true;

  // Use fetch with streaming reader
  fetch(`${API_BASE}/api/models/pull`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model: name }),
  })
    .then((response) => {
      const reader = response.body.getReader();
      const decoder = new TextDecoder();

      function read() {
        reader.read().then(({ done, value }) => {
          if (done) {
            pullStatusText.textContent = `Download complete for ${name}!`;
            pullProgressBar.style.width = "100%";
            pullPercentText.textContent = "100%";
            btnPullModel.disabled = false;
            loadModelsList();
            return;
          }
          const chunk = decoder.decode(value);
          const lines = chunk.split("\n");
          lines.forEach((l) => {
            if (l.startsWith("data: ")) {
              try {
                const parsed = JSON.parse(l.substring(6));
                if (parsed.status) {
                  pullStatusText.textContent = parsed.status;
                }
                if (parsed.total && parsed.completed) {
                  const pct = Math.round((parsed.completed / parsed.total) * 100);
                  pullProgressBar.style.width = `${pct}%`;
                  pullPercentText.textContent = `${pct}%`;
                }
              } catch (e) {}
            }
          });
          read();
        });
      }
      read();
    })
    .catch((err) => {
      pullStatusText.textContent = `Pull error: ${err.message}`;
      btnPullModel.disabled = false;
    });
}

// 5. Cloud AI Keys
function setupCloudKeys() {
  btnSaveKeys.forEach((btn) => {
    btn.addEventListener("click", async () => {
      const prov = btn.getAttribute("data-provider");
      const input = document.getElementById(`key-${prov}`);
      const val = input.value.trim();
      if (!val) return;

      try {
        const res = await fetch(`${API_BASE}/api/cloud/set_key`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ provider: prov, key: val }),
        });
        const data = await res.json();
        if (data.success) {
          input.value = "";
          alert(`Successfully saved API key for ${prov.toUpperCase()}!`);
          loadCloudConfig();
        }
      } catch (err) {
        alert(`Failed to save key: ${err.message}`);
      }
    });
  });
}

async function loadCloudConfig() {
  try {
    const res = await fetch(`${API_BASE}/api/cloud/config`);
    const data = await res.json();
    data.providers.forEach((p) => {
      const badge = document.getElementById(`${p.id}-badge`);
      if (badge) {
        if (p.has_key) {
          badge.textContent = "Status: Key Ready";
          badge.className = "card-badge ready";
        } else {
          badge.textContent = "Status: No Key";
          badge.className = "card-badge";
        }
      }
    });
  } catch (err) {
    console.error("Cloud config load error:", err);
  }
}

// 6. Antigravity Supervisor
function setupAntigravity() {
  btnRunAntigravity.addEventListener("click", async () => {
    const task = antigravityTaskInput.value.trim();
    if (!task) return;

    appendLog(`[START] Running autonomous task supervisor: "${task}"`);
    try {
      const res = await fetch(`${API_BASE}/api/antigravity/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ task }),
      });
      const data = await res.json();
      if (data.success) {
        appendLog(`[STEERING] ${data.message}`);
        appendLog(`[STATUS] Continuous supervisor loop iterating across milestones...`);
      } else {
        appendLog(`[ERROR] ${data.error}`);
      }
    } catch (err) {
      appendLog(`[CONNECTION ERROR] ${err.message}`);
    }
  });
}

function appendLog(line) {
  const div = document.createElement("div");
  div.className = "log-line info";
  div.textContent = `[${new Date().toLocaleTimeString()}] ${line}`;
  antigravityLog.appendChild(div);
  antigravityLog.scrollTop = antigravityLog.scrollHeight;
}

// 7. Tools & Health
function setupTools() {
  btnGetWeather.addEventListener("click", async () => {
    const city = toolWeatherCity.value.trim() || "Colombo";
    weatherResultBox.textContent = `Fetching live weather for ${city}...`;
    try {
      const res = await fetch(`${API_BASE}/api/weather?city=${encodeURIComponent(city)}`);
      const data = await res.json();
      weatherResultBox.textContent = data.message || JSON.stringify(data);
    } catch (err) {
      weatherResultBox.textContent = `Weather error: ${err.message}`;
    }
  });

  btnRunSearch.addEventListener("click", async () => {
    const q = toolSearchQuery.value.trim();
    if (!q) return;
    searchResultBox.textContent = `Searching live web knowledge for "${q}"...`;
    try {
      const res = await fetch(`${API_BASE}/api/search?q=${encodeURIComponent(q)}`);
      const data = await res.json();
      searchResultBox.textContent = data.message || "No results found.";
    } catch (err) {
      searchResultBox.textContent = `Search error: ${err.message}`;
    }
  });
}

async function loadDoctorTelemetry() {
  try {
    const res = await fetch(`${API_BASE}/api/doctor`);
    const data = await res.json();
    document.getElementById("doc-platform").textContent = data.platform;
    document.getElementById("doc-ram").textContent = `${data.ram.available_gb} GB / ${data.ram.total_gb} GB`;
    document.getElementById("doc-model").textContent = data.active_model;
    document.getElementById("doc-python").textContent = data.python_version;
  } catch (err) {
    console.error("Telemetry error:", err);
  }
}

// Helpers
function escapeHtml(text) {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function formatMarkdown(text) {
  let html = escapeHtml(text);
  // Code blocks
  html = html.replace(/```([a-z0-9_\-]+)?\n([\s\S]*?)```/g, (match, lang, code) => {
    return `<pre><code class="language-${lang || 'plaintext'}">${code.trim()}</code></pre>`;
  });
  // Inline code
  html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
  // Bold & Italic
  html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  html = html.replace(/\*([^*]+)\*/g, '<em>$1</em>');
  // Paragraphs
  html = html.replace(/\n\n+/g, '</p><p>');
  html = `<p>${html}</p>`;
  return html;
}
