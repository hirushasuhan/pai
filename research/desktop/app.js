/**
 * PAI Studio Desktop UI Client Application.
 * Communicates with local loopback bridge server on http://127.0.0.1:8765.
 */

const API_BASE = "http://127.0.0.1:8765";

// State
let currentTab = "chat";
let activeModel = "llama3.2:3b";
let activeProjectPath = "";
let activeProjectName = "";
let currentOpenFile = "";
let chatHistory = [];
let availableModels = [];
let projectsData = { active_project: "", projects: [] };
let teamRosterData = [];
let currentDeliverables = { plan: "", specialist: "", code: {}, qa: "" };

// SVG Icon Library
const SVG_ICONS = {
  check: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>`,
  alert: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>`,
  info: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>`,
  trash: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>`,
  folder: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>`,
  file: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path><polyline points="13 2 13 9 20 9"></polyline></svg>`,
  pm: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="8.5" cy="7" r="4"></circle><line x1="20" y1="8" x2="20" y2="14"></line><line x1="23" y1="11" x2="17" y2="11"></line></svg>`,
  dev: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>`,
  specialist: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"></path></svg>`,
  qa: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><polyline points="9 12 11 14 15 10"></polyline></svg>`,
  shield: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>`,
  globe: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>`,
  users: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg>`,
  image: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><circle cx="8.5" cy="8.5" r="1.5"></circle><polyline points="21 15 16 10 5 21"></polyline></svg>`,
  layers: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 2 7 12 12 22 7 12 2"></polygon><polyline points="2 17 12 22 22 17"></polyline><polyline points="2 12 12 17 22 12"></polyline></svg>`,
  cpu: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="4" width="16" height="16" rx="2" ry="2"></rect><rect x="9" y="9" width="6" height="6"></rect><line x1="9" y1="1" x2="9" y2="4"></line><line x1="15" y1="1" x2="15" y2="4"></line><line x1="9" y1="20" x2="9" y2="23"></line><line x1="15" y1="20" x2="15" y2="23"></line><line x1="20" y1="9" x2="23" y2="9"></line><line x1="20" y1="14" x2="23" y2="14"></line><line x1="1" y1="9" x2="4" y2="9"></line><line x1="1" y1="14" x2="4" y2="14"></line></svg>`,
};

// DOM Elements
const navItems = document.querySelectorAll(".nav-item");
const tabViews = document.querySelectorAll(".tab-view");
const serverStatusDot = document.getElementById("server-status-dot");
const serverStatusText = document.getElementById("server-status-text");
const headerModelSelect = document.getElementById("header-model-select");
const headerProjectSelect = document.getElementById("header-project-select");
const toggleInternet = document.getElementById("toggle-internet");
const toggleFactcheck = document.getElementById("toggle-factcheck");

// Chat DOM
const messagesList = document.getElementById("messages-list");
const chatForm = document.getElementById("chat-form");
const chatInput = document.getElementById("chat-input");
const btnSend = document.getElementById("btn-send");
const chatProjectBanner = document.getElementById("chat-project-banner");
const chatProjectName = document.getElementById("chat-project-name");
const chatProjectPath = document.getElementById("chat-project-path");
const btnClearChatProj = document.getElementById("btn-clear-chat-proj");

// Projects DOM
const createProjectForm = document.getElementById("create-project-form");
const projNameInput = document.getElementById("proj-name-input");
const projPathInput = document.getElementById("proj-path-input");
const projectsListContainer = document.getElementById("projects-list-container");
const savedProjectsCount = document.getElementById("saved-projects-count");
const currentOpenFilename = document.getElementById("current-open-filename");
const btnRefreshFiles = document.getElementById("btn-refresh-files");
const btnNewFile = document.getElementById("btn-new-file");
const btnSaveFile = document.getElementById("btn-save-file");
const fileTreeContainer = document.getElementById("file-tree-container");
const codeEditorTextarea = document.getElementById("code-editor-textarea");

// Team DOM
const teamRosterCards = document.getElementById("team-roster-cards");
const teamSprintForm = document.getElementById("team-sprint-form");
const teamTaskInput = document.getElementById("team-task-input");
const btnRunTeam = document.getElementById("btn-run-team");
const teamTargetProjNote = document.getElementById("team-target-proj-note");
const teamActivityFeed = document.getElementById("team-activity-feed");
const teamDeliverableView = document.getElementById("team-deliverable-view");
const delivTabBtns = document.querySelectorAll(".deliv-tab-btn");
const btnCopyDeliverable = document.getElementById("btn-copy-deliverable");

// Skills DOM
const skillsCatalogGrid = document.getElementById("skills-catalog-grid");

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
const cloudForm = document.getElementById("cloud-model-form");
const cfgModelName = document.getElementById("cfg-model-name");
const cfgProviderUrl = document.getElementById("cfg-provider-url");
const cfgApiKey = document.getElementById("cfg-api-key");
const btnToggleKeyVis = document.getElementById("btn-toggle-key-visibility");
const saveStatusNotice = document.getElementById("save-model-status");
const configuredModelsList = document.getElementById("configured-models-list");
const configuredCountSpan = document.getElementById("configured-count");

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

// Toast Container
const toastContainer = document.getElementById("toast-container");

// Initial Setup
document.addEventListener("DOMContentLoaded", () => {
  setupNavigation();
  setupChat();
  setupProjects();
  setupTeam();
  setupSkills();
  setupModels();
  setupCloudKeys();
  setupAntigravity();
  setupTools();
  checkServerHealth();
  setInterval(checkServerHealth, 5000);
});

// Toast Notification System
function showToast(message, type = "info", title = "", duration = 4000) {
  if (!toastContainer) return;
  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  
  const iconSvg = type === "success" ? SVG_ICONS.check :
                  type === "error" ? SVG_ICONS.alert :
                  type === "warning" ? SVG_ICONS.alert : SVG_ICONS.info;
  
  const defaultTitle = type === "success" ? "Success" :
                       type === "error" ? "Error" :
                       type === "warning" ? "Notice" : "Information";

  toast.innerHTML = `
    <div class="toast-icon">${iconSvg}</div>
    <div class="toast-body">
      <div class="toast-title">${escapeHtml(title || defaultTitle)}</div>
      <div class="toast-msg">${escapeHtml(message)}</div>
    </div>
    <button type="button" class="toast-close" title="Dismiss">&times;</button>
  `;

  const closeBtn = toast.querySelector(".toast-close");
  const dismiss = () => {
    toast.classList.add("toast-hiding");
    setTimeout(() => toast.remove(), 250);
  };
  closeBtn.addEventListener("click", dismiss);

  toastContainer.appendChild(toast);
  setTimeout(dismiss, duration);
}

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
        showToast(`Switched active model to ${selected}`, "success", "Model Changed");
      }
    } catch (err) {
      console.error("Failed to switch model:", err);
      showToast(`Failed to switch model: ${err.message}`, "error");
    }
  });

  headerProjectSelect.addEventListener("change", async (e) => {
    const selectedPath = e.target.value;
    await activateProject(selectedPath);
  });

  toggleInternet.addEventListener("change", async (e) => {
    const val = e.target.checked;
    try {
      await fetch(`${API_BASE}/api/settings/toggle`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ feature: "internet", value: val }),
      });
      showToast(`Real-Time Internet grounding ${val ? "enabled" : "disabled"}`, "info");
      loadSkills();
    } catch (err) {
      console.error("Internet toggle error:", err);
    }
  });

  toggleFactcheck.addEventListener("change", async (e) => {
    const val = e.target.checked;
    try {
      await fetch(`${API_BASE}/api/settings/toggle`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ feature: "factcheck", value: val }),
      });
      showToast(`Live Fact-Checking engine ${val ? "enabled" : "disabled"}`, "info");
      loadSkills();
    } catch (err) {
      console.error("Factcheck toggle error:", err);
    }
  });
}

function switchTab(tab) {
  currentTab = tab;
  navItems.forEach((btn) => {
    if (btn.getAttribute("data-tab") === tab) {
      btn.classList.add("active");
    } else {
      btn.classList.remove("active");
    }
  });

  tabViews.forEach((view) => {
    if (view.id === `view-${tab}`) {
      view.classList.add("active");
    } else {
      view.classList.remove("active");
    }
  });

  if (tab === "models") loadInstalledModels();
  if (tab === "cloud") loadCloudModels();
  if (tab === "projects") loadProjects();
  if (tab === "team") loadTeamRoster();
  if (tab === "skills") loadSkills();
  if (tab === "tools") loadDoctorTelemetry();
}

// 2. Chat System
function setupChat() {
  chatForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const prompt = chatInput.value.trim();
    if (!prompt) return;

    chatInput.value = "";
    appendUserMessage(prompt);
    btnSend.disabled = true;

    const botMsgId = "msg-" + Date.now();
    appendAssistantPlaceholder(botMsgId);

    try {
      const res = await fetch(`${API_BASE}/api/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          prompt,
          model: activeModel,
          history: chatHistory,
          project_path: activeProjectPath,
        }),
      });

      const data = await res.json();
      if (data.success) {
        if (data.is_image) {
          updateAssistantMessageImage(botMsgId, data.image_url, data.prompt, data.model, data.filename);
        } else {
          updateAssistantMessage(botMsgId, data.response, data.factcheck, data.grounding);
        }
        chatHistory.push({ role: "user", content: prompt });
        chatHistory.push({ role: "assistant", content: data.response || `[Generated Image: ${data.prompt}]` });
      } else {
        updateAssistantError(botMsgId, data.error || "Execution error");
      }
    } catch (err) {
      updateAssistantError(botMsgId, `Server connection error: ${err.message}`);
    } finally {
      btnSend.disabled = false;
      chatInput.focus();
    }
  });

  chatInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      chatForm.dispatchEvent(new Event("submit"));
    }
  });

  btnClearChatProj.addEventListener("click", () => {
    activateProject("");
  });
}

function appendUserMessage(text) {
  const msg = document.createElement("div");
  msg.className = "message user";
  msg.innerHTML = `
    <div class="msg-header">
      <span class="avatar-badge">YOU</span>
      <span class="msg-author">User</span>
      <span class="msg-time">${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
    </div>
    <div class="msg-body">
      <p>${escapeHtml(text)}</p>
    </div>
  `;
  messagesList.appendChild(msg);
  messagesList.scrollTop = messagesList.scrollHeight;
}

function appendAssistantPlaceholder(id) {
  const msg = document.createElement("div");
  msg.className = "message assistant";
  msg.id = id;
  msg.innerHTML = `
    <div class="msg-header">
      <span class="avatar-badge">PAI</span>
      <span class="msg-author">PAI Assistant</span>
      <span class="msg-time">${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
    </div>
    <div class="msg-body loading-indicator">
      <span class="dot-flashing"></span>
      <span class="text-muted" style="margin-left: 8px;">Thinking & grounding...</span>
    </div>
  `;
  messagesList.appendChild(msg);
  messagesList.scrollTop = messagesList.scrollHeight;
}

function updateAssistantMessage(id, text, factcheck, grounding) {
  const msg = document.getElementById(id);
  if (!msg) return;
  const body = msg.querySelector(".msg-body");
  body.classList.remove("loading-indicator");

  let html = formatMarkdown(text);

  if (grounding && grounding.length > 0) {
    html += `
      <div class="grounding-badge-list">
        <span class="grounding-label">${SVG_ICONS.globe} Web Citations:</span>
        ${grounding.map(g => `<a href="${escapeHtml(g.url)}" target="_blank" class="grounding-pill">${escapeHtml(g.title || g.url)}</a>`).join("")}
      </div>
    `;
  }

  if (factcheck && factcheck.report) {
    html += `
      <div class="factcheck-box">
        <div class="factcheck-header">
          <span class="fc-title">${SVG_ICONS.shield} Real-Time Fact-Check Verdict</span>
          <span class="fc-score">Trust: ${Math.round((factcheck.score || 1.0) * 100)}%</span>
        </div>
        <div class="factcheck-body">${escapeHtml(factcheck.report)}</div>
      </div>
    `;
  }

  body.innerHTML = html;
  messagesList.scrollTop = messagesList.scrollHeight;
}

function updateAssistantMessageImage(id, dataUrl, prompt, model, filename) {
  const msg = document.getElementById(id);
  if (!msg) return;
  const body = msg.querySelector(".msg-body");
  body.classList.remove("loading-indicator");

  body.innerHTML = `
    <div class="chat-image-card">
      <div class="image-preview-wrap">
        <img src="${dataUrl}" alt="${escapeHtml(prompt)}" class="generated-chat-image" onclick="window.open('${dataUrl}', '_blank')" />
      </div>
      <div class="image-actions">
        <div class="image-info">
          <span class="image-prompt-badge">"${escapeHtml(prompt)}"</span>
          <span class="image-model-badge">${SVG_ICONS.image} ${escapeHtml(model)}</span>
        </div>
        <a href="${dataUrl}" download="${escapeHtml(filename || 'pai-generated.png')}" class="btn btn-sm btn-download-image">
          <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
          Download PNG
        </a>
      </div>
    </div>
  `;
  messagesList.scrollTop = messagesList.scrollHeight;
}

function updateAssistantError(id, errText) {
  const msg = document.getElementById(id);
  if (!msg) return;
  const body = msg.querySelector(".msg-body");
  body.classList.remove("loading-indicator");
  body.innerHTML = `<p class="error-text">Error: ${escapeHtml(errText)}</p>`;
  messagesList.scrollTop = messagesList.scrollHeight;
}

// 3. Project Workspace System
function setupProjects() {
  createProjectForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const name = projNameInput.value.trim();
    const folderPath = projPathInput.value.trim();
    if (!name || !folderPath) return;

    try {
      const res = await fetch(`${API_BASE}/api/projects/save`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, path: folderPath }),
      });
      const data = await res.json();
      if (data.success) {
        showToast(`Saved project "${name}"`, "success", "Workspace Added");
        projNameInput.value = "";
        projPathInput.value = "";
        await loadProjects();
        await activateProject(folderPath);
      } else {
        showToast(data.error || "Failed to save project", "error");
      }
    } catch (err) {
      showToast(`Error saving project: ${err.message}`, "error");
    }
  });

  btnRefreshFiles.addEventListener("click", () => {
    if (activeProjectPath) {
      loadProjectFiles(activeProjectPath);
      showToast("Refreshed project file tree", "info");
    }
  });

  btnNewFile.addEventListener("click", () => {
    if (!activeProjectPath) {
      showToast("Please activate a project first", "warning");
      return;
    }
    const fname = prompt("Enter new filename (e.g. index.html or utils.js):");
    if (fname) {
      currentOpenFile = fname.trim();
      currentOpenFilename.textContent = currentOpenFile;
      codeEditorTextarea.value = "";
      codeEditorTextarea.removeAttribute("readonly");
      btnSaveFile.removeAttribute("disabled");
      codeEditorTextarea.focus();
    }
  });

  btnSaveFile.addEventListener("click", async () => {
    if (!activeProjectPath || !currentOpenFile) return;
    const content = codeEditorTextarea.value;
    try {
      const res = await fetch(`${API_BASE}/api/projects/file/save`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          path: activeProjectPath,
          file: currentOpenFile,
          content: content,
        }),
      });
      const data = await res.json();
      if (data.success) {
        showToast(`Saved file "${currentOpenFile}" successfully!`, "success", "File Saved");
        loadProjectFiles(activeProjectPath);
      } else {
        showToast(data.error || "Failed to save file", "error");
      }
    } catch (err) {
      showToast(`Save error: ${err.message}`, "error");
    }
  });
}

async function loadProjects() {
  try {
    const res = await fetch(`${API_BASE}/api/projects`);
    const data = await res.json();
    if (data.success) {
      projectsData = data;
      renderProjectsList(data.projects, data.active_project);
      populateHeaderProjectDropdown(data.projects, data.active_project);

      activeProjectPath = data.active_project || "";
      const activeObj = data.projects.find(p => p.path === activeProjectPath);
      activeProjectName = activeObj ? activeObj.name : "";
      updateActiveProjectUI();

      if (activeProjectPath) {
        loadProjectFiles(activeProjectPath);
      }
    }
  } catch (err) {
    console.error("Failed to load projects:", err);
  }
}

function populateHeaderProjectDropdown(projects, activePath) {
  headerProjectSelect.innerHTML = `<option value="">No Active Project (Global)</option>`;
  projects.forEach((p) => {
    const opt = document.createElement("option");
    opt.value = p.path;
    opt.textContent = `${p.name} (${p.path})`;
    if (p.path === activePath) opt.selected = true;
    headerProjectSelect.appendChild(opt);
  });
}

function renderProjectsList(projects, activePath) {
  savedProjectsCount.textContent = projects.length;
  if (projects.length === 0) {
    projectsListContainer.innerHTML = `<div class="text-muted text-sm" style="padding: 10px;">No projects saved yet. Create one above to get started.</div>`;
    return;
  }

  projectsListContainer.innerHTML = "";
  projects.forEach((p) => {
    const isActive = p.path === activePath;
    const card = document.createElement("div");
    card.className = `project-card ${isActive ? "active" : ""}`;
    card.innerHTML = `
      <div class="project-card-header">
        <span class="project-card-name">${escapeHtml(p.name)}</span>
        ${isActive ? `<span class="project-card-badge">ACTIVE</span>` : ""}
      </div>
      <div class="project-card-path" title="${escapeHtml(p.path)}">${escapeHtml(p.path)}</div>
      <div class="project-card-actions">
        ${!isActive ? `<button type="button" class="btn btn-secondary btn-sm btn-activate-proj" data-path="${escapeHtml(p.path)}">Set Active</button>` : ""}
        <button type="button" class="btn btn-secondary btn-sm btn-del-proj" data-path="${escapeHtml(p.path)}" title="Delete project">&times;</button>
      </div>
    `;

    const actBtn = card.querySelector(".btn-activate-proj");
    if (actBtn) {
      actBtn.addEventListener("click", () => activateProject(p.path));
    }
    const delBtn = card.querySelector(".btn-del-proj");
    if (delBtn) {
      delBtn.addEventListener("click", () => deleteProject(p.path));
    }

    projectsListContainer.appendChild(card);
  });
}

async function activateProject(folderPath) {
  try {
    const res = await fetch(`${API_BASE}/api/projects/set_active`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path: folderPath }),
    });
    const data = await res.json();
    if (data.success) {
      activeProjectPath = folderPath;
      const projObj = (projectsData.projects || []).find(p => p.path === folderPath);
      activeProjectName = projObj ? projObj.name : (folderPath ? "Workspace" : "");
      updateActiveProjectUI();
      renderProjectsList(projectsData.projects || [], activeProjectPath);
      headerProjectSelect.value = folderPath;
      if (folderPath) {
        showToast(`Workspace set to: ${activeProjectName}`, "success", "Active Project");
        loadProjectFiles(folderPath);
      } else {
        showToast("Switched to Global mode (no active project)", "info");
        fileTreeContainer.innerHTML = `<div class="file-tree-empty text-muted">Activate a project to browse its files.</div>`;
        codeEditorTextarea.value = "";
        codeEditorTextarea.setAttribute("readonly", "true");
        btnSaveFile.setAttribute("disabled", "true");
        currentOpenFilename.textContent = "Select a file to view or edit";
      }
    }
  } catch (err) {
    showToast(`Failed to activate project: ${err.message}`, "error");
  }
}

async function deleteProject(folderPath) {
  if (!confirm(`Are you sure you want to remove this project workspace? (Your disk files will not be deleted)`)) return;
  try {
    const res = await fetch(`${API_BASE}/api/projects/delete`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path: folderPath }),
    });
    const data = await res.json();
    if (data.success) {
      showToast("Project workspace removed", "info");
      await loadProjects();
    }
  } catch (err) {
    showToast(`Delete error: ${err.message}`, "error");
  }
}

function updateActiveProjectUI() {
  if (activeProjectPath && activeProjectName) {
    chatProjectBanner.classList.remove("hidden");
    chatProjectName.textContent = activeProjectName;
    chatProjectPath.textContent = activeProjectPath;
    teamTargetProjNote.textContent = `Target: ${activeProjectName} (${activeProjectPath})`;
  } else {
    chatProjectBanner.classList.add("hidden");
    teamTargetProjNote.textContent = "Target: Standalone sprint directory";
  }
}

async function loadProjectFiles(folderPath) {
  if (!folderPath) return;
  fileTreeContainer.innerHTML = `<div class="file-tree-empty text-muted">Loading project files...</div>`;
  try {
    const res = await fetch(`${API_BASE}/api/projects/files?path=${encodeURIComponent(folderPath)}`);
    const data = await res.json();
    if (data.success) {
      renderFileTree(data.files, folderPath);
    } else {
      fileTreeContainer.innerHTML = `<div class="file-tree-empty error-text">${escapeHtml(data.error)}</div>`;
    }
  } catch (err) {
    fileTreeContainer.innerHTML = `<div class="file-tree-empty error-text">${escapeHtml(err.message)}</div>`;
  }
}

function renderFileTree(files, basePath) {
  if (!files || files.length === 0) {
    fileTreeContainer.innerHTML = `<div class="file-tree-empty text-muted">No text or code files found in project.</div>`;
    return;
  }

  fileTreeContainer.innerHTML = "";
  files.forEach((f) => {
    const item = document.createElement("div");
    item.className = `file-item ${f === currentOpenFile ? "active" : ""}`;
    item.innerHTML = `${SVG_ICONS.file} <span>${escapeHtml(f)}</span>`;
    item.addEventListener("click", () => openProjectFile(basePath, f, item));
    fileTreeContainer.appendChild(item);
  });
}

async function openProjectFile(basePath, filename, itemElem) {
  document.querySelectorAll(".file-item").forEach(el => el.classList.remove("active"));
  if (itemElem) itemElem.classList.add("active");

  currentOpenFile = filename;
  currentOpenFilename.textContent = filename;
  codeEditorTextarea.value = "Loading file content...";
  codeEditorTextarea.setAttribute("readonly", "true");
  btnSaveFile.setAttribute("disabled", "true");

  try {
    const res = await fetch(`${API_BASE}/api/projects/file/content?path=${encodeURIComponent(basePath)}&file=${encodeURIComponent(filename)}`);
    const data = await res.json();
    if (data.success) {
      codeEditorTextarea.value = data.content;
      codeEditorTextarea.removeAttribute("readonly");
      btnSaveFile.removeAttribute("disabled");
    } else {
      codeEditorTextarea.value = `// Error loading file: ${data.error}`;
      showToast(data.error, "error");
    }
  } catch (err) {
    codeEditorTextarea.value = `// Connection error: ${err.message}`;
    showToast(err.message, "error");
  }
}

// 4. AI Team System (FIPA-ACL Multi-Agent SDLC)
function setupTeam() {
  delivTabBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      delivTabBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      const tab = btn.getAttribute("data-tab");
      renderDeliverableTab(tab);
    });
  });

  btnCopyDeliverable.addEventListener("click", () => {
    const activeTab = document.querySelector(".deliv-tab-btn.active")?.getAttribute("data-tab") || "code";
    let text = "";
    if (activeTab === "plan") text = currentDeliverables.plan;
    else if (activeTab === "specialist") text = currentDeliverables.specialist;
    else if (activeTab === "qa") text = currentDeliverables.qa;
    else if (activeTab === "code") {
      text = Object.entries(currentDeliverables.code || {})
        .map(([fname, c]) => `=== File: ${fname} ===\n${c}\n`)
        .join("\n\n");
    }
    if (text) {
      navigator.clipboard.writeText(text);
      showToast("Copied deliverables to clipboard!", "success");
    }
  });

  teamSprintForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const task = teamTaskInput.value.trim();
    if (!task) return;

    btnRunTeam.disabled = true;
    teamActivityFeed.innerHTML = `
      <div class="fipa-msg-card inform">
        <div class="fipa-header">
          <span class="fipa-badge">COORDINATOR</span>
          <span class="fipa-agents">PAI MultiAgentTeam &rarr; Engine</span>
        </div>
        <div class="fipa-body">Initiating IEEE / FIPA-ACL collaborative sprint for task: "${escapeHtml(task)}"...</div>
      </div>
    `;

    try {
      const res = await fetch(`${API_BASE}/api/team/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          task,
          project_dir: activeProjectPath,
        }),
      });

      const data = await res.json();
      if (data.success) {
        showToast("Team sprint completed successfully!", "success", "Sprint Done");
        currentDeliverables = {
          plan: data.plan,
          specialist: data.specialist_assets,
          code: data.code_updates,
          qa: data.qa_verdict,
        };

        // Render FIPA-ACL messages
        renderTeamMessages(data.messages || []);

        // Render deliverable
        renderDeliverableTab("plan");

        // If files were written and active project matches, reload files
        if (activeProjectPath) {
          loadProjectFiles(activeProjectPath);
        }
      } else {
        showToast(data.error || "Team sprint failed", "error");
        const errCard = document.createElement("div");
        errCard.className = "fipa-msg-card reject";
        errCard.innerHTML = `
          <div class="fipa-header">
            <span class="fipa-badge">ERROR</span>
            <span class="fipa-agents">Sprint Aborted</span>
          </div>
          <div class="fipa-body">${escapeHtml(data.error || "Execution error")}</div>
        `;
        teamActivityFeed.appendChild(errCard);
      }
    } catch (err) {
      showToast(`Team sprint connection error: ${err.message}`, "error");
    } finally {
      btnRunTeam.disabled = false;
    }
  });
}

async function loadTeamRoster() {
  try {
    const res = await fetch(`${API_BASE}/api/team/roster`);
    const data = await res.json();
    if (data.success) {
      teamRosterData = data.roster;
      renderTeamRoster(data.roster, data.available_models);
    }
  } catch (err) {
    console.error("Failed to load team roster:", err);
  }
}

function renderTeamRoster(roster, availableModels) {
  teamRosterCards.innerHTML = "";
  roster.forEach((member) => {
    const card = document.createElement("div");
    card.className = "team-role-card";
    
    const iconSvg = member.role === "project_manager" ? SVG_ICONS.pm :
                    member.role === "senior_developer" ? SVG_ICONS.dev :
                    member.role === "specialist_developer" ? SVG_ICONS.specialist : SVG_ICONS.qa;

    let modelOptions = availableModels.map(m => `<option value="${m}" ${m === member.current_model ? "selected" : ""}>${m}</option>`).join("");
    // Also include configured cloud models
    (window.__configuredCloudModels || []).forEach(cm => {
      modelOptions += `<option value="${cm.model_name}" ${cm.model_name === member.current_model ? "selected" : ""}>${cm.model_name} (Cloud)</option>`;
    });

    card.innerHTML = `
      <div class="role-card-header">
        <div class="role-icon-box">${iconSvg}</div>
        <div class="role-title-box">
          <span class="role-title">${escapeHtml(member.title)}</span>
          <span class="role-tag">${escapeHtml(member.role)}</span>
        </div>
      </div>
      <div class="role-desc">${escapeHtml(member.description)}</div>
      <div class="role-assignment">
        <label>Assigned Model:</label>
        <select class="role-model-select" data-role="${member.role}">
          ${modelOptions}
        </select>
      </div>
    `;

    const select = card.querySelector(".role-model-select");
    select.addEventListener("change", async (e) => {
      const newModel = e.target.value;
      try {
        const res = await fetch(`${API_BASE}/api/team/assign`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ role: member.role, model: newModel }),
        });
        const d = await res.json();
        if (d.success) {
          showToast(`Assigned ${newModel} to ${member.title}`, "success");
        }
      } catch (err) {
        showToast(`Assignment failed: ${err.message}`, "error");
      }
    });

    teamRosterCards.appendChild(card);
  });
}

function renderTeamMessages(messages) {
  teamActivityFeed.innerHTML = "";
  if (!messages || messages.length === 0) {
    teamActivityFeed.innerHTML = `<div class="text-muted feed-placeholder">Sprint completed without FIPA-ACL log.</div>`;
    return;
  }

  messages.forEach((msg) => {
    const card = document.createElement("div");
    const perf = (msg.performative || "inform").toLowerCase();
    card.className = `fipa-msg-card ${perf}`;
    card.innerHTML = `
      <div class="fipa-header">
        <span class="fipa-badge">[${escapeHtml(msg.performative || "INFORM")}]</span>
        <span class="fipa-agents"><strong>${escapeHtml(msg.sender)}</strong> &rarr; <strong>${escapeHtml(msg.recipient)}</strong></span>
      </div>
      <div class="fipa-body">${escapeHtml(msg.content)}</div>
    `;
    teamActivityFeed.appendChild(card);
  });
  teamActivityFeed.scrollTop = teamActivityFeed.scrollHeight;
}

function renderDeliverableTab(tab) {
  if (tab === "plan") {
    teamDeliverableView.innerHTML = `<pre>${escapeHtml(currentDeliverables.plan || "No WBS plan generated yet.")}</pre>`;
  } else if (tab === "specialist") {
    teamDeliverableView.innerHTML = `<pre>${escapeHtml(currentDeliverables.specialist || "No specialist assets generated.")}</pre>`;
  } else if (tab === "code") {
    const files = currentDeliverables.code || {};
    const keys = Object.keys(files);
    if (keys.length === 0) {
      teamDeliverableView.innerHTML = `<div class="text-muted">No synthesized code files.</div>`;
      return;
    }
    let html = "";
    keys.forEach((f) => {
      html += `<h4>File: <code>${escapeHtml(f)}</code></h4>`;
      html += `<pre><code>${escapeHtml(files[f])}</code></pre>`;
    });
    teamDeliverableView.innerHTML = html;
  } else if (tab === "qa") {
    teamDeliverableView.innerHTML = `<pre>${escapeHtml(currentDeliverables.qa || "No QA verdict available.")}</pre>`;
  }
}

// 5. Skills System
function setupSkills() {
  // Initial load
}

async function loadSkills() {
  try {
    const res = await fetch(`${API_BASE}/api/skills`);
    const data = await res.json();
    if (data.success) {
      renderSkillsList(data.skills);
    }
  } catch (err) {
    console.error("Failed to load skills:", err);
  }
}

function renderSkillsList(skills) {
  skillsCatalogGrid.innerHTML = "";
  skills.forEach((skill) => {
    const card = document.createElement("div");
    card.className = `skill-card ${skill.enabled ? "active" : ""}`;

    const iconSvg = SVG_ICONS[skill.icon] || SVG_ICONS.shield;

    card.innerHTML = `
      <div class="skill-header">
        <div class="skill-identity">
          <div class="skill-icon-wrap">${iconSvg}</div>
          <div class="skill-title-group">
            <span class="skill-name">${escapeHtml(skill.name)}</span>
            <span class="skill-cat">${escapeHtml(skill.category)}</span>
          </div>
        </div>
        <label class="switch">
          <input type="checkbox" class="skill-toggle-input" data-id="${skill.id}" ${skill.enabled ? "checked" : ""} />
          <span class="slider"></span>
        </label>
      </div>
      <div class="skill-desc">${escapeHtml(skill.description)}</div>
      <div class="skill-footer">
        <span class="skill-status-tag ${skill.enabled ? "enabled" : "disabled"}">${skill.enabled ? "ACTIVE" : "INACTIVE"}</span>
      </div>
    `;

    const toggle = card.querySelector(".skill-toggle-input");
    toggle.addEventListener("change", async (e) => {
      const val = e.target.checked;
      try {
        const res = await fetch(`${API_BASE}/api/skills/toggle`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ skill: skill.id, enabled: val }),
        });
        const d = await res.json();
        if (d.success) {
          showToast(`Skill "${skill.name}" ${val ? "activated" : "deactivated"}`, "info", "Skill Updated");
          // Sync header toggles if it's internet or factcheck
          if (skill.id === "internet") toggleInternet.checked = val;
          if (skill.id === "factcheck") toggleFactcheck.checked = val;
          loadSkills();
        }
      } catch (err) {
        showToast(`Failed to toggle skill: ${err.message}`, "error");
      }
    });

    skillsCatalogGrid.appendChild(card);
  });
}

// 6. Models Management
function setupModels() {
  btnRefreshModels.addEventListener("click", loadInstalledModels);

  btnPullModel.addEventListener("click", () => {
    const name = pullModelNameInput.value.trim();
    if (!name) return;
    pullModel(name);
  });
}

async function loadInstalledModels() {
  try {
    const res = await fetch(`${API_BASE}/api/models`);
    const data = await res.json();
    if (data.models) {
      availableModels = data.models;
      renderInstalledModels(data.models);
      populateModelSelectors(data.models);
    }
  } catch (err) {
    console.error("Models fetch error:", err);
  }
}

function renderInstalledModels(models) {
  installedModelsList.innerHTML = "";
  if (models.length === 0) {
    installedModelsList.innerHTML = `<div class="text-muted">No models detected. Pull one above.</div>`;
    return;
  }

  models.forEach((m) => {
    const card = document.createElement("div");
    card.className = `model-card ${m.is_active ? "active" : ""}`;
    card.innerHTML = `
      <div class="model-card-header">
        <span class="model-name">${escapeHtml(m.name)}</span>
        ${m.is_active ? `<span class="active-badge">Active</span>` : ""}
      </div>
      <div class="model-meta">
        <span>Size: ${m.size_gb} GB</span>
      </div>
      <div class="model-actions">
        ${!m.is_active ? `<button class="btn btn-secondary btn-sm btn-activate-model" data-name="${escapeHtml(m.name)}">Activate</button>` : ""}
      </div>
    `;

    const actBtn = card.querySelector(".btn-activate-model");
    if (actBtn) {
      actBtn.addEventListener("click", async () => {
        await switchModel(m.name);
      });
    }

    installedModelsList.appendChild(card);
  });
}

function populateModelSelectors(models) {
  const currentVal = headerModelSelect.value;
  headerModelSelect.innerHTML = "";

  models.forEach((m) => {
    const opt = document.createElement("option");
    opt.value = m.name;
    opt.textContent = `${m.name} (Local)`;
    if (m.name === currentVal || m.is_active) {
      opt.selected = true;
      activeModel = m.name;
    }
    headerModelSelect.appendChild(opt);
  });

  // Also include configured cloud models in header selector
  (window.__configuredCloudModels || []).forEach((cm) => {
    const opt = document.createElement("option");
    opt.value = cm.model_name;
    opt.textContent = `${cm.model_name} (${cm.model_type === "image" ? "Cloud Image" : "Cloud Chat"})`;
    if (cm.model_name === currentVal) opt.selected = true;
    headerModelSelect.appendChild(opt);
  });
}

async function switchModel(modelName) {
  try {
    const res = await fetch(`${API_BASE}/api/models/switch`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ model: modelName }),
    });
    const data = await res.json();
    if (data.success) {
      activeModel = modelName;
      headerModelSelect.value = modelName;
      showToast(`Model switched to ${modelName}`, "success");
      loadInstalledModels();
    }
  } catch (err) {
    showToast(`Failed to switch model: ${err.message}`, "error");
  }
}

function pullModel(modelName) {
  pullProgressContainer.classList.remove("hidden");
  pullProgressBar.style.width = "0%";
  pullStatusText.textContent = `Starting download for ${modelName}...`;
  pullPercentText.textContent = "0%";
  btnPullModel.disabled = true;

  const eventSource = new EventSource(`${API_BASE}/api/models/pull`, {
    withCredentials: false,
  });

  // Fallback to POST fetch streaming if EventSource is not preferred
  fetch(`${API_BASE}/api/models/pull`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model: modelName }),
  }).then(response => {
    const reader = response.body.getReader();
    const decoder = new TextDecoder();

    function read() {
      reader.read().then(({ done, value }) => {
        if (done) {
          pullStatusText.textContent = "Download complete!";
          pullProgressBar.style.width = "100%";
          pullPercentText.textContent = "100%";
          btnPullModel.disabled = false;
          showToast(`Successfully downloaded ${modelName}!`, "success", "Download Complete");
          loadInstalledModels();
          return;
        }

        const chunk = decoder.decode(value);
        const lines = chunk.split("\n");
        for (const line of lines) {
          if (line.startsWith("data: ")) {
            try {
              const d = JSON.parse(line.substring(6));
              if (d.status) pullStatusText.textContent = d.status;
              if (d.total && d.completed) {
                const pct = Math.round((d.completed / d.total) * 100);
                pullProgressBar.style.width = `${pct}%`;
                pullPercentText.textContent = `${pct}%`;
              }
            } catch (e) {}
          }
        }
        read();
      });
    }
    read();
  }).catch(err => {
    pullStatusText.textContent = `Download error: ${err.message}`;
    btnPullModel.disabled = false;
    showToast(`Download failed: ${err.message}`, "error");
  });
}

// 7. Cloud Keys & Config
function setupCloudKeys() {
  document.querySelectorAll(".preset-pill").forEach((btn) => {
    btn.addEventListener("click", () => {
      cfgModelName.value = btn.getAttribute("data-name") || "";
      cfgProviderUrl.value = btn.getAttribute("data-url") || "";
      const mtype = btn.getAttribute("data-type") || "chat";
      const radio = document.querySelector(`input[name="model-type"][value="${mtype}"]`);
      if (radio) radio.checked = true;
      cfgApiKey.focus();
    });
  });

  btnToggleKeyVis.addEventListener("click", () => {
    if (cfgApiKey.type === "password") {
      cfgApiKey.type = "text";
    } else {
      cfgApiKey.type = "password";
    }
  });

  cloudForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const modelName = cfgModelName.value.trim();
    const providerUrl = cfgProviderUrl.value.trim();
    const apiKey = cfgApiKey.value.trim();
    const modelType = document.querySelector('input[name="model-type"]:checked')?.value || "chat";

    if (!modelName || !providerUrl || !apiKey) {
      showToast("Please fill in model name, provider URL, and API key", "warning");
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/api/cloud/save_model`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model_name: modelName,
          provider_url: providerUrl,
          api_key: apiKey,
          model_type: modelType,
        }),
      });
      const data = await res.json();
      if (data.success) {
        showToast(`Cloud model "${modelName}" configured & activated!`, "success", "Model Connected");
        cfgApiKey.value = "";
        loadCloudModels();
      } else {
        showToast(data.error || "Failed to save cloud model", "error");
      }
    } catch (err) {
      showToast(`Save error: ${err.message}`, "error");
    }
  });
}

async function loadCloudModels() {
  try {
    const res = await fetch(`${API_BASE}/api/cloud/config`);
    const data = await res.json();
    if (data.configured_models) {
      window.__configuredCloudModels = data.configured_models;
      renderConfiguredCloudModels(data.configured_models, data.active_model);
      populateModelSelectors(availableModels);
    }
  } catch (err) {
    console.error("Cloud config error:", err);
  }
}

function renderConfiguredCloudModels(models, activeModel) {
  configuredCountSpan.textContent = `${models.length} model${models.length === 1 ? '' : 's'}`;
  configuredModelsList.innerHTML = "";
  if (models.length === 0) {
    configuredModelsList.innerHTML = `<div class="text-muted">No external models configured yet. Use the form above to add one!</div>`;
    return;
  }

  models.forEach((m) => {
    const card = document.createElement("div");
    const isActive = m.model_name === activeModel;
    card.className = `model-card configured-model-card ${isActive ? 'active' : ''}`;
    card.innerHTML = `
      <div class="model-card-header">
        <span class="model-name">${escapeHtml(m.model_name)}</span>
        <span class="type-badge ${m.model_type}">${m.model_type.toUpperCase()}</span>
      </div>
      <div class="model-meta">
        <span>Endpoint: ${escapeHtml(m.provider_url)}</span>
      </div>
      <div class="model-actions">
        ${!isActive ? `<button class="btn btn-secondary btn-sm btn-activate-cloud-model" data-name="${escapeHtml(m.model_name)}">Activate</button>` : `<span class="active-badge">Active</span>`}
        <button class="btn btn-secondary btn-sm btn-delete-cloud-model" data-name="${escapeHtml(m.model_name)}" title="Delete Model">&times;</button>
      </div>
    `;

    const actBtn = card.querySelector(".btn-activate-cloud-model");
    if (actBtn) {
      actBtn.addEventListener("click", () => switchModel(m.model_name));
    }

    const delBtn = card.querySelector(".btn-delete-cloud-model");
    if (delBtn) {
      delBtn.addEventListener("click", async () => {
        if (!confirm(`Delete configuration for model "${m.model_name}"?`)) return;
        try {
          const res = await fetch(`${API_BASE}/api/cloud/delete_model`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ model_name: m.model_name }),
          });
          const d = await res.json();
          if (d.success) {
            showToast(`Model ${m.model_name} removed`, "info");
            loadCloudModels();
          }
        } catch (err) {
          showToast(`Delete failed: ${err.message}`, "error");
        }
      });
    }

    configuredModelsList.appendChild(card);
  });
}

// 8. Antigravity Autonomous Supervisor
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

// 9. Tools & Health
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

// Server Health Heartbeat
async function checkServerHealth() {
  try {
    const res = await fetch(`${API_BASE}/api/status`);
    const data = await res.json();
    if (data.status === "ok") {
      serverStatusDot.className = "status-dot online";
      serverStatusText.textContent = "Engine Ready";
    } else {
      serverStatusDot.className = "status-dot offline";
      serverStatusText.textContent = "Degraded";
    }
  } catch (err) {
    serverStatusDot.className = "status-dot offline";
    serverStatusText.textContent = "Offline";
  }
}

// Helpers
function escapeHtml(text) {
  if (!text) return "";
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function formatMarkdown(text) {
  if (!text) return "";
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
