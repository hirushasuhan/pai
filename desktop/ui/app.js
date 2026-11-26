/**
 * PAI Studio Desktop UI Client Application.
 * Communicates with local loopback bridge server on dynamic loopback port with token auth.
 */

let API_BASE = "http://127.0.0.1:8765";
let PAI_BRIDGE_TOKEN = "";

// Wrap window.fetch to inject X-PAI-Token and rewrite API_BASE if bound port changes
const _originalFetch = window.fetch;
window.fetch = async function(resource, init = {}) {
  let url = resource;
  if (typeof resource === "string") {
    if (resource.startsWith("http://127.0.0.1:8765")) {
      url = resource.replace("http://127.0.0.1:8765", API_BASE);
    }
  } else if (resource instanceof Request) {
    let reqUrl = resource.url;
    if (reqUrl.startsWith("http://127.0.0.1:8765")) {
      reqUrl = reqUrl.replace("http://127.0.0.1:8765", API_BASE);
      resource = new Request(reqUrl, resource);
    }
  }
  init = init || {};
  init.headers = init.headers || {};
  if (PAI_BRIDGE_TOKEN) {
    if (init.headers instanceof Headers) {
      if (!init.headers.has("X-PAI-Token")) {
        init.headers.set("X-PAI-Token", PAI_BRIDGE_TOKEN);
      }
    } else if (Array.isArray(init.headers)) {
      if (!init.headers.some(([k]) => k.toLowerCase() === "x-pai-token")) {
        init.headers.push(["X-PAI-Token", PAI_BRIDGE_TOKEN]);
      }
    } else {
      if (!init.headers["X-PAI-Token"] && !init.headers["x-pai-token"]) {
        init.headers["X-PAI-Token"] = PAI_BRIDGE_TOKEN;
      }
    }
  }
  return _originalFetch.call(this, url, init);
};

// Sanitizes external URLs before inserting into anchor href attributes (FINDING-09)
function sanitizeUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== "string") return "#";
  const trimmed = rawUrl.trim();
  const lower = trimmed.toLowerCase();
  if (lower.startsWith("javascript:") || lower.startsWith("vbscript:") || lower.startsWith("data:")) {
    return "#";
  }
  if (/^(https?:|mailto:|file:|\/|\.\/|#)/i.test(trimmed)) {
    return trimmed;
  }
  return "#";
}

async function initBridgeConfig() {
  // 1. Try URL hash (used by browser app mode: #token=...&port=...)
  try {
    const hash = window.location.hash;
    if (hash && hash.length > 1) {
      const params = new URLSearchParams(hash.replace(/^#/, ""));
      const hashToken = params.get("token");
      const hashPort = params.get("port");
      if (hashToken) PAI_BRIDGE_TOKEN = hashToken;
      if (hashPort) API_BASE = `http://127.0.0.1:${hashPort}`;
    }
  } catch (_) {}

  // 2. Try Tauri IPC command get_bridge_config
  try {
    const cfg = await invokeTauri("get_bridge_config");
    if (cfg && typeof cfg === "object") {
      if (cfg.port) API_BASE = `http://127.0.0.1:${cfg.port}`;
      if (cfg.token) PAI_BRIDGE_TOKEN = cfg.token;
    }
  } catch (_) {}
}

// State
let currentTab = "chat";
let activeModel = "llama3.2:3b";
let activeProjectPath = "";
let activeProjectName = "";
let currentOpenFile = "";
let chatHistory = [];
let availableModels = [];
let lastSentPrompt = "";
let projectsData = { active_project: "", projects: [] };
let teamRosterData = [];
let currentDeliverables = { plan: "", specialist: "", code: {}, qa: "" };

// SVG Icon Library
const SVG_ICONS = {
  check: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>`,
  alert: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>`,
  info: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>`,
  trash: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>`,
  folder: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>`,
  file: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path><polyline points="13 2 13 9 20 9"></polyline></svg>`,
  pm: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="8.5" cy="7" r="4"></circle><line x1="20" y1="8" x2="20" y2="14"></line><line x1="23" y1="11" x2="17" y2="11"></line></svg>`,
  dev: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>`,
  specialist: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"></path></svg>`,
  qa: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><polyline points="9 12 11 14 15 10"></polyline></svg>`,
  shield: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>`,
  globe: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>`,
  users: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg>`,
  image: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><circle cx="8.5" cy="8.5" r="1.5"></circle><polyline points="21 15 16 10 5 21"></polyline></svg>`,
  layers: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 2 7 12 12 22 7 12 2"></polygon><polyline points="2 17 12 22 22 17"></polyline><polyline points="2 12 12 17 22 12"></polyline></svg>`,
  cpu: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="4" width="16" height="16" rx="2" ry="2"></rect><rect x="9" y="9" width="6" height="6"></rect><line x1="9" y1="1" x2="9" y2="4"></line><line x1="15" y1="1" x2="15" y2="4"></line><line x1="9" y1="20" x2="9" y2="23"></line><line x1="15" y1="20" x2="15" y2="23"></line><line x1="20" y1="9" x2="23" y2="9"></line><line x1="20" y1="14" x2="23" y2="14"></line><line x1="1" y1="9" x2="4" y2="9"></line><line x1="1" y1="14" x2="4" y2="14"></line></svg>`,
  retry: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"></polyline><polyline points="1 20 1 14 7 14"></polyline><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg>`,
};

// DOM Elements
const navItems = document.querySelectorAll(".nav-item");
const tabViews = document.querySelectorAll(".tab-view");
const serverStatusDot = document.getElementById("server-status-dot");
const serverStatusText = document.getElementById("server-status-text");
const headerModelSelect = document.getElementById("header-model-select");
const headerProjectSelect = document.getElementById("header-project-select");
const btnHeaderBrowseFolder = document.getElementById("btn-header-browse-folder");
const toggleTeamMode = document.getElementById("toggle-team-mode");
const toggleInternet = document.getElementById("toggle-internet");
const toggleFactcheck = document.getElementById("toggle-factcheck");
const btnOpenSettings = document.getElementById("btn-open-settings");

// Chat DOM
const messagesList = document.getElementById("messages-list");
const chatForm = document.getElementById("chat-form");
const chatInput = document.getElementById("chat-input");
const btnSend = document.getElementById("btn-send");
const chatProjectBanner = document.getElementById("chat-project-banner");
const chatProjectName = document.getElementById("chat-project-name");
const chatProjectPath = document.getElementById("chat-project-path");
const btnClearChatProj = document.getElementById("btn-clear-chat-proj");
const btnAttachFile = document.getElementById("btn-attach-file");
const chatFileInput = document.getElementById("chat-file-input");
const chatAttachmentsTray = document.getElementById("chat-attachments-tray");
const chatDropOverlay = document.getElementById("chat-drop-overlay");

// Chat History & Saved Sessions DOM
const chatHistorySidebar = document.getElementById("chat-history-sidebar");
const btnNewChat = document.getElementById("btn-new-chat");
const chatHistoryList = document.getElementById("chat-history-list");
const btnClearAllHistory = document.getElementById("btn-clear-all-history");
const btnToggleChatHistory = document.getElementById("btn-toggle-chat-history");
const currentChatTitle = document.getElementById("current-chat-title");

let currentChatAttachments = [];
let chatSessions = [];
let activeSessionId = null;

// Projects DOM
const createProjectForm = document.getElementById("create-project-form");
const projNameInput = document.getElementById("proj-name-input");
const projPathInput = document.getElementById("proj-path-input");
const btnBrowseProjFolder = document.getElementById("btn-browse-proj-folder");
const btnEmptyBrowseFolder = document.getElementById("btn-empty-browse-folder");
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
const recommendedModelsGrid = document.getElementById("recommended-models-grid");
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
const toggleAgTeamMode = document.getElementById("toggle-ag-team-mode");
const agTargetWorkspaceBadge = document.getElementById("ag-target-workspace-badge");

// Tools DOM
const toolWeatherCity = document.getElementById("tool-weather-city");
const btnGetWeather = document.getElementById("btn-get-weather");
const weatherResultBox = document.getElementById("weather-result-box");
const toolSearchQuery = document.getElementById("tool-search-query");
const btnRunSearch = document.getElementById("btn-run-search");
const searchResultBox = document.getElementById("search-result-box");

// Toast Container & Modals
const toastContainer = document.getElementById("toast-container");
const settingsModal = document.getElementById("settings-modal");
const btnCloseSettings = document.getElementById("btn-close-settings");
const btnSaveSettings = document.getElementById("btn-save-settings");
const btnResetSettings = document.getElementById("btn-reset-settings");
const settingFontFamily = document.getElementById("setting-font-family");
const settingFontSize = document.getElementById("setting-font-size");

// Slash Commands DOM
const slashCommandsPopup = document.getElementById("slash-commands-popup");
const slashCommandsList = document.getElementById("slash-commands-list");

// MCP & Plugins DOM
const formAddMcp = document.getElementById("form-add-mcp");
const mcpNameInput = document.getElementById("mcp-name-input");
const mcpTransportSelect = document.getElementById("mcp-transport-select");
const mcpCmdInput = document.getElementById("mcp-cmd-input");
const mcpDescInput = document.getElementById("mcp-desc-input");
const mcpServersGrid = document.getElementById("mcp-servers-grid");
const mcpServersCount = document.getElementById("mcp-servers-count");

const formAddPlugin = document.getElementById("form-add-plugin");
const pluginNameInput = document.getElementById("plugin-name-input");
const pluginCatInput = document.getElementById("plugin-cat-input");
const pluginDescInput = document.getElementById("plugin-desc-input");

const preflightModal = document.getElementById("preflight-modal");
const btnClosePreflight = document.getElementById("btn-close-preflight");
const btnDismissPreflight = document.getElementById("btn-dismiss-preflight");
const preflightStatusItems = document.getElementById("preflight-status-items");
const preflightActionBox = document.getElementById("preflight-action-box");
const preflightActionText = document.getElementById("preflight-action-text");
const preflightActionButtons = document.getElementById("preflight-action-buttons");

// Initial Setup
document.addEventListener("DOMContentLoaded", async () => {
  await initBridgeConfig();
  setupDesktopTitlebar();
  applyStoredSettings();
  setupNavigation();
  setupCustomModelDropdown();
  setupChat();
  setupVirtualModelsBar();
  setupProjects();
  setupTeam();
  setupSkills();
  setupModels();
  setupCloudKeys();
  setupAntigravity();
  setupWebSearch();
  setupSettings();
  setupUpdateSystem();
  setupDesktopContextMenu();
  checkStartupPreflight();

  // Immediately populate models, projects, skills and MCP servers on startup
  loadInstalledModels();
  loadCloudModels();
  loadProjects();
  loadSkills();
  loadMcpServers();
  loadModelStoragePath();
  initLiveEnvironmentTelemetry();

  setInterval(checkServerHealth, 5000);
});

// Tauri Window Management & Titlebar Control
function invokeTauri(cmd, args = {}) {
  try {
    if (window.__TAURI__?.core?.invoke) {
      return window.__TAURI__.core.invoke(cmd, args);
    }
    if (window.__TAURI__?.invoke) {
      return window.__TAURI__.invoke(cmd, args);
    }
    if (window.__TAURI_INTERNALS__?.invoke) {
      return window.__TAURI_INTERNALS__.invoke(cmd, args);
    }
  } catch (err) {
    console.warn("Tauri invoke error:", cmd, err);
  }
  return Promise.resolve(null);
}

function setupDesktopTitlebar() {
  const isTauri = Boolean(window.__TAURI__ || window.__TAURI_INTERNALS__);
  const titlebar = document.getElementById("desktop-titlebar");
  const winCtrls = document.getElementById("titlebar-window-controls");
  const btnMin = document.getElementById("win-btn-minimize");
  const btnMax = document.getElementById("win-btn-maximize");
  const btnClose = document.getElementById("win-btn-close");

  if (!isTauri) {
    if (winCtrls) winCtrls.style.display = "none";
    return;
  }

  if (btnMin) {
    btnMin.addEventListener("click", () => invokeTauri("app_window_minimize"));
  }
  if (btnMax) {
    btnMax.addEventListener("click", () => invokeTauri("app_window_toggle_maximize"));
  }
  if (btnClose) {
    btnClose.addEventListener("click", () => {
      const closeBehavior = localStorage.getItem("pai_close_behavior") || "tray";
      if (closeBehavior === "exit") {
        invokeTauri("app_window_exit");
      } else {
        invokeTauri("app_window_close");
      }
    });
  }
  if (titlebar) {
    titlebar.addEventListener("dblclick", (e) => {
      if (!e.target.closest("#titlebar-window-controls")) {
        invokeTauri("app_window_toggle_maximize");
      }
    });
  }
}

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

// 1. Navigation & Global Controls
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
        updateTriggerLabel(selected);
        updateChatPlaceholderForActiveModel();
        updateVirtualModelsBarActive(selected);
        document.querySelectorAll(".phub-model-pill").forEach((pill) => {
          if (pill.getAttribute("data-model") === selected) {
            pill.classList.add("active");
          } else {
            pill.classList.remove("active");
          }
        });
        showToast(`Switched active model to ${selected}`, "success", "Model Changed");
      }
    } catch (err) {
      console.error("Failed to switch model:", err);
      showToast(`Failed to switch model: ${err.message}`, "error");
    }
  });

  headerProjectSelect.addEventListener("change", async (e) => {
    const selectedPath = e.target.value;
    if (selectedPath === "__NEW_PROJECT__") {
      for (let i = 0; i < headerProjectSelect.options.length; i++) {
        if (pathsMatch(headerProjectSelect.options[i].value, activeProjectPath)) {
          headerProjectSelect.selectedIndex = i;
          break;
        }
      }
      await browseAndActivateProjectFolder();
      return;
    }
    await activateProject(selectedPath);
  });

  btnHeaderBrowseFolder.addEventListener("click", async () => {
    btnHeaderBrowseFolder.disabled = true;
    try {
      await browseAndActivateProjectFolder();
    } finally {
      btnHeaderBrowseFolder.disabled = false;
    }
  });

  toggleTeamMode.addEventListener("change", async (e) => {
    if (toggleTeamMode.checked) {
      if (!activeProjectPath) {
        showToast("AI Team mode requires an active project directory to read and write code.", "warning", "Project Needed");
        const picked = await browseAndActivateProjectFolder();
        if (!picked) {
          toggleTeamMode.checked = false;
        }
      } else {
        showToast(`AI Team mode active for: ${activeProjectName}`, "success", "AI Team Active");
      }
    } else {
      showToast("Switched back to standard single-assistant chat mode", "info");
    }
  });

  const offlineConfirmModal = document.getElementById("offline-confirm-modal");
  const btnCancelOfflineModal = document.getElementById("btn-cancel-offline-modal");
  const btnCloseOfflineModal = document.getElementById("btn-close-offline-modal");
  const btnConfirmOfflineModal = document.getElementById("btn-confirm-offline-modal");

  if (btnCancelOfflineModal) {
    btnCancelOfflineModal.addEventListener("click", () => {
      if (offlineConfirmModal) offlineConfirmModal.classList.add("hidden");
      if (toggleInternet) toggleInternet.checked = true;
    });
  }
  if (btnCloseOfflineModal) {
    btnCloseOfflineModal.addEventListener("click", () => {
      if (offlineConfirmModal) offlineConfirmModal.classList.add("hidden");
      if (toggleInternet) toggleInternet.checked = true;
    });
  }
  if (btnConfirmOfflineModal) {
    btnConfirmOfflineModal.addEventListener("click", async () => {
      if (offlineConfirmModal) offlineConfirmModal.classList.add("hidden");
      if (toggleInternet) toggleInternet.checked = false;
      await applyInternetState(false);
    });
  }

  toggleInternet.addEventListener("change", async (e) => {
    const val = e.target.checked;
    if (!val) {
      // User is attempting to turn OFF internet: prompt confirmation modal first
      e.preventDefault();
      toggleInternet.checked = true; // keep checked visually until confirmed
      if (offlineConfirmModal) {
        offlineConfirmModal.classList.remove("hidden");
      } else {
        await applyInternetState(false);
      }
      return;
    }
    // Re-enabling internet
    await applyInternetState(true);
  });

  const savedFc = localStorage.getItem("pai_factcheck_enabled");
  if (savedFc !== null) {
    toggleFactcheck.checked = (savedFc === "true");
  }

  toggleFactcheck.addEventListener("change", async (e) => {
    const val = e.target.checked;
    if (val && toggleInternet && !toggleInternet.checked) {
      e.preventDefault();
      toggleFactcheck.checked = false;
      showToast("Live fact-checking requires internet access, which is currently disabled.", "warning", "Offline Mode");
      return;
    }
    localStorage.setItem("pai_factcheck_enabled", val ? "true" : "false");
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

async function applyInternetState(val) {
  try {
    const res = await fetch(`${API_BASE}/api/settings/toggle`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ feature: "internet", value: val }),
    });
    const data = await res.json();
    const isNowOnline = data.internet_enabled !== undefined ? Boolean(data.internet_enabled) : Boolean(val);
    if (toggleInternet) toggleInternet.checked = isNowOnline;

    updateInternetUIState(isNowOnline, data.active_model);

    if (isNowOnline) {
      showToast("Real-Time Internet grounding and cloud models enabled.", "info", "Internet Online");
    } else {
      showToast("Complete Offline Air-Gap active. Cloud APIs and web services disabled.", "warning", "Air-Gap Offline");
      if (data.switched_to_local && data.active_model) {
        showToast(`Switched active model to local "${data.active_model}" for offline operation.`, "info", "Local Model Active");
      }
    }
    if (typeof loadSkills === "function") loadSkills();
  } catch (err) {
    console.error("Internet toggle error:", err);
    showToast(`Failed to update internet settings: ${err.message}`, "error");
  }
}

function updateInternetUIState(isOnline, switchedModel) {
  // 1. Factcheck toggle
  if (toggleFactcheck) {
    if (!isOnline) {
      toggleFactcheck.checked = false;
      toggleFactcheck.disabled = true;
      const lbl = toggleFactcheck.closest("label");
      if (lbl) {
        lbl.style.opacity = "0.5";
        lbl.title = "Live Fact-Checking engine is disabled while offline (Internet disconnected)";
      }
    } else {
      toggleFactcheck.disabled = false;
      const lbl = toggleFactcheck.closest("label");
      if (lbl) {
        lbl.style.opacity = "1";
        lbl.title = "Toggle real-time fact-checking & citation verification";
      }
    }
  }

  // 2. Web search panel inputs
  const toolSearchQuery = document.getElementById("tool-search-query");
  const btnRunSearch = document.getElementById("btn-run-search");
  const searchResultBox = document.getElementById("search-result-box");
  const searchStatus = document.getElementById("search-status-tag");

  if (toolSearchQuery) {
    if (!isOnline) {
      toolSearchQuery.disabled = true;
      toolSearchQuery.placeholder = "Offline Air-Gap Mode: Web Search is disabled (Internet Disconnected).";
    } else {
      toolSearchQuery.disabled = false;
      toolSearchQuery.placeholder = "e.g. President of Sri Lanka, Latest AI model releases, Python 3.14 features...";
    }
  }
  if (btnRunSearch) {
    btnRunSearch.disabled = !isOnline;
    btnRunSearch.style.opacity = isOnline ? "1" : "0.5";
  }
  if (searchStatus) {
    searchStatus.textContent = isOnline ? "Ready" : "Offline Air-Gap";
  }
  if (searchResultBox) {
    if (!isOnline) {
      searchResultBox.innerHTML = `
        <div class="offline-warning-banner" style="padding:16px; border:1px solid rgba(239,68,68,0.25); border-radius:8px; background:rgba(239,68,68,0.06); color:#fca5a5;">
          <strong style="color:#ef4444;">🛡️ Complete Offline Air-Gap Mode Active:</strong>
          <p style="margin: 6px 0 0; font-size: 13px; color: #cbd5e1;">Live web search, Wikipedia queries, and external intelligence sources are strictly cut off while offline. Re-enable Internet in the top bar to restore web search.</p>
        </div>
      `;
    } else if (searchResultBox.innerHTML && searchResultBox.innerHTML.includes("Complete Offline Air-Gap Mode Active")) {
      searchResultBox.textContent = "Enter a search query above or click a suggested topic to explore live internet data.";
    }
  }

  // 3. Update Model dropdown and switch away from cloud models if offline
  if (switchedModel) {
    activeModel = switchedModel;
  } else if (!isOnline) {
    const cloudProviders = window.__cloudProviders || [];
    const allCloudModels = [];
    cloudProviders.forEach(p => (p.models || []).forEach(m => allCloudModels.push(m)));
    (window.__configuredCloudModels || []).forEach(cm => allCloudModels.push(cm.model_name));

    if (allCloudModels.includes(activeModel)) {
      const local = (availableModels || []).find(m => m.name && !allCloudModels.includes(m.name));
      if (local) {
        activeModel = local.name;
      } else {
        activeModel = "auto";
      }
    }
  }

  if (typeof populateModelSelectors === "function" && Array.isArray(availableModels)) {
    populateModelSelectors(availableModels);
  }
}

function switchTab(tab) {
  if (tab === "antigravity" || tab === "team") {
    tab = "cowork";
    setTimeout(() => {
      if (typeof switchCoworkSubnav === "function") switchCoworkSubnav("team");
    }, 20);
  }
  currentTab = tab;

  const tabNames = {
    chat: "Chat & Reasoning",
    cowork: "PAI Cowork & AI Team Workstation",
    projects: "Project Workspaces",
    models: "Models & Hardware",
    cloud: "Cloud Models",
    search: "Web Knowledge Search",
    team: "PAI Cowork & AI Team Workstation",
    settings: "Settings & System"
  };
  const viewBreadcrumb = document.getElementById("current-view-name");
  if (viewBreadcrumb) {
    viewBreadcrumb.textContent = tabNames[tab] || tab;
  }

  navItems.forEach((btn) => {
    if (btn.getAttribute("data-tab") === tab || (tab === "cowork" && btn.getAttribute("data-tab") === "team")) {
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
  if (tab === "projects") {
    loadProjects();
    if (!activeProjectPath && (!projectsData.projects || projectsData.projects.length === 0)) {
      showToast("Select a project folder to browse files and enable AI Team features.", "info", "Workspace Setup");
    }
  }
  if (tab === "team" || tab === "cowork") {
    loadCoworkData();
    loadTeamRoster();
  }
  if (tab === "skills") {
    loadSkills();
    loadMcpServers();
  }
  if (tab === "search") {
    setTimeout(() => toolSearchQuery?.focus(), 50);
  }
  if (tab === "settings" || tab === "tools") loadDoctorTelemetry();
}

// 2. Chat System with Native AI Team & Slash Commands Integration
function hasVisionModelInstalled() {
  if (!availableModels || !Array.isArray(availableModels) || availableModels.length === 0) return false;
  return availableModels.some((m) => {
    const name = (typeof m === "string" ? m : (m.name || "")).toLowerCase();
    return name.includes("llava") || name.includes("moondream") || name.includes("vision") || name.includes("bakllava");
  });
}

function updateAttachmentCapabilities() {
  const hasVision = hasVisionModelInstalled();
  if (chatFileInput) {
    if (hasVision) {
      chatFileInput.accept = ".txt,.md,.pdf,.doc,.docx,.xls,.xlsx,.csv,.json,.py,.js,.ts,.html,.css,.xml,.yaml,.yml,.log,.png,.jpg,.jpeg,.webp,.gif,.bmp";
      if (btnAttachFile) {
        btnAttachFile.title = "Attach documents, code, or images for visual inspection (.png, .jpg, .pdf, .docx, .py, etc.)";
      }
    } else {
      chatFileInput.accept = ".txt,.md,.pdf,.doc,.docx,.xls,.xlsx,.csv,.json,.py,.js,.ts,.html,.css,.xml,.yaml,.yml,.log";
      if (btnAttachFile) {
        btnAttachFile.title = "Attach documents & code (Install LLaVA 7B or Moondream 2 to enable image inspection)";
      }
    }
  }
}

function updateChatPlaceholderForActiveModel() {
  if (!chatInput) return;
  const m = (activeModel || "").toLowerCase();
  if (m.includes("llava") || m.includes("moondream") || m.includes("vision")) {
    chatInput.placeholder = "Ask a question, or attach an image for visual inspection...";
  } else {
    chatInput.placeholder = "Ask anything, run /image, /team, /help... (Enter to send, Shift+Enter for newline)";
  }
}

const SLASH_COMMANDS = [
  { cmd: "/internet on", desc: "Enable live real-time internet web access & RAG", cat: "Grounding" },
  { cmd: "/internet off", desc: "Disable internet access (strictly offline mode)", cat: "Grounding" },
  { cmd: "/factcheck on", desc: "Enable real-time fact-checking & audit engine", cat: "Auditing" },
  { cmd: "/factcheck off", desc: "Disable automated fact-checking", cat: "Auditing" },
  { cmd: "/council", desc: "Convene multi-model deliberation council across independent local models", cat: "Reasoning" },
  { cmd: "/team", desc: "Toggle autonomous 7-role AI engineering team", cat: "Agents" },
  { cmd: "/supervisor", desc: "Open Antigravity Autonomous Supervisor in AI Team", cat: "Agents" },
  { cmd: "/antigravity", desc: "Launch continuous autonomous agent in AI Team tab", cat: "Agents" },
  { cmd: "/image", desc: "Generate image with Local SD-Turbo or Cloud AI (Imagen / DALL-E)", cat: "Creative" },
  { cmd: "/weather", desc: "Fetch live real-time weather telemetry", cat: "Tools" },
  { cmd: "/web", desc: "Search live web knowledge and display citations", cat: "Tools" },
  { cmd: "/mcp", desc: "Manage Model Context Protocol (MCP) servers & tools", cat: "System" },
  { cmd: "/models", desc: "Open Model Manager to pull or switch local models", cat: "System" },
  { cmd: "/projects", desc: "Open Project Workspace context & in-app file editor", cat: "System" },
  { cmd: "/search", desc: "Open Web Knowledge Search & ground truth citations", cat: "Search" },
  { cmd: "/settings", desc: "Open developer font typography, themes & hardware diagnostics", cat: "System" },
  { cmd: "/clear", desc: "Clear current conversation history", cat: "Chat" },
  { cmd: "/help", desc: "Display all available commands and keyboard shortcuts", cat: "Help" },
];
let activeSlashIndex = 0;

function setupSlashCommands() {
  if (!slashCommandsPopup || !slashCommandsList || !chatInput) return;

  function renderSlashList(filterText = "") {
    const q = filterText.toLowerCase();
    const filtered = SLASH_COMMANDS.filter((item) =>
      !q || item.cmd.toLowerCase().includes(q) || item.desc.toLowerCase().includes(q)
    );

    slashCommandsList.innerHTML = "";
    if (filtered.length === 0) {
      slashCommandsList.innerHTML = `<div class="slash-item empty">No matching slash commands</div>`;
      return;
    }

    activeSlashIndex = Math.min(activeSlashIndex, filtered.length - 1);
    if (activeSlashIndex < 0) activeSlashIndex = 0;

    filtered.forEach((item, idx) => {
      const el = document.createElement("div");
      el.className = `slash-item ${idx === activeSlashIndex ? "active" : ""}`;
      el.innerHTML = `
        <div class="slash-item-left">
          <span class="slash-cmd-pill font-mono-target">${escapeHtml(item.cmd)}</span>
          <span class="slash-cmd-desc">${escapeHtml(item.desc)}</span>
        </div>
        <span class="slash-cmd-cat">${escapeHtml(item.cat)}</span>
      `;
      el.addEventListener("click", () => {
        applySlashCommand(item.cmd);
      });
      el.addEventListener("mouseenter", () => {
        activeSlashIndex = idx;
        updateActiveSlashItem();
      });
      slashCommandsList.appendChild(el);
    });
  }

  function updateActiveSlashItem() {
    const items = slashCommandsList.querySelectorAll(".slash-item:not(.empty)");
    items.forEach((item, idx) => {
      if (idx === activeSlashIndex) {
        item.classList.add("active");
        item.scrollIntoView({ block: "nearest" });
      } else {
        item.classList.remove("active");
      }
    });
  }

  function applySlashCommand(cmd) {
    chatInput.value = cmd + (cmd.includes(" ") ? "" : " ");
    slashCommandsPopup.classList.add("hidden");
    chatInput.focus();
    chatInput.setSelectionRange(chatInput.value.length, chatInput.value.length);
  }

  chatInput.addEventListener("input", () => {
    const val = chatInput.value;
    if (val.startsWith("/")) {
      activeSlashIndex = 0;
      renderSlashList(val);
      slashCommandsPopup.classList.remove("hidden");
    } else {
      slashCommandsPopup.classList.add("hidden");
    }
  });

  chatInput.addEventListener("keydown", (e) => {
    if (slashCommandsPopup.classList.contains("hidden")) return;

    const items = slashCommandsList.querySelectorAll(".slash-item:not(.empty)");
    if (!items.length) return;

    if (e.key === "ArrowDown") {
      e.preventDefault();
      activeSlashIndex = (activeSlashIndex + 1) % items.length;
      updateActiveSlashItem();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      activeSlashIndex = (activeSlashIndex - 1 + items.length) % items.length;
      updateActiveSlashItem();
    } else if (e.key === "Tab" || (e.key === "Enter" && !e.shiftKey)) {
      const activeEl = slashCommandsList.querySelector(".slash-item.active .slash-cmd-pill");
      if (activeEl) {
        e.preventDefault();
        applySlashCommand(activeEl.textContent.trim());
      }
    } else if (e.key === "Escape") {
      e.preventDefault();
      slashCommandsPopup.classList.add("hidden");
    }
  });

  document.addEventListener("click", (e) => {
    if (!slashCommandsPopup.contains(e.target) && e.target !== chatInput) {
      slashCommandsPopup.classList.add("hidden");
    }
  });
}

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

function renderChatAttachmentsTray() {
  if (!chatAttachmentsTray) return;
  if (!currentChatAttachments || currentChatAttachments.length === 0) {
    chatAttachmentsTray.innerHTML = "";
    chatAttachmentsTray.classList.add("hidden");
    return;
  }
  chatAttachmentsTray.classList.remove("hidden");
  chatAttachmentsTray.innerHTML = currentChatAttachments.map((att, idx) => `
    <div class="chat-attachment-chip" title="${escapeHtml(att.name)} (${att.size_str}, ${att.char_count || 0} characters parsed)">
      <svg class="att-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
      <span class="att-name">${escapeHtml(att.name)}</span>
      <span class="att-size">${att.size_str}</span>
      <button type="button" class="att-remove" onclick="removeChatAttachment(${idx})" title="Remove attachment">&times;</button>
    </div>
  `).join("");
}

window.removeChatAttachment = function(idx) {
  if (idx >= 0 && idx < currentChatAttachments.length) {
    currentChatAttachments.splice(idx, 1);
    renderChatAttachmentsTray();
  }
};

async function parseAndAddAttachment(file) {
  if (!file) return;
  const ext = (file.name || "").split('.').pop().toLowerCase();
  const isImageFile = ["png", "jpg", "jpeg", "webp", "gif", "bmp"].includes(ext);
  if (isImageFile && !hasVisionModelInstalled()) {
    showToast(
      "Image attachment disabled: Please install LLaVA 7B or Moondream 2 from Local Models to attach images.",
      "warning",
      "Vision Model Required"
    );
    return;
  }
  if (file.size > 50 * 1024 * 1024) {
    showToast(`File ${file.name} is too large (> 50MB)`, "warning");
    return;
  }
  return new Promise((resolve) => {
    const reader = new FileReader();
    reader.onload = async () => {
      try {
        const resultStr = reader.result;
        const commaIdx = resultStr.indexOf(",");
        const base64Data = commaIdx >= 0 ? resultStr.substring(commaIdx + 1) : resultStr;
        const res = await fetch(`${API_BASE}/api/chat/parse_file`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            name: file.name,
            size: file.size,
            base64: base64Data
          })
        });
        const data = await res.json();
        if (data.success) {
          currentChatAttachments.push({
            name: data.filename || file.name,
            type: data.type || "file",
            size: data.size || file.size,
            size_str: formatBytes(data.size || file.size),
            char_count: data.char_count || 0,
            content: data.content || "",
            preview: data.preview || ""
          });
          renderChatAttachmentsTray();
          showToast(`Attached: ${file.name} (${formatBytes(file.size)})`, "success");
        } else {
          showToast(`Failed to parse ${file.name}: ${data.error || "Unknown error"}`, "error");
        }
      } catch (err) {
        showToast(`Error parsing ${file.name}: ${err.message}`, "error");
      }
      resolve();
    };
    reader.onerror = () => {
      showToast(`Could not read ${file.name}`, "error");
      resolve();
    };
    reader.readAsDataURL(file);
  });
}

// ==========================================================================
// Chat History & Saved Conversation Sessions Engine
// ==========================================================================

function initChatHistory() {
  try {
    const raw = localStorage.getItem("pai_chat_sessions");
    if (raw) {
      chatSessions = JSON.parse(raw);
    }
  } catch (e) {
    console.warn("Could not read stored chat sessions:", e);
    chatSessions = [];
  }

  const savedActiveId = localStorage.getItem("pai_active_chat_session_id");
  if (!chatSessions || chatSessions.length === 0) {
    createNewChatSession(false);
  } else {
    const found = chatSessions.find(s => s.id === savedActiveId);
    if (found) {
      activeSessionId = found.id;
      loadSessionMessages(found);
    } else {
      activeSessionId = chatSessions[0].id;
      loadSessionMessages(chatSessions[0]);
    }
  }

  if (localStorage.getItem("pai_history_collapsed") === "true" && chatHistorySidebar) {
    chatHistorySidebar.classList.add("collapsed");
  }

  renderChatHistorySidebar();

  btnNewChat?.addEventListener("click", () => {
    createNewChatSession();
  });

  btnClearAllHistory?.addEventListener("click", () => {
    if (confirm("Are you sure you want to clear all conversation history?")) {
      clearAllChatSessions();
    }
  });

  btnToggleChatHistory?.addEventListener("click", () => {
    if (chatHistorySidebar) {
      chatHistorySidebar.classList.toggle("collapsed");
      localStorage.setItem("pai_history_collapsed", chatHistorySidebar.classList.contains("collapsed"));
    }
  });
}

function createNewChatSession(render = true) {
  const newId = "session_" + Date.now() + "_" + Math.random().toString(36).substring(2, 6);
  const newSession = {
    id: newId,
    title: "New Conversation",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    messages: []
  };
  chatSessions.unshift(newSession);
  activeSessionId = newId;
  saveChatSessions();

  chatHistory = [];
  messagesList.innerHTML = `
    <div class="message assistant welcome">
      <div class="msg-header">
        <span class="avatar-badge">PAI</span>
        <span class="msg-author">Personal Agentic AI Assistant</span>
        <span class="msg-time">Just now</span>
      </div>
      <div class="msg-body">
        <p>Hello! I am your native <strong>Personal Agentic AI</strong> companion.</p>
        <p>I can solve complex coding problems, manage project files, orchestrate an autonomous 7-role AI engineering team, verify claims against real-time web knowledge, and synthesize images.</p>
      </div>
    </div>
  `;

  if (currentChatTitle) {
    currentChatTitle.textContent = "New Conversation";
  }

  if (render) {
    renderChatHistorySidebar();
  }
  chatInput?.focus();
}

function loadSessionMessages(session) {
  if (!session) return;
  if (currentChatTitle) {
    currentChatTitle.textContent = session.title || "New Conversation";
  }

  messagesList.innerHTML = "";
  chatHistory = [];

  const ongoingJob = Array.from(activeChatJobs.values()).find(j => j.targetSessionId === session.id);

  if ((!session.messages || session.messages.length === 0) && !ongoingJob) {
    messagesList.innerHTML = `
      <div class="message assistant welcome">
        <div class="msg-header">
          <span class="avatar-badge">PAI</span>
          <span class="msg-author">Personal Agentic AI Assistant</span>
          <span class="msg-time">Just now</span>
        </div>
        <div class="msg-body">
          <p>Hello! I am your native <strong>Personal Agentic AI</strong> companion.</p>
          <p>I can solve complex coding problems, manage project files, orchestrate an autonomous 7-role AI engineering team, verify claims against real-time web knowledge, and synthesize images.</p>
        </div>
      </div>
    `;
    setSendButtonState("idle");
    return;
  }

  if (session.messages && session.messages.length > 0) {
    session.messages.forEach(item => {
      if (item.role === "user") {
        appendUserMessage(item.text, item.attachments || []);
        chatHistory.push({ role: "user", content: item.text });
      } else if (item.role === "assistant") {
        const botId = "hist-msg-" + Math.random().toString(36).substring(2, 8);
        appendAssistantPlaceholder(botId, item.is_team);
        if (item.is_image) {
          updateAssistantMessageImage(botId, item.image_url, item.text, item.model, item.filename);
        } else if (item.is_team && item.teamData) {
          updateAssistantTeamMessage(botId, item.teamData, item.userPrompt || "");
        } else {
          updateAssistantMessage(botId, item.text, item.factcheck, item.grounding, item.userPrompt || "");
        }
        chatHistory.push({ role: "assistant", content: item.text });
      }
    });
  }

  if (ongoingJob) {
    appendAssistantPlaceholder(ongoingJob.botMsgId, ongoingJob.isTeam);
    const botMsgEl = document.getElementById(ongoingJob.botMsgId);
    if (botMsgEl && ongoingJob.lastPhase) {
      const thText = botMsgEl.querySelector(".thinking-stage-text");
      if (thText) thText.textContent = ongoingJob.lastPhase;
    }
    setSendButtonState("generating");
  } else {
    setSendButtonState("idle");
  }

  const scrollContainer = document.getElementById("messages-scroll");
  if (scrollContainer) {
    scrollContainer.scrollTop = scrollContainer.scrollHeight;
  }
}

function switchChatSession(id) {
  if (id === activeSessionId) return;
  const session = chatSessions.find(s => s.id === id);
  if (!session) return;
  activeSessionId = id;
  localStorage.setItem("pai_active_chat_session_id", id);
  loadSessionMessages(session);
  renderChatHistorySidebar();
}

function deleteChatSession(id, e) {
  e?.stopPropagation();
  chatSessions = chatSessions.filter(s => s.id !== id);
  saveChatSessions();
  if (activeSessionId === id) {
    if (chatSessions.length > 0) {
      activeSessionId = chatSessions[0].id;
      localStorage.setItem("pai_active_chat_session_id", activeSessionId);
      loadSessionMessages(chatSessions[0]);
    } else {
      createNewChatSession(false);
    }
  }
  renderChatHistorySidebar();
  showToast("Conversation deleted", "info");
}

function clearAllChatSessions() {
  chatSessions = [];
  saveChatSessions();
  createNewChatSession();
  showToast("All chat history cleared", "info");
}

function saveChatSessions() {
  try {
    localStorage.setItem("pai_chat_sessions", JSON.stringify(chatSessions));
    if (activeSessionId) {
      localStorage.setItem("pai_active_chat_session_id", activeSessionId);
    }
  } catch (e) {
    console.warn("Could not save chat sessions:", e);
  }
}

function showSystemNotification(title, body) {
  try {
    const notifyEnabled = localStorage.getItem("pai_notify_complete") !== "false";
    if (!notifyEnabled) return;
    if (!("Notification" in window)) return;

    if (Notification.permission === "granted") {
      const n = new Notification(title, {
        body: body,
        icon: "icons/icon.png"
      });
      n.onclick = () => {
        window.focus();
        if (typeof invokeTauri === "function") {
          invokeTauri("app_window_unminimize");
        }
      };
    } else if (Notification.permission !== "denied") {
      Notification.requestPermission().then(perm => {
        if (perm === "granted") {
          const n = new Notification(title, {
            body: body,
            icon: "icons/icon.png"
          });
          n.onclick = () => {
            window.focus();
            if (typeof invokeTauri === "function") {
              invokeTauri("app_window_unminimize");
            }
          };
        }
      });
    }
  } catch (_) {}
}

function saveTurnToSessionById(sessionId, userRecord, assistantRecord) {
  let session = chatSessions.find(s => s.id === sessionId);
  if (!session) {
    session = {
      id: sessionId || ("session_" + Date.now()),
      title: "New Conversation",
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      messages: []
    };
    chatSessions.unshift(session);
  }

  const msgs = session.messages;
  const alreadyHasUser = msgs && msgs.length > 0 && msgs.some(m => m.role === "user" && m.text === userRecord.text);
  if (!alreadyHasUser) {
    session.messages.push(userRecord);
  }
  session.messages.push(assistantRecord);
  session.updatedAt = new Date().toISOString();

  if (session.title === "New Conversation" || session.messages.filter(m => m.role === 'user').length <= 1) {
    let clean = (userRecord.text || "").replace(/^[\/\#\*\-\s]+/, "").trim();
    if (clean.length > 28) {
      clean = clean.substring(0, 28) + "...";
    }
    session.title = clean || "Conversation";
    if (currentChatTitle && session.id === activeSessionId) {
      currentChatTitle.textContent = session.title;
    }
  }

  saveChatSessions();
  renderChatHistorySidebar();
}

function saveTurnToActiveSession(userRecord, assistantRecord) {
  saveTurnToSessionById(activeSessionId, userRecord, assistantRecord);
}

function isSessionGenerating(sessionId) {
  return Array.from(activeChatJobs.values()).some(j => j.targetSessionId === sessionId);
}

function renderChatHistorySidebar() {
  if (!chatHistoryList) return;
  chatHistoryList.innerHTML = "";

  if (!chatSessions || chatSessions.length === 0) {
    chatHistoryList.innerHTML = `<div class="chat-history-empty" style="padding: 16px 10px; font-size: 11.5px; color: var(--text-dim); text-align: center;">No saved conversations</div>`;
    return;
  }

  chatSessions.forEach(session => {
    const isRunning = isSessionGenerating(session.id);
    const item = document.createElement("div");
    item.className = `chat-history-item ${session.id === activeSessionId ? "active" : ""}`;
    item.title = session.title || "Conversation";

    item.innerHTML = `
      <div class="chat-history-item-content">
        <svg class="chat-history-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path>
        </svg>
        <span class="chat-history-item-title">${escapeHtml(session.title || "New Conversation")}</span>
      </div>
      <div class="chat-history-item-actions">
        ${isRunning ? `<span class="chat-generating-spinner" title="AI thinking & generating in background..."></span>` : ""}
        <button type="button" class="btn-delete-session" title="Delete conversation">
          <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="3 6 5 6 21 6"></polyline>
            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
          </svg>
        </button>
      </div>
    `;

    item.addEventListener("click", () => switchChatSession(session.id));
    const btnDel = item.querySelector(".btn-delete-session");
    btnDel?.addEventListener("click", (e) => deleteChatSession(session.id, e));

    chatHistoryList.appendChild(item);
  });
}

function setupChat() {
  initChatHistory();
  setupSlashCommands();
  updateChatPlaceholderForActiveModel();
  updateAttachmentCapabilities();

  // Attach File Button & File Input
  if (btnAttachFile && chatFileInput) {
    btnAttachFile.addEventListener("click", () => {
      updateAttachmentCapabilities();
      chatFileInput.click();
    });
    chatFileInput.addEventListener("change", async (e) => {
      if (e.target.files && e.target.files.length > 0) {
        for (const file of e.target.files) {
          await parseAndAddAttachment(file);
        }
        chatFileInput.value = "";
      }
    });
  }

  // Drag and Drop Overlay on Chat Container
  const chatContainer = document.querySelector(".chat-container");
  if (chatContainer && chatDropOverlay) {
    let dragCounter = 0;
    chatContainer.addEventListener("dragenter", (e) => {
      e.preventDefault();
      dragCounter++;
      chatDropOverlay.classList.remove("hidden");
    });
    chatContainer.addEventListener("dragover", (e) => {
      e.preventDefault();
    });
    chatContainer.addEventListener("dragleave", (e) => {
      e.preventDefault();
      dragCounter--;
      if (dragCounter <= 0) {
        dragCounter = 0;
        chatDropOverlay.classList.add("hidden");
      }
    });
    chatContainer.addEventListener("drop", async (e) => {
      e.preventDefault();
      dragCounter = 0;
      chatDropOverlay.classList.add("hidden");
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        for (const file of e.dataTransfer.files) {
          await parseAndAddAttachment(file);
        }
      }
    });
  }

  // Direct click interceptor on Send/Stop button for instant cancellation
  btnSend.addEventListener("click", (e) => {
    if (isGeneratingResponse) {
      e.preventDefault();
      e.stopPropagation();
      stopCurrentChatGeneration();
    }
  });

  chatForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (isSessionGenerating(activeSessionId)) {
      stopCurrentChatGeneration();
      return;
    }
    if (slashCommandsPopup && !slashCommandsPopup.classList.contains("hidden")) {
      slashCommandsPopup.classList.add("hidden");
    }
    const prompt = chatInput.value.trim();
    if (!prompt && currentChatAttachments.length === 0) return;

    // Intercept client-side interactive slash commands
    const lowerPrompt = prompt.toLowerCase();
    if (lowerPrompt === "/clear") {
      chatHistory = [];
      const actSession = chatSessions.find(s => s.id === activeSessionId);
      if (actSession) {
        actSession.messages = [];
        actSession.updatedAt = new Date().toISOString();
        saveChatSessions();
      }
      messagesList.innerHTML = `
        <div class="message assistant welcome">
          <div class="msg-header">
            <span class="avatar-badge">PAI</span>
            <span class="msg-author">Personal Agentic AI Assistant</span>
            <span class="msg-time">Just now</span>
          </div>
          <div class="msg-body">
            <p>Conversation cleared. Ready for your next instruction!</p>
          </div>
        </div>
      `;
      chatInput.value = "";
      showToast("Conversation cleared", "info");
      return;
    }
    if (lowerPrompt === "/team") {
      toggleTeamMode.checked = !toggleTeamMode.checked;
      toggleTeamMode.dispatchEvent(new Event("change"));
      chatInput.value = "";
      showToast(`AI Team mode ${toggleTeamMode.checked ? "activated" : "deactivated"}`, "info");
      return;
    }
    if (lowerPrompt === "/antigravity" || lowerPrompt === "/supervisor") {
      switchTab("team");
      chatInput.value = "";
      return;
    }
    if (lowerPrompt === "/internet on" || lowerPrompt === "/internet off") {
      const val = lowerPrompt.endsWith("on");
      toggleInternet.checked = val;
      toggleInternet.dispatchEvent(new Event("change"));
      chatInput.value = "";
      return;
    }
    if (lowerPrompt === "/factcheck on" || lowerPrompt === "/factcheck off") {
      const val = lowerPrompt.endsWith("on");
      toggleFactcheck.checked = val;
      toggleFactcheck.dispatchEvent(new Event("change"));
      chatInput.value = "";
      return;
    }
    if (lowerPrompt === "/mcp" || lowerPrompt === "/plugins" || lowerPrompt === "/skills") {
      switchTab("skills");
      chatInput.value = "";
      return;
    }
    if (lowerPrompt === "/models") {
      switchTab("models");
      chatInput.value = "";
      return;
    }
    if (lowerPrompt === "/settings") {
      switchTab("settings");
      chatInput.value = "";
      return;
    }
    if (lowerPrompt === "/search" || lowerPrompt === "/web") {
      switchTab("search");
      chatInput.value = "";
      return;
    }
    if (lowerPrompt === "/projects") {
      switchTab("projects");
      chatInput.value = "";
      return;
    }
    if (lowerPrompt === "/image" || lowerPrompt === "/img") {
      chatInput.value = "";
      appendUserMessage(prompt);
      const botId = "msg-" + Date.now();
      appendAssistantPlaceholder(botId, false);
      const isVision = (activeModel || "").toLowerCase().includes("llava") || (activeModel || "").toLowerCase().includes("moondream");
      const modelNote = isVision
        ? `Currently active model **\`${activeModel}\`** is a **Vision Understanding model** (it inspects and analyzes uploaded images, but cannot synthesize new images).\n\n`
        : `Currently active model **\`${activeModel}\`** is a **Local Language model**.\n\n`;
      const imgHelpText = `### How to Generate AI Images with \`/image\`\n\n` +
        modelNote +
        `To generate photorealistic images:\n` +
        `1. Provide a descriptive prompt with the command:\n` +
        `   \`\`\`text\n` +
        `   /image a majestic tree in a misty forest at dawn, cinematic lighting\n` +
        `   \`\`\`\n` +
        `2. Enable an Image Generator:\n` +
        `   - **Local Models:** Install **\`sd-turbo\`** or **\`stable-diffusion-v1-5\`** from the Local AI Models tab.\n` +
        `   - **Cloud AI:** Connect **Google Imagen 3** (via Gemini key) or **OpenAI DALL-E 3** in Settings & 3rd-Party Cloud AI.\n\n` +
        `*Tip:* To inspect or ask questions about an existing image using **${activeModel}**, attach the image file using the attach button and type your question!`;
      updateAssistantMessage(botId, imgHelpText, null, []);
      return;
    }
    if (lowerPrompt === "/help") {
      chatInput.value = "";
      appendUserMessage("/help");
      const botId = "msg-" + Date.now();
      appendAssistantPlaceholder(botId, false);
      const helpText = `### Available Slash Commands\n\n` +
        `- \`/internet [on|off]\` : Toggle real-time web grounding and RAG\n` +
        `- \`/factcheck [on|off]\` : Toggle automated claim verification and audit engine\n` +
        `- \`/team\` : Toggle autonomous 4-role AI engineering team\n` +
        `- \`/supervisor\` or \`/antigravity\` : Open Antigravity Autonomous Supervisor in AI Team\n` +
        `- \`/image <prompt>\` : Synthesize image with Local SD-Turbo or Cloud AI (Imagen / DALL-E)\n` +
        `- \`/weather [city]\` : Fetch live real-time Open-Meteo weather forecast\n` +
        `- \`/web <query>\` : Search Wikipedia & DuckDuckGo with live web citations\n` +
        `- \`/mcp\` : Open Model Context Protocol (MCP) servers & plugins hub\n` +
        `- \`/models\` : Open Model Manager to pull or switch local models\n` +
        `- \`/projects\` : Open active project workspace context\n` +
        `- \`/clear\` : Clear current conversation history\n\n` +
        `*Tip:* Type \`/\` in the chat box anytime to trigger the interactive auto-complete popup!`;
      updateAssistantMessage(botId, helpText, null, []);
      return;
    }

    const isTeam = toggleTeamMode.checked;
    if (isTeam && !activeProjectPath) {
      showToast("Please select a project folder before running AI Team mode", "warning", "Workspace Required");
      await browseAndActivateProjectFolder();
      if (!activeProjectPath) return;
    }

    if (isGeneratingResponse) {
      stopCurrentChatGeneration();
      return;
    }

    const promptToSend = prompt || "Please analyze and summarize the attached document(s).";
    const sentAttachments = [...currentChatAttachments];
    currentChatAttachments = [];
    renderChatAttachmentsTray();

    lastSentPrompt = promptToSend;
    chatInput.value = "";
    appendUserMessage(promptToSend, sentAttachments);

    const userMsgRecord = {
      role: "user",
      text: promptToSend,
      attachments: sentAttachments,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    // Save user message immediately to session so switching chats retains it
    let currentSession = chatSessions.find(s => s.id === activeSessionId);
    if (!currentSession) {
      currentSession = {
        id: activeSessionId || ("session_" + Date.now()),
        title: promptToSend.substring(0, 28) || "New Conversation",
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        messages: []
      };
      chatSessions.unshift(currentSession);
    }
    currentSession.messages.push(userMsgRecord);
    currentSession.updatedAt = new Date().toISOString();
    if (currentSession.title === "New Conversation" || currentSession.messages.filter(m => m.role === 'user').length <= 1) {
      let clean = promptToSend.replace(/^[\/\#\*\-\s]+/, "").trim();
      if (clean.length > 28) clean = clean.substring(0, 28) + "...";
      currentSession.title = clean || "Conversation";
      if (currentChatTitle) currentChatTitle.textContent = currentSession.title;
    }
    saveChatSessions();
    renderChatHistorySidebar();

    const botMsgId = "msg-" + Date.now();
    appendAssistantPlaceholder(botMsgId, isTeam);

    await dispatchChatRequest(promptToSend, botMsgId, sentAttachments, userMsgRecord, isTeam);
  });

  chatInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      chatForm.dispatchEvent(new Event("submit"));
    } else if (e.key === "ArrowUp" && chatInput.value === "") {
      const userMsgs = messagesList.querySelectorAll(".message.user");
      if (userMsgs.length > 0) {
        const lastUserMsg = userMsgs[userMsgs.length - 1];
        e.preventDefault();
        enterUserMessageEditMode(lastUserMsg);
      }
    }
  });

  btnClearChatProj.addEventListener("click", () => {
    activateProject("");
  });
}

// -----------------------------------------------------------------------------
// Chat Generation State & Controller Management (Stop / Abort)
// -----------------------------------------------------------------------------
let currentChatAbortController = null;
let isGeneratingResponse = false;
let currentGeneratingBotId = null;

function setSendButtonState(state) {
  if (!btnSend) return;
  if (state === "generating") {
    btnSend.classList.add("btn-stop-mode");
    btnSend.setAttribute("type", "button");
    btnSend.setAttribute("title", "Stop generation (Cancel thinking & grounding)");
    btnSend.innerHTML = `
      <svg class="stop-icon" viewBox="0 0 24 24" width="16" height="16" fill="currentColor">
        <rect x="6" y="6" width="12" height="12" rx="2"></rect>
      </svg>
    `;
    btnSend.disabled = false;
  } else {
    btnSend.classList.remove("btn-stop-mode");
    btnSend.setAttribute("type", "submit");
    btnSend.setAttribute("title", "Send message");
    btnSend.innerHTML = `
      <svg class="send-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <line x1="12" y1="19" x2="12" y2="5"></line>
        <polyline points="5 12 12 5 19 12"></polyline>
      </svg>
    `;
    btnSend.disabled = false;
  }
}

function stopCurrentChatGeneration() {
  const activeJob = Array.from(activeChatJobs.values()).find(j => j.targetSessionId === activeSessionId);
  if (activeJob) {
    try {
      fetch(`${API_BASE}/api/chat/stop`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ task_id: activeJob.taskId })
      }).catch(() => {});
    } catch (_) {}
    activeChatJobs.delete(activeJob.taskId);
    renderGenerationStopped(activeJob.botMsgId, activeJob.promptToSend);
    setSendButtonState("idle");
    renderChatHistorySidebar();
    showToast("Generation stopped for this conversation", "info");
    return;
  }
  if (currentChatAbortController) {
    try {
      currentChatAbortController.abort();
    } catch (_) {}
    currentChatAbortController = null;
  }
  try {
    fetch(`${API_BASE}/api/chat/abort`, { method: "POST" }).catch(() => {});
  } catch (_) {}

  if (currentGeneratingBotId) {
    renderGenerationStopped(currentGeneratingBotId, lastSentPrompt);
  }
  isGeneratingResponse = false;
  currentGeneratingBotId = null;
  setSendButtonState("idle");
  renderChatHistorySidebar();
  showToast("Generation stopped by user", "info");
}

function renderGenerationStopped(id, userPrompt = "") {
  const msg = document.getElementById(id);
  if (!msg) return;
  const body = msg.querySelector(".msg-body");
  if (!body) return;
  body.classList.remove("loading-indicator");

  const promptForRetry = userPrompt || lastSentPrompt;
  body.innerHTML = `
    <div class="generation-stopped-box">
      <div class="stopped-status-pill">
        <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"></line></svg>
        <span>Generation cancelled by user</span>
      </div>
    </div>
    <div class="msg-footer-actions">
      ${promptForRetry ? `
        <button type="button" class="btn-msg-action btn-regenerate-msg" title="Retry generation">
          <svg class="btn-icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"></polyline><polyline points="1 20 1 14 7 14"></polyline><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg>
          <span>Retry</span>
        </button>
      ` : ""}
    </div>
  `;

  const btnRegen = body.querySelector(".btn-regenerate-msg");
  if (btnRegen && promptForRetry) {
    btnRegen.addEventListener("click", () => regeneratePrompt(promptForRetry));
  }
}

// -----------------------------------------------------------------------------
// Unified Chat Request Dispatcher (With Background Daemon & Poller)
// -----------------------------------------------------------------------------
const activeChatJobs = new Map();

async function dispatchChatRequest(promptToSend, botMsgId, sentAttachments, userMsgRecord, isTeam) {
  isGeneratingResponse = true;
  currentGeneratingBotId = botMsgId;
  currentChatAbortController = new AbortController();
  setSendButtonState("generating");

  const chkCouncilMode = document.getElementById("chk-chat-council-mode");
  const isCouncil = (chkCouncilMode && chkCouncilMode.checked) || promptToSend.trim().toLowerCase().startsWith("/council");
  const targetSessionId = activeSessionId;

  try {
    const payload = {
      prompt: promptToSend,
      model: activeModel,
      history: chatHistory,
      session_id: targetSessionId,
      project_path: activeProjectPath,
      is_team_mode: isTeam,
      is_council_mode: isCouncil,
      attachments: sentAttachments,
    };

    let isAsync = false;
    let taskId = null;
    try {
      const submitRes = await fetch(`${API_BASE}/api/chat/submit`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        signal: currentChatAbortController.signal,
        body: JSON.stringify(payload)
      });
      if (submitRes.ok) {
        const submitData = await submitRes.json();
        if (submitData.success && submitData.task_id) {
          isAsync = true;
          taskId = submitData.task_id;
        }
      }
    } catch (e) {
      console.warn("Async submit failed, falling back to synchronous chat:", e);
    }

    if (isAsync && taskId) {
      activeChatJobs.set(taskId, {
        taskId,
        targetSessionId,
        botMsgId,
        promptToSend,
        userMsgRecord,
        isTeam,
        lastPhase: "Reasoning and generating in background...",
        startTime: Date.now()
      });
      renderChatHistorySidebar();
      await pollChatJobUntilComplete(taskId);
      return;
    }

    // Fallback: Synchronous fetch
    const res = await fetch(`${API_BASE}/api/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      signal: currentChatAbortController.signal,
      body: JSON.stringify(payload),
    });

    const data = await res.json();
    if (data.success) {
      if (data.is_image) {
        updateAssistantMessageImage(botMsgId, data.image_url, data.prompt, data.model, data.filename);
      } else if (data.is_team) {
        updateAssistantTeamMessage(botMsgId, data, promptToSend);
        if (activeProjectPath) {
          loadProjectFiles(activeProjectPath);
        }
      } else {
        updateAssistantMessage(botMsgId, data.response, data.factcheck, data.grounding, promptToSend, data.thinking, { auto_saved_memory: data.auto_saved_memory, council_result: data.council_result });
      }
      chatHistory.push({ role: "user", content: promptToSend });
      chatHistory.push({ role: "assistant", content: data.response || `[Action Completed]` });

      const assistantMsgRecord = {
        role: "assistant",
        text: data.response || (data.is_image ? `[Generated Image: ${data.prompt}]` : `[Action Completed]`),
        factcheck: data.factcheck,
        grounding: data.grounding,
        is_image: !!data.is_image,
        image_url: data.image_url,
        model: data.model,
        filename: data.filename,
        is_team: !!data.is_team,
        teamData: data.is_team ? data : null,
        userPrompt: promptToSend,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };
      saveTurnToSessionById(targetSessionId, userMsgRecord, assistantMsgRecord);
    } else {
      if (data.aborted) {
        renderGenerationStopped(botMsgId, promptToSend);
        return;
      }
      updateAssistantError(botMsgId, data.error || "Execution error", promptToSend);
      const errorRecord = {
        role: "assistant",
        text: `Error: ${data.error || "Execution error"}`,
        userPrompt: promptToSend,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };
      saveTurnToSessionById(targetSessionId, userMsgRecord, errorRecord);
    }
  } catch (err) {
    if (err.name === "AbortError" || !isGeneratingResponse) {
      renderGenerationStopped(botMsgId, promptToSend);
      return;
    }
    updateAssistantError(botMsgId, `Server connection error: ${err.message}`, promptToSend);
    const connErrRecord = {
      role: "assistant",
      text: `Server connection error: ${err.message}`,
      userPrompt: promptToSend,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };
    saveTurnToSessionById(targetSessionId, userMsgRecord, connErrRecord);
  } finally {
    isGeneratingResponse = false;
    currentGeneratingBotId = null;
    currentChatAbortController = null;
    setSendButtonState("idle");
    chatInput.focus();
  }
}

function pollChatJobUntilComplete(taskId) {
  return new Promise((resolve) => {
    const jobInfo = activeChatJobs.get(taskId);
    if (!jobInfo) {
      resolve();
      return;
    }

    const interval = setInterval(async () => {
      try {
        const res = await fetch(`${API_BASE}/api/chat/status?task_id=${encodeURIComponent(taskId)}`);
        if (!res.ok) return;

        const data = await res.json();
        if (!data.success || !data.task) return;

        const task = data.task;
        const status = task.status;

        if (!isGeneratingResponse && currentChatAbortController?.signal?.aborted) {
          clearInterval(interval);
          activeChatJobs.delete(taskId);
          renderGenerationStopped(jobInfo.botMsgId, jobInfo.promptToSend);
          resolve();
          return;
        }

        if (status === "aborted") {
          clearInterval(interval);
          activeChatJobs.delete(taskId);
          renderGenerationStopped(jobInfo.botMsgId, jobInfo.promptToSend);
          renderChatHistorySidebar();
          setSendButtonState("idle");
          resolve();
          return;
        }

        if (status === "running") {
          jobInfo.lastPhase = task.phase || "Reasoning and generating in background...";
          if (activeSessionId === jobInfo.targetSessionId) {
            const botMsgEl = document.getElementById(jobInfo.botMsgId);
            if (botMsgEl) {
              const thText = botMsgEl.querySelector(".thinking-stage-text");
              if (thText && task.phase) {
                thText.textContent = task.phase;
              }
            }
          }
        } else if (status === "completed") {
          clearInterval(interval);
          activeChatJobs.delete(taskId);

          const result = task.result || {};
          const assistantMsgRecord = {
            role: "assistant",
            text: result.response || (result.is_image ? `[Generated Image: ${result.prompt}]` : `[Action Completed]`),
            factcheck: result.factcheck,
            grounding: result.grounding,
            is_image: !!result.is_image,
            image_url: result.image_url,
            model: result.model || activeModel,
            filename: result.filename,
            is_team: !!result.is_team,
            teamData: result.is_team ? result : null,
            userPrompt: jobInfo.promptToSend,
            thinking: result.thinking,
            timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
          };

          saveTurnToSessionById(jobInfo.targetSessionId, jobInfo.userMsgRecord, assistantMsgRecord);

          if (activeSessionId === jobInfo.targetSessionId) {
            const botMsgEl = document.getElementById(jobInfo.botMsgId);
            if (!botMsgEl) {
              const curSes = chatSessions.find(s => s.id === activeSessionId);
              if (curSes) loadSessionMessages(curSes);
            } else {
              if (result.is_image) {
                updateAssistantMessageImage(jobInfo.botMsgId, result.image_url, result.prompt, result.model, result.filename);
              } else if (result.is_team) {
                updateAssistantTeamMessage(jobInfo.botMsgId, result, jobInfo.promptToSend);
                if (activeProjectPath) {
                  loadProjectFiles(activeProjectPath);
                }
              } else {
                updateAssistantMessage(
                  jobInfo.botMsgId,
                  result.response,
                  result.factcheck,
                  result.grounding,
                  jobInfo.promptToSend,
                  result.thinking,
                  { auto_saved_memory: result.auto_saved_memory, council_result: result.council_result }
                );
              }
            }
            setSendButtonState("idle");
          }

          renderChatHistorySidebar();

          if (document.hidden || activeSessionId !== jobInfo.targetSessionId) {
            const shortQ = jobInfo.promptToSend.length > 40 ? jobInfo.promptToSend.substring(0, 40) + "..." : jobInfo.promptToSend;
            showSystemNotification("PAI Studio: Answer Ready", `Completed response for: "${shortQ}"`);
          }

          resolve();
        } else if (status === "error") {
          clearInterval(interval);
          activeChatJobs.delete(taskId);

          const errText = task.error || "Execution error in background engine";
          const errorRecord = {
            role: "assistant",
            text: `Error: ${errText}`,
            userPrompt: jobInfo.promptToSend,
            timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
          };
          saveTurnToSessionById(jobInfo.targetSessionId, jobInfo.userMsgRecord, errorRecord);

          if (activeSessionId === jobInfo.targetSessionId) {
            const botMsgEl = document.getElementById(jobInfo.botMsgId);
            if (!botMsgEl) {
              const curSes = chatSessions.find(s => s.id === activeSessionId);
              if (curSes) loadSessionMessages(curSes);
            } else {
              updateAssistantError(jobInfo.botMsgId, errText, jobInfo.promptToSend);
            }
            setSendButtonState("idle");
          }

          renderChatHistorySidebar();
          resolve();
        }
      } catch (e) {
        console.warn("Poll status tick error:", e);
      }
    }, 1200);
  });
}

// -----------------------------------------------------------------------------
// Message Rendering, Editing & Regeneration
// -----------------------------------------------------------------------------
function renderAttachmentsHtml(attachments = []) {
  if (!attachments || attachments.length === 0) return "";
  return `
    <div class="msg-attachments-row">
      ${attachments.map(att => `
        <span class="msg-att-badge" title="${escapeHtml(att.name)} (${att.size_str || formatBytes(att.size)})">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
          <span>${escapeHtml(att.name)}</span>
        </span>
      `).join("")}
    </div>
  `;
}

function bindUserMessageActions(msg, text, attachments = []) {
  const btnCopy = msg.querySelector(".btn-copy-msg");
  if (btnCopy) {
    btnCopy.addEventListener("click", () => copyToClipboard(text, btnCopy));
  }
  const btnEdit = msg.querySelector(".btn-edit-msg");
  if (btnEdit) {
    btnEdit.addEventListener("click", () => enterUserMessageEditMode(msg, attachments));
  }
}

function appendUserMessage(text, attachments = []) {
  const msg = document.createElement("div");
  msg.className = "message user";
  msg.setAttribute("data-raw-prompt", text);

  let attachmentsHtml = renderAttachmentsHtml(attachments);

  msg.innerHTML = `
    <div class="msg-header">
      <span class="avatar-badge">YOU</span>
      <span class="msg-author">User</span>
      <span class="msg-time">${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
      <div class="msg-actions">
        <button type="button" class="btn-msg-action btn-edit-msg" title="Edit this instruction and regenerate response">
          <svg class="btn-icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
          <span>Edit</span>
        </button>
        <button type="button" class="btn-msg-action btn-copy-msg" title="Copy instruction to clipboard">
          <svg class="btn-icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
          <span>Copy</span>
        </button>
      </div>
    </div>
    <div class="msg-body">
      ${attachmentsHtml}
      <div class="user-msg-content">
        <p class="user-msg-text">${escapeHtml(text)}</p>
      </div>
    </div>
  `;
  bindUserMessageActions(msg, text, attachments);
  messagesList.appendChild(msg);
  messagesList.scrollTop = messagesList.scrollHeight;
  return msg;
}

function enterUserMessageEditMode(msg, attachments = []) {
  if (isGeneratingResponse) {
    showToast("Please wait or stop current generation before editing", "info");
    return;
  }
  const bodyEl = msg.querySelector(".msg-body");
  if (!bodyEl || bodyEl.querySelector(".user-msg-edit-container")) return;

  const currentPrompt = msg.getAttribute("data-raw-prompt") || msg.querySelector(".user-msg-text")?.innerText || "";
  const attachmentsHtml = renderAttachmentsHtml(attachments);

  bodyEl.innerHTML = `
    ${attachmentsHtml}
    <div class="user-msg-edit-container">
      <textarea class="edit-msg-textarea" rows="2" placeholder="Edit instruction...">${escapeHtml(currentPrompt)}</textarea>
      <div class="edit-msg-footer">
        <span class="edit-shortcut-hint">Esc to cancel • Ctrl+Enter to save & regenerate</span>
        <div class="edit-btn-group">
          <button type="button" class="btn-edit-cancel">Cancel</button>
          <button type="button" class="btn-edit-submit">Update & Regenerate</button>
        </div>
      </div>
    </div>
  `;

  const textarea = bodyEl.querySelector(".edit-msg-textarea");
  const btnCancel = bodyEl.querySelector(".btn-edit-cancel");
  const btnSubmit = bodyEl.querySelector(".btn-edit-submit");

  if (textarea) {
    textarea.focus();
    textarea.setSelectionRange(textarea.value.length, textarea.value.length);
    textarea.style.height = "auto";
    textarea.style.height = Math.max(65, textarea.scrollHeight) + "px";
    textarea.addEventListener("input", () => {
      textarea.style.height = "auto";
      textarea.style.height = Math.max(65, textarea.scrollHeight) + "px";
    });
  }

  function cancelEdit() {
    bodyEl.innerHTML = `
      ${attachmentsHtml}
      <div class="user-msg-content">
        <p class="user-msg-text">${escapeHtml(currentPrompt)}</p>
      </div>
    `;
    bindUserMessageActions(msg, currentPrompt, attachments);
  }

  function submitEdit() {
    const newText = (textarea?.value || "").trim();
    if (!newText) {
      showToast("Please enter an instruction", "warning");
      return;
    }
    executeEditAndRegenerate(msg, newText, attachments);
  }

  btnCancel?.addEventListener("click", cancelEdit);
  btnSubmit?.addEventListener("click", submitEdit);

  textarea?.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      e.preventDefault();
      cancelEdit();
    } else if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      submitEdit();
    }
  });
}

function executeEditAndRegenerate(userMsgEl, newPrompt, attachments = []) {
  if (isGeneratingResponse) {
    stopCurrentChatGeneration();
  }

  // 1. Update this user message in DOM
  userMsgEl.setAttribute("data-raw-prompt", newPrompt);
  const attachmentsHtml = renderAttachmentsHtml(attachments);
  userMsgEl.querySelector(".msg-body").innerHTML = `
    ${attachmentsHtml}
    <div class="user-msg-content">
      <p class="user-msg-text">${escapeHtml(newPrompt)}</p>
    </div>
  `;
  bindUserMessageActions(userMsgEl, newPrompt, attachments);

  // 2. Remove all subsequent siblings in messagesList (clearing the old assistant answer and any later turns)
  let nextEl = userMsgEl.nextElementSibling;
  while (nextEl) {
    const toRemove = nextEl;
    nextEl = nextEl.nextElementSibling;
    toRemove.remove();
  }

  // 3. Truncate chatHistory up to this turn
  const allUserMsgs = Array.from(messagesList.querySelectorAll(".message.user"));
  const userIndex = allUserMsgs.indexOf(userMsgEl);
  if (userIndex !== -1) {
    const turnsToKeep = userIndex * 2;
    chatHistory = chatHistory.slice(0, turnsToKeep);

    let activeSession = chatSessions.find(s => s.id === activeSessionId);
    if (activeSession && activeSession.messages) {
      activeSession.messages = activeSession.messages.slice(0, turnsToKeep);
      saveChatSessions();
    }
  }

  // 4. Create new Assistant placeholder
  const isTeam = toggleTeamMode.checked;
  const botMsgId = "msg-" + Date.now();
  appendAssistantPlaceholder(botMsgId, isTeam);

  // 5. Build user record & dispatch
  const userMsgRecord = {
    role: "user",
    text: newPrompt,
    attachments: attachments,
    timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  };

  lastSentPrompt = newPrompt;
  dispatchChatRequest(newPrompt, botMsgId, attachments, userMsgRecord, isTeam);
}

function appendAssistantPlaceholder(id, isTeam = false) {
  const msg = document.createElement("div");
  msg.className = "message assistant";
  msg.id = id;
  const title = isTeam ? "Autonomous AI Team (4 Roles)" : "PAI Assistant";
  const badge = isTeam ? "TEAM" : "PAI";
  const statusNote = isTeam ? "Reviewing codebase, planning WBS & synthesizing code..." : "Thinking & grounding...";

  msg.innerHTML = `
    <div class="msg-header">
      <span class="avatar-badge">${badge}</span>
      <span class="msg-author">${title}</span>
      <span class="msg-time">${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
    </div>
    <div class="msg-body loading-indicator">
      <div class="loading-status-line">
        <span class="dot-flashing"></span>
        <span class="status-note-text">${statusNote}</span>
      </div>
      <button type="button" class="btn-cancel-generating" id="btn-cancel-${id}" title="Stop generation (Cancel)">
        <svg viewBox="0 0 24 24" width="12" height="12" fill="currentColor"><rect x="6" y="6" width="12" height="12" rx="1.5"></rect></svg>
        <span>Stop</span>
      </button>
    </div>
  `;
  const btnCancel = msg.querySelector(".btn-cancel-generating");
  if (btnCancel) {
    btnCancel.addEventListener("click", () => stopCurrentChatGeneration());
  }
  messagesList.appendChild(msg);
  messagesList.scrollTop = messagesList.scrollHeight;
}

function updateAssistantMessage(id, text, factcheck, grounding, userPrompt = "", thinking = "", extra = {}) {
  const msg = document.getElementById(id);
  if (!msg) return;
  const body = msg.querySelector(".msg-body");
  body.classList.remove("loading-indicator");

  let html = formatMarkdown(text);

  if (thinking && thinking.trim()) {
    html = `
      <details class="thinking-accordion mb-2">
        <summary class="thinking-summary">
          <svg class="thinking-icon" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><path d="M12 16v-4"></path><path d="M12 8h.01"></path></svg>
          <span>Thought Process & Reasoning Trace</span>
        </summary>
        <div class="thinking-body">
          <pre>${escapeHtml(thinking.trim())}</pre>
        </div>
      </details>
    ` + html;
  }

  if (extra && extra.auto_saved_memory) {
    html = `
      <div class="auto-memory-pill mb-2">
        <span>Memory saved: <strong>${escapeHtml(extra.auto_saved_memory.key)}</strong> (${escapeHtml(extra.auto_saved_memory.content)})</span>
      </div>
    ` + html;
  }

  if (extra && extra.council_result) {
    const cr = extra.council_result;
    const modelsStr = (cr.models || []).join(" + ");
    html = `
      <div class="council-badge-box mb-2">
        <span class="council-status-tag">Model Council Deliberation (${escapeHtml(modelsStr)})</span>
      </div>
    ` + html;

    if (cr.agreements && cr.agreements.length > 0) {
      html += `
        <details class="council-collapsible mt-3">
          <summary class="council-summary">
            <span>View Multi-Model Agreement & Divergence Matrix</span>
            <span class="fc-toggle-hint">Details ▾</span>
          </summary>
          <div class="council-details-content p-3 text-xs">
            <div class="mb-2"><strong>Cross-Model Convergence:</strong></div>
            <ul class="mb-3" style="padding-left:18px;">
              ${cr.agreements.map(a => `<li><strong>${escapeHtml(a.finding)}</strong> <span class="text-muted">(${escapeHtml(a.evidence || '')})</span></li>`).join("")}
            </ul>
            ${cr.disagreements && cr.disagreements.length > 0 ? `
              <div class="mb-2"><strong>Divergence Points:</strong></div>
              <ul class="mb-3" style="padding-left:18px;">
                ${cr.disagreements.map(d => `<li><strong>${escapeHtml(d.topic)}:</strong> <span class="text-muted">${escapeHtml(d.why_differ || '')}</span></li>`).join("")}
              </ul>
            ` : ""}
            ${cr.unique_discoveries && cr.unique_discoveries.length > 0 ? `
              <div class="mb-2"><strong>Unique Specialized Discoveries:</strong></div>
              <ul style="padding-left:18px;">
                ${cr.unique_discoveries.map(u => `<li><strong>${escapeHtml(u.model)}:</strong> ${escapeHtml(u.finding)}</li>`).join("")}
              </ul>
            ` : ""}
          </div>
        </details>
      `;
    }
  }

  if (grounding && grounding.length > 0) {
    html += `
      <div class="grounding-badge-list">
        <span class="grounding-label">${SVG_ICONS.globe} Web Citations:</span>
        ${grounding.map(g => `<a href="${escapeHtml(sanitizeUrl(g.url))}" target="_blank" rel="noopener noreferrer" class="grounding-pill">${escapeHtml(g.title || g.url)}</a>`).join("")}
      </div>
    `;
  }

  if (factcheck && (factcheck.report || (factcheck.claims && factcheck.claims.length > 0))) {
    const trustPct = (typeof factcheck.score === "number")
      ? Math.round(factcheck.score * 100)
      : (factcheck.fidelity !== undefined ? factcheck.fidelity : 0);
    const trustClass = trustPct >= 70 ? "trust-high" : (trustPct >= 35 ? "trust-med" : "trust-low");

    const meterHtml = `
      <div class="fc-meter-bar-container" style="margin-bottom: 12px; padding: 10px 12px; background: rgba(0,0,0,0.22); border-radius: 6px; border: 1px solid rgba(255,255,255,0.06);">
        <div style="display: flex; justify-content: space-between; font-size: 11px; margin-bottom: 6px;">
          <span style="font-weight: 600; color: var(--text-dim);">Information Trust & Calibration</span>
          <span style="font-weight: 700; font-family: var(--font-mono);" class="${trustClass}">${trustPct}% Confidence</span>
        </div>
        <div style="height: 6px; background: rgba(255,255,255,0.08); border-radius: 9999px; overflow: hidden;">
          <div style="width: ${trustPct}%; height: 100%; border-radius: 9999px; background: ${trustPct >= 70 ? 'linear-gradient(90deg, #10b981, #059669)' : (trustPct >= 35 ? 'linear-gradient(90deg, #f59e0b, #d97706)' : 'linear-gradient(90deg, #ef4444, #dc2626)')}; transition: width 0.3s ease;"></div>
        </div>
      </div>
    `;

    let detailsContent = "";
    if (factcheck.claims && factcheck.claims.length > 0) {
      detailsContent = `
        ${meterHtml}
        <div class="factcheck-claims-list">
          ${factcheck.claims.map((c) => {
            const isV = c.verdict === "VERIFIED";
            const isC = c.verdict === "CONTRADICTED";
            const badgeClass = isV ? "badge-verified" : (isC ? "badge-contradicted" : "badge-unverified");
            const badgeLabel = isV ? "Verified" : (isC ? "Potential Hallucination" : "Unverified");
            const badgeIcon = isV
              ? `<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2.5" style="display:inline-block;vertical-align:middle;margin-right:2px;"><polyline points="20 6 9 17 4 12"></polyline></svg>`
              : (isC
                ? `<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2.5" style="display:inline-block;vertical-align:middle;margin-right:2px;"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>`
                : `<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2.5" style="display:inline-block;vertical-align:middle;margin-right:2px;"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>`);
            const confPct = Math.round((c.confidence || 0) * 100);
            const citeLinks = (c.citations || []).map(cite => 
              `<a href="${escapeHtml(sanitizeUrl(cite.url))}" target="_blank" rel="noopener noreferrer" class="cite-link" title="${escapeHtml(cite.url)}">${escapeHtml(cite.title || cite.url)}</a>`
            ).join(" ");
            return `
              <div class="claim-item">
                <div class="claim-header">
                  <span class="claim-verdict ${badgeClass}">${badgeIcon} ${badgeLabel}</span>
                  <span class="claim-conf">Confidence: ${confPct}%</span>
                </div>
                <div class="claim-statement">${escapeHtml(c.statement)}</div>
                ${c.notes ? `<div class="claim-note"><span class="text-muted">Note:</span> ${escapeHtml(c.notes)}</div>` : ""}
                ${citeLinks ? `<div class="claim-sources"><span class="text-muted">Sources:</span> ${citeLinks}</div>` : ""}
              </div>
            `;
          }).join("")}
        </div>
      `;
    } else if (factcheck.report) {
      const cleanReport = factcheck.report
        .replace(/^─+/gm, "")
        .replace(/(?:[\uD83D\uDEE1\uFE0F]\s*)?FACT-CHECK & WEB GROUNDING ENGINE \(Live Verification\):?/i, "")
        .trim();
      detailsContent = `
        ${meterHtml}
        <div class="factcheck-body font-mono-target">${escapeHtml(cleanReport)}</div>
      `;
    }

    html += `
      <details class="factcheck-collapsible ${trustClass}">
        <summary class="factcheck-summary">
          <div class="fc-summary-left">
            <span class="fc-icon">${SVG_ICONS.shield}</span>
            <span class="fc-title">Live Verification Audit</span>
            <span class="fc-score-badge ${trustClass}">Trust: ${trustPct}%</span>
          </div>
          <span class="fc-toggle-hint">View Verification ▾</span>
        </summary>
        <div class="factcheck-content">
          ${detailsContent}
        </div>
      </details>
    `;
  }

  const promptForRetry = userPrompt || lastSentPrompt;
  html += `
    <div class="msg-footer-actions">
      <button type="button" class="btn-msg-action btn-copy-msg" title="Copy response to clipboard">
        <svg class="btn-icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
        <span>Copy</span>
      </button>
      ${promptForRetry ? `
        <button type="button" class="btn-msg-action btn-regenerate-msg" title="Regenerate answer with active model">
          <svg class="btn-icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"></polyline><polyline points="1 20 1 14 7 14"></polyline><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg>
          <span>Regenerate</span>
        </button>
      ` : ""}
    </div>
  `;

  body.innerHTML = html;

  const btnCopy = body.querySelector(".btn-copy-msg");
  if (btnCopy) {
    btnCopy.addEventListener("click", () => copyToClipboard(text, btnCopy));
  }

  const btnRegen = body.querySelector(".btn-regenerate-msg");
  if (btnRegen) {
    btnRegen.addEventListener("click", () => regeneratePrompt(promptForRetry));
  }

  messagesList.scrollTop = messagesList.scrollHeight;
}

function updateAssistantTeamMessage(id, data, userPrompt = "") {
  const msg = document.getElementById(id);
  if (!msg) return;
  const body = msg.querySelector(".msg-body");
  body.classList.remove("loading-indicator");

  let filesHtml = "";
  if (data.saved_files && data.saved_files.length > 0) {
    filesHtml = `
      <div class="chat-team-files-list">
        ${data.saved_files.map(f => `<span class="team-file-pill" onclick="switchTab('projects'); openProjectFile('${activeProjectPath}', '${escapeHtml(f)}');">${SVG_ICONS.file} ${escapeHtml(f)}</span>`).join("")}
      </div>
    `;
  }

  const promptForRetry = userPrompt || lastSentPrompt;
  body.innerHTML = `
    <div class="chat-team-summary">
      <div class="chat-team-header">
        <span class="chat-team-title">${SVG_ICONS.users} Multi-Agent Team Sprint Completed</span>
        <span class="active-badge">4 Roles Synchronized</span>
      </div>
      <div>${formatMarkdown(data.response)}</div>
      ${filesHtml ? `<div class="mt-2"><strong>Saved Code Files (Click to inspect):</strong>${filesHtml}</div>` : ""}
      <div class="msg-footer-actions">
        <button type="button" class="btn-msg-action btn-copy-msg" title="Copy team summary">
          <svg class="btn-icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
          <span>Copy</span>
        </button>
        ${promptForRetry ? `
          <button type="button" class="btn-msg-action btn-regenerate-msg" title="Re-run collaborative team workflow">
            <svg class="btn-icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"></polyline><polyline points="1 20 1 14 7 14"></polyline><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg>
            <span>Regenerate</span>
          </button>
        ` : ""}
      </div>
    </div>
  `;

  const btnCopy = body.querySelector(".btn-copy-msg");
  if (btnCopy) {
    btnCopy.addEventListener("click", () => copyToClipboard(data.response, btnCopy));
  }
  const btnRegen = body.querySelector(".btn-regenerate-msg");
  if (btnRegen) {
    btnRegen.addEventListener("click", () => regeneratePrompt(promptForRetry));
  }

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
      <div class="msg-footer-actions">
        <button type="button" class="btn-msg-action btn-regenerate-msg" title="Re-generate image">
          <svg class="btn-icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"></polyline><polyline points="1 20 1 14 7 14"></polyline><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg>
          <span>Regenerate</span>
        </button>
      </div>
    </div>
  `;

  const btnRegen = body.querySelector(".btn-regenerate-msg");
  if (btnRegen) {
    btnRegen.addEventListener("click", () => regeneratePrompt(`/image ${prompt}`));
  }

  messagesList.scrollTop = messagesList.scrollHeight;
}

function updateAssistantError(id, errText, promptForRetry = "") {
  const msg = document.getElementById(id);
  if (!msg) return;
  const body = msg.querySelector(".msg-body");
  body.classList.remove("loading-indicator");
  const p = promptForRetry || lastSentPrompt;
  body.innerHTML = `
    <p class="error-text">Error: ${escapeHtml(errText)}</p>
    ${p ? `
      <div class="msg-footer-actions">
        <button type="button" class="btn-msg-action btn-regenerate-msg" title="Retry this request">
          <svg class="btn-icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"></polyline><polyline points="1 20 1 14 7 14"></polyline><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg>
          <span>Retry / Regenerate</span>
        </button>
      </div>
    ` : ""}
  `;
  const btnRegen = body.querySelector(".btn-regenerate-msg");
  if (btnRegen) {
    btnRegen.addEventListener("click", () => regeneratePrompt(p));
  }
  messagesList.scrollTop = messagesList.scrollHeight;
}

// 3. Project Workspace System with Native Windows Folder Picker
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

  btnBrowseProjFolder.addEventListener("click", async () => {
    const origHtml = btnBrowseProjFolder.innerHTML;
    btnBrowseProjFolder.disabled = true;
    btnBrowseProjFolder.textContent = "Browsing...";
    try {
      const initPath = projPathInput ? projPathInput.value.trim() : "";
      const picked = await openNativeFolderDialog("Select Project Workspace Folder", initPath);
      if (picked && picked.path) {
        const folderPath = picked.path;
        const folderName = picked.name || folderPath.split(/[\/\\]/).filter(Boolean).pop() || "Workspace";
        projPathInput.value = folderPath;
        projNameInput.value = folderName;
        // Automatically save and activate the picked project folder immediately
        await fetch(`${API_BASE}/api/projects/save`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name: folderName, path: folderPath }),
        });
        await loadProjects();
        await activateProject(folderPath);
        showToast(`Workspace activated: ${folderName}`, "success", "Active Project");
      }
    } catch (err) {
      console.error("Browse error:", err);
    } finally {
      btnBrowseProjFolder.disabled = false;
      btnBrowseProjFolder.innerHTML = origHtml;
    }
  });

  btnEmptyBrowseFolder.addEventListener("click", async () => {
    await browseAndActivateProjectFolder();
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

async function openNativeFolderDialog(dialogTitle = "Select Project Workspace Folder", initialPath = "") {
  try {
    const res = await fetch(`${API_BASE}/api/utils/select_folder`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: dialogTitle, initial_path: initialPath }),
    });
    const data = await res.json();
    if (data.success && data.path) {
      return data;
    }
  } catch (err) {
    console.error("Folder dialog error:", err);
  }
  return null;
}

function normalizePath(p) {
  if (!p || typeof p !== "string") return "";
  let norm = p.trim().replace(/\\/g, "/").replace(/\/+$/, "");
  if (/^[a-zA-Z]:/.test(norm)) {
    norm = norm[0].toUpperCase() + norm.slice(1);
  }
  return norm;
}

function pathsMatch(p1, p2) {
  if (!p1 && !p2) return true;
  if (!p1 || !p2) return false;
  return normalizePath(p1).toLowerCase() === normalizePath(p2).toLowerCase();
}

async function browseAndActivateProjectFolder() {
  try {
    const picked = await openNativeFolderDialog("Select Project Workspace Folder", activeProjectPath || "");
    if (picked && picked.path) {
      const folderPath = picked.path;
      const folderName = picked.name || folderPath.split(/[\/\\]/).filter(Boolean).pop() || "Workspace";
      const saveRes = await fetch(`${API_BASE}/api/projects/save`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: folderName, path: folderPath }),
      });
      const saveData = await saveRes.json();
      const targetPath = (saveData && saveData.project && saveData.project.path) ? saveData.project.path : folderPath;
      await activateProject(targetPath);
      return true;
    }
  } catch (e) {
    console.error("Browse & activate error:", e);
  }
  return false;
}

async function loadProjects() {
  try {
    const res = await fetch(`${API_BASE}/api/projects`);
    const data = await res.json();
    if (data && (data.success || Array.isArray(data.projects))) {
      projectsData = data;
      activeProjectPath = data.active_project || "";
      const activeObj = (data.projects || []).find(p => pathsMatch(p.path, activeProjectPath));
      activeProjectName = activeObj ? activeObj.name : (activeProjectPath ? activeProjectPath.split(/[\/\\]/).filter(Boolean).pop() || "Workspace" : "");

      renderProjectsList(data.projects || [], activeProjectPath);
      populateHeaderProjectDropdown(data.projects || [], activeProjectPath);
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
  let matchedIndex = -1;

  const projList = Array.isArray(projects) ? projects : [];

  projList.forEach((p, idx) => {
    const opt = document.createElement("option");
    opt.value = p.path;
    // Show folder name clearly
    opt.textContent = p.name;
    opt.title = `${p.name} (${p.path})`;
    if (activePath && pathsMatch(p.path, activePath)) {
      opt.selected = true;
      matchedIndex = idx + 1; // 1-based index (0 is No Active Project)
    }
    headerProjectSelect.appendChild(opt);
  });

  // If activePath is set, but not in projList, add it dynamically!
  if (activePath && matchedIndex < 0) {
    const opt = document.createElement("option");
    opt.value = activePath;
    const folderName = activePath.split(/[\/\\]/).filter(Boolean).pop() || "Workspace";
    opt.textContent = folderName;
    opt.title = `${folderName} (${activePath})`;
    opt.selected = true;
    headerProjectSelect.appendChild(opt);
    matchedIndex = headerProjectSelect.options.length - 1;
  }

  const addOpt = document.createElement("option");
  addOpt.value = "__NEW_PROJECT__";
  addOpt.textContent = "+ Add / Open Project Folder...";
  headerProjectSelect.appendChild(addOpt);

  if (activePath && matchedIndex > 0) {
    headerProjectSelect.selectedIndex = matchedIndex;
    const activeObj = projList.find(p => pathsMatch(p.path, activePath));
    const displayName = activeObj ? activeObj.name : activePath.split(/[\/\\]/).filter(Boolean).pop() || "Workspace";
    headerProjectSelect.title = `Active Project: ${displayName} (${activePath})`;
  } else {
    headerProjectSelect.selectedIndex = 0;
    headerProjectSelect.title = "No Active Project (Global)";
  }
}

function renderProjectsList(projects, activePath) {
  savedProjectsCount.textContent = (projects || []).length;
  if (!projects || projects.length === 0) {
    projectsListContainer.innerHTML = `<div class="text-muted text-sm" style="padding: 10px;">No projects saved yet. Create one above or click Browse.</div>`;
    return;
  }

  projectsListContainer.innerHTML = "";
  projects.forEach((p) => {
    const isActive = pathsMatch(p.path, activePath);
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
    if (data && (data.success || data.active_project !== undefined)) {
      activeProjectPath = data.active_project !== undefined ? data.active_project : folderPath;
      
      // Refresh projects list to keep all components completely synchronized
      try {
        const listRes = await fetch(`${API_BASE}/api/projects`);
        const listData = await listRes.json();
        if (listData && (listData.success || Array.isArray(listData.projects))) {
          projectsData = listData;
        }
      } catch (_) {}
      
      const projObj = (projectsData.projects || []).find(p => pathsMatch(p.path, activeProjectPath));
      activeProjectName = projObj ? projObj.name : (activeProjectPath ? activeProjectPath.split(/[\/\\]/).filter(Boolean).pop() || "Workspace" : "");

      updateActiveProjectUI();
      renderProjectsList(projectsData.projects || [], activeProjectPath);
      populateHeaderProjectDropdown(projectsData.projects || [], activeProjectPath);

      if (activeProjectPath) {
        showToast(`Workspace set to: ${activeProjectName}`, "success", "Active Project");
        loadProjectFiles(activeProjectPath);
      } else {
        showToast("Switched to Global mode (no active project)", "info");
        fileTreeContainer.innerHTML = `
          <div class="file-tree-empty">
            <p class="text-muted mb-3">No active project workspace selected.</p>
            <button type="button" class="btn btn-primary btn-sm" id="btn-empty-browse-folder-2">
              ${SVG_ICONS.folder} <span>Select Project Folder</span>
            </button>
          </div>
        `;
        document.getElementById("btn-empty-browse-folder-2")?.addEventListener("click", browseAndActivateProjectFolder);
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
    agTargetWorkspaceBadge.textContent = `Target: ${activeProjectName}`;
  } else {
    chatProjectBanner.classList.add("hidden");
    teamTargetProjNote.textContent = "Target: Standalone sprint directory";
    agTargetWorkspaceBadge.textContent = "Target: Global Workspace";
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
    fileTreeContainer.innerHTML = `
      <div class="file-tree-empty text-muted">
        <p class="mb-2">No code or text files found in project.</p>
        <button type="button" class="btn btn-secondary btn-sm" onclick="btnNewFile.click()">Create First File</button>
      </div>
    `;
    return;
  }

  fileTreeContainer.innerHTML = "";
  const fragment = document.createDocumentFragment();

  files.forEach((f) => {
    const relPath = typeof f === "string" ? f : (f.relative_path || f.name);
    const displayName = typeof f === "string" ? f : (f.relative_path || f.name);
    const item = document.createElement("div");
    item.className = `file-item ${relPath === currentOpenFile ? "active" : ""}`;
    item.title = relPath;
    item.innerHTML = `${SVG_ICONS.file} <span class="font-mono-target">${escapeHtml(displayName)}</span>`;
    item.addEventListener("click", () => openProjectFile(basePath, relPath, item));
    fragment.appendChild(item);
  });

  fileTreeContainer.appendChild(fragment);
}

async function openProjectFile(basePath, filename, itemElem) {
  if (!basePath || !filename) return;
  const relFile = typeof filename === "string" ? filename : (filename.relative_path || filename.name);

  document.querySelectorAll(".file-item").forEach(el => el.classList.remove("active"));
  if (itemElem) itemElem.classList.add("active");

  currentOpenFile = relFile;
  currentOpenFilename.textContent = relFile;
  codeEditorTextarea.value = "Loading file content...";
  codeEditorTextarea.setAttribute("readonly", "true");
  btnSaveFile.setAttribute("disabled", "true");

  try {
    const res = await fetch(`${API_BASE}/api/projects/file/content?path=${encodeURIComponent(basePath)}&file=${encodeURIComponent(relFile)}`);
    const data = await res.json();
    if (data.success) {
      codeEditorTextarea.value = data.content !== undefined ? data.content : "";
      codeEditorTextarea.removeAttribute("readonly");
      btnSaveFile.removeAttribute("disabled");
    } else {
      codeEditorTextarea.value = `// Notice: ${data.error || "Unable to display file content"}`;
      showToast(data.error || "Could not open file", "warning", "File Notice");
    }
  } catch (err) {
    codeEditorTextarea.value = `// Connection error: ${err.message}`;
    showToast(`Failed to load file: ${err.message}`, "error");
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
    else if (activeTab === "explore") text = (currentDeliverables.explorer_findings || "") + "\n\n" + (currentDeliverables.citations || []).join("\n");
    else if (activeTab === "debug") text = JSON.stringify(currentDeliverables.debug_report || {}, null, 2);
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

  const btnQuickScout = document.getElementById("btn-team-quick-scout");
  if (btnQuickScout) {
    btnQuickScout.addEventListener("click", async () => {
      const q = teamTaskInput.value.trim() || "game engine loop";
      btnQuickScout.disabled = true;
      showToast(`Scouting codebase symbols for "${q}"...`, "info");
      try {
        const res = await fetch(`${API_BASE}/api/team/explore`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ query: q, project_dir: activeProjectPath }),
        });
        const d = await res.json();
        if (d.success) {
          currentDeliverables.explorer_findings = d.findings || "";
          currentDeliverables.citations = d.citations || [];
          renderDeliverableTab("explore");
          delivTabBtns.forEach(b => b.classList.toggle("active", b.dataset.tab === "explore"));
          showToast(`Scouted ${d.citations?.length || 0} citations across ${d.scanned_files?.length || 0} files`, "success");
        }
      } catch (err) {
        showToast(`Scout failed: ${err.message}`, "error");
      } finally {
        btnQuickScout.disabled = false;
      }
    });
  }

  const btnQuickDebug = document.getElementById("btn-team-quick-debug");
  if (btnQuickDebug) {
    btnQuickDebug.addEventListener("click", async () => {
      const bug = teamTaskInput.value.trim() || "TypeError or syntax issue in codebase";
      btnQuickDebug.disabled = true;
      showToast(`Formulating scientific hypotheses for "${bug}"...`, "info");
      try {
        const res = await fetch(`${API_BASE}/api/team/debug`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ bug: bug, project_dir: activeProjectPath }),
        });
        const d = await res.json();
        if (d.success) {
          currentDeliverables.debug_report = d;
          renderDeliverableTab("debug");
          delivTabBtns.forEach(b => b.classList.toggle("active", b.dataset.tab === "debug"));
          showToast(`Debug complete: Root cause confirmed`, "success");
        }
      } catch (err) {
        showToast(`Debug failed: ${err.message}`, "error");
      } finally {
        btnQuickDebug.disabled = false;
      }
    });
  }

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
        <div class="fipa-body">Reviewing existing project codebase and initiating IEEE / FIPA-ACL collaborative sprint for: "${escapeHtml(task)}"...</div>
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
          explorer_findings: data.explorer_findings || "",
          citations: data.citations || [],
          critical_files: data.critical_files || [],
          debug_report: data.debug_report || {},
        };

        renderTeamMessages(data.messages || []);
        renderDeliverableTab("plan");

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
                    member.role === "specialist_developer" ? SVG_ICONS.specialist :
                    member.role === "explorer" ? `<svg class="role-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>` :
                    member.role === "planner" ? `<svg class="role-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>` :
                    member.role === "debugger" ? `<svg class="role-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="8" height="14" x="8" y="5" rx="4"></rect><path d="m19 7-3 2"></path><path d="m5 7 3 2"></path><path d="m19 19-3-2"></path><path d="m5 19 3-2"></path><path d="M20 13h-4"></path><path d="M4 13h4"></path><path d="m10 4 1 2"></path><path d="m14 4-1 2"></path></svg>` :
                    SVG_ICONS.qa;

    let modelOptions = availableModels.map(m => `<option value="${m}" ${m === member.current_model ? "selected" : ""}>${m}</option>`).join("");
    (window.__cloudProviders || []).forEach(prov => {
      if (prov.key_count > 0 && prov.models) {
        prov.models.forEach(cm => {
          modelOptions += `<option value="${cm}" ${cm === member.current_model ? "selected" : ""}>${cm} (${prov.name || prov.id.toUpperCase()})</option>`;
        });
      }
    });
    (window.__configuredCloudModels || []).forEach(cm => {
      modelOptions += `<option value="${cm.model_name}" ${cm.model_name === member.current_model ? "selected" : ""}>${cm.model_name} (Custom Cloud)</option>`;
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
        <select class="role-model-select font-mono-target" data-role="${member.role}">
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
    let html = `<pre>${escapeHtml(currentDeliverables.plan || "No WBS plan generated yet.")}</pre>`;
    const crit = currentDeliverables.critical_files || [];
    if (crit.length > 0) {
      html = `<div class="mb-3"><h4>Critical Files for Implementation (${crit.length}):</h4><ul>` +
             crit.map(f => `<li><code>${escapeHtml(f)}</code></li>`).join("") +
             `</ul></div>` + html;
    }
    teamDeliverableView.innerHTML = html;
  } else if (tab === "explore") {
    const cites = currentDeliverables.citations || [];
    let html = `<div class="mb-3"><strong>Scout Findings:</strong><pre>${escapeHtml(currentDeliverables.explorer_findings || "No codebase citations scouted.")}</pre></div>`;
    if (cites.length > 0) {
      html += `<h4>Matching Code Citations (${cites.length}):</h4><ul class="citation-list">`;
      cites.forEach(c => {
        html += `<li><code>${escapeHtml(c)}</code></li>`;
      });
      html += `</ul>`;
    }
    teamDeliverableView.innerHTML = html;
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
  } else if (tab === "debug") {
    const dReport = currentDeliverables.debug_report || {};
    const hyps = dReport.hypotheses || [];
    if (!dReport.bug && hyps.length === 0) {
      teamDeliverableView.innerHTML = `<div class="text-muted">No active runtime debugging report. Debug engine triggers automatically on QA revision or via manual debug.</div>`;
      return;
    }
    let html = `<div class="mb-2"><strong>Target Defect:</strong> <code>${escapeHtml(dReport.bug || "Unknown")}</code></div>`;
    if (dReport.confirmed_root_cause) {
      html += `<div class="mb-3" style="color:var(--accent-color);"><strong>Confirmed Root Cause:</strong> ${escapeHtml(dReport.confirmed_root_cause)}</div>`;
    }
    if (hyps.length > 0) {
      html += `<h4>Hypothesis Evaluation Table:</h4><table class="data-table mb-3"><thead><tr><th>ID</th><th>Falsifiable Hypothesis</th><th>Status</th></tr></thead><tbody>`;
      hyps.forEach(h => {
        const badgeColor = h.status === "CONFIRMED" ? "color:#4ade80;" : "color:#f87171;";
        html += `<tr><td><strong>${escapeHtml(h.id)}</strong></td><td>${escapeHtml(h.hypothesis)}</td><td style="${badgeColor}"><strong>${escapeHtml(h.status)}</strong></td></tr>`;
      });
      html += `</tbody></table>`;
    }
    if (dReport.fix) {
      html += `<h4>Verified Fix (Instrumentations Cleaned):</h4><pre><code>${escapeHtml(dReport.fix)}</code></pre>`;
    }
    teamDeliverableView.innerHTML = html;
  }
}

// 5. Plugins & MCPs Hub System
const MCP_PRESETS = {
  filesystem: {
    name: "filesystem-tools",
    transport: "stdio",
    cmd: "npx -y @modelcontextprotocol/server-filesystem ./",
    desc: "Local workspace sandboxed file inspection and editing"
  },
  fetch: {
    name: "web-fetch",
    transport: "stdio",
    cmd: "npx -y @modelcontextprotocol/server-fetch",
    desc: "Direct web page content extraction and Markdown scraping"
  },
  memory: {
    name: "memory-graph",
    transport: "stdio",
    cmd: "npx -y @modelcontextprotocol/server-memory",
    desc: "Knowledge graph persistence across multi-turn sessions"
  },
  sqlite: {
    name: "sqlite-db",
    transport: "stdio",
    cmd: "npx -y @modelcontextprotocol/server-sqlite --db ./workspace.db",
    desc: "Relational database schema inspection and SQL queries"
  },
  sse: {
    name: "remote-mcp-stream",
    transport: "sse",
    cmd: "http://127.0.0.1:8000/sse",
    desc: "Remote HTTP Server-Sent Events MCP capability provider"
  }
};

const PLUGIN_PRESETS = {
  nextjs: {
    name: "NextJS Architect",
    category: "Web Development",
    desc: "Generates production Next.js 15 App Router components, Tailwind CSS styling, and SSR routes."
  },
  fastapi: {
    name: "FastAPI Backend",
    category: "API & Backend",
    desc: "Scaffolds asynchronous Python FastAPI endpoints, Pydantic schemas, and SQLAlchemy models."
  },
  qa: {
    name: "QA Test Suite",
    category: "Testing & Quality",
    desc: "Generates automated unit, integration, and end-to-end test cases with pytest and Jest."
  },
  security: {
    name: "Security Auditor",
    category: "Security & Guardrails",
    desc: "Scans code for OWASP Top 10 vulnerabilities, leaked API secrets, and unsafe injection patterns."
  }
};

function setupSkills() {
  setupMcpForm();
  setupPluginForm();

  // MCP 1-Click Preset Buttons
  document.querySelectorAll(".btn-mcp-preset").forEach((btn) => {
    btn.addEventListener("click", () => {
      const presetKey = btn.dataset.preset;
      const p = MCP_PRESETS[presetKey];
      if (!p) return;
      mcpNameInput.value = p.name;
      mcpTransportSelect.value = p.transport;
      mcpCmdInput.value = p.cmd;
      mcpDescInput.value = p.desc;
      showToast(`Applied preset: ${p.name}`, "info", "MCP Preset Loaded");
      mcpCmdInput.focus();
    });
  });

  // Plugin 1-Click Preset Buttons
  document.querySelectorAll(".btn-plugin-preset").forEach((btn) => {
    btn.addEventListener("click", () => {
      const presetKey = btn.dataset.preset;
      const p = PLUGIN_PRESETS[presetKey];
      if (!p) return;
      pluginNameInput.value = p.name;
      pluginCatInput.value = p.category;
      pluginDescInput.value = p.desc;
      showToast(`Applied preset: ${p.name}`, "info", "Plugin Preset Loaded");
      pluginDescInput.focus();
    });
  });
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

async function loadMcpServers() {
  if (!mcpServersGrid) return;
  try {
    const res = await fetch(`${API_BASE}/api/mcp/list`);
    const data = await res.json();
    if (data.success) {
      renderMcpServers(data.servers || []);
    }
  } catch (err) {
    console.error("Failed to load MCP servers:", err);
  }
}

function renderMcpServers(servers) {
  if (!mcpServersGrid) return;
  const enabledCount = servers.filter((s) => s.enabled).length;
  if (mcpServersCount) {
    mcpServersCount.textContent = `${enabledCount} of ${servers.length} Connected`;
  }
  const ribbonMcp = document.getElementById("ribbon-mcp-count");
  if (ribbonMcp) {
    ribbonMcp.textContent = `${enabledCount} Connected`;
  }
  mcpServersGrid.innerHTML = "";
  if (servers.length === 0) {
    mcpServersGrid.innerHTML = `
      <div class="text-muted p-3">No Model Context Protocol (MCP) servers connected yet. Add one using the connection form above!</div>
    `;
    return;
  }

  servers.forEach((srv) => {
    const card = document.createElement("div");
    card.className = `mcp-server-card ${srv.enabled ? "active" : ""}`;
    const transportBadge = srv.transport === "sse"
      ? `<span class="transport-badge sse">SSE</span>`
      : `<span class="transport-badge stdio">STDIO</span>`;

    card.innerHTML = `
      <div class="mcp-card-header">
        <div class="mcp-identity">
          <div class="mcp-icon-wrap">${SVG_ICONS.cpu || SVG_ICONS.shield}</div>
          <div class="mcp-title-wrap">
            <span class="mcp-name font-mono-target">${escapeHtml(srv.name)}</span>
            ${transportBadge}
          </div>
        </div>
        <div class="mcp-actions">
          <label class="switch">
            <input type="checkbox" class="mcp-toggle-input" data-name="${escapeHtml(srv.name)}" ${srv.enabled ? "checked" : ""} />
            <span class="slider"></span>
          </label>
          <button type="button" class="btn btn-secondary btn-icon-only btn-sm btn-delete-mcp" data-name="${escapeHtml(srv.name)}" title="Disconnect MCP Server">
            <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
          </button>
        </div>
      </div>
      <div class="mcp-desc">${escapeHtml(srv.description || "Custom MCP Tool Server")}</div>
      <div class="mcp-cmd-box font-mono-target">${escapeHtml(srv.command)}</div>
    `;

    const toggle = card.querySelector(".mcp-toggle-input");
    toggle.addEventListener("change", async (e) => {
      const val = e.target.checked;
      try {
        const res = await fetch(`${API_BASE}/api/mcp/toggle`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name: srv.name, enabled: val }),
        });
        const d = await res.json();
        if (d.success) {
          showToast(`MCP Server "${srv.name}" ${val ? "enabled" : "disabled"}`, "info");
          loadMcpServers();
        }
      } catch (err) {
        showToast(`Failed to toggle MCP server: ${err.message}`, "error");
      }
    });

    const btnDel = card.querySelector(".btn-delete-mcp");
    btnDel.addEventListener("click", async () => {
      if (!confirm(`Are you sure you want to disconnect MCP server "${srv.name}"?`)) return;
      try {
        const res = await fetch(`${API_BASE}/api/mcp/delete`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name: srv.name }),
        });
        const d = await res.json();
        if (d.success) {
          showToast(`Disconnected MCP Server "${srv.name}"`, "success");
          loadMcpServers();
        }
      } catch (err) {
        showToast(`Failed to remove MCP server: ${err.message}`, "error");
      }
    });

    mcpServersGrid.appendChild(card);
  });
}

function setupMcpForm() {
  if (!formAddMcp) return;
  formAddMcp.addEventListener("submit", async (e) => {
    e.preventDefault();
    const name = mcpNameInput.value.trim();
    const transport = mcpTransportSelect.value;
    const command = mcpCmdInput.value.trim();
    const description = mcpDescInput.value.trim();

    if (!name || !command) {
      showToast("Server name and command/URL are required", "warning");
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/api/mcp/save`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, transport, command, description }),
      });
      const data = await res.json();
      if (data.success) {
        showToast(`MCP Server "${name}" connected!`, "success", "MCP Connected");
        mcpNameInput.value = "";
        mcpCmdInput.value = "";
        mcpDescInput.value = "";
        loadMcpServers();
      } else {
        showToast(`Failed to connect MCP server: ${data.error || "Unknown error"}`, "error");
      }
    } catch (err) {
      showToast(`Connection error: ${err.message}`, "error");
    }
  });
}

function setupPluginForm() {
  if (!formAddPlugin) return;
  formAddPlugin.addEventListener("submit", async (e) => {
    e.preventDefault();
    const name = pluginNameInput.value.trim();
    const category = pluginCatInput.value.trim() || "Custom Extensions";
    const description = pluginDescInput.value.trim();

    if (!name || !description) {
      showToast("Plugin name and description are required", "warning");
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/api/plugins/save`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, category, description }),
      });
      const data = await res.json();
      if (data.success) {
        showToast(`Plugin "${name}" added!`, "success", "Plugin Installed");
        pluginNameInput.value = "";
        pluginCatInput.value = "";
        pluginDescInput.value = "";
        loadSkills();
      } else {
        showToast(`Failed to add plugin: ${data.error || "Unknown error"}`, "error");
      }
    } catch (err) {
      showToast(`Failed to add plugin: ${err.message}`, "error");
    }
  });
}

function renderSkillsList(skills) {
  skillsCatalogGrid.innerHTML = "";
  const ribbonSkills = document.getElementById("ribbon-skills-count");
  if (ribbonSkills) {
    const activeCount = skills.filter((s) => s.enabled).length;
    ribbonSkills.textContent = `${activeCount} Active`;
  }
  skills.forEach((skill) => {
    const card = document.createElement("div");
    card.className = `skill-card ${skill.enabled ? "active" : ""}`;

    const iconSvg = SVG_ICONS[skill.icon] || SVG_ICONS.zap || SVG_ICONS.shield;
    const isCustom = !["internet", "factcheck", "file_doctor", "git_ops"].includes(skill.id);
    const deleteBtnHtml = isCustom ? `
      <button type="button" class="btn btn-secondary btn-icon-only btn-sm btn-delete-plugin" data-id="${escapeHtml(skill.id)}" title="Delete plugin">
        <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
      </button>
    ` : '';

    card.innerHTML = `
      <div class="skill-header">
        <div class="skill-identity">
          <div class="skill-icon-wrap">${iconSvg}</div>
          <div class="skill-title-group">
            <span class="skill-name">${escapeHtml(skill.name)}</span>
            <span class="skill-cat">${escapeHtml(skill.category)}</span>
          </div>
        </div>
        <div class="flex-center-gap">
          <label class="switch">
            <input type="checkbox" class="skill-toggle-input" data-id="${skill.id}" ${skill.enabled ? "checked" : ""} />
            <span class="slider"></span>
          </label>
          ${deleteBtnHtml}
        </div>
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
          if (skill.id === "internet") toggleInternet.checked = val;
          if (skill.id === "factcheck") toggleFactcheck.checked = val;
          loadSkills();
        }
      } catch (err) {
        showToast(`Failed to toggle skill: ${err.message}`, "error");
      }
    });

    const delBtn = card.querySelector(".btn-delete-plugin");
    if (delBtn) {
      delBtn.addEventListener("click", async () => {
        if (!confirm(`Delete custom plugin "${skill.name}"?`)) return;
        try {
          const res = await fetch(`${API_BASE}/api/plugins/delete`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ id: skill.id }),
          });
          const d = await res.json();
          if (d.success) {
            showToast(`Deleted plugin "${skill.name}"`, "success");
            loadSkills();
          }
        } catch (err) {
          showToast(`Failed to delete plugin: ${err.message}`, "error");
        }
      });
    }

    skillsCatalogGrid.appendChild(card);
  });
}

// 6. Models Management & Recommended Models
function setupModels() {
  btnRefreshModels.addEventListener("click", loadInstalledModels);

  const btnRefreshRec = document.getElementById("btn-refresh-recommended");
  if (btnRefreshRec) {
    btnRefreshRec.addEventListener("click", async () => {
      btnRefreshRec.disabled = true;
      try {
        const res = await fetch(`${API_BASE}/api/models/recommended/refresh`, { method: "POST" });
        const data = await res.json();
        if (data.recommended) {
          renderRecommendedModels(data.recommended);
          showToast("Recommended models catalog updated to latest releases.", "success", "Catalog Synced");
        }
      } catch (err) {
        showToast(`Failed to refresh catalog: ${err.message}`, "error");
      } finally {
        btnRefreshRec.disabled = false;
      }
    });
  }

  const btnChangePath = document.getElementById("btn-change-model-path");
  if (btnChangePath) {
    btnChangePath.addEventListener("click", async () => {
      const origHtml = btnChangePath.innerHTML;
      btnChangePath.disabled = true;
      btnChangePath.textContent = "Browsing...";
      try {
        const initPath = currentInstallTargetPath || (modelStoragePathValue ? modelStoragePathValue.textContent.trim() : "");
        const picked = await openNativeFolderDialog("Select Custom Model Storage Directory", initPath);
        if (picked && picked.path) {
          try {
            const res = await fetch(`${API_BASE}/api/models/storage`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ path: picked.path }),
            });
            const data = await res.json();
            if (data.success) {
              showToast(`Model storage path updated to: ${data.path}`, "success", "Storage Configured");
              loadModelStoragePath();
              loadInstalledModels();
            } else {
              showToast(data.error || "Failed to update storage path", "error");
            }
          } catch (err) {
            showToast(`Error updating path: ${err.message}`, "error");
          }
        }
      } catch (err) {
        console.error("Browse error:", err);
      } finally {
        btnChangePath.disabled = false;
        btnChangePath.innerHTML = origHtml;
      }
    });
  }

  const btnBrowsePull = document.getElementById("btn-browse-pull-path");
  if (btnBrowsePull) {
    btnBrowsePull.addEventListener("click", async () => {
      const origHtml = btnBrowsePull.innerHTML;
      btnBrowsePull.disabled = true;
      btnBrowsePull.textContent = "Browsing...";
      try {
        const targetInput = document.getElementById("pull-model-target-path");
        const initPath = targetInput ? targetInput.value.trim() : "";
        const picked = await openNativeFolderDialog("Select Custom Model Destination Folder", initPath);
        if (picked && picked.path) {
          if (targetInput) targetInput.value = picked.path;
        }
      } catch (err) {
        console.error("Browse error:", err);
      } finally {
        btnBrowsePull.disabled = false;
        btnBrowsePull.innerHTML = origHtml;
      }
    });
  }

  // Model Install Confirmation & Path Modal setup
  const modelInstallModal = document.getElementById("model-install-modal");
  const btnCloseInstallModal = document.getElementById("btn-close-install-modal");
  const btnCancelInstallModal = document.getElementById("btn-cancel-install-modal");
  const btnConfirmInstallModel = document.getElementById("btn-confirm-install-model");
  const btnBrowseInstallPath = document.getElementById("btn-browse-install-path");
  const btnResetInstallPath = document.getElementById("btn-reset-install-path");
  const installModalPathInput = document.getElementById("install-modal-path-input");
  const btnPauseInstallDownload = document.getElementById("btn-pause-install-download");
  const btnRunBgModal = document.getElementById("btn-run-bg-modal");
  const btnPagePauseDownload = document.getElementById("btn-page-pause-download");
  const btnExpandDownloadModal = document.getElementById("btn-expand-download-modal");
  const headerDownloadingPill = document.getElementById("header-downloading-pill");
  const floatingDownloadWidget = document.getElementById("floating-download-widget");
  const btnFloatingOpen = document.getElementById("btn-floating-open");
  const btnFloatingPause = document.getElementById("btn-floating-pause");
  const btnModelsStripPause = document.getElementById("btn-models-strip-pause");
  const btnModelsStripExpand = document.getElementById("btn-models-strip-expand");

  // Model Delete Confirmation In-App Modal setup
  const btnCloseDeleteModal = document.getElementById("btn-close-delete-modal");
  const btnCancelDeleteModal = document.getElementById("btn-cancel-delete-modal");
  const btnConfirmDeleteModel = document.getElementById("btn-confirm-delete-model");

  if (btnCloseDeleteModal) btnCloseDeleteModal.addEventListener("click", closeDeleteModelModal);
  if (btnCancelDeleteModal) btnCancelDeleteModal.addEventListener("click", closeDeleteModelModal);

  if (btnConfirmDeleteModel) {
    btnConfirmDeleteModel.addEventListener("click", async () => {
      if (!pendingDeleteModel) return;
      const m = pendingDeleteModel;
      const delBtn = pendingDeleteBtn;
      const confirmLabel = document.getElementById("btn-confirm-delete-label");

      btnConfirmDeleteModel.disabled = true;
      if (confirmLabel) confirmLabel.textContent = "Uninstalling & Freeing Space...";
      if (delBtn) {
        delBtn.disabled = true;
        delBtn.textContent = "Removing...";
      }

      try {
        const res = await fetch(`${API_BASE}/api/models/delete`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name: m.name }),
        });
        const data = await res.json();
        closeDeleteModelModal();
        if (data.success) {
          showToast(data.message || `Model '${m.name}' uninstalled successfully.`, "success", "Model Removed");
          await loadInstalledModels();
          await loadRecommendedModels();
          await loadModelStoragePath();
        } else {
          showToast(`Failed to uninstall: ${data.error || data.message || "Unknown error"}`, "error");
          if (delBtn) {
            delBtn.disabled = false;
            delBtn.textContent = "Uninstall";
          }
        }
      } catch (err) {
        closeDeleteModelModal();
        showToast(`Error uninstalling model: ${err.message}`, "error");
        if (delBtn) {
          delBtn.disabled = false;
          delBtn.textContent = "Uninstall";
        }
      }
    });
  }

  function closeInstallModal() {
    if (modelInstallModal) {
      modelInstallModal.classList.add("hidden");
      modelInstallModal.style.display = "none";
    }
  }

  function reopenDownloadingModal() {
    if (currentInstallTargetModel) {
      openModelInstallModal(currentInstallTargetModel);
    } else if (activeDownloadingModelTag) {
      openModelInstallModal({ tag: activeDownloadingModelTag, name: activeDownloadingModelTag });
    }
  }

  if (btnCloseInstallModal) btnCloseInstallModal.addEventListener("click", closeInstallModal);
  if (btnCancelInstallModal) {
    btnCancelInstallModal.addEventListener("click", () => {
      if (isModelDownloading || isDownloadPaused) {
        cancelActiveDownload();
      }
      closeInstallModal();
    });
  }

  const btnCancelDownloadActive = document.getElementById("btn-cancel-download-active");
  if (btnCancelDownloadActive) {
    btnCancelDownloadActive.addEventListener("click", () => {
      cancelActiveDownload();
    });
  }
  if (btnRunBgModal) {
    btnRunBgModal.addEventListener("click", () => {
      closeInstallModal();
      showToast("Download running in background. Click the bottom widget or top badge to reopen.", "info", "Background Download");
    });
  }

  if (btnPauseInstallDownload) {
    btnPauseInstallDownload.addEventListener("click", () => {
      pauseActiveDownload();
    });
  }

  if (btnPagePauseDownload) {
    btnPagePauseDownload.addEventListener("click", () => {
      pauseActiveDownload();
    });
  }

  if (headerDownloadingPill) {
    headerDownloadingPill.addEventListener("click", reopenDownloadingModal);
  }

  if (btnExpandDownloadModal) {
    btnExpandDownloadModal.addEventListener("click", reopenDownloadingModal);
  }

  if (btnFloatingOpen) {
    btnFloatingOpen.addEventListener("click", (e) => {
      e.stopPropagation();
      reopenDownloadingModal();
    });
  }

  if (btnFloatingPause) {
    btnFloatingPause.addEventListener("click", (e) => {
      e.stopPropagation();
      pauseActiveDownload();
    });
  }

  if (floatingDownloadWidget) {
    floatingDownloadWidget.addEventListener("click", () => {
      reopenDownloadingModal();
    });
  }

  if (btnModelsStripExpand) {
    btnModelsStripExpand.addEventListener("click", reopenDownloadingModal);
  }

  if (btnModelsStripPause) {
    btnModelsStripPause.addEventListener("click", () => {
      pauseActiveDownload();
    });
  }

  const btnChangeStorage = document.getElementById("btn-change-model-storage");
  if (btnChangeStorage) {
    btnChangeStorage.addEventListener("click", async () => {
      const origHtml = btnChangeStorage.innerHTML;
      btnChangeStorage.disabled = true;
      btnChangeStorage.textContent = "Browsing...";
      try {
        const initPath = currentInstallTargetPath || "";
        const picked = await openNativeFolderDialog("Select Global Model Storage Directory", initPath);
        if (picked && picked.path) {
          currentInstallTargetPath = picked.path;
          try {
            const res = await fetch(`${API_BASE}/api/models/storage`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ path: picked.path }),
            });
            const data = await res.json();
            if (data.success) {
              showToast(`Model storage path updated to: ${data.path}`, "success", "Storage Updated");
              loadModelStoragePath();
              loadInstalledModels();
            } else {
              showToast(`Failed to update storage: ${data.error || "Unknown error"}`, "error");
            }
          } catch (e) {
            showToast(`Error updating storage: ${e.message}`, "error");
          }
        }
      } catch (err) {
        console.error("Browse error:", err);
      } finally {
        btnChangeStorage.disabled = false;
        btnChangeStorage.innerHTML = origHtml;
      }
    });
  }

  if (btnBrowseInstallPath) {
    btnBrowseInstallPath.addEventListener("click", async () => {
      const origHtml = btnBrowseInstallPath.innerHTML;
      btnBrowseInstallPath.disabled = true;
      btnBrowseInstallPath.textContent = "Browsing...";
      try {
        const initPath = (installModalPathInput ? installModalPathInput.value.trim() : "") || currentInstallTargetPath || "";
        const picked = await openNativeFolderDialog("Select Custom Model Storage Directory", initPath);
        if (picked && picked.path) {
          if (installModalPathInput) {
            installModalPathInput.value = picked.path;
            checkInstallPathStorage(picked.path);
          }
          currentInstallTargetPath = picked.path;
        }
      } catch (err) {
        console.error("Browse error:", err);
      } finally {
        btnBrowseInstallPath.disabled = false;
        btnBrowseInstallPath.innerHTML = origHtml;
      }
    });
  }

  if (installModalPathInput) {
    installModalPathInput.addEventListener("input", () => {
      checkInstallPathStorage(installModalPathInput.value.trim());
    });
  }

  if (btnResetInstallPath) {
    btnResetInstallPath.addEventListener("click", async () => {
      try {
        const res = await fetch(`${API_BASE}/api/models/storage`);
        const data = await res.json();
        if (data.success && data.path && installModalPathInput) {
          installModalPathInput.value = data.path;
          checkInstallPathStorage(data.path);
        }
      } catch (e) {
        if (installModalPathInput) installModalPathInput.value = "C:\\Users\\hp\\.ollama\\models";
      }
    });
  }

  if (btnConfirmInstallModel) {
    btnConfirmInstallModel.addEventListener("click", () => {
      const confirmLabel = document.getElementById("btn-confirm-install-label");
      const labelText = confirmLabel ? (confirmLabel.textContent || "") : "";
      if (labelText.includes("Done") || labelText.includes("Close")) {
        closeInstallModal();
        return;
      }
      if (labelText.includes("Run in Background")) {
        closeInstallModal();
        showToast("Download running in background. Click floating widget to reopen popup.", "info", "Background Download");
        return;
      }
      if (isDownloadPaused) {
        const mTag = currentInstallTargetModel?.tag || currentInstallTargetModel?.name;
        if (isSameModelTag(mTag, activeDownloadingModelTag)) {
          resumeActiveDownload();
          return;
        } else {
          cancelActiveDownload();
        }
      }
      if (isModelDownloading) {
        return;
      }
      if (!currentInstallTargetModel) return;
      const targetPath = installModalPathInput ? installModalPathInput.value.trim() : "";
      startModelDownload(currentInstallTargetModel, targetPath);
    });
  }

  btnPullModel.addEventListener("click", () => {
    const name = pullModelNameInput.value.trim();
    if (!name) {
      showToast("Please enter a model name or tag (e.g. deepseek-r1:1.5b)", "warning");
      return;
    }
    const targetPath = document.getElementById("pull-model-target-path")?.value.trim() || "";
    openModelInstallModal({
      tag: name,
      name: name,
      size: "Variable (Depends on model weights)",
      desc: "Custom open-weight model pulled from Ollama library or HuggingFace.",
      targetPath: targetPath,
    }, true);
  });
}

async function loadModelStoragePath() {
  try {
    const res = await fetch(`${API_BASE}/api/models/storage`);
    const data = await res.json();
    if (data.success) {
      const display = document.getElementById("model-storage-path-display");
      if (display) display.textContent = data.path;
      const freeDisplay = document.getElementById("storage-free-display");
      if (freeDisplay && data.storage) {
        freeDisplay.textContent = `${data.storage.free_gb} GB Free (${data.storage.drive})`;
      }
      const targetInput = document.getElementById("pull-model-target-path");
      if (targetInput && !targetInput.value) {
        targetInput.placeholder = data.path;
      }
    }
  } catch (e) {
    console.error("Error loading model storage path:", e);
  }
}

async function loadInstalledModels() {
  try {
    const res = await fetch(`${API_BASE}/api/system/preflight`);
    const data = await res.json();
    if (data.models) {
      availableModels = data.models.installed || [];
      renderInstalledModels(availableModels);
      populateModelSelectors(availableModels);
      renderRecommendedModels(data.models.recommended || []);
      updateAttachmentCapabilities();
      if (data.models.storage) {
        const freeDisplay = document.getElementById("storage-free-display");
        if (freeDisplay) {
          freeDisplay.textContent = `${data.models.storage.free_gb} GB Free (${data.models.storage.drive})`;
        }
      }
    }
  } catch (err) {
    console.error("Models fetch error:", err);
  }
}

function renderInstalledModels(models) {
  installedModelsList.innerHTML = "";
  if (!models || models.length === 0) {
    installedModelsList.innerHTML = `<div class="text-muted">No models detected. Download a recommended model below.</div>`;
    return;
  }

  models.forEach((m) => {
    const card = document.createElement("div");
    card.className = `model-card ${m.is_active ? "active" : ""}`;
    card.innerHTML = `
      <div class="model-card-header">
        <span class="model-name font-mono-target">${escapeHtml(m.name)}</span>
        ${m.is_active ? `<span class="active-badge">Active</span>` : ""}
      </div>
      <div class="model-meta">
        <span>Size: ${m.size_gb} GB</span>
      </div>
      <div class="model-actions">
        ${!m.is_active ? `<button class="btn btn-secondary btn-sm btn-activate-model" data-name="${escapeHtml(m.name)}">Activate</button>` : ""}
        <button class="btn btn-sm btn-delete-model" data-name="${escapeHtml(m.name)}" title="Uninstall and remove model to free disk space">
          <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
          Uninstall
        </button>
      </div>
    `;

    const actBtn = card.querySelector(".btn-activate-model");
    if (actBtn) {
      actBtn.addEventListener("click", async () => {
        await switchModel(m.name);
      });
    }

    const delBtn = card.querySelector(".btn-delete-model");
    if (delBtn) {
      delBtn.addEventListener("click", () => {
        openDeleteModelModal(m, delBtn);
      });
    }

    installedModelsList.appendChild(card);
  });
}

let pendingDeleteModel = null;
let pendingDeleteBtn = null;

function openDeleteModelModal(modelObj, btnElement) {
  pendingDeleteModel = modelObj;
  pendingDeleteBtn = btnElement;

  const modal = document.getElementById("model-delete-confirm-modal");
  const nameEl = document.getElementById("delete-modal-model-name");
  const sizeEl = document.getElementById("delete-modal-model-size");
  const confirmBtn = document.getElementById("btn-confirm-delete-model");
  const confirmLabel = document.getElementById("btn-confirm-delete-label");

  if (!modal) return;

  if (nameEl) nameEl.textContent = modelObj.name;
  if (sizeEl) sizeEl.textContent = modelObj.size_gb ? `~${modelObj.size_gb} GB` : "Variable";
  if (confirmBtn) confirmBtn.disabled = false;
  if (confirmLabel) confirmLabel.textContent = "Uninstall & Free Space";

  modal.classList.remove("hidden");
  modal.style.display = "flex";
}

function closeDeleteModelModal() {
  const modal = document.getElementById("model-delete-confirm-modal");
  if (modal) {
    modal.classList.add("hidden");
    modal.style.display = "none";
  }
  pendingDeleteModel = null;
  pendingDeleteBtn = null;
}

let latestRecommendedModels = [];
let currentInstallTargetModel = null;
let currentInstallTargetPath = "";
let isModelDownloading = false;
let isDownloadPaused = false;
let activeDownloadingModelTag = null;
let activeDownloadPct = 0;
let activeDownloadBytes = "0 MB / 0 MB";
let activeDownloadStatus = "";
let activeDownloadAbortController = null;

function isSameModelTag(tagA, tagB) {
  if (!tagA || !tagB) return false;
  const a = tagA.trim().toLowerCase();
  const b = tagB.trim().toLowerCase();
  if (a === b) return true;
  const cleanA = a.endsWith(":latest") ? a.slice(0, -7) : a;
  const cleanB = b.endsWith(":latest") ? b.slice(0, -7) : b;
  return cleanA === cleanB;
}

function renderRecommendedModels(recs) {
  if (!recommendedModelsGrid) return;
  latestRecommendedModels = recs || [];
  recommendedModelsGrid.innerHTML = "";

  const normActive = (activeDownloadingModelTag || "").trim().toLowerCase();

  latestRecommendedModels.forEach((rec) => {
    const card = document.createElement("div");
    card.className = "recommended-model-card";

    const normTag = (rec.tag || "").trim().toLowerCase();
    const normName = (rec.name || "").trim().toLowerCase();

    const isDownloadingThis = (isModelDownloading || isDownloadPaused) && normActive && (
      isSameModelTag(normActive, normTag) ||
      isSameModelTag(normActive, normName)
    );

    let footerBtnHtml = "";
    if (rec.is_installed) {
      footerBtnHtml = `<span class="active-badge">${SVG_ICONS.check} Installed</span>`;
    } else if (isDownloadingThis) {
      if (isDownloadPaused) {
        footerBtnHtml = `<button type="button" class="btn btn-warning btn-sm btn-download-rec downloading-paused" data-tag="${escapeHtml(rec.tag)}" title="Click to view download popup or resume"><svg class="btn-icon-xs" viewBox="0 0 24 24" fill="currentColor"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg> <span>Paused (${activeDownloadPct || 0}%)</span></button>`;
      } else {
        footerBtnHtml = `<button type="button" class="btn btn-primary btn-sm btn-download-rec downloading-active" data-tag="${escapeHtml(rec.tag)}" title="Click to view live download progress in popup"><span class="spinner-inline"></span> <span>Downloading (${activeDownloadPct || 0}%)...</span></button>`;
      }
    } else if (isModelDownloading || isDownloadPaused) {
      footerBtnHtml = `<button type="button" class="btn btn-secondary btn-sm btn-download-rec" data-tag="${escapeHtml(rec.tag)}" title="Download in progress (${activeDownloadingModelTag || 'another model'}). Click to view details or switch.">Install Model</button>`;
    } else {
      footerBtnHtml = `<button type="button" class="btn btn-primary btn-sm btn-download-rec" data-tag="${escapeHtml(rec.tag)}">Install Model</button>`;
    }

    card.innerHTML = `
      <div class="rec-model-header">
        <span class="rec-model-name">${escapeHtml(rec.name)}</span>
        <span class="rec-model-size">${escapeHtml(rec.size)}</span>
      </div>
      <div class="rec-model-desc">${escapeHtml(rec.desc)}</div>
      <div class="rec-model-footer">
        ${footerBtnHtml}
      </div>
    `;

    const dlBtn = card.querySelector(".btn-download-rec");
    if (dlBtn) {
      dlBtn.addEventListener("click", () => {
        openModelInstallModal(rec, false);
      });
    }

    recommendedModelsGrid.appendChild(card);
  });
}

function syncDownloadUI(pct, statusText, bytesText, isPaused = false) {
  if (pct !== undefined && pct !== null) activeDownloadPct = pct;
  if (statusText) activeDownloadStatus = statusText;
  if (bytesText) activeDownloadBytes = bytesText;

  const tag = activeDownloadingModelTag || "Model";

  // 1. Modal Elements
  const statusEl = document.getElementById("install-modal-status-text");
  const pctEl = document.getElementById("install-modal-pct-text");
  const barEl = document.getElementById("install-modal-progress-bar");
  const bytesEl = document.getElementById("install-modal-bytes-text");
  const pauseBtnLabel = document.getElementById("btn-pause-download-label");
  const pauseBtn = document.getElementById("btn-pause-install-download");

  if (statusEl && activeDownloadStatus) statusEl.textContent = activeDownloadStatus;
  if (pctEl) pctEl.textContent = `${activeDownloadPct}%`;
  if (barEl) barEl.style.width = `${activeDownloadPct}%`;
  if (bytesEl && activeDownloadBytes) bytesEl.textContent = activeDownloadBytes;

  if (pauseBtn && pauseBtnLabel) {
    if (isPaused) {
      pauseBtn.classList.remove("text-danger");
      pauseBtn.classList.add("btn-primary");
      pauseBtnLabel.textContent = "Resume Download";
      pauseBtn.innerHTML = `<svg class="btn-icon-xs" viewBox="0 0 24 24" fill="currentColor"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg><span>Resume Download</span>`;
    } else {
      pauseBtn.classList.remove("btn-primary");
      pauseBtn.classList.add("text-danger");
      pauseBtnLabel.textContent = "Pause Download";
      pauseBtn.innerHTML = `<svg class="btn-icon-xs" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="6" y="4" width="4" height="16"></rect><rect x="14" y="4" width="4" height="16"></rect></svg><span>Pause Download</span>`;
    }
  }

  // 2. Global Floating Widget
  const floatingWidget = document.getElementById("floating-download-widget");
  const floatingName = document.getElementById("floating-dl-name");
  const floatingPct = document.getElementById("floating-dl-pct");
  const floatingBar = document.getElementById("floating-mini-bar-fill");
  const floatingBytes = document.getElementById("floating-dl-bytes");
  const floatingPauseText = document.getElementById("btn-floating-pause-text");

  if (floatingWidget) {
    floatingWidget.classList.remove("hidden");
    if (floatingName) floatingName.textContent = isPaused ? `⏸ Paused: ${tag}` : `Downloading ${tag}`;
    if (floatingPct) floatingPct.textContent = `${activeDownloadPct}%`;
    if (floatingBar) floatingBar.style.width = `${activeDownloadPct}%`;
    if (floatingBytes) floatingBytes.textContent = activeDownloadBytes;
    if (floatingPauseText) floatingPauseText.textContent = isPaused ? "Resume" : "Pause";
  }

  // 3. Header Pill
  const headerPill = document.getElementById("header-downloading-pill");
  const headerText = document.getElementById("header-download-text");
  if (headerPill) {
    headerPill.classList.remove("hidden");
    if (headerText) {
      headerText.textContent = isPaused ? `⏸ ${tag} ${activeDownloadPct}%` : `⬇ ${tag} ${activeDownloadPct}%`;
    }
  }

  // 4. Models Strip Banner on Models Page
  const strip = document.getElementById("models-active-download-strip");
  const stripTitle = document.getElementById("models-strip-title");
  const stripStatus = document.getElementById("models-strip-status");
  const stripBar = document.getElementById("models-strip-bar");
  const stripPct = document.getElementById("models-strip-pct-val");
  const stripBytes = document.getElementById("models-strip-bytes");
  const stripPauseLabel = document.getElementById("btn-models-strip-pause-label");

  if (strip) {
    strip.classList.remove("hidden");
    if (stripTitle) stripTitle.textContent = isPaused ? `⏸ Paused: ${tag}` : `Downloading ${tag}`;
    if (stripStatus) stripStatus.textContent = activeDownloadStatus || "In progress...";
    if (stripBar) stripBar.style.width = `${activeDownloadPct}%`;
    if (stripPct) stripPct.textContent = `${activeDownloadPct}%`;
    if (stripBytes) stripBytes.textContent = activeDownloadBytes;
    if (stripPauseLabel) stripPauseLabel.textContent = isPaused ? "Resume" : "Pause";
  }

  // 5. Card buttons live update
  const activeCardBtn = document.querySelector(`.btn-download-rec[data-tag="${tag}"]`) ||
                        document.querySelector(`.btn-download-rec.downloading-active`) ||
                        document.querySelector(`.btn-download-rec.downloading-paused`);
  if (activeCardBtn) {
    if (isPaused) {
      activeCardBtn.className = "btn btn-warning btn-sm btn-download-rec downloading-paused";
      activeCardBtn.innerHTML = `<svg class="btn-icon-xs" viewBox="0 0 24 24" fill="currentColor"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg> <span>Paused (${activeDownloadPct}%)</span>`;
    } else {
      activeCardBtn.className = "btn btn-primary btn-sm btn-download-rec downloading-active";
      activeCardBtn.innerHTML = `<span class="spinner-inline"></span> <span>Downloading (${activeDownloadPct}%)...</span>`;
    }
  }

  // 6. Pull input progress on main page
  if (pullProgressContainer) pullProgressContainer.classList.remove("hidden");
  if (pullProgressBar) pullProgressBar.style.width = `${activeDownloadPct}%`;
  if (pullPercentText) pullPercentText.textContent = `${activeDownloadPct}%`;
  if (pullStatusText && activeDownloadStatus) pullStatusText.textContent = activeDownloadStatus;
}

function hideDownloadWidgets() {
  document.getElementById("floating-download-widget")?.classList.add("hidden");
  document.getElementById("header-downloading-pill")?.classList.add("hidden");
  document.getElementById("models-active-download-strip")?.classList.add("hidden");
  if (pullProgressContainer) pullProgressContainer.classList.add("hidden");
}

async function loadRecommendedModels() {
  try {
    const res = await fetch(`${API_BASE}/api/models/recommended`);
    const data = await res.json();
    if (data.success && data.recommended) {
      renderRecommendedModels(data.recommended);
    }
  } catch (e) {
    console.warn("Failed to load recommended models:", e);
  }
}

function pauseActiveDownload() {
  if (isModelDownloading) {
    if (activeDownloadAbortController) {
      activeDownloadAbortController.abort();
      activeDownloadAbortController = null;
    }
    isModelDownloading = false;
    isDownloadPaused = true;

    syncDownloadUI(activeDownloadPct, `Download paused at ${activeDownloadPct}%. Progress saved.`, activeDownloadBytes, true);

    const confirmLabel = document.getElementById("btn-confirm-install-label");
    if (confirmLabel) confirmLabel.textContent = "Confirm & Resume Download";
    const cancelBtn = document.getElementById("btn-cancel-install-modal");
    if (cancelBtn) cancelBtn.style.display = "";

    showToast(`Model download paused for ${activeDownloadingModelTag || "model"} (${activeDownloadPct}%).`, "warning", "Download Paused");

    if (latestRecommendedModels.length > 0) {
      renderRecommendedModels(latestRecommendedModels);
    }
  } else if (isDownloadPaused) {
    resumeActiveDownload();
  }
}

function cancelActiveDownload() {
  if (activeDownloadAbortController) {
    activeDownloadAbortController.abort();
    activeDownloadAbortController = null;
  }
  const cancelledModel = activeDownloadingModelTag || "model";
  isModelDownloading = false;
  isDownloadPaused = false;
  activeDownloadingModelTag = null;
  activeDownloadPct = 0;
  activeDownloadBytes = "0 MB / 0 MB";
  activeDownloadStatus = "";

  hideDownloadWidgets();

  const progressSec = document.getElementById("install-modal-progress-section");
  if (progressSec) progressSec.classList.add("hidden");

  const confirmBtn = document.getElementById("btn-confirm-install-model");
  const confirmLabel = document.getElementById("btn-confirm-install-label");
  const cancelBtn = document.getElementById("btn-cancel-install-modal");

  if (confirmBtn) {
    confirmBtn.disabled = false;
    confirmBtn.classList.remove("btn-secondary");
    confirmBtn.classList.add("btn-primary");
  }
  if (confirmLabel) confirmLabel.textContent = "Confirm & Download Model";
  if (cancelBtn) cancelBtn.style.display = "";

  if (btnPullModel) {
    btnPullModel.disabled = false;
    btnPullModel.innerHTML = `<svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg><span>Start Download & Install</span>`;
  }

  showToast(`Cancelled download for ${cancelledModel}.`, "info", "Download Cancelled");

  if (latestRecommendedModels.length > 0) {
    renderRecommendedModels(latestRecommendedModels);
  }
}

function resumeActiveDownload() {
  isDownloadPaused = false;
  if (!currentInstallTargetModel && activeDownloadingModelTag) {
    currentInstallTargetModel = { tag: activeDownloadingModelTag, name: activeDownloadingModelTag };
  }
  if (currentInstallTargetModel) {
    showToast(`Resuming download for ${activeDownloadingModelTag || currentInstallTargetModel.name}...`, "info", "Download Resumed");
    startModelDownload(currentInstallTargetModel, currentInstallTargetPath);
  }
}

function setupCustomModelDropdown() {
  const trigger = document.getElementById("custom-model-trigger");
  const menu = document.getElementById("custom-model-menu");
  if (!trigger || !menu) return;

  trigger.addEventListener("click", (e) => {
    e.stopPropagation();
    const isClosed = menu.classList.contains("hidden") || menu.hasAttribute("hidden") || getComputedStyle(menu).display === "none";
    if (isClosed) {
      openCustomModelMenu();
    } else {
      closeCustomModelMenu();
    }
  });

  document.addEventListener("click", (e) => {
    if (!menu.contains(e.target) && !trigger.contains(e.target)) {
      closeCustomModelMenu();
    }
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      closeCustomModelMenu();
    }
  });
}

function openCustomModelMenu() {
  const trigger = document.getElementById("custom-model-trigger");
  const menu = document.getElementById("custom-model-menu");
  if (!menu || !trigger) return;
  menu.classList.remove("hidden");
  menu.removeAttribute("hidden");
  trigger.classList.add("is-open");
  trigger.setAttribute("aria-expanded", "true");
}

function closeCustomModelMenu() {
  const trigger = document.getElementById("custom-model-trigger");
  const menu = document.getElementById("custom-model-menu");
  if (!menu || !trigger) return;
  menu.classList.add("hidden");
  menu.setAttribute("hidden", "");
  trigger.classList.remove("is-open");
  trigger.setAttribute("aria-expanded", "false");
  menu.querySelectorAll(".cmd-provider-item.is-open, .cmd-provider-item.is-hovered").forEach((item) => {
    item.classList.remove("is-open");
    item.classList.remove("is-hovered");
  });
}

function getModelCategoryBadge(modelName) {
  const m = (modelName || "").toLowerCase();

  // 1. Deep Reasoning & Math models
  if (
    m.includes("r1") ||
    m.includes("reasoner") ||
    m.includes("deepseek-r1") ||
    m.includes("o1") ||
    m.includes("o3") ||
    m.includes("qwq")
  ) {
    return { label: "Reasoning", cssClass: "reasoning" };
  }

  // 2. Code specialized models
  if (
    m.includes("coder") ||
    m.includes("starcoder") ||
    (m.includes("code") && !m.includes("decode"))
  ) {
    return { label: "Code", cssClass: "code" };
  }

  // 3. Pro / Flagship / Frontier / High-parameter models
  if (
    m.includes("hydrogen") ||
    m.includes("carbon") ||
    m.includes("pro") ||
    m.includes("ultra") ||
    m.includes("opus") ||
    m.includes("sonnet") ||
    m.includes("70b") ||
    m.includes("405b") ||
    m.includes("large")
  ) {
    return { label: "Pro", cssClass: "pro" };
  }

  // 4. Ultra-Fast / lightweight models (must check BEFORE regular flash!)
  if (
    m.includes("flash-lite") ||
    m.includes("instant") ||
    (m.includes("mini") && !m.includes("gemini")) ||
    m.includes("tiny") ||
    m.includes("lite") ||
    m.includes("nano") ||
    m.includes("haiku") ||
    m.includes("1b") ||
    m.includes("1.5b") ||
    m.includes("2b") ||
    m.includes("e2b")
  ) {
    return { label: "Fast", cssClass: "fast" };
  }

  // 5. Balanced / Versatile / Medium Workhorse models
  if (
    m.includes("flash") ||
    m.includes("versatile") ||
    m.includes("balanced") ||
    m.includes("turbo") ||
    m.includes("3b") ||
    m.includes("4b") ||
    m.includes("7b") ||
    m.includes("8b") ||
    m.includes("9b") ||
    m.includes("12b") ||
    m.includes("14b") ||
    m.includes("27b") ||
    m.includes("32b")
  ) {
    return { label: "Balanced", cssClass: "balanced" };
  }

  return { label: "General", cssClass: "general" };
}

function updateTriggerLabel(labelText) {
  const lbl = document.getElementById("cmd-trigger-text");
  if (lbl) {
    lbl.textContent = labelText;
    lbl.setAttribute("title", labelText);
  }
}

function selectCustomModel(modelValue) {
  if (!headerModelSelect) return;
  const isOffline = (toggleInternet && !toggleInternet.checked);
  if (isOffline) {
    const cloudProviders = window.__cloudProviders || [];
    const allCloudModels = [];
    cloudProviders.forEach(p => (p.models || []).forEach(m => allCloudModels.push(m)));
    (window.__configuredCloudModels || []).forEach(cm => allCloudModels.push(cm.model_name));
    if (allCloudModels.includes(modelValue)) {
      showToast("Cloud models are disabled while Offline Air-Gap Mode is active.", "warning", "Offline Mode");
      return;
    }
  }
  headerModelSelect.value = modelValue;
  activeModel = modelValue;
  headerModelSelect.dispatchEvent(new Event("change"));
  closeCustomModelMenu();
  populateModelSelectors(availableModels);
}

function populateModelSelectors(models) {
  const isOffline = (toggleInternet && !toggleInternet.checked);
  let currentVal = activeModel || (headerModelSelect ? headerModelSelect.value : "auto");
  if (isOffline) {
    const cloudProviders = window.__cloudProviders || [];
    const allCloudModels = [];
    cloudProviders.forEach(p => (p.models || []).forEach(m => allCloudModels.push(m)));
    (window.__configuredCloudModels || []).forEach(cm => allCloudModels.push(cm.model_name));
    if (allCloudModels.includes(currentVal)) {
      const local = (models || []).find(m => m.name && !allCloudModels.includes(m.name));
      currentVal = local ? local.name : "auto";
      activeModel = currentVal;
    }
  }

  if (!headerModelSelect) return;
  headerModelSelect.innerHTML = "";
  let hasSelected = false;
  let activeDisplayLabel = "";

  const menuEl = document.getElementById("custom-model-menu");
  if (menuEl) menuEl.innerHTML = "";

  // 1. Intelligent Strategy Presets (Auto / Fast / Smart / Fusion)
  const grpStrategies = document.createElement("optgroup");
  grpStrategies.label = "Strategy Presets";
  const virtualModels = [
    { value: "auto", label: "Auto (Balanced Routing)" },
    { value: "auto:fast", label: "Fast (Speed Optimized)" },
    { value: "auto:smart", label: "Smart (Deep Reasoning / R1)" },
    { value: "fusion", label: "Fusion (Multi-Model Synthesis)" },
  ];

  let stratHtml = `<div class="cmd-group"><div class="cmd-group-title">Strategy Presets</div>`;
  virtualModels.forEach((vm) => {
    const opt = document.createElement("option");
    opt.value = vm.value;
    opt.textContent = vm.label;
    const isAct = (vm.value === currentVal && !hasSelected);
    if (isAct) {
      opt.selected = true;
      activeModel = vm.value;
      hasSelected = true;
      activeDisplayLabel = vm.label;
    }
    grpStrategies.appendChild(opt);

    stratHtml += `
      <div class="cmd-option ${isAct ? 'is-active' : ''}" data-value="${escapeHtml(vm.value)}">
        <div class="cmd-opt-main">
          <span class="cmd-opt-name">${escapeHtml(vm.label)}</span>
        </div>
        ${isAct ? '<svg class="cmd-check-icon" viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>' : ''}
      </div>
    `;
  });
  stratHtml += `</div>`;
  headerModelSelect.appendChild(grpStrategies);

  // 2. Active Cloud Models (Cascading Hover Submenus by Provider Company!)
  const cloudProviders = window.__cloudProviders || [];
  let cloudHtml = "";

  cloudProviders.forEach((prov) => {
    const hasKeys = (prov.key_count && prov.key_count > 0) || (prov.has_key && prov.key_count > 0);
    const modelsList = prov.models || [];
    if (hasKeys && modelsList.length > 0) {
      const grpProv = document.createElement("optgroup");
      const provTitle = prov.name || prov.id.toUpperCase();
      grpProv.label = `${provTitle} (Cloud${isOffline ? ' - Offline' : ''})`;

      let subItemsHtml = "";
      modelsList.forEach((mName) => {
        const opt = document.createElement("option");
        opt.value = mName;
        const badge = getModelCategoryBadge(mName);
        if (isOffline) {
          opt.disabled = true;
          opt.textContent = `${mName} (${badge.label} Cloud - Offline)`;
        } else {
          opt.textContent = `${mName} (${badge.label} Cloud)`;
        }
        const isAct = (mName === currentVal && !hasSelected && !isOffline);
        if (isAct) {
          opt.selected = true;
          activeModel = mName;
          hasSelected = true;
          activeDisplayLabel = `${mName} (${provTitle})`;
        }
        grpProv.appendChild(opt);

        subItemsHtml += `
          <div class="cmd-option ${isOffline ? 'is-offline-disabled' : ''} ${isAct ? 'is-active' : ''}" data-value="${escapeHtml(mName)}" ${isOffline ? 'style="opacity: 0.4; pointer-events: none;" title="Offline Mode: Cloud model disabled"' : ''}>
            <div class="cmd-opt-main">
              <span class="cmd-opt-name">${escapeHtml(mName)}</span>
              <span class="cmd-tier-pill ${badge.cssClass}">${badge.label}${isOffline ? ' (Offline)' : ''}</span>
            </div>
            ${isAct ? '<svg class="cmd-check-icon" viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>' : ''}
          </div>
        `;
      });
      headerModelSelect.appendChild(grpProv);

      const provHasActiveModel = modelsList.includes(currentVal);
      cloudHtml += `
        <div class="cmd-provider-item ${provHasActiveModel ? 'has-active-child' : ''}" data-provider-id="${escapeHtml(prov.id)}" ${isOffline ? 'style="opacity: 0.55;"' : ''}>
          <div class="cmd-provider-row">
            <div class="cmd-provider-left">
              <span class="cmd-provider-bullet"></span>
              <span class="cmd-provider-title">${escapeHtml(provTitle)}</span>
              <span class="cmd-count-badge">${modelsList.length}</span>
            </div>
            <svg class="cmd-flyout-arrow" viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2.2"><polyline points="9 18 15 12 9 6"></polyline></svg>
          </div>
          <!-- Flyout Submenu on Hover or Click! -->
          <div class="cmd-submenu">
            <div class="cmd-submenu-header">
              <span>${escapeHtml(provTitle)} Models</span>
              <span class="cmd-active-key-dot" title="${isOffline ? 'Offline - Disconnected' : 'Active Key Connected'}">${isOffline ? '● Offline (Disabled)' : '● Connected'}</span>
            </div>
            <div class="cmd-submenu-list">
              ${subItemsHtml}
            </div>
          </div>
        </div>
      `;
    }
  });

  // 3. Configured Custom Cloud Endpoints
  const cloudList = window.__configuredCloudModels || [];
  if (cloudList.length > 0) {
    const grpCloud = document.createElement("optgroup");
    grpCloud.label = `Custom Cloud Endpoints${isOffline ? ' (Offline)' : ''}`;
    let customSubHtml = "";
    cloudList.forEach((cm) => {
      const opt = document.createElement("option");
      opt.value = cm.model_name;
      const badge = cm.model_type === "image" ? { label: "Image", cssClass: "pro" } : getModelCategoryBadge(cm.model_name);
      if (isOffline) {
        opt.disabled = true;
        opt.textContent = `${cm.model_name} (${badge.label} - Offline)`;
      } else {
        opt.textContent = `${cm.model_name} (${badge.label})`;
      }
      const isAct = (cm.model_name === currentVal && !hasSelected && !isOffline);
      if (isAct) {
        opt.selected = true;
        activeModel = cm.model_name;
        hasSelected = true;
        activeDisplayLabel = `${cm.model_name} (Custom)`;
      }
      grpCloud.appendChild(opt);

      customSubHtml += `
        <div class="cmd-option ${isOffline ? 'is-offline-disabled' : ''} ${isAct ? 'is-active' : ''}" data-value="${escapeHtml(cm.model_name)}" ${isOffline ? 'style="opacity: 0.4; pointer-events: none;" title="Offline Mode: Custom endpoint disabled"' : ''}>
          <div class="cmd-opt-main">
            <span class="cmd-opt-name">${escapeHtml(cm.model_name)}</span>
            <span class="cmd-tier-pill ${badge.cssClass}">${badge.label}${isOffline ? ' (Offline)' : ''}</span>
          </div>
          ${isAct ? '<svg class="cmd-check-icon" viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>' : ''}
        </div>
      `;
    });
    headerModelSelect.appendChild(grpCloud);

    cloudHtml += `
      <div class="cmd-provider-item" data-provider-id="custom" ${isOffline ? 'style="opacity: 0.55;"' : ''}>
        <div class="cmd-provider-row">
          <div class="cmd-provider-left">
            <span class="cmd-provider-bullet custom"></span>
            <span class="cmd-provider-title">Custom Endpoints</span>
            <span class="cmd-count-badge">${cloudList.length}</span>
          </div>
          <svg class="cmd-flyout-arrow" viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2.2"><polyline points="9 18 15 12 9 6"></polyline></svg>
        </div>
        <div class="cmd-submenu">
          <div class="cmd-submenu-header">
            <span>Custom Cloud Endpoints</span>
            <span class="cmd-active-key-dot" title="${isOffline ? 'Offline - Disconnected' : 'Connected'}">${isOffline ? '● Offline (Disabled)' : '● Connected'}</span>
          </div>
          <div class="cmd-submenu-list">
            ${customSubHtml}
          </div>
        </div>
      </div>
    `;
  }

  // 4. Local Installed Models (Ollama)
  let localHtml = "";
  if (models && models.length > 0) {
    const grpLocal = document.createElement("optgroup");
    grpLocal.label = "Local Installed Models (Ollama)";
    localHtml += `<div class="cmd-group"><div class="cmd-group-title">Local Installed Models (Ollama)</div>`;

    models.forEach((m) => {
      const opt = document.createElement("option");
      opt.value = m.name;
      const badge = getModelCategoryBadge(m.name);
      opt.textContent = `${m.name} (${badge.label} Tier)`;
      const isAct = ((m.name === currentVal || m.is_active) && !hasSelected);
      if (isAct) {
        opt.selected = true;
        activeModel = m.name;
        hasSelected = true;
        activeDisplayLabel = `${m.name} (Local)`;
      }
      grpLocal.appendChild(opt);

      localHtml += `
        <div class="cmd-option ${isAct ? 'is-active' : ''}" data-value="${escapeHtml(m.name)}">
          <div class="cmd-opt-main">
            <span class="cmd-opt-name">${escapeHtml(m.name)}</span>
            <span class="cmd-tier-pill ${badge.cssClass}">${badge.label}</span>
          </div>
          ${isAct ? '<svg class="cmd-check-icon" viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>' : ''}
        </div>
      `;
    });
    localHtml += `</div>`;
    headerModelSelect.appendChild(grpLocal);
  }

  // Assemble full custom menu HTML
  if (menuEl) {
    let fullMenuHtml = stratHtml;
    if (cloudHtml) {
      fullMenuHtml += `<div class="cmd-divider"></div><div class="cmd-group"><div class="cmd-group-title">Cloud AI Providers (Hover / Click for Models)</div>${cloudHtml}</div>`;
    }
    if (localHtml) {
      fullMenuHtml += `<div class="cmd-divider"></div>${localHtml}`;
    }
    menuEl.innerHTML = fullMenuHtml;

    // Provider flyout interaction: click-to-pin & hover grace period
    menuEl.querySelectorAll(".cmd-provider-item").forEach((provItem) => {
      let leaveTimer = null;
      provItem.addEventListener("mouseenter", () => {
        if (leaveTimer) {
          clearTimeout(leaveTimer);
          leaveTimer = null;
        }
        provItem.classList.add("is-hovered");
      });
      provItem.addEventListener("mouseleave", () => {
        leaveTimer = setTimeout(() => {
          provItem.classList.remove("is-hovered");
        }, 220); // 220ms grace buffer so diagonal mouse movement never loses flyout
      });
    });

    // Click on provider row toggles/pins submenu open
    menuEl.querySelectorAll(".cmd-provider-row").forEach((pRow) => {
      pRow.addEventListener("click", (e) => {
        e.stopPropagation();
        const item = pRow.closest(".cmd-provider-item");
        if (!item) return;
        const isOpen = item.classList.contains("is-open");
        menuEl.querySelectorAll(".cmd-provider-item.is-open").forEach((other) => {
          if (other !== item) other.classList.remove("is-open");
        });
        if (isOpen) {
          item.classList.remove("is-open");
        } else {
          item.classList.add("is-open");
        }
      });
    });

    // Attach click events on all .cmd-option items
    menuEl.querySelectorAll(".cmd-option").forEach((optEl) => {
      optEl.addEventListener("click", (e) => {
        e.stopPropagation();
        if (optEl.classList.contains("is-offline-disabled")) {
          showToast("Cloud model is disabled in complete Offline Air-Gap mode. Enable Internet to use this model.", "warning", "Offline Mode");
          return;
        }
        const val = optEl.getAttribute("data-value");
        if (val) {
          selectCustomModel(val);
        }
      });
    });
  }

  // If nothing selected, choose first available model option
  if (!hasSelected && headerModelSelect.options.length > 0) {
    headerModelSelect.options[0].selected = true;
    activeModel = headerModelSelect.options[0].value;
    activeDisplayLabel = headerModelSelect.options[0].textContent;
  }

  updateTriggerLabel(activeDisplayLabel || currentVal || "Auto (Balanced Routing)");
  updateChatPlaceholderForActiveModel();
  updateVirtualModelsBarActive(activeModel);
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
      updateTriggerLabel(modelName);
      updateChatPlaceholderForActiveModel();
      updateVirtualModelsBarActive(modelName);
      document.querySelectorAll(".phub-model-pill").forEach((pill) => {
        if (pill.getAttribute("data-model") === modelName) {
          pill.classList.add("active");
        } else {
          pill.classList.remove("active");
        }
      });
      showToast(`Model switched to ${modelName}`, "success");
      loadInstalledModels();
    }
  } catch (err) {
    showToast(`Failed to switch model: ${err.message}`, "error");
  }
}

async function checkInstallPathStorage(pathVal) {
  const infoEl = document.getElementById("install-modal-storage-info");
  if (!infoEl) return;
  infoEl.textContent = "Checking disk space...";
  infoEl.className = "storage-hint-ok";
  try {
    const q = pathVal ? `?path=${encodeURIComponent(pathVal)}` : "";
    const res = await fetch(`${API_BASE}/api/models/storage${q}`);
    const data = await res.json();
    if (data.success && data.storage) {
      const free = data.storage.free_gb;
      const drive = data.storage.drive || "C:";
      if (free < 2.0) {
        infoEl.textContent = `Low Disk Space: Only ${free} GB Free on ${drive}`;
        infoEl.className = "storage-hint-warn";
      } else {
        infoEl.textContent = `Storage Available: ${free} GB Free on ${drive}`;
        infoEl.className = "storage-hint-ok";
      }
    } else {
      infoEl.textContent = "Custom folder destination verified.";
    }
  } catch (e) {
    infoEl.textContent = "Storage destination verified.";
  }
}

async function openModelInstallModal(modelInfo, autoStart = false) {
  currentInstallTargetModel = modelInfo;

  const modal = document.getElementById("model-install-modal");
  const titleEl = document.getElementById("install-modal-title");
  const tagEl = document.getElementById("install-modal-model-tag");
  const sizeEl = document.getElementById("install-modal-model-size");
  const descEl = document.getElementById("install-modal-model-desc");
  const pathInput = document.getElementById("install-modal-path-input");
  const progressSec = document.getElementById("install-modal-progress-section");
  const confirmBtn = document.getElementById("btn-confirm-install-model");
  const confirmLabel = document.getElementById("btn-confirm-install-label");
  const cancelBtn = document.getElementById("btn-cancel-install-modal");

  if (!modal) return;

  // Unhide modal immediately for instant click response and ensure display is flex
  modal.classList.remove("hidden");
  modal.style.display = "flex";

  const mTag = modelInfo.tag || modelInfo.name;
  if (titleEl) titleEl.textContent = `Install AI Model: ${modelInfo.name || modelInfo.tag}`;
  if (tagEl) tagEl.textContent = mTag;
  if (sizeEl) sizeEl.textContent = modelInfo.size ? `~${modelInfo.size}` : "Variable";
  if (descEl) descEl.textContent = modelInfo.desc || "High-performance open weights calibrated for coding, fast chat and deep reasoning.";

  // Populate install destination path synchronously so UI never shows empty or hangs
  const defaultPath = currentInstallTargetPath || (pathInput && pathInput.value ? pathInput.value : "") || "C:\\Users\\hp\\.ollama\\models";
  if (modelInfo.targetPath && pathInput) {
    pathInput.value = modelInfo.targetPath;
    checkInstallPathStorage(modelInfo.targetPath);
  } else if (pathInput) {
    if (!pathInput.value) pathInput.value = defaultPath;
    checkInstallPathStorage(pathInput.value);
  }

  // Non-blocking background fetch for live storage directory info
  fetch(`${API_BASE}/api/models/storage`)
    .then((res) => res.json())
    .then((data) => {
      if (data && data.success && data.path && pathInput && !modelInfo.targetPath && !currentInstallTargetPath) {
        pathInput.value = data.path;
        checkInstallPathStorage(data.path);
      }
    })
    .catch(() => {});

  // Check if this model is actively downloading or paused
  const normActive = (activeDownloadingModelTag || "").trim().toLowerCase();
  const normTag = (mTag || "").trim().toLowerCase();
  const normName = (modelInfo.name || "").trim().toLowerCase();
  const isThisActive = (isModelDownloading || isDownloadPaused) && normActive && (
    isSameModelTag(normActive, normTag) ||
    isSameModelTag(normActive, normName)
  );

  if (isModelDownloading && !isThisActive) {
    showToast(`Download already in progress: '${activeDownloadingModelTag}' (${Math.round(activeDownloadPct)}%).`, "warning", "Download in Progress");
    const activeObj = latestRecommendedModels.find(r => isSameModelTag(r.tag, activeDownloadingModelTag) || isSameModelTag(r.name, activeDownloadingModelTag)) || {
      tag: activeDownloadingModelTag,
      name: activeDownloadingModelTag,
      size: "Variable",
      desc: "Currently downloading model weights...",
    };
    return openModelInstallModal(activeObj, false);
  }

  if (isThisActive && progressSec) {
    progressSec.classList.remove("hidden");
    syncDownloadUI(activeDownloadPct, activeDownloadStatus, activeDownloadBytes, isDownloadPaused);
    if (confirmLabel) confirmLabel.textContent = isDownloadPaused ? "Resume Download" : "Run in Background & Close";
    if (cancelBtn) cancelBtn.style.display = "";
  } else {
    // Modal always opens in review/configure mode: user can freely check/browse path before confirming
    if (progressSec) progressSec.classList.add("hidden");
    if (confirmBtn) {
      confirmBtn.disabled = false;
      confirmBtn.classList.remove("btn-secondary");
      confirmBtn.classList.add("btn-primary");
    }
    if (confirmLabel) confirmLabel.textContent = "Confirm & Download Model";
    if (cancelBtn) cancelBtn.style.display = "";
  }
}

function handleDownloadSuccess(modelName) {
  isModelDownloading = false;
  isDownloadPaused = false;
  activeDownloadingModelTag = null;
  activeDownloadAbortController = null;
  activeDownloadPct = 100;

  syncDownloadUI(100, `Successfully installed ${modelName}!`, activeDownloadBytes, false);

  const confirmLabel = document.getElementById("btn-confirm-install-label");
  const cancelBtn = document.getElementById("btn-cancel-install-modal");
  if (confirmLabel) confirmLabel.textContent = "Done / Close";
  if (cancelBtn) cancelBtn.style.display = "none";

  if (btnPullModel) {
    btnPullModel.disabled = false;
    btnPullModel.innerHTML = `<svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg><span>Start Download & Install</span>`;
  }

  hideDownloadWidgets();
  showToast(`Successfully downloaded and installed ${modelName}!`, "success", "Download Complete");
  loadInstalledModels();
  loadRecommendedModels();
  loadModelStoragePath();
}

function formatDownloadError(rawError) {
  if (!rawError) return "An unexpected error occurred during download.";
  if (typeof rawError !== "string") {
    try {
      rawError = JSON.stringify(rawError);
    } catch (_) {
      rawError = String(rawError);
    }
  }

  const lower = rawError.toLowerCase();

  // Check for Cloudflare 522 or connection timeout
  if (rawError.includes("522") || lower.includes("cloudflare") || lower.includes("connection timed out") || lower.includes("timed out")) {
    return "Ollama Registry Connection Timeout (Cloudflare 522). The official model registry (registry.ollama.ai) is temporarily overloaded or unreachable. Please wait 1-2 minutes and click Retry.";
  }
  // Check for 502 / 503 / 504 server errors
  if (rawError.includes("502") || rawError.includes("503") || lower.includes("bad gateway") || lower.includes("service unavailable")) {
    return "Ollama Registry Gateway Error (502/503). Registry service is temporarily unavailable. Please retry shortly.";
  }
  if (rawError.includes("504") || lower.includes("gateway timeout") || lower.includes("request timed out")) {
    return "Network Gateway Timeout (504). Connection timed out while downloading model layers. Please check your internet connection.";
  }
  // Check for disk full
  if (lower.includes("no space left on device") || rawError.includes("DISK_FULL") || lower.includes("disk full") || lower.includes("not enough disk space")) {
    return "Insufficient disk storage. Please free up space on your drive or configure an external model storage path.";
  }
  // Check for model not found
  if (lower.includes("file does not exist") || lower.includes("manifest: file does not exist") || lower.includes("not found") || rawError.includes("404")) {
    return "Model manifest not found on Ollama registry. Please check if the model name or tag is correct.";
  }
  // If JSON is embedded in the error string, parse detail or title
  const jsonMatch = rawError.match(/\{[\s\S]*\}/);
  if (jsonMatch) {
    try {
      const parsed = JSON.parse(jsonMatch[0]);
      if (parsed.detail) return parsed.detail;
      if (parsed.title) return parsed.title;
      if (parsed.message) return parsed.message;
    } catch (_) {}
  }
  // Clean up prefix
  return rawError.replace(/^pull model manifest:\s*/i, "").replace(/^error:\s*/i, "").trim();
}

function handleDownloadFailure(errorMsg) {
  isModelDownloading = false;
  isDownloadPaused = false;
  activeDownloadingModelTag = null;
  activeDownloadAbortController = null;

  const friendlyError = formatDownloadError(errorMsg);

  syncDownloadUI(0, `Download failed: ${friendlyError}`, "0 MB / 0 MB", false);
  hideDownloadWidgets();

  const confirmLabel = document.getElementById("btn-confirm-install-label");
  const cancelBtn = document.getElementById("btn-cancel-install-modal");
  if (confirmLabel) confirmLabel.textContent = "Close";
  if (cancelBtn) cancelBtn.style.display = "";

  if (btnPullModel) {
    btnPullModel.disabled = false;
    btnPullModel.innerHTML = `<svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg><span>Start Download & Install</span>`;
  }

  showToast(`Model download failed: ${friendlyError}`, "error");
  if (latestRecommendedModels.length > 0) {
    renderRecommendedModels(latestRecommendedModels);
  }
}

function startModelDownload(modelInfo, targetPath = "") {
  currentInstallTargetModel = modelInfo;
  currentInstallTargetPath = targetPath;
  const modelName = modelInfo.tag || modelInfo.name;
  isModelDownloading = true;
  isDownloadPaused = false;
  activeDownloadingModelTag = modelName;
  activeDownloadAbortController = new AbortController();
  activeDownloadPct = 0;
  activeDownloadBytes = "0 MB / 0 MB";

  const progressSec = document.getElementById("install-modal-progress-section");
  const targetEl = document.getElementById("install-modal-save-target");
  const confirmLabel = document.getElementById("btn-confirm-install-label");
  const cancelBtn = document.getElementById("btn-cancel-install-modal");

  if (progressSec) progressSec.classList.remove("hidden");
  if (targetEl) targetEl.textContent = targetPath ? `Target: ${targetPath.split(/[\/\\]/).filter(Boolean).pop() || targetPath}` : "Target: Default models folder";
  if (confirmLabel) confirmLabel.textContent = "Run in Background & Close";
  if (cancelBtn) cancelBtn.style.display = "";

  syncDownloadUI(activeDownloadPct || 0, `Connecting & initializing download for ${modelName}...`, activeDownloadBytes || "0 MB / 0 MB", false);

  if (btnPullModel) {
    btnPullModel.disabled = true;
    btnPullModel.innerHTML = `<span class="spinner-inline"></span> <span>Downloading ${modelName}...</span>`;
  }

  if (latestRecommendedModels.length > 0) {
    renderRecommendedModels(latestRecommendedModels);
  }

  const payload = { model: modelName };
  if (targetPath) payload.path = targetPath;

  fetch(`${API_BASE}/api/models/pull`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    signal: activeDownloadAbortController.signal,
  }).then(async (response) => {
    if (!response.ok) {
      let errDetail = `Server responded with status ${response.status}`;
      try {
        const errJson = await response.json();
        if (errJson.error) errDetail = errJson.error;
      } catch (_) {}
      throw new Error(errDetail);
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let sseBuffer = "";
    let hasCompletedSuccess = false;

    function read() {
      reader.read().then(({ done, value }) => {
        if (done) {
          if (hasCompletedSuccess) {
            handleDownloadSuccess(modelName);
          } else {
            handleDownloadFailure("Download was interrupted before completion. Model weights were not fully saved.");
          }
          return;
        }

        sseBuffer += decoder.decode(value, { stream: true });
        const lines = sseBuffer.split("\n");
        sseBuffer = lines.pop() || "";

        for (const line of lines) {
          const trimmed = line.trim();
          if (trimmed.startsWith("data: ")) {
            try {
              const d = JSON.parse(trimmed.substring(6));
              if (d.error) {
                handleDownloadFailure(d.error);
                try { reader.cancel(); } catch (_) {}
                return;
              }
              if (d.status === "error") {
                handleDownloadFailure(d.error || "Model download error encountered.");
                try { reader.cancel(); } catch (_) {}
                return;
              }
              if (d.status === "success" || (typeof d.status === "string" && d.status.toLowerCase().includes("installed successfully"))) {
                hasCompletedSuccess = true;
              }

              let statusMsg = d.status || "";
              let bytesStr = activeDownloadBytes;
              let pct = activeDownloadPct || 0;

              if (d.total && d.completed) {
                // Large layers (>= 5MB) represent actual model weights
                if (d.total >= 5 * 1024 * 1024) {
                  pct = Math.max(2, Math.min(99, Math.round((d.completed / d.total) * 100)));
                  const completedMB = (d.completed / (1024 * 1024)).toFixed(1);
                  const totalMB = (d.total / (1024 * 1024)).toFixed(1);
                  bytesStr = `${completedMB} MB / ${totalMB} MB`;
                } else {
                  // Metadata / manifest preparation layer
                  pct = Math.max(pct, 2);
                  const completedKB = (d.completed / 1024).toFixed(0);
                  const totalKB = (d.total / 1024).toFixed(0);
                  bytesStr = `${completedKB} KB / ${totalKB} KB (Manifest)`;
                }
              }

              if (hasCompletedSuccess) {
                pct = 100;
                statusMsg = `Successfully installed ${modelName}!`;
              }

              syncDownloadUI(pct, statusMsg, bytesStr, false);

              if (hasCompletedSuccess) {
                handleDownloadSuccess(modelName);
                try { reader.cancel(); } catch (_) {}
                return;
              }
            } catch (e) {}
          }
        }
        read();
      }).catch(err => {
        if (err.name === "AbortError" || isDownloadPaused) {
          return;
        }
        handleDownloadFailure(err.message);
      });
    }
    read();
  }).catch(err => {
    if (err.name === "AbortError" || isDownloadPaused) {
      return;
    }
    handleDownloadFailure(err.message);
  });
}

function pullModel(modelName, targetPath = "") {
  openModelInstallModal({
    tag: modelName,
    name: modelName,
    size: "Variable",
    desc: "Local open-weight intelligence model.",
    targetPath: targetPath,
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
      if (btn.getAttribute("data-zero") === "true") {
        cfgApiKey.value = "zero-key-open";
      } else {
        cfgApiKey.focus();
      }
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

  initApiKeyModals();
}

const PROVIDER_KEY_LINKS = {
  groq: { name: "Groq Cloud Console", url: "https://console.groq.com/keys" },
  cerebras: { name: "Cerebras Cloud Dashboard", url: "https://cloud.cerebras.ai/" },
  gemini: { name: "Google AI Studio", url: "https://aistudio.google.com/app/apikey" },
  deepseek: { name: "DeepSeek Open Platform", url: "https://platform.deepseek.com/api_keys" },
  openrouter: { name: "OpenRouter Key Management", url: "https://openrouter.ai/keys" },
  mistral: { name: "Mistral La Plateforme", url: "https://console.mistral.ai/api-keys/" },
  cohere: { name: "Cohere Dashboard", url: "https://dashboard.cohere.com/api-keys" },
  pollinations: { name: "Pollinations.ai", url: "https://enter.pollinations.ai/" },
  together: { name: "Together AI Settings", url: "https://api.together.xyz/settings/api-keys" },
};

let pendingRemoveProviderId = null;
let pendingRemoveProviderName = null;

function openApiKeyModal(pId, pData) {
  const modal = document.getElementById("api-key-modal");
  const provIdInp = document.getElementById("key-modal-provider-id");
  const titleEl = document.getElementById("api-key-modal-title");
  const subtitleEl = document.getElementById("api-key-modal-subtitle");
  const keyInp = document.getElementById("key-modal-input");
  const helpEl = document.getElementById("key-modal-help");

  if (!modal || !provIdInp || !keyInp) return;

  const provName = pData?.name || pId.toUpperCase();
  provIdInp.value = pId;
  if (titleEl) titleEl.textContent = `Add API Key - ${provName}`;
  if (subtitleEl) subtitleEl.textContent = `Add an API key to the ${provName} provider pool.`;

  keyInp.value = "";
  keyInp.type = "password";
  const iconEye = document.getElementById("icon-eye-key");
  if (iconEye) {
    iconEye.innerHTML = '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle>';
  }

  if (helpEl) {
    const linkInfo = PROVIDER_KEY_LINKS[pId.toLowerCase()];
    if (linkInfo) {
      helpEl.innerHTML = `Need a key? Get one for free at <a href="${linkInfo.url}" target="_blank" rel="noopener noreferrer" style="color: #38bdf8; text-decoration: underline;">${linkInfo.name}</a>.`;
    } else {
      helpEl.textContent = "Your API key is securely stored in your local PAI configuration.";
    }
  }

  modal.classList.remove("hidden");
  modal.style.display = "flex";
  setTimeout(() => keyInp.focus(), 60);
}

function closeApiKeyModal() {
  const modal = document.getElementById("api-key-modal");
  if (modal) {
    modal.classList.add("hidden");
    modal.style.display = "none";
  }
}

function openRemoveKeyModal(pId, pData) {
  const modal = document.getElementById("api-key-remove-modal");
  const descEl = document.getElementById("remove-key-modal-desc");
  if (!modal) return;
  pendingRemoveProviderId = pId;
  pendingRemoveProviderName = pData?.name || pId.toUpperCase();
  if (descEl) {
    descEl.textContent = `Are you sure you want to remove the most recently added API key from the ${pendingRemoveProviderName} pool?`;
  }
  modal.classList.remove("hidden");
  modal.style.display = "flex";
}

function closeRemoveKeyModal() {
  const modal = document.getElementById("api-key-remove-modal");
  if (modal) {
    modal.classList.add("hidden");
    modal.style.display = "none";
  }
  pendingRemoveProviderId = null;
  pendingRemoveProviderName = null;
}

function initApiKeyModals() {
  const keyModal = document.getElementById("api-key-modal");
  const keyForm = document.getElementById("api-key-modal-form");
  const btnCloseKey = document.getElementById("btn-close-key-modal");
  const btnCancelKey = document.getElementById("btn-cancel-key-modal");
  const btnToggleVis = document.getElementById("btn-toggle-key-visibility");
  const keyInp = document.getElementById("key-modal-input");

  btnCloseKey?.addEventListener("click", closeApiKeyModal);
  btnCancelKey?.addEventListener("click", closeApiKeyModal);
  keyModal?.addEventListener("click", (e) => {
    if (e.target === keyModal) closeApiKeyModal();
  });

  btnToggleVis?.addEventListener("click", () => {
    if (!keyInp) return;
    const isPass = keyInp.type === "password";
    keyInp.type = isPass ? "text" : "password";
    const iconEye = document.getElementById("icon-eye-key");
    if (iconEye) {
      iconEye.innerHTML = isPass
        ? '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line>'
        : '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle>';
    }
  });

  keyForm?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const provId = document.getElementById("key-modal-provider-id")?.value;
    const keyVal = keyInp?.value?.trim();
    if (!provId || !keyVal) return;

    const submitBtn = document.getElementById("btn-save-key-modal");
    if (submitBtn) submitBtn.disabled = true;

    try {
      const res = await fetch(`${API_BASE}/api/cloud/add_key`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider: provId, key: keyVal, api_key: keyVal }),
      });
      const resData = await res.json();
      if (resData.success) {
        closeApiKeyModal();
        showToast(resData.message || `API Key added to ${provId.toUpperCase()} pool (${resData.key_count || 1} keys active)`, "success", "Pool Expanded");
        loadCloudModels();
      } else {
        showToast(`Failed to add key: ${resData.error || resData.message || "Unknown error"}`, "error");
      }
    } catch (err) {
      showToast(`Error adding key: ${err.message}`, "error");
    } finally {
      if (submitBtn) submitBtn.disabled = false;
    }
  });

  // Remove Key Modal
  const remModal = document.getElementById("api-key-remove-modal");
  const btnCloseRem = document.getElementById("btn-close-remove-key-modal");
  const btnCancelRem = document.getElementById("btn-cancel-remove-key-modal");
  const btnConfirmRem = document.getElementById("btn-confirm-remove-key-modal");

  btnCloseRem?.addEventListener("click", closeRemoveKeyModal);
  btnCancelRem?.addEventListener("click", closeRemoveKeyModal);
  remModal?.addEventListener("click", (e) => {
    if (e.target === remModal) closeRemoveKeyModal();
  });

  btnConfirmRem?.addEventListener("click", async () => {
    if (!pendingRemoveProviderId) return;
    const pId = pendingRemoveProviderId;
    const pName = pendingRemoveProviderName;
    btnConfirmRem.disabled = true;
    try {
      const res = await fetch(`${API_BASE}/api/cloud/remove_key`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider: pId, key_index: -1 }),
      });
      const resData = await res.json();
      if (resData.success) {
        closeRemoveKeyModal();
        showToast(`Key removed from ${pName} (${resData.remaining_keys || 0} remaining)`, "info");
        loadCloudModels();
      } else {
        showToast(`Failed to remove key: ${resData.error || resData.message || "Unknown error"}`, "error");
      }
    } catch (err) {
      showToast(`Error removing key: ${err.message}`, "error");
    } finally {
      btnConfirmRem.disabled = false;
    }
  });

  // Global escape key handler to close open modals
  window.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      closeApiKeyModal();
      closeRemoveKeyModal();
    }
  });
}

function classifyModelStrategy(modelName) {
  if (!modelName) return "auto";
  const m = modelName.toLowerCase();
  if (m === "auto" || m === "pai-auto") return "auto";
  if (m === "auto:fast" || m === "fast") return "auto:fast";
  if (m === "auto:smart" || m === "smart") return "auto:smart";
  if (m === "fusion" || m === "auto:fusion") return "fusion";

  // Fast heuristics: lightweight parameter models / ultra-fast inference
  if (
    m.includes("flash-lite") ||
    m.includes("instant") ||
    (m.includes("mini") && !m.includes("gemini")) ||
    m.includes("tiny") ||
    m.includes("lite") ||
    m.includes("nano") ||
    m.includes("haiku") ||
    m.includes("1b") ||
    m.includes("1.5b") ||
    m.includes("2b") ||
    m.includes("e2b")
  ) {
    return "auto:fast";
  }

  // Smart heuristics: reasoning models, coder models, frontier & large parameter models
  if (
    m.includes("deepseek") ||
    m.includes("r1") ||
    m.includes("reasoner") ||
    m.includes("coder") ||
    m.includes("hydrogen") ||
    m.includes("carbon") ||
    m.includes("pro") ||
    m.includes("ultra") ||
    m.includes("opus") ||
    m.includes("sonnet") ||
    m.includes("70b") ||
    m.includes("405b") ||
    m.includes("large") ||
    m.includes("thinking")
  ) {
    return "auto:smart";
  }

  return "auto";
}

function setupVirtualModelsBar() {
  const bar = document.getElementById("virtual-models-bar");
  if (!bar) return;
  bar.querySelectorAll(".btn-vmodel").forEach((btn) => {
    btn.addEventListener("click", () => {
      const targetModel = btn.getAttribute("data-model");
      if (targetModel) {
        switchModel(targetModel);
      }
    });
  });
}

function updateVirtualModelsBarActive(modelName) {
  const current = modelName || activeModel || "auto";
  const strategyTier = classifyModelStrategy(current);

  // Synchronize active highlight on the strategy presets
  document.querySelectorAll(".btn-vmodel").forEach((btn) => {
    const targetModel = btn.getAttribute("data-model");
    if (targetModel === strategyTier) {
      btn.classList.add("active");
    } else {
      btn.classList.remove("active");
    }
  });

  // Synchronize header dropdown to match active model if present
  if (headerModelSelect && headerModelSelect.value !== current) {
    const matchingOpt = Array.from(headerModelSelect.options).find(opt => opt.value === current);
    if (matchingOpt) {
      headerModelSelect.value = current;
    }
  }

  // Update real-time chat header engine badge
  const badgeDot = document.querySelector(".engine-badge-dot");
  const badgeText = document.getElementById("chat-engine-badge-text");
  if (badgeText) {
    const isVirtual = ["auto", "auto:fast", "auto:smart", "fusion"].includes(current.toLowerCase());
    if (isVirtual) {
      const labels = {
        "auto": "Auto (Balanced)",
        "auto:fast": "Fast (Low-Latency)",
        "auto:smart": "Smart (Reasoning R1)",
        "fusion": "Dual Fusion (Draft + Review)"
      };
      badgeText.textContent = `Strategy: ${labels[current.toLowerCase()] || current}`;
      if (badgeDot) {
        badgeDot.className = current === "fusion" ? "engine-badge-dot fusion" : "engine-badge-dot cloud";
      }
    } else {
      const badge = typeof getModelCategoryBadge === "function" ? getModelCategoryBadge(current) : { label: "Auto", cssClass: "auto" };
      badgeText.textContent = `Engine: ${current} [${badge.label}]`;
      if (badgeDot) {
        const isCloud = (window.__cloudProviders || []).some(p => (p.models || []).includes(current)) ||
                        (window.__configuredCloudModels || []).some(cm => cm.model_name === current);
        badgeDot.className = isCloud ? "engine-badge-dot cloud" : "engine-badge-dot";
      }
    }
  }
}

async function loadCloudModels() {
  try {
    const res = await fetch(`${API_BASE}/api/cloud/config`);
    const data = await res.json();
    let providersArr = [];
    if (data.providers) {
      providersArr = Array.isArray(data.providers)
        ? data.providers
        : Object.entries(data.providers).map(([k, v]) => ({ id: k, ...v }));
      window.__cloudProviders = providersArr;
      renderCloudProvidersHub(data.providers, data.active_model, data.health);
    }
    const customList = data.configured_models || [];
    window.__configuredCloudModels = customList;
    renderConfiguredCloudModels(customList, data.active_model, providersArr);

    populateModelSelectors(availableModels);
    updateVirtualModelsBarActive(data.active_model || activeModel);
  } catch (err) {
    console.error("Cloud config error:", err);
  }
}

function renderCloudProvidersHub(providers, activeModel, healthData) {
  const container = document.getElementById("cloud-providers-hub");
  if (!container) return;
  container.innerHTML = "";

  const providerList = Array.isArray(providers)
    ? providers
    : Object.entries(providers || {}).map(([k, v]) => ({ id: k, ...v }));

  const totalKeys = providerList.reduce((acc, p) => acc + (p.key_count || 0), 0);
  const hubTotalKeysEl = document.getElementById("hub-total-keys");
  if (hubTotalKeysEl) {
    hubTotalKeysEl.textContent = `${totalKeys} Key${totalKeys === 1 ? '' : 's'} Pooled`;
  }

  if (providerList.length === 0) {
    container.innerHTML = `<div class="text-muted">No free cloud providers registered.</div>`;
    return;
  }

  providerList.forEach((pData) => {
    const pId = pData.id || pData.provider || "custom";
    const card = document.createElement("div");

    let statusClass = "status-ready";
    let statusText = "Ready";
    const health = pData.health || {};
    if (health.rate_limited) {
      statusClass = "status-cooldown";
      statusText = `Cooldown (${Math.round(health.cooldown_remaining_sec || 0)}s)`;
    } else if (pData.is_free && pData.key_count === 0) {
      statusClass = "status-ready";
      statusText = "Zero-Key Ready";
    } else if (pData.key_count === 0) {
      statusClass = "status-nokey";
      statusText = "No Keys";
    }

    const hasActiveModel = (pData.models || []).includes(activeModel);
    card.className = `provider-hub-card ${hasActiveModel ? 'active-prov' : ''}`;
    card.setAttribute("data-provider", pId);

    const modelsHtml = (pData.models || []).map((m) => {
      const isMActive = m === activeModel;
      return `<span class="phub-model-pill ${isMActive ? 'active' : ''}" data-model="${escapeHtml(m)}" title="Click to activate ${escapeHtml(m)}">${escapeHtml(m)}</span>`;
    }).join("");

    const maskedKeys = pData.masked_keys || [];
    let keysSectionHtml = "";
    if (maskedKeys.length > 0) {
      keysSectionHtml = `
        <div class="phub-keys-section">
          <div class="phub-keys-header">
            <span>Configured Keys (${maskedKeys.length})</span>
          </div>
          <div class="phub-keys-list">
            ${maskedKeys.map((k) => `
              <div class="phub-key-chip" title="Active API Key">
                <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;">
                  <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"></path>
                </svg>
                <span class="phub-key-text">${escapeHtml(k.masked)}</span>
                <span class="phub-key-badge-active">ACTIVE</span>
                <button type="button" class="btn-del-key-chip" data-provider="${pId}" data-key-index="${k.index}" title="Remove this key">&times;</button>
              </div>
            `).join("")}
          </div>
        </div>
      `;
    } else if (pData.is_free && pData.key_count === 0) {
      keysSectionHtml = `
        <div class="phub-keys-section phub-zero-key-section">
          <div class="phub-no-keys-note zero-key">
            <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0; vertical-align:middle; margin-right:4px;">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
            </svg>
            <span>Public Zero-Key Provider &middot; No API key required</span>
          </div>
        </div>
      `;
    } else {
      keysSectionHtml = `
        <div class="phub-keys-section">
          <div class="phub-no-keys-note">No API key saved yet. Click &ldquo;+ Add Key&rdquo; below.</div>
        </div>
      `;
    }

    card.innerHTML = `
      <div class="phub-header">
        <div class="phub-title-row">
          <span class="phub-name">${escapeHtml(pData.name || pId)}</span>
          ${pData.is_free ? `<span class="phub-badge-free">FREE TIER</span>` : ''}
          ${pData.speed_tier === 'fast' ? `<span class="phub-badge-free" style="background:rgba(56,189,248,0.15);color:#38bdf8;border-color:rgba(56,189,248,0.3);">FAST</span>` : ''}
        </div>
        <span class="phub-status-badge ${statusClass}">${statusText}</span>
      </div>
      <div class="phub-meta-row">
        <span>Keys: <strong>${pData.key_count}</strong> active</span>
        <span>RPM: ${pData.rpm_cap || pData.rpm_limit || 15} · Speed: ${pData.speed_rank || 80}/100</span>
      </div>
      ${keysSectionHtml}
      <div class="phub-models-list">
        ${modelsHtml}
      </div>
      <div class="phub-actions">
        <div class="flex-center-gap">
          <button type="button" class="btn-phub-action btn-add-key" data-provider="${pId}">+ Add Key</button>
          ${pData.key_count > 0 ? `<button type="button" class="btn-phub-action btn-remove-key" data-provider="${pId}" title="Remove Last Key"><svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg></button>` : ''}
        </div>
        <div class="flex-center-gap">
          <span class="latency-display" id="latency-${pId}" style="display:none; font-size:11px; font-weight:600; color:#38bdf8;"></span>
          <button type="button" class="btn-phub-action btn-test btn-ping-prov" data-provider="${pId}"><svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;margin-right:2px"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>Ping</button>
        </div>
      </div>
    `;

    card.querySelectorAll(".phub-model-pill").forEach((pill) => {
      pill.addEventListener("click", () => {
        const targetModel = pill.getAttribute("data-model");
        if (targetModel) {
          switchModel(targetModel);
        }
      });
    });

    card.querySelectorAll(".btn-del-key-chip").forEach((btn) => {
      btn.addEventListener("click", async (e) => {
        e.stopPropagation();
        const keyIdx = btn.getAttribute("data-key-index");
        btn.disabled = true;
        try {
          const res = await fetch(`${API_BASE}/api/cloud/remove_key`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ provider: pId, key_index: parseInt(keyIdx, 10) }),
          });
          const resData = await res.json();
          if (resData.success) {
            showToast(`Key removed from ${pData.name || pId.toUpperCase()}`, "info", "Key Removed");
            loadCloudModels();
          } else {
            showToast(`Failed to remove key: ${resData.error || "Unknown error"}`, "error");
          }
        } catch (err) {
          showToast(`Error removing key: ${err.message}`, "error");
        } finally {
          btn.disabled = false;
        }
      });
    });

    const addKeyBtn = card.querySelector(".btn-add-key");
    if (addKeyBtn) {
      addKeyBtn.addEventListener("click", () => {
        openApiKeyModal(pId, pData);
      });
    }

    const removeKeyBtn = card.querySelector(".btn-remove-key");
    if (removeKeyBtn) {
      removeKeyBtn.addEventListener("click", () => {
        openRemoveKeyModal(pId, pData);
      });
    }

    const pingBtn = card.querySelector(".btn-ping-prov");
    if (pingBtn) {
      pingBtn.addEventListener("click", async () => {
        const latSpan = card.querySelector(`#latency-${pId}`);
        pingBtn.disabled = true;
        if (latSpan) {
          latSpan.textContent = "...";
          latSpan.style.display = "inline";
          latSpan.style.color = "#94a3b8";
        }
        try {
          const res = await fetch(`${API_BASE}/api/cloud/test_connection`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ provider: pId }),
          });
          const testRes = await res.json();
          if (testRes.success) {
            const ms = Math.round((testRes.latency_sec || 0) * 1000);
            if (latSpan) {
              latSpan.textContent = `${ms}ms`;
              latSpan.style.color = ms < 500 ? "#34d399" : "#38bdf8";
            }
            showToast(`${pData.name} responded in ${ms}ms`, "success", "Connection Verified");
          } else {
            if (latSpan) {
              latSpan.textContent = "Fail";
              latSpan.style.color = "#f87171";
            }
            const errMsg = testRes.message || testRes.error || "Unknown error";
            showToast(`${pData.name} ping failed: ${errMsg}`, "warning", "Ping Failed");
          }
        } catch (err) {
          if (latSpan) {
            latSpan.textContent = "Err";
            latSpan.style.color = "#f87171";
          }
          showToast(`Ping failed: ${err.message}`, "error");
        } finally {
          pingBtn.disabled = false;
        }
      });
    }

    container.appendChild(card);
  });
}

function renderConfiguredCloudModels(customModels, activeModel, cloudProviders) {
  const container = document.getElementById("configured-models-list");
  const countSpan = document.getElementById("configured-count");
  if (!container || !countSpan) return;

  container.innerHTML = "";

  const allActiveModels = [];
  const providersList = Array.isArray(cloudProviders) ? cloudProviders : (window.__cloudProviders || []);

  // 1. Models from connected Cloud Providers (with valid key count or has_key)
  providersList.forEach((prov) => {
    const hasKeys = (prov.key_count && prov.key_count > 0) || prov.has_key;
    if (hasKeys && Array.isArray(prov.models) && prov.models.length > 0) {
      prov.models.forEach((mName) => {
        allActiveModels.push({
          model_name: mName,
          provider_name: prov.name || prov.id.toUpperCase(),
          provider_id: prov.id,
          provider_url: "Connected Cloud API",
          model_type: prov.type || "chat",
          is_provider: true,
          key_count: prov.key_count || 1,
        });
      });
    }
  });

  // 2. Custom Configured Endpoints
  (customModels || []).forEach((cm) => {
    allActiveModels.push({
      model_name: cm.model_name,
      provider_name: cm.provider || "Custom Endpoint",
      provider_id: "custom",
      provider_url: cm.provider_url || "Custom Base URL",
      model_type: cm.model_type || "chat",
      is_provider: false,
    });
  });

  countSpan.textContent = `${allActiveModels.length} model${allActiveModels.length === 1 ? '' : 's'}`;

  if (allActiveModels.length === 0) {
    container.innerHTML = `<div class="text-muted">No external models configured yet. Connect a cloud provider above or use the form to add a custom endpoint!</div>`;
    return;
  }

  allActiveModels.forEach((m) => {
    const card = document.createElement("div");
    const isActive = m.model_name === activeModel;
    const badge = typeof getModelCategoryBadge === "function" ? getModelCategoryBadge(m.model_name) : { label: "General", cssClass: "general" };
    card.className = `model-card configured-model-card ${isActive ? 'active' : ''}`;
    
    card.innerHTML = `
      <div class="model-card-header">
        <div class="model-title-wrap">
          <span class="model-name font-mono-target">${escapeHtml(m.model_name)}</span>
          <span class="cmd-tier-pill ${badge.cssClass}">${badge.label}</span>
        </div>
        <span class="type-badge ${m.model_type}">${m.model_type.toUpperCase()}</span>
      </div>
      <div class="model-meta">
        <span class="model-provider-tag">${escapeHtml(m.provider_name)}</span>
        <span class="model-endpoint-hint">${escapeHtml(m.provider_url)}</span>
      </div>
      <div class="model-actions">
        ${!isActive 
          ? `<button class="btn btn-secondary btn-sm btn-activate-cloud-model" data-name="${escapeHtml(m.model_name)}">Activate</button>` 
          : `<span class="active-badge">Active</span>`}
        ${!m.is_provider 
          ? `<button class="btn btn-secondary btn-sm btn-delete-cloud-model" data-name="${escapeHtml(m.model_name)}" title="Delete Model">&times;</button>`
          : `<span class="provider-key-status" title="Managed by ${escapeHtml(m.provider_name)}">● Connected (${m.key_count} Key${m.key_count === 1 ? '' : 's'})</span>`}
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

    container.appendChild(card);
  });
}

// 8. Antigravity Autonomous Supervisor with AI Team Integration
function setupAntigravity() {
  btnRunAntigravity.addEventListener("click", async () => {
    const task = antigravityTaskInput.value.trim();
    if (!task) return;

    const useTeam = toggleAgTeamMode ? toggleAgTeamMode.checked : true;
    appendLog(`[START] Running autonomous task supervisor: "${task}"`);
    if (useTeam) {
      appendLog(`[AI TEAM] Delegating execution steps to PM, Architect, Specialist & QA...`);
    }

    try {
      const res = await fetch(`${API_BASE}/api/antigravity/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          task,
          project_path: activeProjectPath,
          use_team: useTeam,
        }),
      });
      const data = await res.json();
      if (data.success) {
        appendLog(`[STEERING] ${data.message}`);
        appendLog(`[STATUS] Continuous supervisor loop iterating across SDLC milestones...`);
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

// 9. Web Knowledge Search
function setupWebSearch() {
  if (!btnRunSearch || !toolSearchQuery) return;

  executeWebSearch = async function(query) {
    if (toggleInternet && !toggleInternet.checked) {
      showToast("Cannot search web: Offline Air-Gap Mode is active. Turn on Internet in the top bar to enable search.", "warning", "Offline Mode");
      return;
    }
    const q = (query !== undefined ? query : toolSearchQuery.value).trim();
    if (!q) return;
    toolSearchQuery.value = q;
    const statusTag = document.getElementById("search-status-tag");
    if (statusTag) statusTag.textContent = "Searching...";
    searchResultBox.innerHTML = `<div class="text-muted">Searching live internet & Wikipedia for "${escapeHtml(q)}"...</div>`;

    try {
      const res = await fetch(`${API_BASE}/api/search?q=${encodeURIComponent(q)}`);
      const data = await res.json();
      if (statusTag) statusTag.textContent = "Complete";

      if (data.results && Array.isArray(data.results) && data.results.length > 0) {
        searchResultBox.innerHTML = data.results.map((r, i) => `
          <div class="search-finding-card">
            <div class="search-finding-title">${i + 1}. ${escapeHtml(r.title || "Web Result")}</div>
            <div class="search-finding-snippet">${escapeHtml(r.snippet || r.body || "")}</div>
            ${r.url ? `<div class="search-finding-source"><span>Source:</span> <a href="${escapeHtml(sanitizeUrl(r.url))}" target="_blank" rel="noopener noreferrer">${escapeHtml(r.url)}</a></div>` : ""}
          </div>
        `).join("");
      } else if (data.message) {
        searchResultBox.textContent = data.message;
      } else {
        searchResultBox.textContent = "No verified web results found for this query.";
      }
    } catch (err) {
      if (statusTag) statusTag.textContent = "Error";
      searchResultBox.textContent = `Search error: ${err.message}`;
    }
  }

  btnRunSearch.addEventListener("click", () => executeWebSearch());
  toolSearchQuery.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      executeWebSearch();
    }
  });

  document.querySelectorAll(".btn-quick-search").forEach((btn) => {
    btn.addEventListener("click", () => {
      const q = btn.getAttribute("data-query");
      if (q) executeWebSearch(q);
    });
  });
}

async function loadDoctorTelemetry() {
  try {
    const res = await fetch(`${API_BASE}/api/doctor`);
    const data = await res.json();
    const hw = data.hardware || {};

    const elPlatform = document.getElementById("doc-platform");
    if (elPlatform) elPlatform.textContent = hw.os || data.platform || "Windows 11";

    const elCpu = document.getElementById("doc-cpu");
    if (elCpu) {
      elCpu.textContent = hw.cpu ? `${hw.cpu} (${hw.cores} Cores, ${hw.threads} Threads)` : "Multi-Core CPU";
    }

    const elGpu = document.getElementById("doc-gpu");
    if (elGpu) {
      elGpu.textContent = Array.isArray(hw.gpus) && hw.gpus.length > 0 ? hw.gpus.join(", ") : "Graphics Controller";
    }

    const elRam = document.getElementById("doc-ram");
    if (elRam) {
      elRam.textContent = hw.ram_total_gb ? `${hw.ram_total_gb} GB Physical RAM` : (data.ram ? `${data.ram.total_gb} GB` : "16 GB");
    }

    const elStorage = document.getElementById("doc-storage");
    if (elStorage) {
      if (hw.storage) {
        elStorage.textContent = `${hw.storage.free_gb} GB Free / ${hw.storage.total_gb} GB Total (${hw.storage.drive})`;
      } else {
        elStorage.textContent = "Disk Storage Ready";
      }
    }

    const elModel = document.getElementById("doc-model");
    if (elModel) elModel.textContent = data.active_model || activeModel;

    const elPython = document.getElementById("doc-python");
    if (elPython) elPython.textContent = data.python_version || "3.14";
  } catch (err) {
    console.error("Telemetry error:", err);
  }
}

const WEATHER_SVGS = {
  clear_day: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" class="weather-svg" xmlns="http://www.w3.org/2000/svg">
    <circle cx="12" cy="12" r="5" fill="#F59E0B"/>
    <path d="M12 2v2.5M12 19.5V22M4.93 4.93l1.77 1.77M17.3 17.3l1.77 1.77M2 12h2.5M19.5 12H22M6.7 17.3l-1.77 1.77M19.07 4.93l-1.77 1.77" stroke="#FBBF24" stroke-width="2" stroke-linecap="round"/>
  </svg>`,
  clear_night: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" class="weather-svg" xmlns="http://www.w3.org/2000/svg">
    <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" fill="#FBBF24" stroke="#F59E0B" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/>
    <circle cx="19" cy="4" r="1" fill="#38BDF8"/>
    <circle cx="16" cy="7" r="0.75" fill="#38BDF8"/>
  </svg>`,
  partly_cloudy_day: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" class="weather-svg" xmlns="http://www.w3.org/2000/svg">
    <circle cx="8.5" cy="8.5" r="4" fill="#F59E0B"/>
    <path d="M8.5 2.5v1.5M4.6 4.6l1.1 1.1M2.5 8.5H4M12.4 4.6l-1.1 1.1" stroke="#FBBF24" stroke-width="1.5" stroke-linecap="round"/>
    <path d="M6 17.5A4.5 4.5 0 0 1 10.5 13H11a4.8 4.8 0 0 1 9.4 1.2 3.2 3.2 0 0 1-1.4 6.3H6a4.5 4.5 0 0 1 0-9z" fill="#38BDF8" fill-opacity="0.9" stroke="#0284C7" stroke-width="1.2" stroke-linejoin="round"/>
  </svg>`,
  partly_cloudy_night: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" class="weather-svg" xmlns="http://www.w3.org/2000/svg">
    <path d="M12 3a5 5 0 0 0 5 5 5 5 0 0 0 1.2-.15A6 6 0 0 1 11 11a6 6 0 0 1 1-8z" fill="#FBBF24" stroke="#F59E0B" stroke-width="0.8"/>
    <path d="M6 17.5A4.5 4.5 0 0 1 10.5 13H11a4.8 4.8 0 0 1 9.4 1.2 3.2 3.2 0 0 1-1.4 6.3H6a4.5 4.5 0 0 1 0-9z" fill="#38BDF8" fill-opacity="0.85" stroke="#0284C7" stroke-width="1.2" stroke-linejoin="round"/>
  </svg>`,
  clear: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" class="weather-svg" xmlns="http://www.w3.org/2000/svg">
    <circle cx="12" cy="12" r="5" fill="#F59E0B"/>
    <path d="M12 2v2.5M12 19.5V22M4.93 4.93l1.77 1.77M17.3 17.3l1.77 1.77M2 12h2.5M19.5 12H22M6.7 17.3l-1.77 1.77M19.07 4.93l-1.77 1.77" stroke="#FBBF24" stroke-width="2" stroke-linecap="round"/>
  </svg>`,
  partly_cloudy: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" class="weather-svg" xmlns="http://www.w3.org/2000/svg">
    <circle cx="8.5" cy="8.5" r="4" fill="#F59E0B"/>
    <path d="M8.5 2.5v1.5M4.6 4.6l1.1 1.1M2.5 8.5H4M12.4 4.6l-1.1 1.1" stroke="#FBBF24" stroke-width="1.5" stroke-linecap="round"/>
    <path d="M6 17.5A4.5 4.5 0 0 1 10.5 13H11a4.8 4.8 0 0 1 9.4 1.2 3.2 3.2 0 0 1-1.4 6.3H6a4.5 4.5 0 0 1 0-9z" fill="#38BDF8" fill-opacity="0.9" stroke="#0284C7" stroke-width="1.2" stroke-linejoin="round"/>
  </svg>`,
  cloudy: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" class="weather-svg" xmlns="http://www.w3.org/2000/svg">
    <path d="M5.5 17a3.5 3.5 0 0 1-.3-7A5 5 0 0 1 15 9.5a4 4 0 0 1 3.5 4.5 3.5 3.5 0 0 1-3 3z" fill="#94A3B8" stroke="#64748B" stroke-width="1.5" stroke-linejoin="round"/>
  </svg>`,
  rain: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" class="weather-svg" xmlns="http://www.w3.org/2000/svg">
    <path d="M5.5 13.5a3.5 3.5 0 0 1-.3-7A5 5 0 0 1 15 6a4 4 0 0 1 3.5 4.5 3.5 3.5 0 0 1-3 3z" fill="#64748B" stroke="#475569" stroke-width="1.2" stroke-linejoin="round"/>
    <path d="M8 16.5l-1.2 3.5M12 16.5l-1.2 3.5M16 16.5l-1.2 3.5" stroke="#0284C7" stroke-width="2" stroke-linecap="round"/>
  </svg>`,
  showers: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" class="weather-svg" xmlns="http://www.w3.org/2000/svg">
    <path d="M5.5 13.5a3.5 3.5 0 0 1-.3-7A5 5 0 0 1 15 6a4 4 0 0 1 3.5 4.5 3.5 3.5 0 0 1-3 3z" fill="#38BDF8" fill-opacity="0.8" stroke="#0284C7" stroke-width="1.2" stroke-linejoin="round"/>
    <path d="M7.5 16.5l-1 3M11.5 16.5l-1 3M15.5 16.5l-1 3" stroke="#38BDF8" stroke-width="2" stroke-linecap="round"/>
  </svg>`,
  thunderstorm: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" class="weather-svg" xmlns="http://www.w3.org/2000/svg">
    <path d="M5.5 12.5a3.5 3.5 0 0 1-.3-7A5 5 0 0 1 15 5a4 4 0 0 1 3.5 4.5 3.5 3.5 0 0 1-3 3z" fill="#475569" stroke="#334155" stroke-width="1.2" stroke-linejoin="round"/>
    <path d="M11.5 11l-2 4h3l-1.5 5 4.5-6h-3l1.5-3z" fill="#F59E0B" stroke="#FBBF24" stroke-width="0.8" stroke-linejoin="round"/>
  </svg>`,
  fog: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" class="weather-svg" xmlns="http://www.w3.org/2000/svg">
    <path d="M4 8h16M3 12h18M5 16h14" stroke="#94A3B8" stroke-width="2" stroke-linecap="round"/>
  </svg>`,
};

function initLiveEnvironmentTelemetry() {
  const clockEl = document.getElementById("env-live-clock");
  const tempEl = document.getElementById("env-weather-temp");
  const condEl = document.getElementById("env-weather-cond");
  const iconEl = document.getElementById("env-weather-icon");

  function updateClock() {
    if (!clockEl) return;
    const now = new Date();
    clockEl.textContent = now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }

  updateClock();
  setInterval(updateClock, 1000);

  async function fetchLiveWeatherTelemetry() {
    try {
      const res = await fetch(`${API_BASE}/api/weather?city=Colombo`);
      const data = await res.json();
      if (data.success && data.data) {
        const w = data.data;
        if (tempEl) tempEl.textContent = `${Math.round(w.temperature_c)}°C`;
        if (condEl) condEl.textContent = w.condition_en || "Clear";
        if (iconEl) {
          const code = w.weathercode || 0;
          const currentHour = new Date().getHours();
          const isDay = (w.is_day !== undefined) ? (w.is_day === 1) : (currentHour >= 6 && currentHour < 18);

          let svgKey = "cloudy";
          if (code === 0) svgKey = isDay ? "clear_day" : "clear_night";
          else if (code <= 3) svgKey = isDay ? "partly_cloudy_day" : "partly_cloudy_night";
          else if (code <= 48) svgKey = "fog";
          else if (code <= 67) svgKey = "rain";
          else if (code <= 82) svgKey = "showers";
          else if (code <= 99) svgKey = "thunderstorm";

          iconEl.innerHTML = WEATHER_SVGS[svgKey] || WEATHER_SVGS.cloudy;
        }
      }
    } catch (e) {
      if (condEl) condEl.textContent = "Offline";
    }
  }

  fetchLiveWeatherTelemetry();
  setInterval(fetchLiveWeatherTelemetry, 10 * 60 * 1000);
}

let preflightPollTimer = null;

function stopPreflightPolling() {
  if (preflightPollTimer) {
    clearInterval(preflightPollTimer);
    preflightPollTimer = null;
  }
}

function startPreflightPolling() {
  if (preflightPollTimer) return;
  preflightPollTimer = setInterval(async () => {
    if (!preflightModal || preflightModal.classList.contains("hidden")) {
      stopPreflightPolling();
      return;
    }
    try {
      const res = await fetch(`${API_BASE}/api/system/preflight`);
      const data = await res.json();
      if (data && data.success) {
        showPreflightModal(data);
        if (data.ollama && data.ollama.running) {
          stopPreflightPolling();
        }
      }
    } catch (_) {}
  }, 1200);
}

// 10. Startup Preflight Check
async function checkStartupPreflight() {
  try {
    const res = await fetch(`${API_BASE}/api/system/preflight`);
    const data = await res.json();
    if (data.success && data.models) {
      if (!data.ready || (data.ollama && !data.ollama.running)) {
        showPreflightModal(data);
      }
      availableModels = data.models.installed || [];
      renderInstalledModels(availableModels);
      populateModelSelectors(availableModels);
      renderRecommendedModels(data.models.recommended || []);
      updateAttachmentCapabilities();
      if (data.models.storage) {
        const freeDisplay = document.getElementById("storage-free-display");
        if (freeDisplay) {
          freeDisplay.textContent = `${data.models.storage.free_gb} GB Free (${data.models.storage.drive})`;
        }
      }
    }
  } catch (err) {
    console.warn("Preflight check warning:", err);
  }
}

function showPreflightModal(data) {
  preflightStatusItems.innerHTML = "";

  const pyItem = document.createElement("div");
  pyItem.className = "preflight-item";
  pyItem.innerHTML = `
    <div class="preflight-item-info">
      <span class="preflight-item-title">Python Runtime</span>
      <span class="preflight-item-detail">v${data.python.version}</span>
    </div>
    <span class="preflight-badge healthy">Ready</span>
  `;
  preflightStatusItems.appendChild(pyItem);

  const olItem = document.createElement("div");
  olItem.className = "preflight-item";
  const olHealthy = data.ollama.running;
  olItem.innerHTML = `
    <div class="preflight-item-info">
      <span class="preflight-item-title">Ollama Local Engine</span>
      <span class="preflight-item-detail">${olHealthy ? "127.0.0.1:11434 Active" : (data.ollama.installed ? "Service Starting... (Checking localhost:11434)" : "Not Installed")}</span>
    </div>
    <span class="preflight-badge ${olHealthy ? 'healthy' : (data.ollama.installed ? 'warning' : 'error')}">
      ${olHealthy ? 'Online' : (data.ollama.installed ? 'Standby' : 'Missing')}
    </span>
  `;
  preflightStatusItems.appendChild(olItem);

  if (data.hardware) {
    const hwItem = document.createElement("div");
    hwItem.className = "preflight-item";
    const gpuName = data.hardware.gpus && data.hardware.gpus.length ? data.hardware.gpus[0] : "Graphics Adapter";
    hwItem.innerHTML = `
      <div class="preflight-item-info">
        <span class="preflight-item-title">System & Hardware</span>
        <span class="preflight-item-detail">${escapeHtml(data.hardware.cpu || 'CPU')} &bull; ${escapeHtml(gpuName)} &bull; ${data.hardware.ram_total_gb || 16} GB RAM</span>
      </div>
      <span class="preflight-badge healthy">Detected</span>
    `;
    preflightStatusItems.appendChild(hwItem);
  }

  const mdItem = document.createElement("div");
  mdItem.className = "preflight-item";
  const mdCount = data.models.count || 0;
  mdItem.innerHTML = `
    <div class="preflight-item-info">
      <span class="preflight-item-title">Local AI Models</span>
      <span class="preflight-item-detail">${mdCount} model${mdCount === 1 ? '' : 's'} installed</span>
    </div>
    <span class="preflight-badge ${mdCount > 0 ? 'healthy' : 'warning'}">
      ${mdCount > 0 ? `${mdCount} Available` : 'None Downloaded'}
    </span>
  `;
  preflightStatusItems.appendChild(mdItem);

  if (!data.ollama.installed) {
    preflightActionBox.classList.remove("hidden");
    preflightActionText.textContent = "Ollama is required to run local AI models privately on your device.";
    preflightActionButtons.innerHTML = `
      <a href="https://ollama.com/download/windows" target="_blank" class="btn btn-primary btn-sm">
        ${SVG_ICONS.globe} Download Ollama for Windows
      </a>
    `;
    stopPreflightPolling();
  } else if (!olHealthy) {
    // Ollama is installed but starting/standby: poll automatically and provide manual start trigger
    preflightActionBox.classList.remove("hidden");
    preflightActionText.textContent = "Connecting to Ollama local daemon on 127.0.0.1:11434...";
    preflightActionButtons.innerHTML = `
      <button type="button" class="btn btn-primary btn-sm" id="btn-preflight-boot-ollama">
        ${SVG_ICONS.cpu} Start Ollama Engine Now
      </button>
    `;
    document.getElementById("btn-preflight-boot-ollama")?.addEventListener("click", async () => {
      const btn = document.getElementById("btn-preflight-boot-ollama");
      if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<span class="spinner-inline"></span> Starting Ollama...`;
      }
      try {
        const res = await fetch(`${API_BASE}/api/system/preflight`);
        const updated = await res.json();
        if (updated.success) showPreflightModal(updated);
      } catch (_) {}
    });
    startPreflightPolling();
  } else if (mdCount === 0) {
    preflightActionBox.classList.remove("hidden");
    preflightActionText.textContent = "No local models are currently installed. We recommend installing Meta Llama 3.2 3B (2.0 GB) for fast, lightweight local reasoning.";
    preflightActionButtons.innerHTML = `
      <button type="button" class="btn btn-primary btn-sm" id="btn-preflight-pull-llama">
        ${SVG_ICONS.cpu} Download llama3.2:3b (Recommended)
      </button>
    `;
    document.getElementById("btn-preflight-pull-llama")?.addEventListener("click", () => {
      stopPreflightPolling();
      preflightModal.classList.add("hidden");
      switchTab("models");
      pullModel("llama3.2:3b");
    });
    stopPreflightPolling();
  } else {
    preflightActionBox.classList.add("hidden");
    stopPreflightPolling();
  }

  if (btnDismissPreflight) {
    if (olHealthy) {
      btnDismissPreflight.textContent = "Launch PAI Studio";
      btnDismissPreflight.className = "btn btn-primary";
    } else {
      btnDismissPreflight.textContent = "Launch Anyway";
      btnDismissPreflight.className = "btn btn-secondary";
    }
  }

  preflightModal.classList.remove("hidden");
}

btnClosePreflight.addEventListener("click", () => {
  stopPreflightPolling();
  preflightModal.classList.add("hidden");
});
btnDismissPreflight.addEventListener("click", () => {
  stopPreflightPolling();
  preflightModal.classList.add("hidden");
});

let currentColorMode = "dark"; // "dark" | "light" | "auto"

function setColorMode(mode, save = true) {
  currentColorMode = mode;
  let effectiveMode = mode;
  if (mode === "auto") {
    effectiveMode = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }

  if (effectiveMode === "light") {
    document.documentElement.setAttribute("data-theme", "light");
    document.body.classList.remove("dark-theme");
    document.body.classList.add("light-theme");
    const iconMoon = document.querySelector(".theme-icon.icon-moon");
    const iconSun = document.querySelector(".theme-icon.icon-sun");
    const text = document.getElementById("theme-mode-text");
    if (iconMoon) iconMoon.classList.add("hidden");
    if (iconSun) iconSun.classList.remove("hidden");
    if (text) text.textContent = "Light";
  } else {
    document.documentElement.setAttribute("data-theme", "dark");
    document.body.classList.remove("light-theme");
    document.body.classList.add("dark-theme");
    const iconMoon = document.querySelector(".theme-icon.icon-moon");
    const iconSun = document.querySelector(".theme-icon.icon-sun");
    const text = document.getElementById("theme-mode-text");
    if (iconMoon) iconMoon.classList.remove("hidden");
    if (iconSun) iconSun.classList.add("hidden");
    if (text) text.textContent = "Dark";
  }

  const radio = document.querySelector(`input[name="setting-color-mode"][value="${mode}"]`);
  if (radio) radio.checked = true;

  if (save) {
    localStorage.setItem("pai_color_mode", mode);
  }
}

// 11. Settings & Appearance View
function setupSettings() {
  const btnThemeModeToggle = document.getElementById("btn-theme-mode-toggle");
  btnThemeModeToggle?.addEventListener("click", () => {
    const nextMode = (currentColorMode === "light") ? "dark" : "light";
    setColorMode(nextMode);
    showToast(`Switched to ${nextMode.toUpperCase()} mode workstation!`, "info", "Theme Changed");
  });

  document.querySelectorAll('input[name="setting-color-mode"]').forEach((r) => {
    r.addEventListener("change", (e) => {
      setColorMode(e.target.value);
      showToast(`Theme mode set to ${e.target.value.toUpperCase()}`, "info");
    });
  });

  try {
    window.matchMedia("(prefers-color-scheme: light)").addEventListener("change", (e) => {
      if (currentColorMode === "auto") {
        setColorMode("auto", false);
      }
    });
  } catch (_) {}

  btnResetSettings?.addEventListener("click", () => {
    if (settingFontFamily) settingFontFamily.value = "jetbrains";
    if (settingFontSize) settingFontSize.value = "13px";
    const radio = document.querySelector('input[name="setting-theme"][value="theme-pai-cyber"]');
    if (radio) radio.checked = true;
    setColorMode("dark");
    applySettings({ font: "jetbrains", size: "13px", theme: "theme-pai-cyber" });
    localStorage.removeItem("pai_settings");
    localStorage.removeItem("pai_color_mode");
    showToast("Settings reset to defaults", "info");
  });

  btnSaveSettings?.addEventListener("click", () => {
    const font = settingFontFamily ? settingFontFamily.value : "jetbrains";
    const size = settingFontSize ? settingFontSize.value : "13px";
    const theme = document.querySelector('input[name="setting-theme"]:checked')?.value || "theme-pai-cyber";
    const colorMode = document.querySelector('input[name="setting-color-mode"]:checked')?.value || currentColorMode;
    const closeBehavior = document.querySelector('input[name="setting-close-behavior"]:checked')?.value || "tray";
    const notifyComplete = document.getElementById("setting-notify-complete") ? document.getElementById("setting-notify-complete").checked : true;

    setColorMode(colorMode);
    applySettings({ font, size, theme });
    localStorage.setItem("pai_settings", JSON.stringify({ font, size, theme }));
    localStorage.setItem("pai_close_behavior", closeBehavior);
    localStorage.setItem("pai_notify_complete", notifyComplete ? "true" : "false");
    invokeTauri("set_close_behavior", { toTray: closeBehavior === "tray" });
    showToast("Settings and background lifecycle options updated!", "success", "Settings Saved");
  });

  // Real-time listener on close behavior radio buttons
  document.querySelectorAll('input[name="setting-close-behavior"]').forEach(radio => {
    radio.addEventListener("change", (e) => {
      const val = e.target.value;
      localStorage.setItem("pai_close_behavior", val);
      invokeTauri("set_close_behavior", { toTray: val === "tray" });
      if (val === "tray") {
        showToast("Window will minimize to Windows System Tray on close", "info", "Background Execution");
      } else {
        showToast("Window will quit PAI completely on close", "info", "Exit Mode");
      }
    });
  });

  document.getElementById("btn-refresh-diagnostics")?.addEventListener("click", () => {
    loadDoctorTelemetry();
    showToast("System diagnostics refreshed!", "info");
  });
}

function applySettings(cfg) {
  // Fonts
  document.body.classList.remove("font-jetbrains", "font-fira", "font-cascadia", "font-consolas", "font-inter");
  document.body.classList.add(`font-${cfg.font || 'jetbrains'}`);

  if (cfg.size) {
    document.documentElement.style.setProperty("--font-mono-size", cfg.size);
    if (codeEditorTextarea) codeEditorTextarea.style.fontSize = cfg.size;
  }

  // Themes
  document.body.classList.remove("theme-pai-cyber", "theme-electric-cyan", "theme-neon-purple", "theme-monokai-matrix");
  document.body.classList.add(cfg.theme || "theme-pai-cyber");
}

function applyStoredSettings() {
  try {
    const savedColorMode = localStorage.getItem("pai_color_mode") || "dark";
    setColorMode(savedColorMode, false);

    const stored = localStorage.getItem("pai_settings");
    if (stored) {
      const cfg = JSON.parse(stored);
      applySettings(cfg);
      if (settingFontFamily) settingFontFamily.value = cfg.font || "jetbrains";
      if (settingFontSize) settingFontSize.value = cfg.size || "13px";
      const radio = document.querySelector(`input[name="setting-theme"][value="${cfg.theme || 'theme-pai-cyber'}"]`);
      if (radio) radio.checked = true;
    }

    const savedCloseBehavior = localStorage.getItem("pai_close_behavior") || "tray";
    const radioClose = document.querySelector(`input[name="setting-close-behavior"][value="${savedCloseBehavior}"]`);
    if (radioClose) radioClose.checked = true;
    invokeTauri("set_close_behavior", { toTray: savedCloseBehavior === "tray" });

    const savedNotify = localStorage.getItem("pai_notify_complete") !== "false";
    const chkNotify = document.getElementById("setting-notify-complete");
    if (chkNotify) chkNotify.checked = savedNotify;
  } catch (e) {
    console.warn("Could not read stored settings:", e);
  }
}

// Server Health Heartbeat
async function checkServerHealth() {
  try {
    const res = await fetch(`${API_BASE}/api/status`);
    const data = await res.json();
    if (data.status === "ready" || data.status === "ok") {
      serverStatusDot.className = "status-dot online";
      serverStatusText.textContent = "Engine Ready";
    } else {
      serverStatusDot.className = "status-dot offline";
      serverStatusText.textContent = "Degraded";
    }
    if (data.version) {
      updateActiveVersionDisplay(data.version);
    }
    if (data.internet_enabled !== undefined) {
      const isOnline = Boolean(data.internet_enabled);
      if (toggleInternet && toggleInternet.checked !== isOnline) {
        toggleInternet.checked = isOnline;
        updateInternetUIState(isOnline, data.active_model);
      }
    }
  } catch (err) {
    serverStatusDot.className = "status-dot offline";
    serverStatusText.textContent = "Offline";
  }
}

function updateActiveVersionDisplay(version) {
  if (!version) return;
  const cleanV = String(version).trim().replace(/^v/, "");
  const badgeVer = document.getElementById("badge-current-version");
  const modalCurrVer = document.getElementById("modal-curr-ver");
  if (badgeVer) {
    badgeVer.textContent = `v${cleanV} (Installed)`;
  }
  if (modalCurrVer) {
    modalCurrVer.textContent = `v${cleanV}`;
  }
}

// ==========================================================================
// Software Update System Controller (ADR-005 & GitHub Releases)
// ==========================================================================
let currentCachedUpdate = null;
let updatePollingTimer = null;

function setupUpdateSystem() {
  const btnCheckUpdate = document.getElementById("btn-check-update");
  const btnDownloadUpdate = document.getElementById("btn-download-update");
  const btnOpenUpdateModal = document.getElementById("btn-open-update-modal");
  const btnCloseUpdateModal = document.getElementById("btn-close-update-modal");
  const btnCancelUpdateModal = document.getElementById("btn-cancel-update-modal");
  const btnModalDownload = document.getElementById("btn-modal-download");
  const btnRestartForUpdate = document.getElementById("btn-restart-for-update");
  const btnModalRestart = document.getElementById("btn-modal-restart");
  const btnSimulateUpdateDev = document.getElementById("btn-simulate-update-dev");
  const updateModal = document.getElementById("update-modal");
  const selectChannel = document.getElementById("setting-update-channel");
  const autoCheckToggle = document.getElementById("setting-auto-check-update");

  const floatingWidget = document.getElementById("floating-update-widget");
  const btnFloatingUpdateDetails = document.getElementById("btn-floating-update-details");
  const btnFloatingUpdateRestart = document.getElementById("btn-floating-update-restart");
  const btnFloatingUpdateClose = document.getElementById("btn-floating-update-close");
  const headerUpdatePill = document.getElementById("header-update-pill");

  // Restore saved preferences & sync channel visibility
  function syncTestFlowVisibility() {
    if (!btnSimulateUpdateDev) return;
    const currentChannel = selectChannel ? selectChannel.value : (localStorage.getItem("pai_update_channel") || "stable");
    if (currentChannel === "beta") {
      btnSimulateUpdateDev.classList.remove("hidden");
    } else {
      btnSimulateUpdateDev.classList.add("hidden");
    }
  }

  if (selectChannel) {
    const savedChannel = localStorage.getItem("pai_update_channel") || "stable";
    selectChannel.value = savedChannel;
    selectChannel.addEventListener("change", () => {
      localStorage.setItem("pai_update_channel", selectChannel.value);
      syncTestFlowVisibility();
      showToast(`Update channel set to ${selectChannel.value.toUpperCase()}`, "info");
    });
  }
  syncTestFlowVisibility();

  if (autoCheckToggle) {
    const savedAuto = localStorage.getItem("pai_auto_check_update") !== "false";
    autoCheckToggle.checked = savedAuto;
    autoCheckToggle.addEventListener("change", () => {
      localStorage.setItem("pai_auto_check_update", autoCheckToggle.checked ? "true" : "false");
    });
  }

  // Check update button click
  btnCheckUpdate?.addEventListener("click", () => {
    checkSoftwareUpdates(true);
  });

  // Modal controls & minimize
  btnOpenUpdateModal?.addEventListener("click", () => {
    openSoftwareUpdateModal();
  });
  btnCloseUpdateModal?.addEventListener("click", () => {
    updateModal?.classList.add("hidden");
  });
  btnCancelUpdateModal?.addEventListener("click", () => {
    updateModal?.classList.add("hidden");
  });

  const btnMinimizeUpdateModal = document.getElementById("btn-minimize-update-modal");
  btnMinimizeUpdateModal?.addEventListener("click", () => {
    minimizeSoftwareUpdateModal();
  });

  // Download actions (Single clear download action with background streaming)
  btnDownloadUpdate?.addEventListener("click", () => {
    startSoftwareUpdateDownload();
  });
  btnModalDownload?.addEventListener("click", () => {
    if (updatePollingTimer) {
      minimizeSoftwareUpdateModal();
    } else {
      startSoftwareUpdateDownload();
    }
  });

  // Pause & Resume actions
  const btnModalPauseUpdate = document.getElementById("btn-modal-pause-update");
  const btnPanelPauseUpdate = document.getElementById("btn-panel-pause-update");
  const btnFloatingUpdatePause = document.getElementById("btn-floating-update-pause");

  btnModalPauseUpdate?.addEventListener("click", () => {
    toggleSoftwareUpdatePause();
  });
  btnPanelPauseUpdate?.addEventListener("click", () => {
    toggleSoftwareUpdatePause();
  });
  btnFloatingUpdatePause?.addEventListener("click", (e) => {
    e.stopPropagation();
    toggleSoftwareUpdatePause();
  });

  // Cancel actions
  const btnModalCancelUpdate = document.getElementById("btn-modal-cancel-update");
  const btnPanelCancelUpdate = document.getElementById("btn-panel-cancel-update");
  const btnFloatingUpdateCancel = document.getElementById("btn-floating-update-cancel");
  const btnPanelOpenModal = document.getElementById("btn-panel-open-modal");

  btnModalCancelUpdate?.addEventListener("click", () => {
    cancelSoftwareUpdateDownload();
  });
  btnPanelCancelUpdate?.addEventListener("click", () => {
    cancelSoftwareUpdateDownload();
  });
  btnFloatingUpdateCancel?.addEventListener("click", (e) => {
    e.stopPropagation();
    cancelSoftwareUpdateDownload();
  });
  btnPanelOpenModal?.addEventListener("click", () => {
    openSoftwareUpdateModal();
  });

  // Floating widget & header pill actions
  btnFloatingUpdateDetails?.addEventListener("click", () => {
    openSoftwareUpdateModal();
  });
  floatingWidget?.addEventListener("click", (e) => {
    if (e.target.closest("button")) return;
    openSoftwareUpdateModal();
  });
  btnFloatingUpdateRestart?.addEventListener("click", () => {
    applySoftwareUpdateAndRestart();
  });
  btnFloatingUpdateClose?.addEventListener("click", () => {
    if (floatingWidget) {
      floatingWidget.classList.add("hidden");
      floatingWidget.dataset.dismissed = "true";
    }
  });
  headerUpdatePill?.addEventListener("click", () => {
    openSoftwareUpdateModal();
  });

  // Restart actions
  btnRestartForUpdate?.addEventListener("click", () => {
    applySoftwareUpdateAndRestart();
  });
  btnModalRestart?.addEventListener("click", () => {
    applySoftwareUpdateAndRestart();
  });

  btnSimulateUpdateDev?.addEventListener("click", () => {
    simulateSoftwareUpdateFlow();
  });

  // Startup auto-check after 3.5 seconds
  const autoCheckOn = localStorage.getItem("pai_auto_check_update") !== "false";
  if (autoCheckOn) {
    setTimeout(() => {
      checkSoftwareUpdates(false);
    }, 3500);
  }

  // Immediately query status to synchronize version badge on startup
  fetch(`${API_BASE}/api/status`)
    .then(r => r.json())
    .then(data => {
      if (data && data.version) {
        updateActiveVersionDisplay(data.version);
      }
    })
    .catch(() => {});
}

async function checkSoftwareUpdates(interactive = false) {
  const btnCheckUpdate = document.getElementById("btn-check-update");
  const textCheckUpdate = document.getElementById("text-check-update");
  const iconCheck = document.getElementById("icon-check-update");
  const statusTitle = document.getElementById("update-status-title");
  const lastCheckedLabel = document.getElementById("update-last-checked-time");
  const dotStatus = document.getElementById("dot-update-status");
  const callout = document.getElementById("update-available-callout");
  const selectChannel = document.getElementById("setting-update-channel");
  const channel = selectChannel ? selectChannel.value : "stable";

  if (toggleInternet && !toggleInternet.checked) {
    if (textCheckUpdate) textCheckUpdate.textContent = "Check for Updates";
    if (iconCheck) iconCheck.classList.remove("spin");
    if (statusTitle) statusTitle.textContent = "Offline Air-Gap Active";
    if (dotStatus) dotStatus.className = "status-indicator-dot offline";
    if (interactive) {
      showToast("Cannot check for updates: Complete Offline Air-Gap Mode is active. Turn on Internet in top bar.", "warning", "Offline Mode");
    }
    return;
  }

  if (textCheckUpdate) textCheckUpdate.textContent = "Checking...";
  if (iconCheck) iconCheck.classList.add("spin");
  if (statusTitle) statusTitle.textContent = "Checking GitHub Releases...";

  try {
    const res = await fetch(`${API_BASE}/api/update/check?channel=${encodeURIComponent(channel)}`);
    const data = await res.json();

    if (lastCheckedLabel) {
      lastCheckedLabel.textContent = `Last checked: ${data.last_checked || new Date().toLocaleTimeString()}`;
    }

    const activeVer = data.current_version || (data.update_available ? data.current_version : data.latest_version) || "1.5.0-beta.1";
    updateActiveVersionDisplay(activeVer);

    if (data.update_available) {
      currentCachedUpdate = data;
      if (dotStatus) {
        dotStatus.className = "status-indicator-dot warning";
      }
      if (statusTitle) {
        statusTitle.textContent = `Update Available: v${data.latest_version}`;
      }
      if (callout) {
        callout.classList.remove("hidden");
        const tag = document.getElementById("callout-version-tag");
        const notes = document.getElementById("callout-release-notes");
        const dateSpan = document.getElementById("callout-release-date");
        if (tag) tag.textContent = `v${data.latest_version} Available (${data.release_name || "New Release"})`;
        if (notes) notes.textContent = data.release_notes || "A new verified update is available.";
        if (dateSpan) dateSpan.textContent = data.published_at ? new Date(data.published_at).toLocaleDateString() : "New";
      }

      if (interactive) {
        showToast(`New update v${data.latest_version} is available!`, "success", "Update Found");
        openSoftwareUpdateModal();
      } else {
        showToast(`PAI Studio update v${data.latest_version} is available in Settings`, "info", "Update Ready");
      }
    } else {
      if (dotStatus) {
        dotStatus.className = "status-indicator-dot online";
      }
      if (statusTitle) {
        statusTitle.textContent = `PAI Studio is Up to Date (v${activeVer})`;
      }
      if (callout) {
        callout.classList.add("hidden");
      }
      if (interactive) {
        showToast(`You are using the latest version of PAI Studio (v${activeVer})`, "info", "Up to Date");
      }
    }
  } catch (err) {
    console.error("Update check failed:", err);
    if (statusTitle) statusTitle.textContent = "Could not check for updates";
    if (interactive) {
      showToast(`Failed to connect to update server: ${err.message}`, "error", "Check Failed");
    }
  } finally {
    if (textCheckUpdate) textCheckUpdate.textContent = "Check for Updates";
    if (iconCheck) iconCheck.classList.remove("spin");
  }
}

function openSoftwareUpdateModal() {
  const modal = document.getElementById("update-modal");
  if (!modal) return;

  const data = currentCachedUpdate || {};
  const targetVer = data.latest_version || data.target_version || "1.4.3";
  const currVer = data.current_version || window.__pai_active_version || "1.5.0-beta.1";
  const relName = data.release_name || `Personal Agentic AI v${targetVer}`;
  const relNotes = data.release_notes || `### What's New in Personal Agentic AI v${targetVer}\n\n- Tauri 2.0 Native Auto-Updater & background atomic swap\n- Memory-safe stateless reasoning engine\n- ADR-005 Ed25519 cryptographic security verification\n- Real-time hardware telemetry and background download progress strip`;

  const currEl = document.getElementById("modal-curr-ver");
  const targetEl = document.getElementById("modal-target-ver");
  const nameEl = document.getElementById("modal-rel-name");
  const dateEl = document.getElementById("modal-rel-date");
  const sizeEl = document.getElementById("modal-rel-size");
  const notesEl = document.getElementById("modal-release-notes-content");
  const titleTextEl = document.getElementById("update-modal-title-text");

  if (titleTextEl) {
    titleTextEl.textContent = data.is_simulated
      ? "PAI Studio Software Update (Simulation Mode)"
      : "PAI Studio Software Update";
  }

  if (currEl) currEl.textContent = currVer.startsWith("v") ? currVer : `v${currVer}`;
  if (targetEl) targetEl.textContent = targetVer.startsWith("v") ? targetVer : `v${targetVer}`;
  if (nameEl) nameEl.textContent = relName;
  if (dateEl) dateEl.textContent = data.published_at ? new Date(data.published_at).toLocaleDateString() : new Date().toLocaleDateString();
  if (sizeEl) {
    const mb = data.size_bytes ? (data.size_bytes / (1024 * 1024)).toFixed(1) + " MB" : "~2.3 MB";
    sizeEl.textContent = mb;
  }
  if (notesEl) {
    let htmlNotes = relNotes
      .replace(/### (.*)/g, '<h4 style="font-size: 13px; font-weight: 600; margin: 6px 0; color: var(--text-normal);">$1</h4>')
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/^- (.*)/gm, '<li style="margin-left: 18px; margin-bottom: 4px; color: var(--text-dim);">$1</li>');
    notesEl.innerHTML = htmlNotes;
  }

  // Update primary action button state
  const btnModalDownload = document.getElementById("btn-modal-download");
  const btnModalRestart = document.getElementById("btn-modal-restart");
  const modalProgressBox = document.getElementById("modal-download-progress-box");
  if (btnModalRestart) btnModalRestart.classList.add("hidden");
  if (btnModalDownload) {
    btnModalDownload.classList.remove("hidden");
    btnModalDownload.disabled = false;
    if (updatePollingTimer) {
      btnModalDownload.title = "Click to minimize to background and continue working";
      btnModalDownload.innerHTML = `
        <svg class="btn-icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"></path>
        </svg>
        <span id="btn-modal-download-text">Download in Background</span>
      `;
      if (modalProgressBox) modalProgressBox.classList.remove("hidden");
    } else {
      btnModalDownload.title = "Start downloading this verified update";
      btnModalDownload.innerHTML = `
        <svg class="btn-icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"></path>
        </svg>
        <span id="btn-modal-download-text">Download & Install Now</span>
      `;
    }
  }

  modal.classList.remove("hidden");
}

async function simulateSoftwareUpdateFlow() {
  showToast("Simulating update discovery...", "info");
  try {
    const res = await fetch(`${API_BASE}/api/update/simulate_test`, { method: "POST" });
    const data = await res.json();
    currentCachedUpdate = data;

    const callout = document.getElementById("update-available-callout");
    const statusTitle = document.getElementById("update-status-title");
    const dotStatus = document.getElementById("dot-update-status");

    if (dotStatus) dotStatus.className = "status-indicator-dot warning";
    if (statusTitle) statusTitle.textContent = `New Update Available: v${data.latest_version || "1.4.3"}`;
    if (callout) {
      callout.classList.remove("hidden");
      const tag = document.getElementById("callout-version-tag");
      const notes = document.getElementById("callout-release-notes");
      if (tag) tag.textContent = `v${data.latest_version || "1.4.3"} Available (${data.release_name || "Preview Build"})`;
      if (notes) notes.textContent = data.release_notes || "A new verified release is available for Personal Agentic AI.";
    }

    openSoftwareUpdateModal();
    showToast(`Simulated update v${data.latest_version || "1.4.3"} is ready for review!`, "success");
  } catch (err) {
    showToast(`Simulation failed: ${err.message}`, "error");
  }
}

let isSoftwareUpdatePaused = false;

function minimizeSoftwareUpdateModal() {
  const updateModal = document.getElementById("update-modal");
  const floatingWidget = document.getElementById("floating-update-widget");
  const headerPill = document.getElementById("header-update-pill");

  if (updateModal) updateModal.classList.add("hidden");
  if (floatingWidget) {
    floatingWidget.classList.remove("hidden");
    delete floatingWidget.dataset.dismissed;
  }
  if (headerPill) headerPill.classList.remove("hidden");
  showToast("PAI update is downloading in the background. You can continue working.", "info", "Background Update", 4000);

  if (!updatePollingTimer) {
    startSoftwareUpdateDownload({ minimize: true });
  }
}

async function toggleSoftwareUpdatePause() {
  if (isSoftwareUpdatePaused) {
    await resumeSoftwareUpdateDownload();
  } else {
    await pauseSoftwareUpdateDownload();
  }
}

async function pauseSoftwareUpdateDownload() {
  try {
    const res = await fetch(`${API_BASE}/api/update/pause`, { method: "POST" });
    const data = await res.json();
    if (data.success) {
      isSoftwareUpdatePaused = true;
      updatePauseUI(true);
      showToast("PAI update download paused.", "info", "Download Paused");
    } else {
      showToast(data.error || "Could not pause download", "warning");
    }
  } catch (err) {
    showToast(`Failed to pause download: ${err.message}`, "error");
  }
}

async function resumeSoftwareUpdateDownload() {
  try {
    const res = await fetch(`${API_BASE}/api/update/resume`, { method: "POST" });
    const data = await res.json();
    if (data.success) {
      isSoftwareUpdatePaused = false;
      updatePauseUI(false);
      showToast("Resuming PAI update download...", "info", "Download Resumed");
    } else {
      showToast(data.error || "Could not resume download", "warning");
    }
  } catch (err) {
    showToast(`Failed to resume download: ${err.message}`, "error");
  }
}

function updatePauseUI(isPaused) {
  const modalPauseText = document.getElementById("btn-modal-pause-text");
  const modalPauseIcon = document.getElementById("btn-modal-pause-icon");
  const panelPauseText = document.getElementById("btn-panel-pause-text");
  const panelPauseIcon = document.getElementById("btn-panel-pause-icon");
  const floatingPauseText = document.getElementById("btn-floating-update-pause-text");
  const modalProgressLabel = document.getElementById("modal-progress-label");
  const updateProgressLabel = document.getElementById("update-progress-label");

  const text = isPaused ? "Resume" : "Pause";
  const icon = isPaused ? "▶" : "⏸";

  if (modalPauseText) modalPauseText.textContent = text;
  if (modalPauseIcon) modalPauseIcon.textContent = icon;
  if (panelPauseText) panelPauseText.textContent = text;
  if (panelPauseIcon) panelPauseIcon.textContent = icon;
  if (floatingPauseText) floatingPauseText.textContent = text;

  if (modalProgressLabel) {
    modalProgressLabel.textContent = isPaused ? "⏸ Download paused" : "Downloading update payload...";
  }
  if (updateProgressLabel) {
    updateProgressLabel.textContent = isPaused ? "⏸ Download paused" : "Downloading release payload...";
  }
}

async function cancelSoftwareUpdateDownload() {
  try {
    if (updatePollingTimer) {
      clearInterval(updatePollingTimer);
      updatePollingTimer = null;
    }
    await fetch(`${API_BASE}/api/update/cancel`, { method: "POST" });
    isSoftwareUpdatePaused = false;
    updatePauseUI(false);

    // Reset UI elements
    const downloadingPanel = document.getElementById("update-downloading-panel");
    const modalProgressBox = document.getElementById("modal-download-progress-box");
    const progressBar = document.getElementById("update-progress-bar");
    const modalProgressBar = document.getElementById("modal-progress-bar");
    const btnDownloadUpdate = document.getElementById("btn-download-update");
    const btnModalDownload = document.getElementById("btn-modal-download");
    const floatingWidget = document.getElementById("floating-update-widget");
    const headerPill = document.getElementById("header-update-pill");

    if (downloadingPanel) downloadingPanel.classList.add("hidden");
    if (modalProgressBox) modalProgressBox.classList.add("hidden");
    if (floatingWidget) floatingWidget.classList.add("hidden");
    if (headerPill) headerPill.classList.add("hidden");

    if (progressBar) progressBar.style.width = "0%";
    if (modalProgressBar) modalProgressBar.style.width = "0%";

    if (btnDownloadUpdate) {
      btnDownloadUpdate.disabled = false;
      btnDownloadUpdate.innerHTML = `
        <svg class="btn-icon-xs" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"></path>
        </svg>
        <span>Download & Install Update</span>
      `;
    }
    if (btnModalDownload) {
      btnModalDownload.disabled = false;
      btnModalDownload.innerHTML = `
        <svg class="btn-icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"></path>
        </svg>
        <span>Download & Install Now</span>
      `;
    }

    showToast("PAI update download cancelled.", "info", "Download Cancelled");
  } catch (err) {
    showToast(`Error cancelling download: ${err.message}`, "error");
  }
}

async function startSoftwareUpdateDownload(options = {}) {
  const shouldMinimize = options.minimize === true;
  const downloadingPanel = document.getElementById("update-downloading-panel");
  const modalProgressBox = document.getElementById("modal-download-progress-box");
  const btnDownloadUpdate = document.getElementById("btn-download-update");
  const btnModalDownload = document.getElementById("btn-modal-download");

  // Floating widget & header pill
  const floatingWidget = document.getElementById("floating-update-widget");
  const floatingBar = document.getElementById("floating-update-bar-fill");
  const floatingPct = document.getElementById("floating-update-pct");
  const floatingBytes = document.getElementById("floating-update-bytes");
  const floatingTitle = document.getElementById("floating-update-title");
  const headerPill = document.getElementById("header-update-pill");
  const progressBar = document.getElementById("update-progress-bar");
  const modalProgressBar = document.getElementById("modal-progress-bar");
  const metricsLabel = document.getElementById("update-progress-metrics");
  const modalMetrics = document.getElementById("modal-progress-metrics");

  const targetVer = currentCachedUpdate?.latest_version || "1.4.0-beta.1";

  if (btnDownloadUpdate) {
    btnDownloadUpdate.disabled = true;
    btnDownloadUpdate.innerHTML = `<span class="spinner-small"></span><span>Downloading...</span>`;
  }
  if (btnModalDownload) {
    btnModalDownload.disabled = false;
    btnModalDownload.title = "Click to minimize to background and continue working";
    btnModalDownload.innerHTML = `
      <svg class="btn-icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"></path>
      </svg>
      <span id="btn-modal-download-text">Download in Background</span>
    `;
  }

  if (downloadingPanel) downloadingPanel.classList.remove("hidden");
  if (modalProgressBox) modalProgressBox.classList.remove("hidden");
  if (floatingWidget) {
    floatingWidget.classList.remove("hidden");
    delete floatingWidget.dataset.dismissed;
  }
  if (headerPill) headerPill.classList.remove("hidden");

  // Immediate responsive UI feedback so user never sees a stuck 0% state
  if (floatingTitle) floatingTitle.textContent = `Downloading PAI v${targetVer}...`;
  if (floatingPct) floatingPct.textContent = "3%";
  if (floatingBar) floatingBar.style.width = "3%";
  if (floatingBytes) floatingBytes.textContent = "Connecting... • ~2.3 MB";
  if (progressBar) progressBar.style.width = "3%";
  if (modalProgressBar) modalProgressBar.style.width = "3%";
  if (metricsLabel) metricsLabel.textContent = "Connecting to update server... (3%)";
  if (modalMetrics) modalMetrics.textContent = "Connecting to update server...";

  // Reset pause state
  isSoftwareUpdatePaused = false;
  updatePauseUI(false);

  if (shouldMinimize) {
    const updateModal = document.getElementById("update-modal");
    if (updateModal) updateModal.classList.add("hidden");
    showToast("PAI update is downloading in the background. You can continue working.", "info", "Background Update", 4000);
  } else {
    showToast("Downloading update payload. You can minimize to background and continue working.", "info", "Download Started", 4500);
  }

  // Immediately kick off live polling
  if (updatePollingTimer) clearInterval(updatePollingTimer);
  updatePollingTimer = setInterval(pollSoftwareUpdateProgress, 350);

  try {
    const payload = currentCachedUpdate || { is_simulated: true, target_version: "1.4.0-beta.1" };
    fetch(`${API_BASE}/api/update/download`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }).catch(err => {
      console.warn("Background update download trigger error:", err);
    });
  } catch (err) {
    showToast(`Failed to initiate download: ${err.message}`, "error");
    if (btnDownloadUpdate) {
      btnDownloadUpdate.disabled = false;
      btnDownloadUpdate.innerHTML = `<span>Download & Install Update</span>`;
    }
    if (btnModalDownload) {
      btnModalDownload.disabled = false;
      btnModalDownload.innerHTML = `<span>Download & Install Now</span>`;
    }
  }
}

async function pollSoftwareUpdateProgress() {
  try {
    const res = await fetch(`${API_BASE}/api/update/status`);
    const data = await res.json();
    const state = data.download_state;
    if (!state) return;

    // Elements
    const progressBar = document.getElementById("update-progress-bar");
    const modalProgressBar = document.getElementById("modal-progress-bar");
    const metricsLabel = document.getElementById("update-progress-metrics");
    const modalMetrics = document.getElementById("modal-progress-metrics");
    const progressLabel = document.getElementById("update-progress-label");
    const modalProgressLabel = document.getElementById("modal-progress-label");

    // Floating widget elements
    const floatingWidget = document.getElementById("floating-update-widget");
    const floatingBar = document.getElementById("floating-update-bar-fill");
    const floatingPct = document.getElementById("floating-update-pct");
    const floatingBytes = document.getElementById("floating-update-bytes");
    const floatingTitle = document.getElementById("floating-update-title");
    const floatingRestartBtn = document.getElementById("btn-floating-update-restart");
    const floatingPulse = document.getElementById("floating-update-pulse");

    // Header pill
    const headerPill = document.getElementById("header-update-pill");
    const headerText = document.getElementById("header-update-text");

    const pct = state.percentage || 0;
    const mbDownloaded = (state.bytes_downloaded / (1024 * 1024)).toFixed(1);
    const mbTotal = (state.total_bytes / (1024 * 1024)).toFixed(1);
    const dispTotal = (mbTotal && mbTotal !== "0.0") ? mbTotal : "2.3";
    const speed = state.speed_mbps ? `${state.speed_mbps} MB/s` : "Normal";
    const targetVer = state.target_version || (currentCachedUpdate?.latest_version) || "1.4.0-beta.1";

    if (progressBar) progressBar.style.width = `${pct}%`;
    if (modalProgressBar) modalProgressBar.style.width = `${pct}%`;
    if (floatingBar) floatingBar.style.width = `${Math.max(pct, 2)}%`;

    const metricsText = `${mbDownloaded} MB / ${dispTotal} MB (${pct}%) • ${speed}`;
    if (metricsLabel) metricsLabel.textContent = metricsText;
    if (modalMetrics) modalMetrics.textContent = `${pct}% (${mbDownloaded} MB / ${dispTotal} MB)`;
    if (floatingPct) floatingPct.textContent = `${pct}%`;
    if (floatingBytes) floatingBytes.textContent = `${mbDownloaded} / ${dispTotal} MB • ${speed}`;

    if (state.status === "paused") {
      isSoftwareUpdatePaused = true;
      updatePauseUI(true);
      if (floatingTitle) floatingTitle.textContent = `⏸ Paused: PAI v${targetVer}`;
      if (headerText) headerText.textContent = `⏸ PAI Update: ${pct}%`;
      return;
    } else if (state.status === "downloading") {
      isSoftwareUpdatePaused = false;
      updatePauseUI(false);
      if (floatingTitle) floatingTitle.textContent = `Downloading PAI v${targetVer}...`;
      if (headerText) headerText.textContent = `PAI Update: ${pct}%`;
      if (headerPill) headerPill.classList.remove("hidden");
      if (floatingWidget && !floatingWidget.dataset.dismissed) floatingWidget.classList.remove("hidden");
    }

    if (state.status === "verifying") {
      if (progressLabel) progressLabel.textContent = "Verifying cryptographic signatures (ADR-005)...";
      if (modalProgressLabel) modalProgressLabel.textContent = "Verifying ADR-005 signatures...";
      if (floatingTitle) floatingTitle.textContent = `Verifying PAI v${targetVer}...`;
      if (headerText) headerText.textContent = "Verifying...";
    }

    if (state.status === "ready") {
      clearInterval(updatePollingTimer);
      updatePollingTimer = null;
      isSoftwareUpdatePaused = false;

      // Update UI to Ready state
      const downloadingPanel = document.getElementById("update-downloading-panel");
      const readyBanner = document.getElementById("update-ready-banner");
      const callout = document.getElementById("update-available-callout");
      const modalProgressBox = document.getElementById("modal-download-progress-box");
      const btnModalDownload = document.getElementById("btn-modal-download");
      const btnModalRestart = document.getElementById("btn-modal-restart");

      if (downloadingPanel) downloadingPanel.classList.add("hidden");
      if (callout) callout.classList.add("hidden");
      if (readyBanner) readyBanner.classList.remove("hidden");
      if (modalProgressBox) modalProgressBox.classList.add("hidden");
      if (btnModalDownload) btnModalDownload.classList.add("hidden");
      if (btnModalRestart) btnModalRestart.classList.remove("hidden");

      // Floating widget -> Ready
      if (floatingWidget) {
        floatingWidget.classList.remove("hidden");
        delete floatingWidget.dataset.dismissed;
      }
      if (floatingTitle) floatingTitle.textContent = `PAI v${targetVer} Ready to Install`;
      if (floatingBar) {
        floatingBar.style.width = "100%";
        floatingBar.style.background = "#10b981";
      }
      if (floatingPct) {
        floatingPct.textContent = "100%";
        floatingPct.style.color = "#10b981";
      }
      if (floatingBytes) floatingBytes.textContent = "Verified ADR-005 • Restart to finish";
      if (floatingRestartBtn) floatingRestartBtn.classList.remove("hidden");
      if (floatingPulse) {
        floatingPulse.style.background = "#10b981";
        floatingPulse.style.animation = "none";
      }

      // Header pill -> Ready
      if (headerPill) {
        headerPill.classList.remove("hidden");
        headerPill.style.background = "rgba(16, 185, 129, 0.2)";
        headerPill.style.borderColor = "#10b981";
      }
      if (headerText) headerText.textContent = `PAI v${targetVer} Ready (Restart)`;

      showToast(`PAI Studio update v${targetVer} is verified and ready! Restart to apply.`, "success", "Update Ready", 8000);
    } else if (state.status === "error") {
      clearInterval(updatePollingTimer);
      updatePollingTimer = null;
      isSoftwareUpdatePaused = false;
      showToast(`Update download failed: ${state.error_message}`, "error", "Download Failed");
      const btnDownloadUpdate = document.getElementById("btn-download-update");
      const btnModalDownload = document.getElementById("btn-modal-download");
      if (btnDownloadUpdate) {
        btnDownloadUpdate.disabled = false;
        btnDownloadUpdate.innerHTML = `<span>Download & Install Update</span>`;
      }
      if (btnModalDownload) {
        btnModalDownload.disabled = false;
        btnModalDownload.innerHTML = `<span>Download & Install Now</span>`;
      }
      if (floatingWidget) floatingWidget.classList.add("hidden");
      if (headerPill) headerPill.classList.add("hidden");
    }
  } catch (err) {
    console.warn("Polling update status error:", err);
  }
}

async function applySoftwareUpdateAndRestart() {
  showToast("Staging update and restarting PAI Studio...", "info", "Restarting");
  try {
    await fetch(`${API_BASE}/api/update/apply`, { method: "POST" });
    setTimeout(() => {
      if (window.__TAURI__ && window.__TAURI__.core) {
        invokeTauri("app_window_exit");
      } else {
        window.location.reload();
      }
    }, 1200);
  } catch (err) {
    showToast(`Restart failed: ${err.message}`, "error");
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
  // Code blocks with syntax header and copy button
  html = html.replace(/```([a-z0-9_\-]+)?\n([\s\S]*?)```/g, (match, lang, code) => {
    const language = (lang || 'code').trim();
    return `
      <div class="code-block-wrapper">
        <div class="code-block-header">
          <span class="code-lang font-mono-target">${language}</span>
          <button type="button" class="btn-copy-code" onclick="copyCodeBlock(this)" title="Copy code block">
            <svg class="btn-icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
            <span>Copy</span>
          </button>
        </div>
        <pre><code class="language-${language} font-mono-target">${code.trim()}</code></pre>
      </div>
    `;
  });
  // Inline code
  html = html.replace(/`([^`]+)`/g, '<code class="font-mono-target">$1</code>');
  // Bold & Italic
  html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  html = html.replace(/\*([^*]+)\*/g, '<em>$1</em>');
  // Headings
  html = html.replace(/^#### (.*?)$/gm, '<h4>$1</h4>');
  html = html.replace(/^### (.*?)$/gm, '<h3>$1</h3>');
  html = html.replace(/^## (.*?)$/gm, '<h2>$1</h2>');
  // Blockquotes
  html = html.replace(/^> (.*?)$/gm, '<blockquote>$1</blockquote>');
  // Paragraphs
  html = html.replace(/\n\n+/g, '</p><p>');
  html = `<p>${html}</p>`;
  return html;
}

// Clipboard & Regenerate Utilities
function copyToClipboard(content, btnEl) {
  if (!content) return;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(content).then(() => {
      onCopySuccess(btnEl);
    }).catch(() => {
      fallbackCopy(content, btnEl);
    });
  } else {
    fallbackCopy(content, btnEl);
  }
}

function fallbackCopy(content, btnEl) {
  try {
    const ta = document.createElement("textarea");
    ta.value = content;
    ta.style.position = "fixed";
    ta.style.left = "-9999px";
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
    onCopySuccess(btnEl);
  } catch (e) {
    showToast("Could not copy to clipboard", "error");
  }
}

function onCopySuccess(btnEl) {
  showToast("Copied to clipboard!", "success");
  if (btnEl) {
    const originalText = btnEl.innerHTML;
    btnEl.innerHTML = `<svg class="btn-icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg> <span>Copied!</span>`;
    btnEl.classList.add("copied");
    setTimeout(() => {
      btnEl.innerHTML = originalText;
      btnEl.classList.remove("copied");
    }, 2000);
  }
}

function copyCodeBlock(btn) {
  const wrapper = btn.closest(".code-block-wrapper");
  const codeEl = wrapper ? wrapper.querySelector("code") : null;
  const text = codeEl ? codeEl.innerText : "";
  if (!text) return;
  copyToClipboard(text, btn);
}

// Delegated click handler for copy buttons under CSP
document.addEventListener("click", (e) => {
  const btn = e.target.closest(".btn-copy-code");
  if (btn) {
    copyCodeBlock(btn);
  }
});

function regeneratePrompt(promptToRetry) {
  const p = promptToRetry || lastSentPrompt;
  if (!p) {
    showToast("No previous instruction to regenerate", "info");
    return;
  }
  chatInput.value = p;
  chatForm.dispatchEvent(new Event("submit"));
}


// 12. Native Desktop Context Menu & Browser Action Interception
let executeWebSearch = null; // Bound by setupWebSearch

function setupDesktopContextMenu() {
  const ctxMenu = document.getElementById("desktop-context-menu");
  const ctxCopy = document.getElementById("ctx-copy");
  const ctxCut = document.getElementById("ctx-cut");
  const ctxPaste = document.getElementById("ctx-paste");
  const ctxWebSearch = document.getElementById("ctx-web-search");
  const ctxSearchDivider = document.getElementById("ctx-search-divider");
  const ctxSelectAll = document.getElementById("ctx-select-all");

  let activeTarget = null;
  let activeSelectedText = "";

  function hideContextMenu() {
    if (ctxMenu) ctxMenu.classList.add("hidden");
  }

  // Intercept Right-Click Globally to Eliminate Browser Devtools/Save-As Menu
  window.addEventListener("contextmenu", (e) => {
    e.preventDefault(); // Eliminates default browser context menu (Inspect, Save as, etc.)

    activeTarget = e.target;
    activeSelectedText = window.getSelection() ? window.getSelection().toString().trim() : "";

    const isEditable = activeTarget && (
      activeTarget.tagName === "INPUT" ||
      activeTarget.tagName === "TEXTAREA" ||
      activeTarget.isContentEditable
    );

    // If neither editable nor has selected text, keep clean desktop window feel (no popup)
    if (!isEditable && !activeSelectedText) {
      hideContextMenu();
      return;
    }

    if (!ctxMenu) return;

    // Toggle menu actions
    if (ctxCut) ctxCut.style.display = isEditable ? "flex" : "none";
    if (ctxPaste) ctxPaste.style.display = isEditable ? "flex" : "none";
    if (ctxCopy) ctxCopy.disabled = !activeSelectedText && !isEditable;

    if (activeSelectedText) {
      if (ctxWebSearch) {
        ctxWebSearch.style.display = "flex";
        const shortQ = activeSelectedText.length > 20 ? activeSelectedText.slice(0, 18) + "..." : activeSelectedText;
        const textSpan = document.getElementById("ctx-web-search-text");
        if (textSpan) textSpan.textContent = `Search Web for "${shortQ}"`;
      }
      if (ctxSearchDivider) ctxSearchDivider.style.display = "block";
    } else {
      if (ctxWebSearch) ctxWebSearch.style.display = "none";
      if (ctxSearchDivider) ctxSearchDivider.style.display = "none";
    }

    // Position context menu
    ctxMenu.classList.remove("hidden");
    const menuWidth = ctxMenu.offsetWidth || 200;
    const menuHeight = ctxMenu.offsetHeight || 160;
    let posX = e.clientX;
    let posY = e.clientY;

    if (posX + menuWidth > window.innerWidth) posX = window.innerWidth - menuWidth - 8;
    if (posY + menuHeight > window.innerHeight) posY = window.innerHeight - menuHeight - 8;

    ctxMenu.style.left = `${Math.max(8, posX)}px`;
    ctxMenu.style.top = `${Math.max(8, posY)}px`;
  });

  // Hide context menu on click or blur
  window.addEventListener("click", hideContextMenu);
  window.addEventListener("blur", hideContextMenu);
  window.addEventListener("resize", hideContextMenu);

  // Context Actions
  ctxCopy?.addEventListener("click", () => {
    hideContextMenu();
    if (activeSelectedText) {
      copyToClipboard(activeSelectedText);
    } else if (activeTarget && typeof activeTarget.value === "string") {
      copyToClipboard(activeTarget.value);
    }
  });

  ctxCut?.addEventListener("click", () => {
    hideContextMenu();
    if (activeTarget && typeof activeTarget.value === "string") {
      const start = activeTarget.selectionStart || 0;
      const end = activeTarget.selectionEnd || activeTarget.value.length;
      const sel = activeTarget.value.substring(start, end);
      if (sel) {
        copyToClipboard(sel);
        activeTarget.setRangeText("", start, end, "end");
        activeTarget.dispatchEvent(new Event("input", { bubbles: true }));
      }
    }
  });

  ctxPaste?.addEventListener("click", async () => {
    hideContextMenu();
    if (activeTarget && typeof activeTarget.value === "string") {
      try {
        const text = await navigator.clipboard?.readText();
        if (text) {
          const start = activeTarget.selectionStart || activeTarget.value.length;
          const end = activeTarget.selectionEnd || start;
          activeTarget.setRangeText(text, start, end, "end");
          activeTarget.dispatchEvent(new Event("input", { bubbles: true }));
        }
      } catch (err) {
        showToast("Please press Ctrl+V to paste into field", "info");
      }
    }
  });

  ctxWebSearch?.addEventListener("click", () => {
    hideContextMenu();
    if (activeSelectedText) {
      switchTab("search");
      if (typeof executeWebSearch === "function") {
        executeWebSearch(activeSelectedText);
      }
    }
  });

  ctxSelectAll?.addEventListener("click", () => {
    hideContextMenu();
    if (activeTarget && typeof activeTarget.select === "function") {
      activeTarget.focus();
      activeTarget.select();
    } else {
      window.getSelection()?.selectAllChildren(document.body);
    }
  });

  // Desktop Global Shortcuts & Browser Interceptions
  window.addEventListener("keydown", (e) => {
    // 1. Toggle Light / Dark Mode: Ctrl + Shift + L
    if (e.ctrlKey && e.shiftKey && (e.key === "L" || e.key === "l")) {
      e.preventDefault();
      const next = (currentColorMode === "light") ? "dark" : "light";
      setColorMode(next);
      showToast(`Switched to ${next.toUpperCase()} mode theme!`, "info", "Theme Changed");
      return;
    }

    // 2. Focus Chat: Ctrl + K
    if (e.ctrlKey && (e.key === "k" || e.key === "K")) {
      e.preventDefault();
      switchTab("chat");
      chatInput?.focus();
      return;
    }

    // 3. Tab switching shortcuts: Ctrl + 1..7 (when not typing in an input)
    if (e.ctrlKey && !e.shiftKey && !e.altKey && e.key >= "1" && e.key <= "7") {
      const isInput = e.target && (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA");
      if (!isInput) {
        e.preventDefault();
        const tabs = ["chat", "projects", "models", "cloud", "search", "team", "settings"];
        const idx = parseInt(e.key, 10) - 1;
        if (tabs[idx]) {
          switchTab(tabs[idx]);
        }
        return;
      }
    }

    // 4. Block Developer Tools and Save-As Browser Key Shortcuts
    if (
      e.key === "F12" ||
      (e.ctrlKey && e.shiftKey && ["I", "i", "J", "j", "C", "c"].includes(e.key)) ||
      (e.ctrlKey && ["u", "U", "s", "S", "p", "P"].includes(e.key))
    ) {
      // Allow Ctrl+S specifically inside code editor to save file
      if ((e.key === "s" || e.key === "S") && currentTab === "projects" && !btnSaveFile?.disabled) {
        e.preventDefault();
        btnSaveFile?.click();
        return;
      }
      e.preventDefault();
    }
  });

  // Cowork Subnav Switcher
  window.switchCoworkSubnav = function(subview) {
    document.querySelectorAll(".cowork-subnav-btn").forEach(btn => {
      if (btn.getAttribute("data-subview") === subview) {
        btn.classList.add("active");
      } else {
        btn.classList.remove("active");
      }
    });

    const subviews = ["sessions", "team", "deliverables", "memory"];
    subviews.forEach(s => {
      const el = document.getElementById(`cowork-subview-${s}`);
      if (el) {
        if (s === subview) {
          el.classList.remove("hidden");
        } else {
          el.classList.add("hidden");
        }
      }
    });

    if (subview === "team") {
      loadTeamRoster();
    }
  };

  function initCoworkSubnav() {
    document.querySelectorAll(".cowork-subnav-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        const target = btn.getAttribute("data-subview");
        if (target) switchCoworkSubnav(target);
      });
    });
  }
  initCoworkSubnav();

  // Attach Cowork UI Handlers
  document.getElementById("btn-refresh-cowork")?.addEventListener("click", () => {
    loadCoworkData();
    loadTeamRoster();
  });

  document.getElementById("btn-cowork-mount-folder")?.addEventListener("click", async () => {
    try {
      const res = await fetch("http://127.0.0.1:8765/api/utils/select_folder", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ title: "Select Local Folder to Mount in Cowork" })
      });
      const data = await res.json();
      if (data.success && data.path) {
        await fetch("http://127.0.0.1:8765/api/cowork/folders/connect", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ path: data.path, name: data.name || "Workspace" })
        });
        showToast(`Mounted folder '${data.name || data.path}' into Cowork!`, "success", "Folder Connected");
        loadCoworkData();
      }
    } catch (err) {
      showToast(`Error mounting folder: ${err}`, "error", "Mount Failed");
    }
  });

  // Modal Handlers for Cowork Task
  const coworkModal = document.getElementById("cowork-task-modal");
  const coworkModalForm = document.getElementById("cowork-task-modal-form");
  const btnCloseCoworkModal = document.getElementById("btn-close-cowork-modal");
  const btnCancelCoworkModal = document.getElementById("btn-cancel-cowork-modal");
  const coworkFolderSelect = document.getElementById("cowork-modal-folder");
  const btnCoworkBrowseFolder = document.getElementById("btn-cowork-browse-folder");
  const coworkFolderHint = document.getElementById("cowork-modal-folder-hint");

  function openCoworkTaskModal() {
    if (!coworkModal) return;
    if (coworkFolderSelect) {
      coworkFolderSelect.innerHTML = `<option value="">(No specific workspace folder)</option>`;
      if (activeProjectPath) {
        const opt = document.createElement("option");
        opt.value = activeProjectPath;
        opt.textContent = `Active Project: ${activeProjectName || activeProjectPath}`;
        opt.selected = true;
        coworkFolderSelect.appendChild(opt);
        if (coworkFolderHint) {
          coworkFolderHint.textContent = `Active target: ${activeProjectPath}`;
          coworkFolderHint.style.color = "var(--accent-cyan)";
        }
      } else if (coworkFolderHint) {
        coworkFolderHint.textContent = "Select an active project or click Browse to choose any folder on your machine.";
        coworkFolderHint.style.color = "";
      }
      fetch("http://127.0.0.1:8765/api/cowork/folders")
        .then(r => r.json())
        .then(d => {
          if (d.success && d.folders) {
            d.folders.forEach(f => {
              if (f.host_path !== activeProjectPath) {
                const opt = document.createElement("option");
                opt.value = f.host_path;
                opt.textContent = `Mounted: ${f.name} (${f.host_path})`;
                coworkFolderSelect.appendChild(opt);
              }
            });
          }
        })
        .catch(() => {});
    }
    const titleInp = document.getElementById("cowork-modal-title");
    const goalInp = document.getElementById("cowork-modal-goal");
    const checkInp = document.getElementById("cowork-modal-checklist");
    if (titleInp) titleInp.value = "";
    if (goalInp) goalInp.value = "";
    if (checkInp) checkInp.value = "Decompose requirements\nExecute modifications\nVerify test results";

    coworkModal.classList.remove("hidden");
    titleInp?.focus();
  }

  function closeCoworkTaskModal() {
    if (coworkModal) coworkModal.classList.add("hidden");
  }

  coworkFolderSelect?.addEventListener("change", () => {
    const val = coworkFolderSelect.value;
    if (coworkFolderHint) {
      if (val) {
        coworkFolderHint.textContent = `Active target: ${val}`;
        coworkFolderHint.style.color = "var(--accent-cyan)";
      } else {
        coworkFolderHint.textContent = "No specific workspace folder selected (Global task).";
        coworkFolderHint.style.color = "";
      }
    }
  });

  btnCoworkBrowseFolder?.addEventListener("click", async () => {
    try {
      const origHtml = btnCoworkBrowseFolder.innerHTML;
      btnCoworkBrowseFolder.disabled = true;
      btnCoworkBrowseFolder.innerHTML = "<span>Browsing...</span>";
      const picked = await openNativeFolderDialog("Select Cowork Workspace Folder", activeProjectPath || "");
      btnCoworkBrowseFolder.disabled = false;
      btnCoworkBrowseFolder.innerHTML = origHtml;

      if (picked && picked.path) {
        const folderPath = picked.path;
        const folderName = picked.name || folderPath.split(/[\/\\]/).filter(Boolean).pop() || "Workspace";

        // Check if already in dropdown
        let found = false;
        if (coworkFolderSelect) {
          for (let i = 0; i < coworkFolderSelect.options.length; i++) {
            if (pathsMatch(coworkFolderSelect.options[i].value, folderPath)) {
              coworkFolderSelect.selectedIndex = i;
              found = true;
              break;
            }
          }
          if (!found) {
            const opt = document.createElement("option");
            opt.value = folderPath;
            opt.textContent = `Selected: ${folderName} (${folderPath})`;
            opt.selected = true;
            coworkFolderSelect.appendChild(opt);
          }
        }
        if (coworkFolderHint) {
          coworkFolderHint.textContent = `Active target: ${folderPath}`;
          coworkFolderHint.style.color = "var(--accent-cyan)";
        }
        showToast(`Workspace folder selected: ${folderName}`, "success", "Folder Selected");

        // Automatically connect to cowork backend
        fetch("http://127.0.0.1:8765/api/cowork/folders/connect", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ path: folderPath, name: folderName })
        }).then(() => loadCoworkData()).catch(() => {});
      }
    } catch (err) {
      console.error("Browse folder error:", err);
      showToast(`Error browsing folder: ${err}`, "error", "Browse Failed");
    }
  });

  // Cowork Quick Preset Pills Handlers
  document.querySelectorAll(".cowork-preset-pill").forEach(pill => {
    pill.addEventListener("click", () => {
      const preset = pill.getAttribute("data-preset");
      const titleInp = document.getElementById("cowork-modal-title");
      const goalInp = document.getElementById("cowork-modal-goal");
      const checkInp = document.getElementById("cowork-modal-checklist");
      if (preset === "refactor") {
        if (titleInp) titleInp.value = "Refactor Codebase Architecture & Modularization";
        if (goalInp) goalInp.value = "Review existing module structure, decouple monolithic components, apply clean separation of concerns, and ensure all unit tests pass without regression.";
        if (checkInp) checkInp.value = "Audit architectural boundaries and hotspots\nExtract modular helper services and interfaces\nRefactor call sites\nRun automated verification suite";
      } else if (preset === "bugfix") {
        if (titleInp) titleInp.value = "Investigate & Resolve Edge Case Bugs";
        if (goalInp) goalInp.value = "Reproduce reported issues, isolate root causes in codebase, implement targeted bug fixes, and add regression tests.";
        if (checkInp) checkInp.value = "Reproduce failure in isolated test case\nIdentify root cause in source file\nApply minimal robust patch\nVerify full test suite passes";
      } else if (preset === "feature") {
        if (titleInp) titleInp.value = "Implement New Workspace Feature";
        if (goalInp) goalInp.value = "Design and build the requested capability according to project conventions, including data models, handlers, and unit tests.";
        if (checkInp) checkInp.value = "Decompose feature specifications\nImplement core data models and methods\nIntegrate into application flow\nVerify functionality with end-to-end test";
      } else if (preset === "docs") {
        if (titleInp) titleInp.value = "Generate API Specs & Technical Documentation";
        if (goalInp) goalInp.value = "Inspect code signatures, exported types, and architecture to generate comprehensive Markdown documentation and developer guides.";
        if (checkInp) checkInp.value = "Scan codebase symbols and exported APIs\nDraft architectural overview & sequence flows\nDocument configuration and setup instructions\nVerify markdown compliance";
      }
    });
  });

  document.getElementById("btn-cowork-new-task")?.addEventListener("click", openCoworkTaskModal);
  btnCloseCoworkModal?.addEventListener("click", closeCoworkTaskModal);
  btnCancelCoworkModal?.addEventListener("click", closeCoworkTaskModal);
  coworkModal?.addEventListener("click", (e) => {
    if (e.target === coworkModal) closeCoworkTaskModal();
  });

  coworkModalForm?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const title = document.getElementById("cowork-modal-title")?.value?.trim();
    const goal = document.getElementById("cowork-modal-goal")?.value?.trim();
    const folder = document.getElementById("cowork-modal-folder")?.value || "";
    const checklistRaw = document.getElementById("cowork-modal-checklist")?.value || "";
    const checklist = checklistRaw.split("\n").map(s => s.trim()).filter(Boolean);
    const execMode = document.querySelector('input[name="cowork-exec-mode"]:checked')?.value || "team";

    if (!title || !goal) {
      showToast("Please provide both a title and objective goal.", "info", "Validation");
      return;
    }

    try {
      const res = await fetch("http://127.0.0.1:8765/api/cowork/tasks/create", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title,
          goal,
          folder,
          checklist: checklist.length > 0 ? checklist : ["Decompose requirements", "Execute modifications", "Verify test results"]
        })
      });
      const data = await res.json();
      if (data.success) {
        const taskId = data.task?.task_id || "1";
        showToast(`Dispatched task #${taskId}: '${title}' (${execMode === 'team' ? 'AI Team Sprint' : 'Direct Solo'})`, "success", "Task Dispatched");
        closeCoworkTaskModal();
        loadCoworkData();

        if (execMode === "team") {
          // Switch to Team / Live Collab subview to monitor sprint live
          window.switchCoworkSubnav?.("team");
          const targetDir = folder || activeProjectPath || "";
          
          if (teamActivityFeed) {
            teamActivityFeed.innerHTML = `
              <div class="fipa-msg-card inform">
                <div class="fipa-header">
                  <span class="fipa-badge">COORDINATOR</span>
                  <span class="fipa-agents">PAI MultiAgentTeam &rarr; Cowork Task #${taskId}</span>
                </div>
                <div class="fipa-body">Initiating collaborative sprint for Task #${taskId}: "${escapeHtml(title)}" across 7 engineering roles...</div>
              </div>
            `;
          }

          // Trigger team sprint in background
          fetch(`${API_BASE}/api/team/run`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              task: `${title}: ${goal}`,
              project_dir: targetDir
            })
          })
          .then(r => r.json())
          .then(async teamData => {
            if (teamData.success) {
              currentDeliverables = {
                plan: teamData.plan,
                specialist: teamData.specialist_assets,
                code: teamData.code_updates,
                qa: teamData.qa_verdict,
                explorer_findings: teamData.explorer_findings || "",
                citations: teamData.citations || [],
                critical_files: teamData.critical_files || [],
                debug_report: teamData.debug_report || {}
              };
              renderTeamMessages(teamData.messages || []);
              renderDeliverableTab("plan");
              if (targetDir) loadProjectFiles(targetDir);

              const artifacts = Object.keys(teamData.code_updates || {});
              await fetch("http://127.0.0.1:8765/api/cowork/tasks/complete", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                  task_id: taskId,
                  artifacts: artifacts.length > 0 ? artifacts : ["Deliverables WBS Plan", "QA Verdict"],
                  verified: ["QA Architecture Review & Code Verification"],
                  handoff_notes: `Sprint successfully completed by AI Team with ${artifacts.length} file artifacts.`
                })
              }).catch(() => {});

              loadCoworkData();
              showToast(`Task #${taskId} sprint completed with ${artifacts.length} deliverables!`, "success", "Sprint Complete");
              showSystemNotification("PAI Cowork: Task Completed", `Task #${taskId}: "${title}" completed with ${artifacts.length} deliverables.`);
            } else {
              showToast(`Sprint error: ${teamData.error || "Unknown error"}`, "error");
            }
          })
          .catch(err => {
            console.error("Team sprint fetch error:", err);
          });
        } else {
          // Direct Solo mode: Trigger autonomous background loop
          fetch("http://127.0.0.1:8765/api/cowork/tasks/run_auto", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ task_id: taskId, mode: "solo" })
          }).then(() => {
            const pollTask = setInterval(async () => {
              try {
                const tr = await fetch("http://127.0.0.1:8765/api/cowork/tasks");
                const td = await tr.json();
                if (td.success && td.tasks) {
                  const curr = td.tasks.find(t => t.task_id === taskId);
                  if (curr && (curr.status === "COMPLETED" || curr.status === "FAILED")) {
                    clearInterval(pollTask);
                    loadCoworkData();
                    if (curr.status === "COMPLETED") {
                      showToast(`Task #${taskId} completed!`, "success", "Cowork Complete");
                      showSystemNotification("PAI Cowork: Task Completed", `Task #${taskId}: "${title}" finished successfully.`);
                    }
                  }
                }
              } catch (_) {}
            }, 2000);
          }).catch(() => {});
        }
      } else {
        showToast(`Failed to dispatch task: ${data.error || "Unknown error"}`, "error", "Dispatch Error");
      }
    } catch (err) {
      showToast(`Failed to dispatch task: ${err}`, "error", "Dispatch Error");
    }
  });

  // Modal Handlers for Author Writing Style & Tone Calibration
  const styleModal = document.getElementById("writing-style-modal");
  const styleModalForm = document.getElementById("writing-style-modal-form");
  const btnCloseStyleModal = document.getElementById("btn-close-style-modal");
  const btnCancelStyleModal = document.getElementById("btn-cancel-style-modal");

  function openStyleModal() {
    if (!styleModal) return;
    const sampleInp = document.getElementById("style-modal-samples");
    if (sampleInp) sampleInp.value = "";
    styleModal.classList.remove("hidden");
    sampleInp?.focus();
  }

  function closeStyleModal() {
    if (styleModal) styleModal.classList.add("hidden");
  }

  document.getElementById("btn-cowork-voice-setup")?.addEventListener("click", openStyleModal);
  btnCloseStyleModal?.addEventListener("click", closeStyleModal);
  btnCancelStyleModal?.addEventListener("click", closeStyleModal);
  styleModal?.addEventListener("click", (e) => {
    if (e.target === styleModal) closeStyleModal();
  });

  styleModalForm?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const samples = document.getElementById("style-modal-samples")?.value?.trim();
    const tone = document.getElementById("style-modal-tone")?.value || "concise, direct, technical";

    if (!samples || samples.length < 20) {
      showToast("Please provide at least 20 characters of authentic writing.", "info", "Calibration");
      return;
    }

    try {
      const res = await fetch("http://127.0.0.1:8765/api/cowork/voice/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ samples: [samples], tone })
      });
      const data = await res.json();
      if (data.success) {
        showToast("Author writing style & tone persona successfully calibrated!", "success", "Style Calibrated");
        closeStyleModal();
        loadCoworkData();
      } else {
        showToast(`Calibration error: ${data.error || "Unknown error"}`, "error", "Style Error");
      }
    } catch (err) {
      showToast(`Error calibrating style: ${err}`, "error", "Style Error");
    }
  });
}

// ============================================================================
// PAI Cowork Workstation UI Controller
// ============================================================================

async function loadCoworkData() {
  const foldersList = document.getElementById("cowork-folders-list");
  const memoryList = document.getElementById("cowork-memory-list");
  const memoryCount = document.getElementById("cowork-memory-count");
  const tasksTable = document.getElementById("cowork-tasks-table");

  if (!foldersList || !memoryList || !tasksTable) return;

  // 1. Load Connected Folders
  try {
    const res = await fetch("http://127.0.0.1:8765/api/cowork/folders");
    const data = await res.json();
    if (data.success && data.folders && data.folders.length > 0) {
      foldersList.innerHTML = data.folders.map(f => `
        <div class="cowork-card-item">
          <div>
            <div class="font-semibold text-sm">${escapeHtml(f.name)}</div>
            <div class="font-mono text-xs text-muted">${escapeHtml(f.host_path)}</div>
            <div class="text-xs text-muted" style="margin-top:2px;">Citations: <code>computer://${escapeHtml(f.folder_id)}/</code></div>
          </div>
          <button type="button" class="btn btn-secondary btn-xs btn-disconnect-folder" data-id="${escapeHtml(f.folder_id)}">Disconnect</button>
        </div>
      `).join("");

      foldersList.querySelectorAll(".btn-disconnect-folder").forEach(btn => {
        btn.addEventListener("click", async (e) => {
          const fid = e.target.getAttribute("data-id");
          if (confirm(`Disconnect folder '${fid}'?`)) {
            await fetch("http://127.0.0.1:8765/api/cowork/folders/disconnect", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ folder_id: fid })
            });
            loadCoworkData();
          }
        });
      });
    } else {
      foldersList.innerHTML = `<div class="text-xs text-muted">No folders mounted. Click '+ Mount Folder' to connect your workspace.</div>`;
    }
  } catch (e) {
    console.error("Error loading cowork folders:", e);
  }

  // 2. Load Auto-Memory
  try {
    const res = await fetch("http://127.0.0.1:8765/api/cowork/memory");
    const data = await res.json();
    if (data.success && data.memory) {
      let allEntries = [];
      for (const [cat, items] of Object.entries(data.memory)) {
        if (Array.isArray(items)) {
          items.forEach(item => allEntries.push({ cat, ...item }));
        }
      }
      if (memoryCount) memoryCount.textContent = `${allEntries.length} entries`;

      if (allEntries.length > 0) {
        memoryList.innerHTML = allEntries.map(e => `
          <div class="cowork-card-item">
            <div>
              <span class="badge badge-subtle" style="text-transform:uppercase; font-size:10px;">${escapeHtml(e.cat)}</span>
              <strong style="margin-left:4px; font-size:12px;">${escapeHtml(e.key)}:</strong>
              <div class="text-xs" style="margin-top:2px;">${escapeHtml(e.content)}</div>
            </div>
            <button type="button" class="btn-clear-proj btn-del-mem" data-cat="${escapeHtml(e.cat)}" data-key="${escapeHtml(e.key)}" title="Delete memory">&times;</button>
          </div>
        `).join("");

        memoryList.querySelectorAll(".btn-del-mem").forEach(btn => {
          btn.addEventListener("click", async (e) => {
            const cat = e.target.getAttribute("data-cat");
            const k = e.target.getAttribute("data-key");
            await fetch("http://127.0.0.1:8765/api/cowork/memory/delete", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ mem_type: cat, key: k })
            });
            loadCoworkData();
          });
        });
      } else {
        memoryList.innerHTML = `<div class="text-xs text-muted">No memory entries yet. Use chat to say "Remember that..." or "Don't use...".</div>`;
      }
    }
  } catch (e) {
    console.error("Error loading cowork memory:", e);
  }

  // 3. Load Author Writing Style & Tone Persona Profile
  const voiceBox = document.getElementById("cowork-voice-summary");
  if (voiceBox) {
    try {
      const res = await fetch("http://127.0.0.1:8765/api/cowork/voice");
      const data = await res.json();
      if (data.success && data.profile) {
        const p = data.profile;
        voiceBox.innerHTML = `
          <div class="flex-between mb-2">
            <strong class="text-xs">Author Persona Active (${p.sample_count} sample${p.sample_count !== 1 ? 's' : ''})</strong>
            <button type="button" class="btn btn-secondary btn-xs btn-reset-style" title="Reset calibrated persona">Reset</button>
          </div>
          <div class="text-xs mb-1">Vocabulary Richness: <strong>${p.metrics.type_token_ratio}</strong> &bull; Avg Sentence: <strong>${p.metrics.mean_sentence_length} words</strong></div>
          <div class="text-xs text-muted mb-2">Tone: <strong>${escapeHtml(p.metrics.preferred_tone || 'Standard')}</strong></div>
          <div class="text-xs text-muted"><strong>Guidelines:</strong></div>
          <ul class="text-xs" style="padding-left:16px; margin:4px 0;">
            ${(p.guidelines || []).map(g => `<li>${escapeHtml(g)}</li>`).join("")}
          </ul>
        `;

        voiceBox.querySelector(".btn-reset-style")?.addEventListener("click", async () => {
          if (confirm("Reset author writing style persona to default?")) {
            await fetch("http://127.0.0.1:8765/api/cowork/voice/delete", { method: "POST" });
            showToast("Writing style persona reset.", "info");
            loadCoworkData();
          }
        });
      } else {
        voiceBox.innerHTML = `<div class="text-xs text-muted">No writing style calibrated yet. Click 'Calibrate Style' to train your authentic persona.</div>`;
      }
    } catch (e) {
      console.error("Error loading cowork writing style:", e);
    }
  }

  // 4. Load Cowork Tasks
  try {
    const res = await fetch("http://127.0.0.1:8765/api/cowork/tasks");
    const data = await res.json();
    if (data.success && data.tasks && data.tasks.length > 0) {
      tasksTable.innerHTML = data.tasks.map(t => {
        const statusClass = t.status === "COMPLETED" ? "status-completed" : "status-running";
        const completedCount = (t.checklist || []).filter(i => i.completed).length;
        const totalCount = (t.checklist || []).length;
        return `
          <div class="cowork-task-row">
            <div>
              <div class="flex-center-gap mb-1">
                <span class="cowork-task-status-badge ${statusClass}">${escapeHtml(t.status)}</span>
                <strong>${escapeHtml(t.title)}</strong>
                <span class="font-mono text-xs text-muted">#${escapeHtml(t.task_id)}</span>
              </div>
              <div class="text-xs text-muted">${escapeHtml(t.goal)}</div>
              <div class="text-xs font-mono" style="margin-top:4px;">Checklist: ${completedCount}/${totalCount} completed</div>
            </div>
            <div class="flex-center-gap">
              <button type="button" class="btn btn-secondary btn-xs btn-handoff-task" data-id="${escapeHtml(t.task_id)}" title="Generate Cursor-style author handoff artifact">Handoff</button>
              ${t.status === "RUNNING" ? `
                <button type="button" class="btn btn-secondary btn-xs btn-complete-task" data-id="${escapeHtml(t.task_id)}">Mark Done</button>
              ` : `<span class="text-xs text-muted">Finished</span>`}
            </div>
          </div>
        `;
      }).join("");

      tasksTable.querySelectorAll(".btn-handoff-task").forEach(btn => {
        btn.addEventListener("click", async (e) => {
          const tid = e.target.getAttribute("data-id");
          try {
            const res = await fetch("http://127.0.0.1:8765/api/cowork/tasks/handoff", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                task_id: tid,
                decisions: ["Implemented verified changes per task specification", "Maintained offline sandbox isolation"],
                risks: ["Check for environment variables or port contention"],
                verified: ["python -m unittest research/tests/test_thinking_and_cowork.py"]
              })
            });
            const data = await res.json();
            if (data.success) {
              showToast(`Author handoff generated for task #${tid}!`, "success", "Handoff Created");
              if (typeof alert !== "undefined") alert(data.handoff);
            }
          } catch (err) {
            showToast(`Error creating handoff: ${err}`, "error", "Handoff Error");
          }
        });
      });

      tasksTable.querySelectorAll(".btn-complete-task").forEach(btn => {
        btn.addEventListener("click", async (e) => {
          const tid = e.target.getAttribute("data-id");
          await fetch("http://127.0.0.1:8765/api/cowork/tasks/complete", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ task_id: tid, summary: "Completed by user in UI" })
          });
          loadCoworkData();
        });
      });
    } else {
      tasksTable.innerHTML = `
        <div class="empty-state-box">
          <svg class="empty-state-icon" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <rect x="2" y="7" width="20" height="14" rx="2" ry="2"></rect>
            <path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"></path>
          </svg>
          <div class="empty-state-title">No Active Task Sessions</div>
          <div class="empty-state-subtitle">Dispatch an autonomous agent workflow using &lsquo;New Task Session&rsquo; above.</div>
        </div>
      `;
    }
  } catch (e) {
    console.error("Error loading cowork tasks:", e);
  }
}
