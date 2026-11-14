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
document.addEventListener("DOMContentLoaded", () => {
  applyStoredSettings();
  setupNavigation();
  setupChat();
  setupProjects();
  setupTeam();
  setupSkills();
  setupModels();
  setupCloudKeys();
  setupAntigravity();
  setupWebSearch();
  setupSettings();
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
        updateChatPlaceholderForActiveModel();
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
      headerProjectSelect.value = activeProjectPath || "";
      await browseAndActivateProjectFolder();
      return;
    }
    await activateProject(selectedPath);
  });

  btnHeaderBrowseFolder.addEventListener("click", async () => {
    await browseAndActivateProjectFolder();
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
  if (tab === "antigravity") tab = "team";
  currentTab = tab;

  const tabNames = {
    chat: "Chat & Reasoning",
    projects: "Project Workspaces",
    models: "Models & Hardware",
    cloud: "Cloud Models",
    search: "Web Knowledge Search",
    team: "Multi-Agent Team",
    settings: "Settings & System"
  };
  const viewBreadcrumb = document.getElementById("current-view-name");
  if (viewBreadcrumb) {
    viewBreadcrumb.textContent = tabNames[tab] || tab;
  }

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
  if (tab === "projects") {
    loadProjects();
    if (!activeProjectPath && (!projectsData.projects || projectsData.projects.length === 0)) {
      showToast("Select a project folder to browse files and enable AI Team features.", "info", "Workspace Setup");
    }
  }
  if (tab === "team") loadTeamRoster();
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
    chatInput.placeholder = "Ask a question, or attach an image (📎) for visual inspection...";
  } else {
    chatInput.placeholder = "Ask anything, run /image, /team, /help... (Enter to send, Shift+Enter for newline)";
  }
}

const SLASH_COMMANDS = [
  { cmd: "/internet on", desc: "Enable live real-time internet web access & RAG", cat: "Grounding" },
  { cmd: "/internet off", desc: "Disable internet access (strictly offline mode)", cat: "Grounding" },
  { cmd: "/factcheck on", desc: "Enable real-time fact-checking & audit engine", cat: "Auditing" },
  { cmd: "/factcheck off", desc: "Disable automated fact-checking", cat: "Auditing" },
  { cmd: "/team", desc: "Toggle autonomous 4-role AI engineering team", cat: "Agents" },
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
        <p>👋 Hello! I am your native <strong>Personal Agentic AI</strong> companion.</p>
        <p>I can solve complex coding problems, manage project files, orchestrate an autonomous 4-role AI engineering team, verify claims against real-time web knowledge, and synthesize images.</p>
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

  if (!session.messages || session.messages.length === 0) {
    messagesList.innerHTML = `
      <div class="message assistant welcome">
        <div class="msg-header">
          <span class="avatar-badge">PAI</span>
          <span class="msg-author">Personal Agentic AI Assistant</span>
          <span class="msg-time">Just now</span>
        </div>
        <div class="msg-body">
          <p>👋 Hello! I am your native <strong>Personal Agentic AI</strong> companion.</p>
          <p>I can solve complex coding problems, manage project files, orchestrate an autonomous 4-role AI engineering team, verify claims against real-time web knowledge, and synthesize images.</p>
        </div>
      </div>
    `;
    return;
  }

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

function saveTurnToActiveSession(userRecord, assistantRecord) {
  let activeSession = chatSessions.find(s => s.id === activeSessionId);
  if (!activeSession) {
    activeSession = {
      id: activeSessionId || ("session_" + Date.now()),
      title: "New Conversation",
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      messages: []
    };
    chatSessions.unshift(activeSession);
    activeSessionId = activeSession.id;
  }

  activeSession.messages.push(userRecord);
  activeSession.messages.push(assistantRecord);
  activeSession.updatedAt = new Date().toISOString();

  if (activeSession.title === "New Conversation" || activeSession.messages.filter(m => m.role === 'user').length === 1) {
    let clean = (userRecord.text || "").replace(/^[\/\#\*\-\s]+/, "").trim();
    if (clean.length > 28) {
      clean = clean.substring(0, 28) + "...";
    }
    activeSession.title = clean || "Conversation";
    if (currentChatTitle) {
      currentChatTitle.textContent = activeSession.title;
    }
  }

  saveChatSessions();
  renderChatHistorySidebar();
}

function renderChatHistorySidebar() {
  if (!chatHistoryList) return;
  chatHistoryList.innerHTML = "";

  if (!chatSessions || chatSessions.length === 0) {
    chatHistoryList.innerHTML = `<div class="chat-history-empty" style="padding: 16px 10px; font-size: 11.5px; color: var(--text-dim); text-align: center;">No saved conversations</div>`;
    return;
  }

  chatSessions.forEach(session => {
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
      <button type="button" class="btn-delete-session" title="Delete conversation">
        <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2">
          <polyline points="3 6 5 6 21 6"></polyline>
          <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
        </svg>
      </button>
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

  chatForm.addEventListener("submit", async (e) => {
    e.preventDefault();
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
        ? `Currently active model **\`${activeModel}\`** is a **Vision Understanding model** (it inspects and analyzes uploaded images via 📎, but cannot synthesize new images).\n\n`
        : `Currently active model **\`${activeModel}\`** is a **Local Language model**.\n\n`;
      const imgHelpText = `### 🎨 How to Generate AI Images with \`/image\`\n\n` +
        modelNote +
        `To generate photorealistic images:\n` +
        `1. Provide a descriptive prompt with the command:\n` +
        `   \`\`\`text\n` +
        `   /image a majestic tree in a misty forest at dawn, cinematic lighting\n` +
        `   \`\`\`\n` +
        `2. Enable an Image Generator:\n` +
        `   - **Local Models:** Install **\`sd-turbo\`** or **\`stable-diffusion-v1-5\`** from the Local AI Models tab.\n` +
        `   - **Cloud AI:** Connect **Google Imagen 3** (via Gemini key) or **OpenAI DALL-E 3** in Settings & 3rd-Party Cloud AI.\n\n` +
        `*Tip:* To inspect or ask questions about an existing image using **${activeModel}**, attach the image file using the paperclip button (📎) and type your question!`;
      updateAssistantMessage(botId, imgHelpText, null, []);
      return;
    }
    if (lowerPrompt === "/help") {
      chatInput.value = "";
      appendUserMessage("/help");
      const botId = "msg-" + Date.now();
      appendAssistantPlaceholder(botId, false);
      const helpText = `### 💡 Available Slash Commands\n\n` +
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

    const promptToSend = prompt || "Please analyze and summarize the attached document(s).";
    const sentAttachments = [...currentChatAttachments];
    currentChatAttachments = [];
    renderChatAttachmentsTray();

    lastSentPrompt = promptToSend;
    chatInput.value = "";
    appendUserMessage(promptToSend, sentAttachments);
    btnSend.disabled = true;

    const userMsgRecord = {
      role: "user",
      text: promptToSend,
      attachments: sentAttachments,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    const botMsgId = "msg-" + Date.now();
    appendAssistantPlaceholder(botMsgId, isTeam);

    try {
      const res = await fetch(`${API_BASE}/api/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          prompt: promptToSend,
          model: activeModel,
          history: chatHistory,
          project_path: activeProjectPath,
          is_team_mode: isTeam,
          attachments: sentAttachments,
        }),
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
          updateAssistantMessage(botMsgId, data.response, data.factcheck, data.grounding, promptToSend);
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
        saveTurnToActiveSession(userMsgRecord, assistantMsgRecord);
      } else {
        updateAssistantError(botMsgId, data.error || "Execution error", promptToSend);
        const errorRecord = {
          role: "assistant",
          text: `⚠️ Error: ${data.error || "Execution error"}`,
          userPrompt: promptToSend,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        };
        saveTurnToActiveSession(userMsgRecord, errorRecord);
      }
    } catch (err) {
      updateAssistantError(botMsgId, `Server connection error: ${err.message}`, promptToSend);
      const connErrRecord = {
        role: "assistant",
        text: `⚠️ Server connection error: ${err.message}`,
        userPrompt: promptToSend,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };
      saveTurnToActiveSession(userMsgRecord, connErrRecord);
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

function appendUserMessage(text, attachments = []) {
  const msg = document.createElement("div");
  msg.className = "message user";

  let attachmentsHtml = "";
  if (attachments && attachments.length > 0) {
    attachmentsHtml = `
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

  msg.innerHTML = `
    <div class="msg-header">
      <span class="avatar-badge">YOU</span>
      <span class="msg-author">User</span>
      <span class="msg-time">${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
      <div class="msg-actions">
        <button type="button" class="btn-msg-action btn-copy-msg" title="Copy instruction to clipboard">
          <svg class="btn-icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
          <span>Copy</span>
        </button>
      </div>
    </div>
    <div class="msg-body">
      ${attachmentsHtml}
      <p>${escapeHtml(text)}</p>
    </div>
  `;
  const btnCopy = msg.querySelector(".btn-copy-msg");
  if (btnCopy) {
    btnCopy.addEventListener("click", () => copyToClipboard(text, btnCopy));
  }
  messagesList.appendChild(msg);
  messagesList.scrollTop = messagesList.scrollHeight;
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
      <span class="dot-flashing"></span>
      <span class="text-muted" style="margin-left: 8px;">${statusNote}</span>
    </div>
  `;
  messagesList.appendChild(msg);
  messagesList.scrollTop = messagesList.scrollHeight;
}

function updateAssistantMessage(id, text, factcheck, grounding, userPrompt = "") {
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
    const trustPct = (typeof factcheck.score === "number")
      ? Math.round(factcheck.score * 100)
      : (factcheck.fidelity !== undefined ? factcheck.fidelity : 0);
    const trustClass = trustPct >= 70 ? "trust-high" : (trustPct >= 35 ? "trust-med" : "trust-low");
    html += `
      <div class="factcheck-box ${trustClass}">
        <div class="factcheck-header">
          <span class="fc-title">${SVG_ICONS.shield} Real-Time Fact-Check Verdict</span>
          <span class="fc-score ${trustClass}">Trust: ${trustPct}%</span>
        </div>
        <div class="factcheck-body font-mono-target">${escapeHtml(factcheck.report)}</div>
      </div>
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
    btnBrowseProjFolder.disabled = true;
    try {
      const picked = await openNativeFolderDialog("Select Project Workspace Folder");
      if (picked && picked.path) {
        projPathInput.value = picked.path;
        if (!projNameInput.value.trim()) {
          projNameInput.value = picked.name || picked.path.split(/[\/\\]/).filter(Boolean).pop() || "Workspace";
        }
        showToast(`Selected project folder: ${picked.name || picked.path}`, "success");
      }
    } catch (err) {
      console.error("Browse error:", err);
    } finally {
      btnBrowseProjFolder.disabled = false;
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

async function openNativeFolderDialog(dialogTitle = "Select Project Workspace Folder") {
  try {
    const res = await fetch(`${API_BASE}/api/utils/select_folder`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: dialogTitle }),
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

async function browseAndActivateProjectFolder() {
  try {
    const picked = await openNativeFolderDialog("Select Project Workspace Folder");
    if (picked && picked.path) {
      const folderPath = picked.path;
      const folderName = picked.name || folderPath.split(/[\/\\]/).filter(Boolean).pop() || "Workspace";
      await fetch(`${API_BASE}/api/projects/save`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: folderName, path: folderPath }),
      });
      await loadProjects();
      await activateProject(folderPath);
      showToast(`Activated workspace: ${folderName}`, "success");
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
  const addOpt = document.createElement("option");
  addOpt.value = "__NEW_PROJECT__";
  addOpt.textContent = "+ Add / Open Project Folder...";
  headerProjectSelect.appendChild(addOpt);
}

function renderProjectsList(projects, activePath) {
  savedProjectsCount.textContent = projects.length;
  if (projects.length === 0) {
    projectsListContainer.innerHTML = `<div class="text-muted text-sm" style="padding: 10px;">No projects saved yet. Create one above or click Browse.</div>`;
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
                    member.role === "specialist_developer" ? SVG_ICONS.specialist : SVG_ICONS.qa;

    let modelOptions = availableModels.map(m => `<option value="${m}" ${m === member.current_model ? "selected" : ""}>${m}</option>`).join("");
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
      const picked = await openNativeFolderDialog("Select Custom Model Storage Directory");
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
    });
  }

  const btnBrowsePull = document.getElementById("btn-browse-pull-path");
  if (btnBrowsePull) {
    btnBrowsePull.addEventListener("click", async () => {
      const picked = await openNativeFolderDialog("Select Custom Model Destination Folder");
      if (picked && picked.path) {
        const targetInput = document.getElementById("pull-model-target-path");
        if (targetInput) targetInput.value = picked.path;
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

  function closeInstallModal() {
    if (modelInstallModal) modelInstallModal.classList.add("hidden");
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
      const picked = await openNativeFolderDialog("Select Global Model Storage Directory");
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
    });
  }

  if (btnBrowseInstallPath) {
    btnBrowseInstallPath.addEventListener("click", async () => {
      const picked = await openNativeFolderDialog("Select Custom Model Storage Directory");
      if (picked && picked.path) {
        if (installModalPathInput) {
          installModalPathInput.value = picked.path;
          checkInstallPathStorage(picked.path);
        }
        currentInstallTargetPath = picked.path;
        try {
          await fetch(`${API_BASE}/api/models/storage`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ path: picked.path }),
          });
          loadModelStoragePath();
        } catch (_) {}
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
      if (isModelDownloading) {
        closeInstallModal();
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
    });
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
      delBtn.addEventListener("click", async () => {
        if (!confirm(`Are you sure you want to uninstall and remove '${m.name}'? This will permanently delete the model weights and free ${m.size_gb} GB of disk space.`)) {
          return;
        }
        delBtn.disabled = true;
        delBtn.textContent = "Removing...";
        try {
          const res = await fetch(`${API_BASE}/api/models/delete`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name: m.name }),
          });
          const data = await res.json();
          if (data.success) {
            showToast(`Model '${m.name}' uninstalled successfully.`, "success", "Model Removed");
            await loadInstalledModels();
          } else {
            showToast(`Failed to uninstall: ${data.error || "Unknown error"}`, "error");
            delBtn.disabled = false;
            delBtn.textContent = "Uninstall";
          }
        } catch (err) {
          showToast(`Error uninstalling model: ${err.message}`, "error");
          delBtn.disabled = false;
          delBtn.textContent = "Uninstall";
        }
      });
    }

    installedModelsList.appendChild(card);
  });
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
        openModelInstallModal(rec);
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
      headerText.textContent = isPaused ? `⏸ Paused: ${tag} (${activeDownloadPct}%)` : `Downloading ${tag} (${activeDownloadPct}%)`;
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

function populateModelSelectors(models) {
  const currentVal = headerModelSelect.value;
  headerModelSelect.innerHTML = "";
  let hasSelected = false;

  models.forEach((m) => {
    const opt = document.createElement("option");
    opt.value = m.name;
    opt.textContent = `${m.name} (Local)`;
    if ((m.name === currentVal || m.is_active) && !hasSelected) {
      opt.selected = true;
      activeModel = m.name;
      hasSelected = true;
    }
    headerModelSelect.appendChild(opt);
  });

  (window.__configuredCloudModels || []).forEach((cm) => {
    const opt = document.createElement("option");
    opt.value = cm.model_name;
    opt.textContent = `${cm.model_name} (${cm.model_type === "image" ? "Cloud Image" : "Cloud Chat"})`;
    if (cm.model_name === currentVal && !hasSelected) {
      opt.selected = true;
      activeModel = cm.model_name;
      hasSelected = true;
    }
    headerModelSelect.appendChild(opt);
  });

  // If nothing selected, choose first available model option
  if (!hasSelected && headerModelSelect.options.length > 0) {
    headerModelSelect.options[0].selected = true;
    activeModel = headerModelSelect.options[0].value;
  }
  updateChatPlaceholderForActiveModel();
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
      updateChatPlaceholderForActiveModel();
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
        infoEl.textContent = `⚠️ Low Disk Space: Only ${free} GB Free on ${drive}`;
        infoEl.className = "storage-hint-warn";
      } else {
        infoEl.textContent = `✓ Storage Available: ${free} GB Free on ${drive}`;
        infoEl.className = "storage-hint-ok";
      }
    } else {
      infoEl.textContent = "Custom folder destination verified.";
    }
  } catch (e) {
    infoEl.textContent = "Storage destination verified.";
  }
}

async function openModelInstallModal(modelInfo) {
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

  // Unhide modal immediately for instant click response
  modal.classList.remove("hidden");

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

  if (isThisActive && progressSec) {
    progressSec.classList.remove("hidden");
    syncDownloadUI(activeDownloadPct, activeDownloadStatus, activeDownloadBytes, isDownloadPaused);
    if (confirmLabel) confirmLabel.textContent = isDownloadPaused ? "Resume Download" : "Run in Background & Close";
    if (cancelBtn) cancelBtn.style.display = "";
  } else {
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

  syncDownloadUI(100, `✓ Successfully installed ${modelName}!`, activeDownloadBytes, false);

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

function handleDownloadFailure(errorMsg) {
  isModelDownloading = false;
  isDownloadPaused = false;
  activeDownloadingModelTag = null;
  activeDownloadAbortController = null;

  syncDownloadUI(0, `Download failed: ${errorMsg}`, "0 MB / 0 MB", false);
  hideDownloadWidgets();

  const confirmLabel = document.getElementById("btn-confirm-install-label");
  const cancelBtn = document.getElementById("btn-cancel-install-modal");
  if (confirmLabel) confirmLabel.textContent = "Close";
  if (cancelBtn) cancelBtn.style.display = "";

  if (btnPullModel) {
    btnPullModel.disabled = false;
    btnPullModel.innerHTML = `<svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg><span>Start Download & Install</span>`;
  }

  showToast(`Model download failed: ${errorMsg}`, "error");
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
          if (hasCompletedSuccess || activeDownloadPct >= 95) {
            handleDownloadSuccess(modelName);
          } else {
            handleDownloadFailure("Download stream ended before completion.");
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
              let pct = activeDownloadPct;

              if (d.total && d.completed) {
                // Ensure small manifest layers don't skew the UI to 100% prematurely
                if (d.total > 5 * 1024 * 1024 || !activeDownloadPct) {
                  pct = Math.min(99, Math.round((d.completed / d.total) * 100));
                }
                const completedMB = (d.completed / (1024 * 1024)).toFixed(1);
                const totalMB = (d.total / (1024 * 1024)).toFixed(1);
                bytesStr = `${completedMB} MB / ${totalMB} MB`;
              }

              if (hasCompletedSuccess) {
                pct = 100;
                statusMsg = `✓ Successfully installed ${modelName}!`;
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
        <span class="model-name font-mono-target">${escapeHtml(m.model_name)}</span>
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
            ${r.url ? `<div class="search-finding-source"><span>Source:</span> <a href="${escapeHtml(r.url)}" target="_blank">${escapeHtml(r.url)}</a></div>` : ""}
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
          if (code === 0) iconEl.textContent = "☀️";
          else if (code <= 3) iconEl.textContent = "⛅";
          else if (code <= 48) iconEl.textContent = "🌫️";
          else if (code <= 67) iconEl.textContent = "🌧️";
          else if (code <= 82) iconEl.textContent = "🌦️";
          else if (code <= 99) iconEl.textContent = "⛈️";
          else iconEl.textContent = "⛅";
        }
      }
    } catch (e) {
      if (condEl) condEl.textContent = "Offline";
    }
  }

  fetchLiveWeatherTelemetry();
  setInterval(fetchLiveWeatherTelemetry, 10 * 60 * 1000);
}

// 10. Startup Preflight Check
async function checkStartupPreflight() {
  try {
    const res = await fetch(`${API_BASE}/api/system/preflight`);
    const data = await res.json();
    if (data.success && data.models) {
      if (!data.ready) {
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
      <span class="preflight-item-detail">${olHealthy ? "127.0.0.1:11434 Active" : (data.ollama.installed ? "Service Starting..." : "Not Installed")}</span>
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
  } else if (mdCount === 0) {
    preflightActionBox.classList.remove("hidden");
    preflightActionText.textContent = "No local models are currently installed. We recommend installing Meta Llama 3.2 3B (2.0 GB) for fast, lightweight local reasoning.";
    preflightActionButtons.innerHTML = `
      <button type="button" class="btn btn-primary btn-sm" id="btn-preflight-pull-llama">
        ${SVG_ICONS.cpu} Download llama3.2:3b (Recommended)
      </button>
    `;
    document.getElementById("btn-preflight-pull-llama")?.addEventListener("click", () => {
      preflightModal.classList.add("hidden");
      switchTab("models");
      pullModel("llama3.2:3b");
    });
  } else {
    preflightActionBox.classList.add("hidden");
  }

  preflightModal.classList.remove("hidden");
}

btnClosePreflight.addEventListener("click", () => preflightModal.classList.add("hidden"));
btnDismissPreflight.addEventListener("click", () => preflightModal.classList.add("hidden"));

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
    if (settingFontSize) settingFontSize.value = "13.5px";
    const radio = document.querySelector('input[name="setting-theme"][value="theme-pai-cyber"]');
    if (radio) radio.checked = true;
    setColorMode("dark");
    applySettings({ font: "jetbrains", size: "13.5px", theme: "theme-pai-cyber" });
    localStorage.removeItem("pai_settings");
    localStorage.removeItem("pai_color_mode");
    showToast("Settings reset to defaults", "info");
  });

  btnSaveSettings?.addEventListener("click", () => {
    const font = settingFontFamily ? settingFontFamily.value : "jetbrains";
    const size = settingFontSize ? settingFontSize.value : "13.5px";
    const theme = document.querySelector('input[name="setting-theme"]:checked')?.value || "theme-pai-cyber";
    const colorMode = document.querySelector('input[name="setting-color-mode"]:checked')?.value || currentColorMode;

    setColorMode(colorMode);
    applySettings({ font, size, theme });
    localStorage.setItem("pai_settings", JSON.stringify({ font, size, theme }));
    showToast("Appearance & Developer font updated!", "success", "Settings Saved");
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
  document.body.classList.remove("theme-pai-cyber", "theme-electric-cyan", "theme-neon-purple");
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
      if (settingFontSize) settingFontSize.value = cfg.size || "13.5px";
      const radio = document.querySelector(`input[name="setting-theme"][value="${cfg.theme || 'theme-pai-cyber'}"]`);
      if (radio) radio.checked = true;
    }
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
}
