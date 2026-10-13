/**
 * IntelliDocs Frontend Application Core JavaScript
 */

const API_BASE = "";

let currentUser = null;
let currentView = "dashboard";
let libraryPage = 1;
const libraryLimit = 15;
let currentDetailUuid = null;
let categoriesList = [];
let foldersList = [];
let tagsList = [];
let searchDebounceTimer = null;
let currentMfaToken = null;

// --- THEME MANAGEMENT ---
function getSavedTheme() {
  return localStorage.getItem("intellidocs_theme") || "light";
}

function initTheme() {
  const currentTheme = getSavedTheme();
  applyTheme(currentTheme);
}

function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  localStorage.setItem("intellidocs_theme", theme);

  const toggleIcon = document.getElementById("theme-toggle-icon");
  const toggleText = document.getElementById("theme-toggle-text");
  if (toggleIcon && toggleText) {
    if (theme === "dark") {
      toggleIcon.innerText = "☀️";
      toggleText.innerText = "Light";
    } else {
      toggleIcon.innerText = "🌙";
      toggleText.innerText = "Dark";
    }
  }

  const themeSelect = document.getElementById("settings-theme-select");
  if (themeSelect) {
    themeSelect.value = theme;
  }
}

function setTheme(theme) {
  applyTheme(theme);
  showToast(`Theme updated to ${theme} mode`, "info");
}

function toggleTheme() {
  const current = document.documentElement.getAttribute("data-theme") || "light";
  const nextTheme = current === "dark" ? "light" : "dark";
  setTheme(nextTheme);
}

// Execute early to prevent theme flash
initTheme();

// --- INITIALIZATION ---
document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  const resetToken = new URLSearchParams(window.location.search).get("reset_token");
  if (resetToken) {
    showPasswordResetPanel(resetToken);
    return;
  }
  checkAuthAndInit();
});

// --- AUTHENTICATION HELPERS ---
function getToken() {
  return localStorage.getItem("intellidocs_access_token");
}

function getRefreshToken() {
  return localStorage.getItem("intellidocs_refresh_token");
}

function setTokens(access, refresh) {
  if (access) localStorage.setItem("intellidocs_access_token", access);
  if (refresh) localStorage.setItem("intellidocs_refresh_token", refresh);
}

function clearTokens() {
  localStorage.removeItem("intellidocs_access_token");
  localStorage.removeItem("intellidocs_refresh_token");
}

async function checkAuthAndInit() {
  const token = getToken();
  if (!token) {
    showAuthView();
    return;
  }

  try {
    const user = await apiFetch("/auth/me");
    currentUser = user;
    showAppView();
    initApp();
  } catch (err) {
    clearTokens();
    showAuthView();
  }
}

function showAuthView() {
  document.getElementById("auth-view").style.display = "flex";
  document.getElementById("app-view").style.display = "none";
}

function showAppView() {
  document.getElementById("auth-view").style.display = "none";
  document.getElementById("app-view").style.display = "flex";
  if (currentUser) {
    document.getElementById("user-display-name").innerText = currentUser.username;
    document.getElementById("user-display-role").innerText = currentUser.role.toUpperCase();
  }
}

function switchAuthTab(tab) {
  const loginTab = document.getElementById("tab-login");
  const regTab = document.getElementById("tab-register");
  const loginForm = document.getElementById("form-login");
  const regForm = document.getElementById("form-register");
  const forgotPanel = document.getElementById("auth-forgot-panel");
  const resetPanel = document.getElementById("auth-reset-panel");
  const forgotLink = document.getElementById("auth-forgot-link");
  if (forgotPanel) forgotPanel.style.display = "none";
  if (resetPanel) resetPanel.style.display = "none";
  if (forgotLink) forgotLink.style.display = tab === "login" ? "flex" : "none";
  const tabs = document.querySelector(".auth-tabs");
  if (tabs) tabs.style.display = "flex";

  if (tab === "login") {
    loginTab.classList.add("active");
    regTab.classList.remove("active");
    loginForm.style.display = "block";
    regForm.style.display = "none";
  } else {
    regTab.classList.add("active");
    loginTab.classList.remove("active");
    regForm.style.display = "block";
    loginForm.style.display = "none";
  }
}

// INTELLIDOCS_AUTH_UI_POLISH_V1
function toggleAuthPassword(inputId, button) {
  const input = document.getElementById(inputId);
  if (!input || !button) return;
  const show = input.type === "password";
  input.type = show ? "text" : "password";
  button.textContent = show ? "Hide" : "Show";
  button.setAttribute("aria-label", show ? "Hide password" : "Show password");
  button.setAttribute("aria-pressed", show ? "true" : "false");
}

function updateRegisterPasswordStrength() {
  const input = document.getElementById("reg-password");
  const wrap = document.getElementById("reg-password-strength");
  const fill = document.getElementById("reg-password-strength-fill");
  const label = document.getElementById("reg-password-strength-label");
  if (!input || !wrap || !fill || !label) return;

  const password = input.value || "";
  if (!password) {
    wrap.dataset.level = "empty";
    fill.style.width = "0%";
    label.textContent = "Use at least 8 characters";
    return;
  }

  let score = 0;
  if (password.length >= 8) score++;
  if (password.length >= 12) score++;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
  if (/\d/.test(password)) score++;
  if (/[^a-zA-Z0-9]/.test(password)) score++;

  const levels = ["weak", "weak", "fair", "good", "strong", "strong"];
  const labels = ["Very weak — use a longer password", "Weak — add more variety", "Fair — add length or variety", "Good password", "Strong password", "Strong password"];
  const boundedScore = Math.min(5, score);
  wrap.dataset.level = levels[boundedScore];
  fill.style.width = `${Math.max(12, boundedScore * 20)}%`;
  label.textContent = labels[boundedScore];
}

async function handleLogin(e) {
  e.preventDefault();
  const username = document.getElementById("login-username").value.trim();
  const password = document.getElementById("login-password").value;

  try {
    const res = await apiFetch("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password })
    });

    if (res.mfa_required) {
      currentMfaToken = res.mfa_token;
      document.getElementById("mfa-login-code").value = "";
      document.getElementById("mfa-login-recovery-code").value = "";
      openModal("modal-mfa-verify-login");
      return;
    }

    setTokens(res.access_token, res.refresh_token);
    showToast("Logged in successfully!", "success");
    await checkAuthAndInit();
  } catch (err) {
    showToast(err.message || "Login failed", "error");
  }
}

async function submitMfaVerifyLogin(e) {
  e.preventDefault();
  const code = document.getElementById("mfa-login-code").value.trim();
  const recovery_code = document.getElementById("mfa-login-recovery-code").value.trim();

  if (!code && !recovery_code) {
    showToast("Please enter a 6-digit TOTP code or recovery code", "error");
    return;
  }

  try {
    const res = await apiFetch("/auth/mfa/verify", {
      method: "POST",
      body: JSON.stringify({
        mfa_token: currentMfaToken,
        code: code || null,
        recovery_code: recovery_code || null
      })
    });
    closeModal("modal-mfa-verify-login");
    currentMfaToken = null;
    setTokens(res.access_token, res.refresh_token);
    showToast("MFA verified! Logged in.", "success");
    await checkAuthAndInit();
  } catch (err) {
    showToast(err.message || "MFA verification failed", "error");
  }
}


async function handleRegister(e) {
  e.preventDefault();
  const username = document.getElementById("reg-username").value.trim();
  const email = document.getElementById("reg-email").value.trim();
  const password = document.getElementById("reg-password").value;
  const confirmPassword = document.getElementById("reg-confirm-password").value;

  if (password.length < 8) {
    showToast("Password must be at least 8 characters long.", "error");
    return;
  }
  if (password !== confirmPassword) {
    showToast("Passwords do not match.", "error");
    document.getElementById("reg-confirm-password").focus();
    return;
  }

  try {
    await apiFetch("/auth/register", {
      method: "POST",
      body: JSON.stringify({ username, email, password })
    });
    showToast("Account created! Logging in...", "success");
    // Auto login
    const res = await apiFetch("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password })
    });
    setTokens(res.access_token, res.refresh_token);
    await checkAuthAndInit();
  } catch (err) {
    showToast(err.message || "Registration failed", "error");
  }
}



// --- PASSWORD RECOVERY UI ---
let currentPasswordResetToken = null;

function _setAuthSubView(panelId) {
  const loginForm = document.getElementById("form-login");
  const registerForm = document.getElementById("form-register");
  const tabs = document.querySelector(".auth-tabs");
  const forgotLink = document.getElementById("auth-forgot-link");
  const forgotPanel = document.getElementById("auth-forgot-panel");
  const resetPanel = document.getElementById("auth-reset-panel");
  if (loginForm) loginForm.style.display = panelId ? "none" : (document.getElementById("tab-login")?.classList.contains("active") ? "block" : "none");
  if (registerForm) registerForm.style.display = panelId ? "none" : (document.getElementById("tab-register")?.classList.contains("active") ? "block" : "none");
  if (tabs) tabs.style.display = panelId ? "none" : "flex";
  if (forgotLink) forgotLink.style.display = !panelId && document.getElementById("tab-login")?.classList.contains("active") ? "flex" : "none";
  if (forgotPanel) forgotPanel.style.display = panelId === "forgot" ? "block" : "none";
  if (resetPanel) resetPanel.style.display = panelId === "reset" ? "block" : "none";
}

function showForgotPassword() {
  switchAuthTab("login");
  const status = document.getElementById("forgot-password-status");
  if (status) status.textContent = "";
  _setAuthSubView("forgot");
  document.getElementById("forgot-email")?.focus();
}

function showPasswordResetPanel(token) {
  currentPasswordResetToken = token;
  showAuthView();
  _setAuthSubView("reset");
  document.getElementById("reset-password-status").textContent = "";
  document.getElementById("reset-new-password")?.focus();
}

function showAuthForm(tab = "login") {
  currentPasswordResetToken = null;
  switchAuthTab(tab);
  _setAuthSubView(null);
  const url = new URL(window.location.href);
  url.searchParams.delete("reset_token");
  window.history.replaceState({}, document.title, url.pathname + url.hash);
}

async function handleForgotPassword(event) {
  event.preventDefault();
  const email = document.getElementById("forgot-email").value.trim();
  const status = document.getElementById("forgot-password-status");
  const button = event.submitter || document.querySelector("#form-forgot-password button[type='submit']");
  if (button) { button.disabled = true; button.textContent = "Sending…"; }
  if (status) { status.className = "auth-flow-status"; status.textContent = ""; }
  try {
    const result = await apiFetch("/auth/forgot-password", {
      method: "POST",
      body: JSON.stringify({ email })
    });
    if (status) {
      status.className = "auth-flow-status is-info";
      status.textContent = result.message || "If the account exists and email delivery is configured, instructions will be sent shortly.";
    }
  } catch (error) {
    if (status) {
      status.className = "auth-flow-status is-error";
      status.textContent = error.message || "Unable to process the request. Please try again later.";
    }
  } finally {
    if (button) { button.disabled = false; button.textContent = "Send reset link"; }
  }
}

async function handlePasswordReset(event) {
  event.preventDefault();
  const password = document.getElementById("reset-new-password").value;
  const confirmation = document.getElementById("reset-confirm-password").value;
  const status = document.getElementById("reset-password-status");
  const button = event.submitter || document.querySelector("#form-reset-password button[type='submit']");
  if (password !== confirmation) {
    if (status) { status.className = "auth-flow-status is-error"; status.textContent = "Passwords do not match."; }
    return;
  }
  if (!currentPasswordResetToken) {
    if (status) { status.className = "auth-flow-status is-error"; status.textContent = "This reset link is missing or expired. Request a new link."; }
    return;
  }
  if (button) { button.disabled = true; button.textContent = "Resetting…"; }
  if (status) { status.className = "auth-flow-status"; status.textContent = ""; }
  try {
    const result = await apiFetch("/auth/reset-password", {
      method: "POST",
      body: JSON.stringify({ token: currentPasswordResetToken, new_password: password })
    });
    clearTokens();
    currentUser = null;
    currentPasswordResetToken = null;
    document.getElementById("login-password").value = "";
    document.getElementById("reset-new-password").value = "";
    document.getElementById("reset-confirm-password").value = "";
    showAuthForm("login");
    showToast(result.message || "Password reset. Please sign in again.", "success");
  } catch (error) {
    if (status) { status.className = "auth-flow-status is-error"; status.textContent = error.message || "The reset link is invalid or expired."; }
  } finally {
    if (button) { button.disabled = false; button.textContent = "Reset password"; }
  }
}


async function handleLogout() {
  try {
    await apiFetch("/auth/logout", { method: "POST" });
  } catch (e) {
    // Ignore logout errors
  }
  clearTokens();
  currentUser = null;
  showAuthView();
  showToast("Logged out.", "info");
}

let lockTokens = {};

function getDocumentLockTokenHeaders(focusedUuid = "") {
  const focusToken = focusedUuid && lockTokens[focusedUuid] ? lockTokens[focusedUuid] : "";
  let mapJson = "{}";
  try {
    // Keep this custom header bounded. The focused document is always represented
    // by the single-token header; the map supplies other recently unlocked candidates.
    const entries = Object.entries(lockTokens || {}).filter(([key, value]) => key && typeof value === "string" && value);
    let selected = entries.slice(-24);
    if (focusedUuid && focusToken && !selected.some(([key]) => key === focusedUuid)) {
      selected = selected.length >= 24 ? selected.slice(1) : selected;
      selected.push([focusedUuid, focusToken]);
    }
    mapJson = JSON.stringify(Object.fromEntries(selected));
  } catch (_) {}
  // Tokens are signed and the backend validates every value against the specific
  // document UUID, recipient ID, and current lock hash before using it.
  return {
    "X-Access-Lock-Token": focusToken,
    "X-Access-Lock-Tokens": mapJson
  };
}

// --- API FETCH WRAPPER ---
async function apiFetch(endpoint, options = {}) {
  const token = getToken();
  const headers = options.headers || {};

  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  // A caller may explicitly supply the lock token for a different focused document.
  // Preserve that explicit header rather than replacing it with the last-opened document's token.
  if (!Object.prototype.hasOwnProperty.call(headers, "X-Access-Lock-Token") &&
      currentDetailUuid && lockTokens[currentDetailUuid]) {
    headers["X-Access-Lock-Token"] = lockTokens[currentDetailUuid];
  }

  if (!(options.body instanceof FormData) && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }

  options.headers = headers;

  let response = await fetch(API_BASE + endpoint, options);

  if (response.status === 401 && getRefreshToken()) {
    // Attempt token refresh
    try {
      const refreshRes = await fetch(API_BASE + "/auth/refresh", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: getRefreshToken() })
      });
      if (refreshRes.ok) {
        const data = await refreshRes.json();
        setTokens(data.access_token, data.refresh_token);
        headers["Authorization"] = `Bearer ${data.access_token}`;
        options.headers = headers;
        response = await fetch(API_BASE + endpoint, options);
      } else {
        clearTokens();
        showAuthView();
        throw new Error("Session expired. Please log in again.");
      }
    } catch (e) {
      clearTokens();
      showAuthView();
      throw e;
    }
  }

  if (!response.ok) {
    let errMsg = `Error ${response.status}: ${response.statusText}`;
    try {
      const errData = await response.json();
      if (errData.detail) {
        errMsg = typeof errData.detail === "string" ? errData.detail : JSON.stringify(errData.detail);
      }
    } catch (e) {}
    throw new Error(errMsg);
  }

  // File downloads or JSON
  const contentType = response.headers.get("content-type");
  if (contentType && contentType.includes("application/json")) {
    return await response.json();
  }
  return response;
}

// --- TOAST NOTIFICATIONS ---
function showToast(message, type = "info") {
  const container = document.getElementById("toast-container");
  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `
    <span>${escapeHtml(message)}</span>
    <span style="cursor:pointer; font-weight:bold;" onclick="this.parentElement.remove()">&times;</span>
  `;
  container.appendChild(toast);

  setTimeout(() => {
    if (toast.parentElement) toast.remove();
  }, 4000);
}

// --- MODAL UTILS ---
function openModal(modalId) {
  const el = document.getElementById(modalId);
  if (el) el.classList.add("active");
}

function closeModal(modalId) {
  const el = document.getElementById(modalId);
  if (el) el.classList.remove("active");
}

// --- NAVIGATION & ROUTING ---
function initApp() {
  loadMetadataDropdowns();
  fetchNotifications();
  fetchBadges();
  navigateTo("dashboard");
}

function navigateTo(viewName) {
  currentView = viewName;
  const views = document.querySelectorAll(".page-view");
  views.forEach(v => v.style.display = "none");

  const navItems = document.querySelectorAll(".nav-item");
  navItems.forEach(n => n.classList.remove("active"));

  const targetView = document.getElementById(`view-${viewName}`);
  const targetNav = document.getElementById(`nav-${viewName}`);

  if (targetView) targetView.style.display = "block";
  if (targetNav) targetNav.classList.add("active");

  // View specific loaders
  if (viewName === "dashboard") loadDashboard();
  else if (viewName === "library") loadLibraryDocuments();
  else if (viewName === "upload") resetUploadForm();
  else if (viewName === "suggestions") loadSuggestions();
  else if (viewName === "duplicates") initDuplicatesPage();
  else if (viewName === "organization") loadOrganizationView();
  else if (viewName === "explorer") loadExplorerGraph();
  else if (viewName === "help") loadHelpSupportView();
  else if (viewName === "profile") loadProfile();
  else if (viewName === "settings") loadSettings();
  else if (viewName === "groups") { loadGroups(); loadSharedDocuments(); }
  else if (viewName === "trash") loadTrashDocuments();
  else if (viewName === "quarantine") loadQuarantinedDocuments();
}

async function loadProfile() {
  try {
    const user = await apiFetch("/auth/me");
    currentUser = user;

    const usernameEl = document.getElementById("profile-username");
    if (usernameEl) usernameEl.innerText = user.username || "User";

    const valUserEl = document.getElementById("profile-val-username");
    if (valUserEl) valUserEl.innerText = user.username || "-";

    const valEmailEl = document.getElementById("profile-val-email");
    if (valEmailEl) valEmailEl.innerText = user.email || "-";
    ensureEmailChangeUI(user);

    const roleStr = (user.role || "user").toUpperCase();
    const valRoleEl = document.getElementById("profile-val-role");
    if (valRoleEl) valRoleEl.innerText = roleStr;

    const badgeRoleEl = document.getElementById("profile-role-badge");
    if (badgeRoleEl) badgeRoleEl.innerText = roleStr;

    const initial = user.username ? user.username.charAt(0).toUpperCase() : "U";
    const avatarEl = document.getElementById("profile-avatar");
    if (avatarEl) avatarEl.innerText = initial;

    let createdStr = user.created_at;
    if (createdStr) {
      try {
        const dt = new Date(createdStr);
        createdStr = dt.toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' });
      } catch (e) {}
    }
    const valCreatedEl = document.getElementById("profile-val-created");
    if (valCreatedEl) valCreatedEl.innerText = createdStr || "N/A";
  } catch (err) {
    showToast("Failed to load profile details", "error");
  }
}



// --- PROFILE: CHANGE EMAIL USING VERIFIED EMAIL OTP ---
function ensureEmailChangeUI(user) {
  const emailEl = document.getElementById("profile-val-email");
  const profileView = document.getElementById("view-profile");
  if (!emailEl || !profileView) return;

  let actions = document.getElementById("profile-email-change-actions");
  if (!actions) {
    actions = document.createElement("div");
    actions.id = "profile-email-change-actions";
    actions.style.cssText = "display:flex;justify-content:flex-end;gap:10px;margin:14px 0 20px;";
    const button = document.createElement("button");
    button.type = "button";
    button.className = "btn btn-secondary btn-sm";
    button.textContent = "Change Email";
    button.addEventListener("click", openEmailChangeModal);
    actions.appendChild(button);
    profileView.appendChild(actions);
  }
  if (!document.getElementById("email-change-modal")) {
    const modal = document.createElement("div");
    modal.id = "email-change-modal";
    modal.setAttribute("role", "dialog");
    modal.setAttribute("aria-modal", "true");
    modal.setAttribute("aria-labelledby", "email-change-title");
    modal.style.cssText = "display:none;position:fixed;inset:0;z-index:30000;background:rgba(5,10,25,.72);padding:20px;align-items:center;justify-content:center;";
    modal.innerHTML = `
      <div class="email-change-card" style="width:min(100%,480px);max-height:90vh;overflow:auto;background:var(--card-bg,var(--surface,#fff));color:var(--text-primary,#222);border:1px solid var(--border-color,#ddd);border-radius:16px;padding:24px;box-shadow:0 24px 70px rgba(0,0,0,.32);">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:8px;">
          <h2 id="email-change-title" style="margin:0;font-size:1.25rem;">Change email address</h2>
          <button type="button" class="btn btn-secondary btn-sm" id="email-change-close" aria-label="Close">✕</button>
        </div>
        <p style="color:var(--text-secondary,#666);margin:0 0 16px;line-height:1.5;">Confirm your password. We will send a 6-digit code to your new email. Your email changes only after the code is verified.</p>
        <div id="email-change-request-fields">
          <label for="email-change-password" style="display:block;margin:12px 0 6px;">Current IntelliDocs password</label>
          <input id="email-change-password" type="password" class="form-control" autocomplete="current-password" style="width:100%;box-sizing:border-box;">
          <label for="email-change-new-email" style="display:block;margin:12px 0 6px;">New email address</label>
          <input id="email-change-new-email" type="email" class="form-control" autocomplete="email" maxlength="254" style="width:100%;box-sizing:border-box;">
          <button type="button" class="btn btn-primary" id="email-change-send" style="margin-top:16px;width:100%;">Send verification code</button>
        </div>
        <div id="email-change-verify-fields" style="display:none;">
          <p id="email-change-target-label" style="overflow-wrap:anywhere;"></p>
          <label for="email-change-otp" style="display:block;margin:12px 0 6px;">6-digit email code</label>
          <input id="email-change-otp" type="text" class="form-control" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" minlength="6" maxlength="6" style="width:100%;box-sizing:border-box;letter-spacing:5px;font-size:1.2rem;">
          <button type="button" class="btn btn-primary" id="email-change-verify" style="margin-top:16px;width:100%;">Verify and update email</button>
          <button type="button" class="btn btn-secondary" id="email-change-back" style="margin-top:8px;width:100%;">Use a different email</button>
        </div>
        <p id="email-change-status" role="status" aria-live="polite" style="margin:12px 0 0;white-space:pre-wrap;overflow-wrap:anywhere;"></p>
      </div>`;
    document.body.appendChild(modal);
    modal.addEventListener("click", e => { if (e.target === modal) closeEmailChangeModal(); });
    document.getElementById("email-change-close").addEventListener("click", closeEmailChangeModal);
    document.getElementById("email-change-send").addEventListener("click", requestEmailChangeCode);
    document.getElementById("email-change-verify").addEventListener("click", submitEmailChangeCode);
    document.getElementById("email-change-back").addEventListener("click", () => {
      document.getElementById("email-change-verify-fields").style.display = "none";
      document.getElementById("email-change-request-fields").style.display = "block";
      document.getElementById("email-change-otp").value = "";
      setEmailChangeStatus("");
    });
  }
}

function setEmailChangeStatus(message, isError = false) {
  const status = document.getElementById("email-change-status");
  if (!status) return;
  status.textContent = message;
  status.style.color = isError ? "#dc4545" : "var(--text-secondary,#666)";
}

function openEmailChangeModal() {
  ensureEmailChangeUI(currentUser || {});
  const modal = document.getElementById("email-change-modal");
  if (!modal) return;
  document.getElementById("email-change-password").value = "";
  document.getElementById("email-change-new-email").value = "";
  document.getElementById("email-change-otp").value = "";
  document.getElementById("email-change-request-fields").style.display = "block";
  document.getElementById("email-change-verify-fields").style.display = "none";
  setEmailChangeStatus("");
  modal.style.display = "flex";
  document.getElementById("email-change-password").focus();
}

function closeEmailChangeModal() {
  const modal = document.getElementById("email-change-modal");
  if (modal) modal.style.display = "none";
}

async function requestEmailChangeCode() {
  const button = document.getElementById("email-change-send");
  const current_password = document.getElementById("email-change-password").value;
  const new_email = document.getElementById("email-change-new-email").value.trim();
  if (!current_password || !new_email) {
    setEmailChangeStatus("Enter your current password and new email address.", true);
    return;
  }
  button.disabled = true;
  button.textContent = "Sending…";
  setEmailChangeStatus("");
  try {
    const result = await apiFetch("/auth/email-change/request", {
      method: "POST", body: JSON.stringify({ current_password, new_email })
    });
    document.getElementById("email-change-target-label").textContent = `Verification code sent to ${new_email}`;
    document.getElementById("email-change-request-fields").style.display = "none";
    document.getElementById("email-change-verify-fields").style.display = "block";
    setEmailChangeStatus(result.message || "Enter the 6-digit code from your email.");
    document.getElementById("email-change-otp").focus();
  } catch (error) {
    setEmailChangeStatus(error.message || "Could not send the verification code.", true);
  } finally {
    button.disabled = false;
    button.textContent = "Send verification code";
  }
}

async function submitEmailChangeCode() {
  const button = document.getElementById("email-change-verify");
  const new_email = document.getElementById("email-change-new-email").value.trim();
  const otp = document.getElementById("email-change-otp").value.trim();
  if (!/^\d{6}$/.test(otp)) {
    setEmailChangeStatus("Enter the 6-digit code from your email.", true);
    return;
  }
  button.disabled = true;
  button.textContent = "Verifying…";
  setEmailChangeStatus("");
  try {
    const result = await apiFetch("/auth/email-change/verify", {
      method: "POST", body: JSON.stringify({ new_email, otp })
    });
    if (currentUser) currentUser.email = result.email || new_email;
    closeEmailChangeModal();
    await loadProfile();
    if (typeof loadSettings === "function") loadSettings();
    showToast(result.message || "Email address updated successfully.", "success");
  } catch (error) {
    setEmailChangeStatus(error.message || "The code could not be verified.", true);
  } finally {
    button.disabled = false;
    button.textContent = "Verify and update email";
  }
}


// --- QUARANTINE SIDEBAR BADGE V3 ---
async function syncQuarantineSidebarBadge() {
  const badgeQ = document.getElementById("badge-quarantine");
  if (!badgeQ) return;

  try {
    // Same endpoint used by the Quarantine page itself.  Keep the sidebar
    // indicator sourced from the exact same backend integration.
    const quarantineList = await apiFetch("/documents/quarantine/list");
    const count = Array.isArray(quarantineList) ? quarantineList.length : 0;

    if (count > 0) {
      badgeQ.innerText = count;
      badgeQ.style.display = "inline-block";
    } else {
      badgeQ.style.display = "none";
    }
  } catch (err) {
    // Do not let a Quarantine badge failure break Suggestions/Duplicates/
    // notification badges. The actual Quarantine page remains authoritative.
    console.warn("[Quarantine badge] Could not refresh sidebar count:", err);
  }
}

// INTELLIDOCS_SIDEBAR_TRASH_RECEIVED_COUNTS_V1
function setSidebarCountBadge(badgeId, value) {
  const badge = document.getElementById(badgeId);
  if (!badge) return;
  const numeric = Number(value);
  const count = Number.isFinite(numeric) ? Math.max(0, Math.floor(numeric)) : 0;
  badge.textContent = String(count);
  badge.style.display = count > 0 ? "inline-block" : "none";
}

function countUniqueReceivedDocuments(items) {
  const documentKeys = new Set();
  for (const item of (Array.isArray(items) ? items : [])) {
    if (!item || item.active === false || item.active === 0) continue;
    const key = String(item.document_uuid || item.document_id || "").trim();
    if (key) documentKeys.add(key);
  }
  return documentKeys.size;
}

async function syncTrashAndReceivedShareBadges() {
  const results = await Promise.allSettled([
    apiFetch("/trash"),
    apiFetch("/shares/received")
  ]);

  if (results[0].status === "fulfilled") {
    const items = results[0].value;
    setSidebarCountBadge("badge-trash", Array.isArray(items) ? items.length : 0);
  } else {
    // Keep the previous badge state if the endpoint is temporarily unavailable.
    console.warn("[Trash badge] Could not refresh item count:", results[0].reason);
  }

  if (results[1].status === "fulfilled") {
    setSidebarCountBadge(
      "badge-shared-received",
      countUniqueReceivedDocuments(results[1].value)
    );
  } else {
    // Do not misrepresent a network/API failure as zero received documents.
    console.warn("[Received shares badge] Could not refresh item count:", results[1].reason);
  }
}
async function fetchBadges() {
    await syncQuarantineSidebarBadge();
    await syncTrashAndReceivedShareBadges();
  try {
    const suggestions = await apiFetch("/suggestions");
    const visibleSuggestionRows =
      typeof window.intelliDocsVisibleSuggestionRows === "function"
        ? window.intelliDocsVisibleSuggestionRows(suggestions)
        : [];

    const visibleSuggestionCount = visibleSuggestionRows.length;
    const badgeS = document.getElementById("badge-suggestions");

    if (badgeS) {
      badgeS.innerText = String(visibleSuggestionCount);
      badgeS.style.display =
        visibleSuggestionCount > 0 ? "inline-block" : "none";
    }

    const duplicateAlerts = await apiFetch("/duplicates/alerts");
    const badgeD = document.getElementById("badge-duplicates");
    const duplicateCount = duplicateAlerts && Number.isFinite(duplicateAlerts.alert_count) ? duplicateAlerts.alert_count : 0;
    if (duplicateCount > 0) {
      badgeD.innerText = duplicateCount;
      badgeD.style.display = "inline-block";
    } else {
      badgeD.style.display = "none";
    }

    const notifs = await apiFetch("/notifications?unread_only=true");
    const bellB = document.getElementById("bell-unread-count");
    if (notifs && notifs.length > 0) {
      bellB.innerText = notifs.length;
      bellB.style.display = "inline-block";
    } else {
      bellB.style.display = "none";
    }
  } catch (e) {}
}

let notificationPopoverOpen = false;

async function toggleNotificationPopover() {
  const popover = document.getElementById("notification-popover");
  if (!popover) return;

  notificationPopoverOpen = !notificationPopoverOpen;
  if (notificationPopoverOpen) {
    popover.classList.add("active");
    await loadNotificationPopover();
  } else {
    popover.classList.remove("active");
  }
}

// Keep the popover open state authoritative and close it only when clicking outside.
document.addEventListener("click", (e) => {
  const container = document.querySelector(".notification-bell-wrap");
  const popover = document.getElementById("notification-popover");
  if (popover && popover.classList.contains("active") && container && !container.contains(e.target)) {
    popover.classList.remove("active");
    notificationPopoverOpen = false;
  }
});

async function loadNotificationPopover() {
  const listBox = document.getElementById("notifications-list-box");
  if (!listBox) return;

  listBox.innerHTML = `<div class="empty-state" style="padding:16px;"><div class="spinner"></div> Loading notifications...</div>`;
  try {
    const notifications = await apiFetch("/notifications?limit=30");
    if (!notifications || notifications.length === 0) {
      listBox.innerHTML = `<div class="empty-state" style="padding:18px;">🎉 No notifications yet</div>`;
      return;
    }

    const typeIcons = {
      "PROCESSING_COMPLETE": "📄",
      "DUPLICATE_DETECTED": "👥",
      "SUGGESTION_READY": "💡",
      "AI_ORGANIZATION_SUGGESTION_READY": "💡",
      "DOCUMENT_RENAMED": "✏️",
      "DOCUMENT_CATEGORIZED": "🏷️",
      "DOCUMENT_MOVED": "📁",
      "SHARE_GRANTED": "🤝",
      "SHARE_REVOKED": "🔒",
      "ACCESS_LOCK_TOGGLED": "🔐"
    };

    listBox.innerHTML = notifications.map(n => {
      const icon = typeIcons[n.event_type] || "🔔";
      const isUnread = Number(n.is_read) === 0;
      const docUuid = n.document_uuid || "";
      return `
        <div class="notification-item ${isUnread ? 'unread' : ''}"
             onclick="handleNotificationClick(${n.id}, '${escapeHtml(docUuid)}')">
          <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:10px;">
            <div style="display:flex; gap:9px; align-items:flex-start; min-width:0;">
              <span style="font-size:16px; flex:0 0 auto;">${icon}</span>
              <div style="min-width:0;">
                <strong class="notification-title">${escapeHtml(n.title)}</strong>
                <div class="notification-msg">${escapeHtml(n.message)}</div>
                <div class="notification-time">${formatDate(n.created_at)}</div>
              </div>
            </div>
            ${isUnread ? '<span style="width:8px; height:8px; background:var(--primary); border-radius:50%; display:inline-block; flex:0 0 auto; margin-top:5px;"></span>' : ''}
          </div>
        </div>`;
    }).join("");
  } catch (err) {
    listBox.innerHTML = `<div class="empty-state" style="padding:16px; color:var(--danger-text);">Failed to load notifications: ${escapeHtml(err.message)}</div>`;
  } finally {
    fetchBadges();
  }
}

// initApp historically calls this name; keep it as the single non-invasive loader.
async function fetchNotifications() {
  const popover = document.getElementById("notification-popover");
  if (popover && popover.classList.contains("active")) {
    await loadNotificationPopover();
  }
}

async function handleNotificationClick(notifId, docUuid) {
  try {
    await apiFetch(`/notifications/${notifId}/read`, { method: "POST" });
  } catch (e) {}

  const popover = document.getElementById("notification-popover");
  if (popover) popover.classList.remove("active");
  notificationPopoverOpen = false;

  if (docUuid && docUuid.length > 5) {
    openDocumentDetail(docUuid);
  } else {
    await fetchNotifications();
    fetchBadges();
  }
}

async function markAllNotificationsRead() {
  try {
    await apiFetch("/notifications/read-all", { method: "POST" });
    showToast("All notifications marked as read.", "success");
    await loadNotificationPopover();
    fetchBadges();
  } catch (err) {
    showToast("Failed to mark notifications read: " + err.message, "error");
  }
}


async function loadMetadataDropdowns() {
  try {
    categoriesList = await apiFetch("/categories");
    foldersList = await apiFetch("/folders");
    tagsList = await apiFetch("/tags");

    // Populate Category filter
    const catSelect = document.getElementById("filter-category");
    catSelect.innerHTML = `<option value="">All Categories</option>`;
    categoriesList.forEach(c => {
      catSelect.innerHTML += `<option value="${escapeHtml(c.name)}">${escapeHtml(c.name)}</option>`;
    });

    // Populate Folder filter & upload target folder
    const folderSelect = document.getElementById("filter-folder");
    const uploadFolderSelect = document.getElementById("upload-target-folder");
    folderSelect.innerHTML = `<option value="">All Folders</option>`;
    uploadFolderSelect.innerHTML = `<option value="">(Root / Unorganized)</option>`;
    foldersList.forEach(f => {
      folderSelect.innerHTML += `<option value="${f.id}">${escapeHtml(f.name)}</option>`;
      uploadFolderSelect.innerHTML += `<option value="${f.id}">${escapeHtml(f.name)}</option>`;
    });
  } catch (e) {}
}

// --- DASHBOARD VIEW ---
async function loadDashboard() {
  const intelligence = document.getElementById("dashboard-intelligence-list");
  const tbody = document.getElementById("dashboard-recent-docs-tbody");

  if (intelligence) intelligence.innerHTML = `<div class="empty-state" style="padding:16px 8px;"><div class="spinner"></div> Loading intelligence...</div>`;
  if (tbody) tbody.innerHTML = `<tr><td colspan="5" class="empty-state"><div class="spinner"></div> Loading recent documents...</td></tr>`;

  try {
    const docs = await apiFetch("/documents?limit=100");
    const suggestions = await apiFetch("/suggestions");
    const trash = await apiFetch("/trash");
    const duplicateAlerts = await apiFetch("/duplicates/alerts");
    const groups = await apiFetch("/groups");
    const unreadNotifications = await apiFetch("/notifications?unread_only=true");

    const duplicateCount = duplicateAlerts && Number.isFinite(duplicateAlerts.alert_count)
      ? duplicateAlerts.alert_count
      : 0;

    // Calculate stats from real backend signals.
    document.getElementById("stat-total-docs").innerText = docs.length;
    const dashboardSuggestionRows = typeof window.intelliDocsVisibleSuggestionRows === "function"
      ? window.intelliDocsVisibleSuggestionRows(suggestions)
      : [];
    document.getElementById("stat-pending-suggestions").innerText = dashboardSuggestionRows.length;
    document.getElementById("stat-duplicates").innerText = duplicateCount;

    let totalBytes = 0;
    docs.forEach(d => totalBytes += d.size_bytes);
    document.getElementById("stat-storage-used").innerText = (totalBytes / (1024 * 1024)).toFixed(2) + " MB";

    // Needs Your Attention Section
    if (intelligence) {
      const items = [];

      // 1. Pending AI Suggestions
      if (dashboardSuggestionRows.length > 0) {
        const topS = dashboardSuggestionRows[0];
        const typeLabel = ({
          categorize: "Category",
          rename: "Filename",
          add_tag: "Tags",
          move_folder: "Folder",
          create_folder_group: "Smart Folder Group"
        })[topS.suggestion_type] || topS.suggestion_type;

        items.push(`
          <div class="attention-item attention-warning" style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
            <div>
              <strong>💡 AI ${escapeHtml(typeLabel.toUpperCase())}: ${escapeHtml(topS.suggested_value)}</strong>
              <div class="text-muted" style="font-size:12px;">Confidence: ${(topS.confidence * 100).toFixed(0)}% · ${escapeHtml(topS.reason)}</div>
            </div>
            <div style="display:flex; gap:6px;">
              <button class="btn btn-primary btn-sm" onclick="acceptSuggestion(${topS.id}, this)">Accept</button>
              <button class="btn btn-secondary btn-sm" onclick="navigateTo('suggestions')">Review All (${dashboardSuggestionRows.length})</button>
            </div>
          </div>
        `);
      }

      // 2. Duplicate Alerts
      if (duplicateCount > 0) {
        const top = duplicateAlerts.alerts && duplicateAlerts.alerts[0];
        const pct = top ? (top.confidence * 100).toFixed(1) : "";
        const methods = top && top.detection_methods ? top.detection_methods.join(", ") : "";
        const detail = top ? `${escapeHtml(top.document_name)} ↔ ${escapeHtml(top.candidate_name)} · ${pct}% similarity (${escapeHtml(methods)})` : "Potential duplicate relationships detected.";
        items.push(`
          <div class="attention-item attention-danger" style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
            <div>
              <strong>👥 ${duplicateCount} Duplicate Alert${duplicateCount === 1 ? '' : 's'}</strong>
              <div class="text-muted" style="font-size:12px;">${detail}</div>
            </div>
            <button class="btn btn-secondary btn-sm" onclick="navigateTo('duplicates')">Review</button>
          </div>
        `);
      }

      // 3. Unread Notifications
      if (unreadNotifications.length > 0) {
        items.push(`
          <div class="attention-item" style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
            <div>
              <strong>🔔 ${unreadNotifications.length} Unread Notification${unreadNotifications.length === 1 ? '' : 's'}</strong>
              <div class="text-muted" style="font-size:12px;">Sharing, security, AI and system events.</div>
            </div>
            <button class="btn btn-secondary btn-sm" onclick="toggleNotificationPopover()">Open Notifications</button>
          </div>
        `);
      }

      // 4. Processing Alerts
      const failedDocs = docs.filter(d => d.processing_status === 'failed');
      const analyzingDocs = docs.filter(d => d.processing_status === 'analyzing' || d.processing_status === 'suggesting' || d.processing_status === 'pending');
      if (failedDocs.length > 0) {
        items.push(`
          <div class="attention-item attention-danger" style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
            <div>
              <strong>⚠️ ${failedDocs.length} Processing Failure${failedDocs.length === 1 ? '' : 's'}</strong>
              <div class="text-muted" style="font-size:12px;">Some document text extraction or processing failed.</div>
            </div>
            <button class="btn btn-secondary btn-sm" onclick="navigateTo('library')">View Library</button>
          </div>
        `);
      } else if (analyzingDocs.length > 0) {
        items.push(`
          <div class="attention-item" style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
            <div>
              <strong>⏳ ${analyzingDocs.length} Document(s) Processing</strong>
              <div class="text-muted" style="font-size:12px;">Background OCR, text analysis, or vector embedding in progress.</div>
            </div>
            <button class="btn btn-secondary btn-sm" onclick="loadDashboard()">Refresh</button>
          </div>
        `);
      }

      if (items.length === 0) {
        items.push(`<div class="empty-state" style="padding:16px 8px;">🎉 Everything is up to date. New AI insights, duplicate alerts, and processing notifications will appear here.</div>`);
      }
      intelligence.innerHTML = items.join("");
    }

    const securitySummary = document.getElementById("dashboard-security-summary");
    if (securitySummary) {
      const lockedDocs = docs.filter(d => Number(d.is_access_locked) === 1).length;
      securitySummary.innerHTML = `
        <div class="clickable-row" onclick="navigateTo('groups')" style="padding: 10px 8px; border-radius: var(--radius-sm); cursor: pointer;" title="View Sharing Groups">
          <span>👥 Sharing Groups</span><strong>${groups.length}</strong>
        </div>
        <div class="clickable-row" onclick="navigateTo('library')" style="padding: 10px 8px; border-radius: var(--radius-sm); cursor: pointer;" title="View Locked Documents in Library">
          <span>🔐 Locked Documents</span><strong>${lockedDocs}</strong>
        </div>
        <div class="clickable-row" onclick="navigateTo('trash')" style="padding: 10px 8px; border-radius: var(--radius-sm); cursor: pointer;" title="View Trash">
          <span>🗑️ Documents in Trash</span><strong>${trash.length}</strong>
        </div>
      `;
    }

    const recents = docs.slice(0, 5);
    if (recents.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" class="empty-state">No uploaded documents yet. Click '+ Upload' to add documents.</td></tr>`;
      return;
    }

    tbody.innerHTML = recents.map(doc => `
      <tr class="clickable-row" onclick="openDocumentDetail('${doc.uuid}')" title="Click to view details">
        <td>
          <a style="font-weight:600; color:var(--primary); cursor:pointer;">
            📄 ${escapeHtml(doc.display_name || doc.original_name)}
          </a>
        </td>
        <td>${escapeHtml(doc.category || 'Uncategorized')}</td>
        <td>${formatBytes(doc.size_bytes)}</td>
        <td>${renderStatusBadge(doc.processing_status)}</td>
        <td style="color:var(--text-muted); font-size:12px;">${formatDate(doc.uploaded_at)}</td>
      </tr>
    `).join("");

  } catch (err) {
    if (intelligence) intelligence.innerHTML = `<div class="empty-state" style="padding:16px 8px; color:var(--danger-text);">Failed to load intelligence signals: ${escapeHtml(err.message)}</div>`;
    if (tbody) tbody.innerHTML = `<tr><td colspan="5" class="empty-state" style="color:var(--danger-text);">Failed to load recent documents: ${escapeHtml(err.message)}</td></tr>`;
    showToast("Failed to load dashboard data: " + err.message, "error");
  }
}

// --- LIBRARY VIEW ---
async function loadLibraryDocuments() {
  const tbody = document.getElementById("library-documents-tbody");
  tbody.innerHTML = `<tr><td colspan="8" class="empty-state"><div class="spinner"></div> Loading documents...</td></tr>`;

  const fileType = document.getElementById("filter-file-type").value;
  const category = document.getElementById("filter-category").value;
  const sensitivity = document.getElementById("filter-sensitivity").value;
  const folderId = document.getElementById("filter-folder").value;
  const sortBy = document.getElementById("filter-sort-by").value;
  const sortOrder = document.getElementById("filter-sort-order").value;

  let query = `/documents?page=${libraryPage}&limit=${libraryLimit}&sort_by=${sortBy}&order=${sortOrder}`;
  if (fileType) query += `&file_type=${encodeURIComponent(fileType)}`;
  if (category) query += `&category=${encodeURIComponent(category)}`;
  if (sensitivity) query += `&sensitivity=${encodeURIComponent(sensitivity)}`;
  if (folderId) query += `&folder_id=${encodeURIComponent(folderId)}`;

  try {
    const docs = await apiFetch(query);
    document.getElementById("library-pagination-info").innerText = `Page ${libraryPage} (${docs.length} items on page)`;

    if (docs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" class="empty-state">No documents match the current filters.</td></tr>`;
      return;
    }

    tbody.innerHTML = docs.map(doc => `
      <tr>
        <td>
          <a style="font-weight:600; color:var(--primary); cursor:pointer;" onclick="openDocumentDetail('${doc.uuid}')">
            📄 ${escapeHtml(doc.display_name || doc.original_name)}
          </a>
        </td>
        <td>${escapeHtml(doc.category || 'Uncategorized')}</td>
        <td>${renderSensitivityBadge(doc.sensitivity)}</td>
        <td>${renderTagPills(doc.tags)}</td>
        <td><span class="badge badge-neutral">v${doc.version_number}</span></td>
        <td>${renderStatusBadge(doc.processing_status)}</td>
        <td style="color:var(--text-muted); font-size:12px;">${formatDate(doc.uploaded_at)}</td>
        <td style="text-align:right;">
          <button class="btn btn-secondary btn-sm" onclick="openDocumentDetail('${doc.uuid}')">View</button>
          <button class="btn btn-secondary btn-sm" onclick="downloadDocument('${doc.uuid}')">📥</button>
          <button class="btn btn-danger btn-sm" onclick="deleteDocumentFromLibrary('${doc.uuid}')">🗑️</button>
        </td>
      </tr>
    `).join("");

  } catch (err) {
    showToast("Failed to load documents: " + err.message, "error");
  }
}

function changeLibraryPage(delta) {
  if (libraryPage + delta < 1) return;
  libraryPage += delta;
  loadLibraryDocuments();
}

async function deleteDocumentFromLibrary(uuid) {
  if (!confirm("Are you sure you want to move this document to Trash?")) return;
  try {
    await apiFetch(`/documents/${uuid}`, { method: "DELETE" });
    showToast("Document moved to Trash.", "success");
    loadLibraryDocuments();
    fetchBadges();
  } catch (err) {
    showToast("Delete failed: " + err.message, "error");
  }
}

/* === IntelliDocs Authenticated Download + History Shape Fix V11 === */
async function downloadDocument(uuid, suggestedName = "") {
  if (!uuid) {
    showToast("Document ID is missing; unable to download.", "error");
    return;
  }
  try {
    // apiFetch supplies Authorization: Bearer and performs refresh when needed.
    const response = await apiFetch(`/documents/${encodeURIComponent(uuid)}/download`);
    if (!response || typeof response.blob !== "function") {
      throw new Error("The server did not return a file. Please retry or sign in again.");
    }
    const blob = await response.blob();
    if (!blob || blob.size === 0) throw new Error("The downloaded file is empty.");
    const disposition = response.headers.get("content-disposition") || "";
    const utf8Name = disposition.match(/filename\*=UTF-8''([^;]+)/i);
    const plainName = disposition.match(/filename="?([^";]+)"?/i);
    let filename = suggestedName || (utf8Name ? decodeURIComponent(utf8Name[1]) : (plainName ? plainName[1] : "")) || `document-${uuid}`;
    filename = filename.replace(/[\\/:*?"<>|]+/g, "_").trim() || `document-${uuid}`;
    const objectUrl = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = objectUrl;
    link.download = filename;
    link.style.display = "none";
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1500);
    showToast("Download started.", "success");
  } catch (err) {
    showToast("Download failed: " + (err && err.message ? err.message : "Unknown error"), "error");
  }
}

async function downloadCurrentDocument(event) {
  if (event) event.preventDefault();
  const name = (document.getElementById("doc-detail-name") || {}).innerText || "";
  return downloadDocument(currentDetailUuid, name);
}


// --- UPLOAD VIEW ---
let selectedFile = null;

function onFileSelected(input) {
  if (input.files && input.files[0]) {
    selectedFile = input.files[0];
    document.getElementById("selected-file-display").innerText = `Selected: ${selectedFile.name} (${formatBytes(selectedFile.size)})`;
    document.getElementById("selected-file-display").style.display = "block";
  }
}

function resetUploadForm() {
  selectedFile = null;
  document.getElementById("upload-file-input").value = "";
  document.getElementById("selected-file-display").style.display = "none";
  document.getElementById("upload-result-card").style.display = "none";
  document.getElementById("upload-progress-box").style.display = "none";
}

// Drag & drop handlers
const dropzone = document.getElementById("upload-dropzone");
if (dropzone) {
  dropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropzone.classList.add("dragover");
  });
  dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));
  dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.classList.remove("dragover");
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      selectedFile = e.dataTransfer.files[0];
      document.getElementById("selected-file-display").innerText = `Selected: ${selectedFile.name} (${formatBytes(selectedFile.size)})`;
      document.getElementById("selected-file-display").style.display = "block";
    }
  });
}

async function handleDocumentUpload(e) {
  e.preventDefault();
  if (!selectedFile) {
    showToast("Please select a file to upload.", "warning");
    return;
  }

  const formData = new FormData();
  formData.append("file", selectedFile);
  const targetFolder = document.getElementById("upload-target-folder").value;
  if (targetFolder) formData.append("folder_id", targetFolder);

  const progressBox = document.getElementById("upload-progress-box");
  const progressFill = document.getElementById("upload-progress-fill");
  const progressPercent = document.getElementById("upload-status-percent");
  const submitBtn = document.getElementById("btn-submit-upload");

  progressBox.style.display = "block";
  progressFill.style.width = "20%";
  progressPercent.innerText = "20% (Untrusted Quarantine)";
  submitBtn.disabled = true;

  try {
    progressFill.style.width = "60%";
    progressPercent.innerText = "60% (Security Assessment Gate)";

    const result = await apiFetch("/documents/upload", {
      method: "POST",
      body: formData
    });

    progressFill.style.width = "100%";
    progressPercent.innerText = "100% (Security Evaluation Complete)";

    const resultCard = document.getElementById("upload-result-card");
    const resultContent = document.getElementById("upload-result-content");
    resultCard.style.display = "block"

    // V10: focus AI Suggestions on this upload so older files do not reappear.
    if (result && Number(result.id) > 0) {
      try {
        sessionStorage.setItem("intellidocs_suggestion_focus_document_id", String(Number(result.id)));
        sessionStorage.setItem("intellidocs_show_all_doc_suggestions", "0");
      } catch (_) {}
    };

    const sec = result.security_assessment || {};
    const verdict = sec.verdict || "SAFE";
    const riskScore = sec.risk_score !== undefined ? sec.risk_score : 0;
    const riskLevel = sec.risk_level || "LOW RISK";
    const confidence = sec.confidence || "HIGH";
    const scannerStatus = sec.scanner_status || "AVAILABLE";

    let cardColor = "#10b981"; // green
    let verdictTitle = "🛡️ SECURITY CLEARED";
    if (verdict === "SUSPICIOUS") {
      cardColor = "#f59e0b"; // amber
      verdictTitle = "⚠️ SECURITY REVIEW REQUIRED";
    } else if (verdict === "BLOCKED") {
      cardColor = "#ef4444"; // red
      verdictTitle = "🚫 UPLOAD BLOCKED / MALICIOUS";
    }

    resultCard.style.borderLeft = `5px solid ${cardColor}`;

    const safeSuccessState = verdict === "SAFE" && scannerStatus === "AVAILABLE" ? `
      <div class="security-pass-state" role="status" aria-live="polite">
        <div class="security-pass-icon" aria-hidden="true">✓</div>
        <div>
          <div class="security-pass-title">Secure</div>
          <div class="security-pass-subtitle">Scan Passed</div>
          <div class="security-pass-text">No Threats Found</div>
        </div>
      </div>` : "";
    const safeLimitedState = verdict === "SAFE" && scannerStatus !== "AVAILABLE" ? `
      <div role="status" aria-live="polite" style="border:1px solid #b45309;background:#451a03;color:#ffedd5;padding:12px;border-radius:8px;">
        <strong>LIMITED SECURITY ASSESSMENT — malware scan not completed</strong>
        <div style="margin-top:5px;">Available static and structural checks did not flag this file, but IntelliDocs has no completed antivirus result. Do not interpret this as a confirmed malware-clean scan.</div>
        <div style="margin-top:6px;">${escapeHtml((sec.check_states || {}).malware_scan_detail || "Install and configure ClamAV on the host, then reassess the document.")}</div>
      </div>` : "";

    let whyItems = (sec.why_explanations || []).map(w => `<li style="margin-bottom:4px;">${escapeHtml(w)}</li>`).join("");
    if (!whyItems) whyItems = "<li>All identity, structure, and signature checks passed.</li>";

    let harmsItems = (sec.potential_harms || []).map(h => `<li style="margin-bottom:4px; color:var(--text-secondary);">${escapeHtml(h)}</li>`).join("");

    let actionButtons = "";
    if (verdict === "SAFE" && result.uuid) {
      actionButtons = `<button class="btn btn-primary btn-sm" onclick="openDocumentDetail('${result.uuid}')">📄 View Document Detail</button>${Number(result.id) > 0 ? ` <button class="btn btn-secondary btn-sm" onclick="navigateTo('suggestions')">✨ Review AI Name &amp; Folder</button>` : ""}`;
    } else if (verdict === "SUSPICIOUS") {
      actionButtons = `
        <button class="btn btn-warning btn-sm" onclick="navigateTo('quarantine')">🛡️ View in Quarantine</button>
        <button class="btn btn-primary btn-sm" onclick="openSecurityReportModal('${sec.quarantine_uuid}')">📋 View Full Security Report</button>
      `;
    } else {
      actionButtons = `
        <button class="btn btn-danger btn-sm" onclick="openSecurityReportModal('${sec.quarantine_uuid}')">🚫 View Blocked Evidence</button>
      `;
    }

    resultContent.innerHTML = `
      <div style="font-size:13px; display:flex; flex-direction:column; gap:12px;">
        ${safeSuccessState}${safeLimitedState}
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <h4 style="margin:0; color:${cardColor}; font-size:15px; font-weight:700;">${verdictTitle}</h4>
          <span class="badge" style="background:${cardColor}; color:#fff; font-weight:bold; padding:4px 10px;">${riskLevel} (Score: ${riskScore}/100)</span>
        </div>

        <div style="display:flex; gap:12px; flex-wrap:wrap; font-size:12px; background:#f8fafc; padding:10px; border-radius:6px; border:1px solid var(--border-color);">
          <div><strong>Confidence:</strong> <span class="badge badge-info">${confidence}</span></div>
          <div><strong>Data Sensitivity:</strong> <span class="badge badge-secondary">${sec.data_sensitivity || 'public'}</span></div>
          <div><strong>Malware Scanner:</strong> <span class="badge ${scannerStatus === 'AVAILABLE' ? 'badge-success' : 'badge-warning'}">${scannerStatus}</span></div>
        </div>

        <div>
          <strong style="color:var(--text-primary); font-size:13px;">Why this assessment score was assigned:</strong>
          <ul style="margin:6px 0 0 18px; padding:0; font-size:12.5px;">${whyItems}</ul>
        </div>

        ${harmsItems ? `
          <div>
            <strong style="color:var(--text-primary); font-size:13px;">Potential Impact / Harm:</strong>
            <ul style="margin:6px 0 0 18px; padding:0; font-size:12.5px;">${harmsItems}</ul>
          </div>
        ` : ''}

        <div style="background:#f1f5f9; padding:10px; border-radius:6px; font-size:12.5px;">
          <strong>Recommended User Action:</strong> ${escapeHtml(sec.recommended_action || '')}
        </div>

        <div style="display:flex; gap:10px; margin-top:8px;">
          ${actionButtons}
          <button class="btn btn-secondary btn-sm" onclick="openSecurityReportModal('${sec.quarantine_uuid}')">🔍 Detailed Security Report</button>
        </div>
      </div>
    `;

    if (verdict === "SAFE" && scannerStatus === "AVAILABLE") {
      showToast("Security Assessment Cleared: scanner returned no known malware signatures.", "success");
    } else if (verdict === "SAFE") {
      showToast("Static checks passed, but the malware scan is unavailable. Assessment is LIMITED.", "warning");
    } else if (verdict === "SUSPICIOUS") {
      showToast("File Security Gate: Document flagged as SUSPICIOUS and quarantined.", "warning");
    } else {
      showToast("File Security Gate: Document BLOCKED due to security risk!", "error");
    }

    // INTELLIDOCS_AUTO_SUGGEST_AFTER_UPLOAD_V1
    // Generate suggestions for this newly uploaded SAFE document.
    if (verdict === "SAFE" && result && Number(result.id) > 0) {
      try {
        const analysisResult = await apiFetch(
          `/suggestions/analyze?document_id=${encodeURIComponent(Number(result.id))}`,
          { method: "POST" }
        );

        console.info(
          "[Suggestions] Automatic document analysis completed.",
          analysisResult
        );

        // Re-evaluate folder groups after the new document is available.
        try {
          await apiFetch("/suggestions/analyze-groups", { method: "POST" });
        } catch (groupAnalysisError) {
          console.warn(
            "[Suggestions] Group re-evaluation did not complete:",
            groupAnalysisError
          );
        }
      } catch (analysisError) {
        console.warn(
          "[Suggestions] Automatic analysis failed after upload:",
          analysisError
        );
        showToast(
          "Document uploaded, but AI suggestions could not be generated automatically. Open Suggestions and run Analyze.",
          "warning"
        );
      }
    }

    resetUploadForm();
    await fetchBadges();
  } catch (err) {
    showToast("Upload failed: " + err.message, "error");
  } finally {
    submitBtn.disabled = false;
  }
}

// ==========================================
// FILE SECURITY INTELLIGENCE REPORT & QUARANTINE UI
// ==========================================

async function openSecurityReportModal(identifier) {
  openModal("modal-security-report");
  const modalContent = document.getElementById("sec-report-modal-content");
  const modalFilename = document.getElementById("sec-report-filename");
  modalContent.innerHTML = `<div class="empty-state">Loading security report...</div>`;

  try {
    const report = await apiFetch(`/documents/security/report/${identifier}`);
    modalFilename.innerText = `${report.original_name} (${report.quarantine_uuid})`;

    let verdictColor = "#10b981";
    if (report.verdict === "SUSPICIOUS") verdictColor = "#f59e0b";
    if (report.verdict === "BLOCKED") verdictColor = "#ef4444";

    const checkStates = report.check_states || {};
    const scannerDiagnostic = typeof checkStates.malware_scan_detail === "string" ? checkStates.malware_scan_detail : "";
    const checkRows = Object.keys(checkStates).filter(chk => chk !== "malware_scan_detail").map(chk => {
      const st = checkStates[chk];
      let badgeCls = "badge-success";
      if (st === "WARNING") badgeCls = "badge-warning";
      if (st === "FAILED" || st === "BLOCKED") badgeCls = "badge-danger";
      if (st === "UNAVAILABLE") badgeCls = "badge-secondary";
      return `
        <tr>
          <td style="font-weight:600; text-transform:capitalize;">${chk.replace('_', ' ')}</td>
          <td><span class="badge ${badgeCls}">${st}</span></td>
        </tr>
      `;
    }).join("");

    const findingsList = (report.findings || []).map(f => `
      <div style="background:#f8fafc; border-left:4px solid ${f.severity === 'CRITICAL' ? '#ef4444' : (f.severity === 'HIGH' ? '#f97316' : '#3b82f6')}; padding:10px 12px; border-radius:4px; margin-bottom:8px;">
        <div style="display:flex; justify-content:space-between;">
          <strong style="font-size:13px; color:var(--text-primary);">${escapeHtml(f.title)}</strong>
          <span class="badge badge-secondary" style="font-size:11px;">Severity: ${f.severity}</span>
        </div>
        <div style="font-size:12px; color:var(--text-secondary); margin-top:4px;"><strong>Evidence:</strong> ${escapeHtml(f.technical_evidence || 'N/A')}</div>
        ${f.potential_harm ? `<div style="font-size:12px; color:var(--warning-text); margin-top:2px;"><strong>Potential Concern:</strong> ${escapeHtml(f.potential_harm)}</div>` : ''}
      </div>
    `).join("");

    const whyList = (report.why_explanations || []).map(w => `<li>${escapeHtml(w)}</li>`).join("");
    const harmsList = (report.potential_harms || []).map(h => `<li>${escapeHtml(h)}</li>`).join("");

    const reportSafeState = report.verdict === "SAFE" && String(report.scanner_status || "").toUpperCase() === "AVAILABLE" ? `
      <div class="security-pass-state security-pass-state-modal" role="status" aria-live="polite">
        <div class="security-pass-icon" aria-hidden="true">✓</div>
        <div>
          <div class="security-pass-title">Secure</div>
          <div class="security-pass-subtitle">Scan Passed</div>
          <div class="security-pass-text">No Threats Found</div>
        </div>
      </div>` : "";
    const reportLimitedState = report.verdict === "SAFE" && String(report.scanner_status || "").toUpperCase() !== "AVAILABLE" ? `
      <div role="status" aria-live="polite" style="border:1px solid #b45309;background:#451a03;color:#ffedd5;padding:12px;border-radius:8px;">
        <strong>LIMITED SECURITY ASSESSMENT</strong>
        <div style="margin-top:5px;">The static checks did not flag this file, but no completed antivirus result is recorded. This is not proof that the file is malware-free.</div>
        ${scannerDiagnostic ? `<div style="margin-top:6px;">${escapeHtml(scannerDiagnostic)}</div>` : ""}
      </div>` : "";

    modalContent.innerHTML = `
      <div style="display:flex; flex-direction:column; gap:16px;">
        ${reportSafeState}${reportLimitedState}
        <!-- Section 1: Overall Result Header -->
        <div style="background:#f1f5f9; padding:14px; border-radius:8px; border:1px solid var(--border-color); display:flex; justify-content:space-between; align-items:center;">
          <div>
            <div style="font-size:11px; text-transform:uppercase; color:var(--text-muted); font-weight:700;">Security Verdict</div>
            <div style="font-size:18px; font-weight:800; color:${verdictColor};">${report.verdict}</div>
          </div>
          <div>
            <div style="font-size:11px; text-transform:uppercase; color:var(--text-muted); font-weight:700;">Risk Score</div>
            <div style="font-size:18px; font-weight:800; color:${verdictColor};">${report.risk_score} / 100 (${report.risk_level})</div>
          </div>
          <div>
            <div style="font-size:11px; text-transform:uppercase; color:var(--text-muted); font-weight:700;">Confidence</div>
            <div style="font-size:14px; font-weight:700;"><span class="badge badge-info">${report.confidence}</span></div>
          </div>
        </div>

        <!-- Section 2: Why? Explanations -->
        <div>
          <h4 style="margin:0 0 8px 0; font-size:14px; color:var(--primary);">1. Why this risk score was assigned:</h4>
          <ul style="margin:0 0 0 20px; font-size:13px; line-height:1.5;">${whyList || '<li>No elevated risk indicators detected.</li>'}</ul>
        </div>

        <!-- Section 3: Potential Harms -->
        ${harmsList ? `
          <div>
            <h4 style="margin:0 0 8px 0; font-size:14px; color:var(--warning-text);">2. What could happen (Potential Harm):</h4>
            <ul style="margin:0 0 0 20px; font-size:13px; line-height:1.5;">${harmsList}</ul>
          </div>
        ` : ''}

        <!-- Section 4: What Did We Check? -->
        <div>
          <h4 style="margin:0 0 8px 0; font-size:14px; color:var(--primary);">3. Security Checks Performed:</h4>
          <table class="data-table" style="font-size:12.5px;">
            <thead>
              <tr><th>Check Name</th><th>Backend Status</th></tr>
            </thead>
            <tbody>${checkRows}</tbody>
          </table>
          ${scannerDiagnostic ? `<div role="note" style="border:1px solid #b45309;background:#451a03;color:#ffedd5;padding:10px;border-radius:6px;font-size:12.5px;"><strong>Malware scanner diagnostic:</strong> ${escapeHtml(scannerDiagnostic)}</div>` : ""}
        </div>

        <!-- Section 5: Recommended Action -->
        <div style="background:#e0f2fe; color:#0369a1; padding:12px; border-radius:6px; font-size:13px;">
          <strong>4. Recommended Action:</strong> ${escapeHtml(report.recommended_action)}
        </div>

        <!-- Detailed Technical Findings -->
        ${findingsList ? `
          <div>
            <h4 style="margin:0 0 8px 0; font-size:14px;">Detailed Security Findings (${(report.findings||[]).length}):</h4>
            ${findingsList}
          </div>
        ` : ''}
      </div>
    `;

    const footer = document.getElementById("sec-report-modal-footer");
    let promoteBtn = "";
    if (report.quarantine_status === "QUARANTINED" && report.verdict === "SUSPICIOUS") {
      promoteBtn = `<button class="btn btn-primary btn-sm" onclick="handlePromoteQuarantine('${report.quarantine_uuid}')">Promote to Library</button>`;
    }
    footer.innerHTML = `
      ${promoteBtn}
      <button class="btn btn-secondary btn-sm" onclick="handleRescanQuarantine('${report.quarantine_uuid}')">Rescan File</button>
      <button class="btn btn-danger btn-sm" onclick="handleDeleteQuarantine('${report.quarantine_uuid}')">Delete File</button>
      <button class="btn btn-secondary btn-sm" onclick="closeModal('modal-security-report')">Close</button>
    `;

  } catch (err) {
    modalContent.innerHTML = `<div class="empty-state" style="color:var(--danger);">Failed to load security report: ${escapeHtml(err.message)}</div>`;
  }
}

async function loadQuarantinedDocuments() {
  const tbody = document.getElementById("quarantine-tbody");
  if (!tbody) return;
  tbody.innerHTML = `<tr><td colspan="7" class="empty-state">Loading quarantined files...</td></tr>`;

  try {
    const list = await apiFetch("/documents/quarantine/list");
    const badgeEl = document.getElementById("badge-quarantine");
    if (badgeEl) {
      if (list.length > 0) {
        badgeEl.innerText = list.length;
        badgeEl.style.display = "inline-block";
      } else {
        badgeEl.style.display = "none";
      }
    }

    if (!list || list.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="empty-state">No files currently in quarantine. All uploads cleared security gates!</td></tr>`;
      return;
    }

    tbody.innerHTML = list.map(item => {
      let vColor = "#10b981";
      if (item.verdict === "SUSPICIOUS") vColor = "#f59e0b";
      if (item.verdict === "BLOCKED") vColor = "#ef4444";

      let promoteBtn = "";
      if (item.quarantine_status === "QUARANTINED" && item.verdict !== "BLOCKED") {
        promoteBtn = `<button class="btn btn-primary btn-xs" onclick="handlePromoteQuarantine('${item.quarantine_uuid}')" title="Approve & Promote to Library">Promote</button>`;
      }

      return `
        <tr>
          <td>
            <strong style="color:var(--text-primary); font-size:13px;">${escapeHtml(item.original_name)}</strong>
            <div style="font-size:11px; color:var(--text-muted);">${item.quarantine_uuid}</div>
          </td>
          <td>${(item.file_type||'').toUpperCase()} (${formatBytes(item.size_bytes)})</td>
          <td>
            <span class="badge" style="background:${vColor}; color:#fff;">${item.risk_level}</span>
            <div style="font-size:11px; color:var(--text-muted); margin-top:2px;">Score: ${item.risk_score}/100</div>
          </td>
          <td><span class="badge badge-info">${item.confidence}</span></td>
          <td>
            <span class="badge badge-secondary">${item.quarantine_status}</span>
          </td>
          <td>${formatDate(item.created_at)}</td>
          <td>
            <div style="display:flex; gap:6px;">
              <button class="btn btn-secondary btn-xs" onclick="openSecurityReportModal('${item.quarantine_uuid}')">Report</button>
              ${promoteBtn}
              <button class="btn btn-danger btn-xs" onclick="handleDeleteQuarantine('${item.quarantine_uuid}')">Delete</button>
            </div>
          </td>
        </tr>
      `;
    }).join("");

  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty-state" style="color:var(--danger);">Error loading quarantine list: ${escapeHtml(err.message)}</td></tr>`;
  }
}

async function handlePromoteQuarantine(quarantineUuid) {
  if (!confirm("Are you sure you want to promote this quarantined document into your library?")) return;
  try {
    const res = await apiFetch(`/documents/quarantine/${encodeURIComponent(quarantineUuid)}/promote`, { method: "POST" });
    showToast(res.message || "Document promoted to library!", "success");
    closeModal("modal-security-report");
    loadQuarantinedDocuments();

    // INTELLIDOCS_POST_PROMOTION_ANALYSIS_FIX_V1
    // Promotion uses a different response contract than direct upload: it returns
    // document_uuid, not the numeric document id needed by suggestions/analyze.
    // Resolve the promoted record, then run the same focused intelligence stages.
    const promotedUuid = String(res && (res.document_uuid || res.uuid || (res.document && res.document.uuid)) || "").trim();
    const analysisIssues = [];
    let promotedDoc = null;
    let promotedId = 0;

    if (promotedUuid) {
      try {
        promotedDoc = await apiFetch(`/documents/${encodeURIComponent(promotedUuid)}`);
      } catch (detailError) {
        console.warn("[Post-promotion analysis] Document detail lookup failed; trying the recent library list.", detailError);
      }

      promotedId = Number(promotedDoc && promotedDoc.id);
      if (!(Number.isFinite(promotedId) && promotedId > 0)) {
        try {
          const docsRaw = await apiFetch("/documents?limit=100&sort_by=uploaded_at&order=desc");
          const docs = Array.isArray(docsRaw) ? docsRaw : [];
          promotedDoc = docs.find(d => d && String(d.uuid || "") === promotedUuid) || null;
          promotedId = Number(promotedDoc && promotedDoc.id);
        } catch (listError) {
          console.warn("[Post-promotion analysis] Recent library lookup failed.", listError);
        }
      }
    }

    if (!(Number.isFinite(promotedId) && promotedId > 0)) {
      analysisIssues.push("could not resolve the promoted document ID");
    } else {
      try {
        // Focus the Suggestions view on the file the user just accepted.
        try { sessionStorage.setItem("intellidocs_suggestion_focus_document_id", String(promotedId)); } catch (_) {}
        await apiFetch(`/suggestions/analyze?document_id=${encodeURIComponent(promotedId)}`, { method: "POST" });
      } catch (suggestionError) {
        console.warn("[Post-promotion analysis] Document suggestions failed.", suggestionError);
        analysisIssues.push("document suggestions");
      }

      try {
        await apiFetch("/suggestions/analyze-groups", { method: "POST" });
      } catch (groupError) {
        console.warn("[Post-promotion analysis] Group re-analysis failed.", groupError);
        analysisIssues.push("related-document grouping");
      }

      try {
        // The promotion service already invokes duplicate processing during storage;
        // this targeted refresh makes the promoted document's duplicate view current.
        await apiFetch(`/duplicates/${encodeURIComponent(promotedUuid)}`);
      } catch (duplicateError) {
        console.warn("[Post-promotion analysis] Targeted duplicate refresh failed.", duplicateError);
        analysisIssues.push("duplicate results refresh");
      }

      try {
        if (typeof loadSuggestions === "function") await loadSuggestions();
      } catch (renderError) {
        console.warn("[Post-promotion analysis] Suggestions UI refresh failed.", renderError);
        analysisIssues.push("Suggestions screen refresh");
      }
    }

    try { await fetchBadges(); } catch (badgeError) {
      console.warn("[Post-promotion analysis] Badge refresh failed.", badgeError);
      analysisIssues.push("badge refresh");
    }

    if (analysisIssues.length) {
      showToast("Document promoted, but some follow-up analysis did not finish: " + analysisIssues.join(", ") + ". Check the console/API response.", "warning");
    } else {
      showToast("Document promoted and analysis refreshed: suggestions, related-document groups, and duplicate results checked.", "success");
    }
  } catch (err) {
    showToast("Promotion failed: " + err.message, "error");
  }
}

async function handleRescanQuarantine(quarantineUuid) {
  try {
    const res = await apiFetch(`/documents/quarantine/${quarantineUuid}/rescan`, { method: "POST" });
    showToast(`Rescan complete! New Verdict: ${res.verdict} (Score: ${res.risk_score}/100)`, "info");
    openSecurityReportModal(quarantineUuid);
    loadQuarantinedDocuments();
  } catch (err) {
    showToast("Rescan failed: " + err.message, "error");
  }
}

async function handleDeleteQuarantine(quarantineUuid) {
  if (!confirm("Permanently delete this quarantined file from storage?")) return;
  try {
    await apiFetch(`/documents/quarantine/${quarantineUuid}`, { method: "DELETE" });
    showToast("Quarantined file deleted safely.", "success");
    closeModal("modal-security-report");
    loadQuarantinedDocuments();
    fetchBadges();
  } catch (err) {
    showToast("Delete failed: " + err.message, "error");
  }
}


async function refreshDocumentAiSummary() {
  if (!currentDetailUuid) return;
  const box = document.getElementById("doc-summary-content");
  const btn = document.getElementById("btn-refresh-ai-summary");
  if (box) box.innerHTML = '<div class="empty-state" style="padding:4px 0;"><div class="spinner"></div> Generating AI summary...</div>';
  if (btn) { btn.disabled = true; btn.innerText = 'Generating…'; }
  try {
    const res = await apiFetch(`/documents/${currentDetailUuid}/summary`, { method: "POST" });
    if (box) box.innerText = res.summary || "No summary available.";
    const topicsBox = document.getElementById("doc-key-topics-container");
    if (topicsBox) {
      topicsBox.innerHTML = (res.key_topics && res.key_topics.length)
        ? res.key_topics.map(t => `<span class="badge badge-info" style="font-size:12px; padding:4px 10px;">🏷️ ${escapeHtml(t)}</span>`).join("")
        : `<span class="empty-state" style="padding:0;">No key topics detected.</span>`;
    }
    showToast("AI summary generated successfully.", "success");
  } catch (err) {
    if (box) box.innerHTML = `<div class="empty-state" style="padding:4px 0; color:var(--danger-text);">${escapeHtml(err.message)}</div>`;
    showToast("AI summary failed: " + err.message, "error");
  } finally {
    if (btn) { btn.disabled = false; btn.innerText = '↻ Refresh Summary'; }
  }
}

// --- DOCUMENT DETAIL VIEW ---
async function openDocumentDetail(uuid) {
  currentDetailUuid = uuid;
  navigateTo("detail");
  switchDetailTab("overview");

  try {
    const doc = await apiFetch(`/documents/${uuid}`);

    document.getElementById("doc-detail-name").innerText = doc.display_name || doc.original_name;
    document.getElementById("doc-detail-meta").innerText = `${doc.file_type.toUpperCase()} • ${formatBytes(doc.size_bytes)} • Uploaded ${formatDate(doc.uploaded_at)}`;

    // Download button
    document.getElementById("btn-doc-download").href = "#"; // Download uses authenticated apiFetch below.

    // Extracted text
    document.getElementById("doc-extracted-text").innerText = doc.extracted_text || "No extracted text available.";

    // Summary
    const summaryBox = document.getElementById("doc-summary-content");
    if (summaryBox) {
      summaryBox.innerText = doc.summary || "No summary available yet. Click Refresh Summary to generate it.";
    }

    // Key Topics
    const topicsBox = document.getElementById("doc-key-topics-container");
    if (topicsBox) {
      if (doc.key_topics && doc.key_topics.length > 0) {
        topicsBox.innerHTML = doc.key_topics.map(t => `
          <span class="badge badge-info" style="font-size:12px; padding:4px 10px;">🏷️ ${escapeHtml(t)}</span>
        `).join("");
      } else {
        topicsBox.innerHTML = `<span class="empty-state" style="padding:0;">No key topics detected.</span>`;
      }
    }

    // Metadata properties
    document.getElementById("meta-uuid").innerText = doc.uuid;
    document.getElementById("meta-filetype").innerText = doc.file_type.toUpperCase();
    document.getElementById("meta-category").innerText = doc.category || "Uncategorized";
    document.getElementById("meta-sensitivity").innerHTML = renderSensitivityBadge(doc.sensitivity);
    document.getElementById("meta-pages").innerText = doc.page_count || "N/A";
    document.getElementById("meta-words").innerText = doc.word_count || "N/A";
    document.getElementById("meta-status").innerHTML = renderStatusBadge(doc.processing_status);
    document.getElementById("meta-hash").innerText = doc.sha256_hash;

    // Tags
    const tagsBox = document.getElementById("doc-tags-container");
    if (doc.tags && doc.tags.length > 0) {
      tagsBox.innerHTML = doc.tags.map(t => `
        <span class="tag-pill" style="background:${t.color}; padding:4px 8px;">
          ${escapeHtml(t.name)}
          <span style="margin-left:6px; cursor:pointer;" onclick="removeTagFromDoc('${doc.uuid}', ${t.id})">&times;</span>
        </span>
      `).join("");
    } else {
      tagsBox.innerHTML = `<span class="empty-state" style="padding:0;">No tags assigned</span>`;
    }

  } catch (err) {
    if (err.message && (err.message.includes("403") || err.message.toLowerCase().includes("access lock") || err.message.toLowerCase().includes("locked"))) {
      openModal("modal-access-lock-unlock");
      showToast("This document is locked. Enter the secret access key to unlock.", "warning");
    } else {
      showToast("Failed to load document details: " + err.message, "error");
    }
  }
}

function switchDetailTab(tabName) {
  const tabs = ["overview", "versions", "related", "history"];
  tabs.forEach(t => {
    const content = document.getElementById(`tab-doc-${t}`);
    if (content) content.style.display = (t === tabName) ? "block" : "none";
  });

  if (tabName === "versions") loadDocumentVersions();
  else if (tabName === "related") loadRelatedDocuments();
  else if (tabName === "history") loadDocumentHistory();
}

function copyExtractedText() {
  const text = document.getElementById("doc-extracted-text").innerText;
  navigator.clipboard.writeText(text);
  showToast("Extracted text copied to clipboard!", "info");
}

// Version History inside detail
async function loadDocumentVersions() {
  const tbody = document.getElementById("versions-tbody");
  tbody.innerHTML = `<tr><td colspan="5" class="empty-state">Loading versions...</td></tr>`;
  try {
    const versions = await apiFetch(`/documents/${currentDetailUuid}/versions`);
    tbody.innerHTML = versions.map(v => `
      <tr>
        <td><span class="badge badge-neutral">v${v.version_number}</span></td>
        <td>${escapeHtml(v.display_name || v.original_name)}</td>
        <td>${formatBytes(v.size_bytes)}</td>
        <td>${formatDate(v.uploaded_at)}</td>
        <td><button class="btn btn-secondary btn-sm" onclick="openDocumentDetail('${v.uuid}')">View</button></td>
      </tr>
    `).join("");
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="5" class="empty-state">Error: ${escapeHtml(err.message)}</td></tr>`;
  }
}

// Related Documents inside detail
async function loadRelatedDocuments() {
  const tbody = document.getElementById("related-tbody");
  tbody.innerHTML = `<tr><td colspan="5" class="empty-state">Loading related documents...</td></tr>`;
  try {
    const res = await apiFetch(`/documents/${currentDetailUuid}/related`);
    if (!res.related_documents || res.related_documents.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" class="empty-state">No related documents found.</td></tr>`;
      return res;
    }

    tbody.innerHTML = res.related_documents.map(rel => `
      <tr>
        <td>
          <a style="font-weight:600; color:var(--primary); cursor:pointer;" onclick="openDocumentDetail('${rel.document_uuid}')">
            ${escapeHtml(rel.original_name)}
          </a>
        </td>
        <td><span class="badge badge-info">${escapeHtml(rel.relation_type)}</span></td>
        <td><strong>${(rel.confidence * 100).toFixed(0)}%</strong></td>
        <td>${(rel.detection_methods || []).join(", ")}</td>
        <td><button class="btn btn-secondary btn-sm" onclick="openDocumentDetail('${rel.document_uuid}')">Inspect</button></td>
      </tr>
    `).join("");
    return res;
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="5" class="empty-state">Error: ${escapeHtml(err.message)}</td></tr>`;
    return null;
  }
}

// Audit History timeline inside detail
async function loadDocumentHistory() {
  const container = document.getElementById("history-timeline-container");
  if (!container) return;
  container.innerHTML = `<div class="empty-state">Loading timeline history...</div>`;
  try {
    const payload = await apiFetch(`/explorer/history/${currentDetailUuid}`);
    // ExplorerService returns { document_uuid, events: [...] }, not an array.
    const events = Array.isArray(payload) ? payload :
      (Array.isArray(payload && payload.events) ? payload.events :
      (Array.isArray(payload && payload.data && payload.data.events) ? payload.data.events : []));
    if (payload && payload.locked) {
      container.innerHTML = `<div class="empty-state">This document is locked. Unlock it to view audit history.</div>`;
      return;
    }
    if (!events.length) {
      container.innerHTML = `<div class="empty-state">No activity history recorded yet.</div>`;
      return;
    }

    container.innerHTML = events.map(ev => {
      const action = String((ev && ev.action) || "Document activity").replaceAll("_", " ");
      const when = (ev && (ev.timestamp || ev.created_at || ev.createdAt)) || null;
      const detail = ev && ev.detail;
      const detailText = detail && typeof detail === "object" ? JSON.stringify(detail) : String(detail || "");
      const result = ev && ev.success === 0 ? "Failed" : (ev && ev.success === 1 ? "Completed" : "Recorded");
      return `<div class="timeline-item">
        <div class="timeline-date">${when ? escapeHtml(formatDate(when)) : "Time unavailable"} · ${result}</div>
        <div class="timeline-content"><strong>${escapeHtml(action)}</strong>
          ${detailText ? `<div style="font-size:11.5px; color:var(--text-secondary); margin-top:2px;">${escapeHtml(detailText)}</div>` : ""}
        </div>
      </div>`;
    }).join("");
  } catch (err) {
    container.innerHTML = `<div class="empty-state">Error loading audit history: ${escapeHtml(err && err.message ? err.message : err)}</div>`;
  }
}

// Delete doc from detail
async function handleDeleteDoc() {
  if (!confirm("Are you sure you want to move this document to Trash?")) return;
  try {
    await apiFetch(`/documents/${currentDetailUuid}`, { method: "DELETE" });
    showToast("Document moved to Trash.", "success");
    navigateTo("library");
  } catch (err) {
    showToast("Delete failed: " + err.message, "error");
  }
}

// Modal: Edit Document Metadata
function openEditDocModal() {
  const catSelect = document.getElementById("edit-category");
  catSelect.innerHTML = `<option value="">Uncategorized</option>`;
  categoriesList.forEach(c => {
    catSelect.innerHTML += `<option value="${escapeHtml(c.name)}">${escapeHtml(c.name)}</option>`;
  });
  openModal("modal-edit-doc");
}

async function submitEditDoc(e) {
  e.preventDefault();
  const displayName = document.getElementById("edit-display-name").value.trim();
  const category = document.getElementById("edit-category").value;
  const sensitivity = document.getElementById("edit-sensitivity").value;

  try {
    await apiFetch(`/documents/${currentDetailUuid}`, {
      method: "PUT",
      body: JSON.stringify({
        display_name: displayName,
        category: category || null,
        sensitivity: sensitivity
      })
    });
    showToast("Document metadata updated!", "success");
    closeModal("modal-edit-doc");
    openDocumentDetail(currentDetailUuid);
  } catch (err) {
    showToast("Update failed: " + err.message, "error");
  }
}

// Modal: Upload Version
function openUploadVersionModal() {
  openModal("modal-upload-version");
}

async function submitUploadVersion(e) {
  e.preventDefault();
  const fileInput = document.getElementById("version-file-input");
  if (!fileInput.files || !fileInput.files[0]) return;

  const formData = new FormData();
  formData.append("file", fileInput.files[0]);

  try {
    await apiFetch(`/documents/${currentDetailUuid}/versions`, {
      method: "POST",
      body: formData
    });
    showToast("New version uploaded!", "success");
    closeModal("modal-upload-version");
    openDocumentDetail(currentDetailUuid);
  } catch (err) {
    showToast("Version upload failed: " + err.message, "error");
  }
}

// Modal: Assign Tags
async function openAssignTagModal() {
  const container = document.getElementById("assign-tags-checklist");
  try {
    tagsList = await apiFetch("/tags");
    const doc = await apiFetch(`/documents/${currentDetailUuid}`);
    const assignedIds = new Set((doc.tags || []).map(t => t.id));

    if (tagsList.length === 0) {
      container.innerHTML = `<div class="empty-state">No tags created yet. Create tags in the Folders & Tags tab first.</div>`;
    } else {
      container.innerHTML = tagsList.map(t => `
        <label style="display:flex; align-items:center; gap:8px; cursor:pointer;">
          <input type="checkbox" value="${t.id}" ${assignedIds.has(t.id) ? 'checked' : ''}>
          <span class="tag-pill" style="background:${t.color};">${escapeHtml(t.name)}</span>
        </label>
      `).join("");
    }

    openModal("modal-assign-tag");
  } catch (err) {
    showToast("Error loading tags: " + err.message, "error");
  }
}

async function submitAssignTags() {
  const checkboxes = document.querySelectorAll("#assign-tags-checklist input[type='checkbox']:checked");
  const selectedIds = Array.from(checkboxes).map(cb => parseInt(cb.value));

  try {
    await apiFetch(`/tags/documents/${currentDetailUuid}/tags`, {
      method: "POST",
      body: JSON.stringify({ tag_ids: selectedIds })
    });
    showToast("Tags updated successfully.", "success");
    closeModal("modal-assign-tag");
    openDocumentDetail(currentDetailUuid);
  } catch (err) {
    showToast("Tag assignment failed: " + err.message, "error");
  }
}

async function removeTagFromDoc(uuid, tagId) {
  try {
    await apiFetch(`/tags/documents/${uuid}/tags/${tagId}`, { method: "DELETE" });
    showToast("Tag removed.", "info");
    openDocumentDetail(uuid);
  } catch (err) {
    showToast("Remove tag failed: " + err.message, "error");
  }
}

// --- SEARCH & AUTOCOMPLETE ---
function handleSearchInput(val) {
  clearTimeout(searchDebounceTimer);
  const dropdown = document.getElementById("search-autocomplete-box");

  if (!val || val.trim().length < 2) {
    dropdown.classList.remove("active");
    return;
  }

  searchDebounceTimer = setTimeout(async () => {
    try {
      const res = await apiFetch(`/search/suggest?prefix=${encodeURIComponent(val.trim())}`);
      if (res.suggestions && res.suggestions.length > 0) {
        dropdown.innerHTML = res.suggestions.map(s => `
          <div class="autocomplete-item" onclick="executeSearch('${escapeHtml(s)}')">
            🔍 <span>${escapeHtml(s)}</span>
          </div>
        `).join("");
        dropdown.classList.add("active");
      } else {
        dropdown.classList.remove("active");
      }
    } catch (e) {
      dropdown.classList.remove("active");
    }
  }, 200);
}

function handleSearchKeyDown(e) {
  if (e.key === "Enter") {
    const val = e.target.value.trim();
    if (val) executeSearch(val);
  }
}

async function executeSearch(query) {
  document.getElementById("search-autocomplete-box").classList.remove("active");
  document.getElementById("global-search-input").value = query;
  navigateTo("search");
  document.getElementById("search-query-subtitle").innerText = `Results for query "${query}"`;

  const resultsList = document.getElementById("search-results-list");
  resultsList.innerHTML = `<div class="empty-state"><div class="spinner"></div> Searching documents...</div>`;

  try {
    const res = await apiFetch(`/search?q=${encodeURIComponent(query)}`);
    if (!res.results || res.results.length === 0) {
      resultsList.innerHTML = `<div class="empty-state">No matching documents found for "${escapeHtml(query)}".</div>`;
      return;
    }

    resultsList.innerHTML = res.results.map(hit => `
      <div class="card" style="margin-bottom:0;">
        <div style="display:flex; justify-content:space-between; align-items:flex-start;">
          <div>
            <a style="font-weight:700; font-size:15px; color:var(--primary); cursor:pointer;" onclick="openDocumentDetail('${hit.document.uuid}')">
              📄 ${escapeHtml(hit.document.display_name || hit.document.original_name)}
            </a>
            <div style="font-size:12px; color:var(--text-muted); margin-top:2px;">
              Category: ${escapeHtml(hit.document.category || 'Uncategorized')} • Score: ${(hit.score * 100).toFixed(0)}%
            </div>
          </div>
          <button class="btn btn-secondary btn-sm" onclick="openDocumentDetail('${hit.document.uuid}')">View Detail</button>
        </div>
        <div style="margin-top:10px; font-size:13px; color:var(--text-secondary); background:#f8fafc; padding:10px; border-radius:var(--radius-sm);">
          "${escapeHtml(hit.snippet)}"
        </div>
      </div>
    `).join("");

  } catch (err) {
    resultsList.innerHTML = `<div class="empty-state">Search error: ${escapeHtml(err.message)}</div>`;
  }
}

// --- SUGGESTIONS VIEW ---
let selectedSuggestionIds = new Set();

function updateBulkSelectionUI() {
  const checkboxes = document.querySelectorAll(".suggestion-select-checkbox");
  const checked = document.querySelectorAll(".suggestion-select-checkbox:checked");
  const selectedCount = checked.length;
  const totalCount = checkboxes.length;

  selectedSuggestionIds = new Set(Array.from(checked).map(cb => parseInt(cb.value)));

  const selectAllCb = document.getElementById("select-all-suggestions-checkbox");
  if (selectAllCb) {
    selectAllCb.checked = totalCount > 0 && selectedCount === totalCount;
    selectAllCb.indeterminate = selectedCount > 0 && selectedCount < totalCount;
  }

  const btnAccept = document.getElementById("btn-bulk-accept");
  const btnReject = document.getElementById("btn-bulk-reject");
  const acceptCountEl = document.getElementById("bulk-accept-count");
  const rejectCountEl = document.getElementById("bulk-reject-count");

  if (btnAccept) btnAccept.disabled = selectedCount === 0;
  if (btnReject) btnReject.disabled = selectedCount === 0;
  if (acceptCountEl) acceptCountEl.innerText = selectedCount;
  if (rejectCountEl) rejectCountEl.innerText = selectedCount;
}

function toggleSelectAllSuggestions(checked) {
  const checkboxes = document.querySelectorAll(".suggestion-select-checkbox");
  checkboxes.forEach(cb => { cb.checked = checked; });
  updateBulkSelectionUI();
}

async function submitBulkAccept() {
  const ids = Array.from(selectedSuggestionIds);
  if (ids.length === 0) return;

  const btnAccept = document.getElementById("btn-bulk-accept");
  const btnReject = document.getElementById("btn-bulk-reject");
  if (btnAccept) { btnAccept.disabled = true; btnAccept.innerText = "Processing..."; }
  if (btnReject) btnReject.disabled = true;

  try {
    const res = await apiFetch("/suggestions/bulk-accept", {
      method: "POST",
      body: JSON.stringify({ suggestion_ids: ids })
    });
    const completed = Array.isArray(res) ? new Set(res.map(item => Number(item.id))) : new Set();
    const failedIds = ids.filter(id => !completed.has(Number(id)));
    selectedSuggestionIds = new Set(failedIds);
    showToast(
      `Accepted ${completed.size} of ${ids.length} selected suggestion(s).` +
      (failedIds.length ? ` ${failedIds.length} remain pending; review and retry if needed.` : ""),
      failedIds.length ? "info" : "success"
    );
    await loadSuggestions();
    await fetchBadges();
  } catch (err) {
    showToast("Bulk accept failed: " + err.message, "error");
  } finally {
    updateBulkSelectionUI();
  }
}

async function submitBulkReject() {
  const ids = Array.from(selectedSuggestionIds);
  if (ids.length === 0) return;

  const btnAccept = document.getElementById("btn-bulk-accept");
  const btnReject = document.getElementById("btn-bulk-reject");
  if (btnReject) { btnReject.disabled = true; btnReject.innerText = "Processing..."; }
  if (btnAccept) btnAccept.disabled = true;

  try {
    const res = await apiFetch("/suggestions/bulk-reject", {
      method: "POST",
      body: JSON.stringify({ suggestion_ids: ids })
    });
    const completed = Array.isArray(res) ? new Set(res.map(item => Number(item.id))) : new Set();
    const failedIds = ids.filter(id => !completed.has(Number(id)));
    selectedSuggestionIds = new Set(failedIds);
    showToast(
      `Rejected ${completed.size} of ${ids.length} selected suggestion(s).` +
      (failedIds.length ? ` ${failedIds.length} remain pending; review and retry if needed.` : ""),
      failedIds.length ? "info" : "success"
    );
    await loadSuggestions();
    await fetchBadges();
  } catch (err) {
    showToast("Bulk reject failed: " + err.message, "error");
  } finally {
    updateBulkSelectionUI();
  }
}

async function loadSuggestions(analysisData = null) {
  const container = document.getElementById("suggestions-list-container");
  container.innerHTML = `<div class="empty-state"><div class="spinner"></div> Loading pending suggestions...</div>`;

  try {
    const list = await apiFetch("/suggestions");
    fetchBadges();

    const summaryDetails = document.getElementById("bulk-summary-details");
    if (summaryDetails) {
      if (analysisData && analysisData.analyzed_count !== undefined) {
        const catStr = analysisData.category_counts ? Object.entries(analysisData.category_counts).map(([k, v]) => `${k} (${v})`).join(", ") : "";
        summaryDetails.innerHTML = `Analyzed <strong>${analysisData.analyzed_count}</strong> document(s) across categories: ${escapeHtml(catStr || 'None')}. Found <strong>${list.length}</strong> pending proposal(s).`;
      } else {
        summaryDetails.innerHTML = `Found <strong>${list.length}</strong> pending AI organization proposal(s). Select items to batch accept or reject.`;
      }
    }

    if (list.length === 0) {
      container.innerHTML = `<div class="empty-state">🎉 All suggestions reviewed! No pending suggestions.</div>`;
      selectedSuggestionIds.clear();
      updateBulkSelectionUI();
      return;
    }

    container.innerHTML = list.map(s => {
      const confidencePct = Math.round((Number(s.confidence) || 0) * 100);
      const needsReview = confidencePct < 70 || s.evidence?.status_label === "NEEDS_REVIEW";
      const typeLabel = ({
        categorize: "Category",
        rename: "Filename",
        add_tag: "Tags",
        move_folder: "Folder",
        create_folder_group: "Smart Folder Group",
        sensitivity: "Sensitivity"
      })[s.suggestion_type] || s.suggestion_type;
      const evidenceRows = s.evidence ? Object.entries(s.evidence)
        .filter(([k, v]) => !["semantic_scores"].includes(k) && v !== null && v !== undefined && v !== "")
        .slice(0, 8)
        .map(([k, v]) => `<div style="margin:2px 0;"><strong>${escapeHtml(k.replaceAll("_", " "))}:</strong> ${escapeHtml(Array.isArray(v) ? v.join(", ") : typeof v === "object" ? JSON.stringify(v) : String(v))}</div>`).join("") : "";

      const isChecked = selectedSuggestionIds.has(s.id);
      const displaySuggestionValue = (value) => {
        if (s.suggestion_type !== "sensitivity") return value ?? "None";
        const normalized = String(value ?? "").trim().toLowerCase();
        return ({
          public: "Public",
          internal: "Internal",
          pii: "Confidential",
          confidential: "Confidential",
          restricted: "Confidential"
        })[normalized] || value || "Needs Review";
      };
      const displayCurrentValue = displaySuggestionValue(s.current_value);
      const displaySuggestedValue = displaySuggestionValue(s.suggested_value);
      return `
      <div class="card suggestion-card" style="margin-bottom:0; border-left:4px solid var(--primary);">
        <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:16px; flex-wrap:wrap;">
          <div style="display:flex; gap:12px; align-items:flex-start;">
            <input type="checkbox" class="suggestion-select-checkbox" value="${s.id}" ${isChecked ? 'checked' : ''} onchange="updateBulkSelectionUI()" style="margin-top:4px; width:18px; height:18px; cursor:pointer;">
            <div>
              <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
                <span class="badge badge-info">AI · ${escapeHtml(typeLabel)}</span>
                <span style="font-size:12px; color:var(--text-muted);">Confidence: ${confidencePct}%</span>
                ${needsReview ? '<span class="badge badge-warning">Needs Review</span>' : ''}
              </div>
              <div style="margin-top:10px; font-size:13.5px;">
                <div><span style="color:var(--text-muted);">Current:</span> <code>${escapeHtml(displayCurrentValue)}</code></div>
                <div style="margin-top:4px;"><span style="color:var(--text-muted);">Suggested:</span> <strong style="color:var(--primary);">${escapeHtml(displaySuggestedValue)}</strong></div>
              </div>
            </div>
          </div>
          <div style="display:flex; gap:8px; flex-wrap:wrap;">
            <button class="btn btn-primary btn-sm" onclick="acceptSuggestion(${s.id}, this)">Accept</button>
            <button class="btn btn-secondary btn-sm" onclick="promptEditSuggestion(${s.id}, '${escapeHtml(s.suggested_value)}', this)">Edit</button>
            <button class="btn btn-secondary btn-sm" onclick="keepSuggestion(${s.id}, this)">Keep As-Is</button>
            <button class="btn btn-danger btn-sm" onclick="rejectSuggestion(${s.id}, this)">Reject</button>
          </div>
        </div>
        <div style="margin-top:12px; font-size:13px; color:var(--text-secondary);">
          <strong>Why:</strong> ${escapeHtml(s.reason)}
        </div>
        ${s.suggestion_type === "sensitivity" && s.evidence?.pii_types?.length
          ? `<div style="margin-top:8px; font-size:12px; color:var(--text-muted);">
               Detected signals: ${escapeHtml(s.evidence.pii_types.join(", "))}
             </div>`
          : ""}
        <!-- AI_SENSITIVITY_UI_V1 -->
        ${evidenceRows ? `<div style="margin-top:10px; padding:10px; background:#f8fafc; border-radius:8px; font-size:12px;"><strong style="color:var(--text-primary);">Evidence</strong>${evidenceRows}</div>` : ''}
      </div>`;
    }).join("");

    updateBulkSelectionUI();

  } catch (err) {
    container.innerHTML = `<div class="empty-state">Error loading suggestions: ${escapeHtml(err.message)}</div>`;
  }
}

async function triggerAnalyzeLibrarySuggestions(buttonEl) {
  const button = buttonEl || document.querySelector("#btn-re-evaluate-suggestions");
  if (button) { button.disabled = true; button.dataset.originalText = button.innerText; button.innerText = "⏳ Analyzing..."; }
  try {
    showToast("Analyzing document library for AI insights...", "info");
    // intellidocs_single_doc_analyze_v10: scope to the currently focused upload.
    let focusId = 0;
    try { focusId = Number(sessionStorage.getItem("intellidocs_suggestion_focus_document_id") || 0); } catch (_) {}
    const analysisUrl = focusId > 0
      ? `/suggestions/analyze?document_id=${encodeURIComponent(focusId)}`
      : "/suggestions/analyze";
    const analysisPlan = await apiFetch(analysisUrl, { method: "POST" });
    showToast("Library AI insights updated!", "success");
    await loadSuggestions(analysisPlan);
    await fetchBadges();
  } catch (err) {
    showToast("Analysis failed: " + err.message, "error");
  } finally {
    if (button) { button.disabled = false; button.innerText = button.dataset.originalText || "⚡ Re-evaluate AI Insights"; }
  }
}


function setSuggestionButtonsBusy(buttonEl) {
  const card = buttonEl?.closest(".suggestion-card, .id-v6-card");
  if (!card) return () => {};
  card.querySelectorAll("button").forEach(b => b.disabled = true);
  return () => card.querySelectorAll("button").forEach(b => b.disabled = false);
}

async function acceptSuggestion(id, buttonEl) {
  const restore = setSuggestionButtonsBusy(buttonEl);
  try {
    await apiFetch(`/suggestions/${id}/accept`, { method: "POST" });
    showToast("Suggestion accepted and applied.", "success");
    await loadSuggestions();
    await fetchBadges();
  } catch (err) {
    restore();
    showToast("Accept failed: " + err.message, "error");
  }
}

async function promptEditSuggestion(id, currentVal, buttonEl) {
  const cardValue = buttonEl?.closest(".id-v6-card")?.querySelector(".id-v6-title")?.textContent?.trim();
  const val = prompt("Enter custom value:", currentVal || cardValue || "");
  if (val === null || !val.trim()) return;

  const restore = setSuggestionButtonsBusy(buttonEl);
  try {
    await apiFetch(`/suggestions/${id}/edit`, {
      method: "POST",
      body: JSON.stringify({ custom_value: val.trim() })
    });
    showToast("Your edited value was applied.", "success");
    await Promise.allSettled([
      loadSuggestions(),
      typeof loadDashboard === "function" ? loadDashboard() : Promise.resolve(),
      typeof loadDocuments === "function" ? loadDocuments() : Promise.resolve(),
      typeof loadFolders === "function" ? loadFolders() : Promise.resolve()
    ]);
  } catch (err) {
    restore();
    showToast("Edit failed: " + err.message, "error");
  }
}

async function keepSuggestion(id, buttonEl) {
  const restore = setSuggestionButtonsBusy(buttonEl);
  try {
    await apiFetch(`/suggestions/${id}/keep`, { method: "POST" });
    showToast("Kept as-is. IntelliDocs will not change this document.", "info");
    await loadSuggestions();
    await fetchBadges();
  } catch (err) {
    restore();
    showToast("Keep as-is failed: " + err.message, "error");
  }
}

async function rejectSuggestion(id, buttonEl) {
  const restore = setSuggestionButtonsBusy(buttonEl);
  try {
    await apiFetch(`/suggestions/${id}/reject`, { method: "POST" });
    showToast("Suggestion rejected.", "info");
    await loadSuggestions();
    await fetchBadges();
  } catch (err) {
    restore();
    showToast("Reject failed: " + err.message, "error");
  }
}



// --- DUPLICATE_POLICY_V11_20261008_FRONTEND -------------------------------
// Final UI guard: only strict text/visual duplicate evidence is rendered.
// This protects the duplicate page if an older/stale backend response still
// contains a low-confidence persisted relation.
function duplicatePolicyV11Normalize(candidate) {
  const scores = (candidate && candidate.scores) || {};
  const textScore = Math.max(
    Number(scores.normalized_content_sim || 0),
    Number(scores.minhash_lsh_sim || 0),
    Number(scores.ocr_text_sim || 0)
  );
  const visualScore = Number(scores.visual_perceptual_sim || 0);
  const shaScore = Number(scores.sha256_match || 0);
  const strictScore = Math.max(textScore, visualScore);

  if (shaScore > 0) {
    return { ...candidate, confidence: 1, relation_type: "exact_duplicate" };
  }
  if (strictScore >= 0.90) {
    return { ...candidate, confidence: strictScore, relation_type: "exact_duplicate" };
  }
  if (strictScore >= 0.65) {
    return { ...candidate, confidence: strictScore, relation_type: "near_duplicate" };
  }
  return null;
}

function duplicatePolicyV11Filter(candidates) {
  return (candidates || []).map(duplicatePolicyV11Normalize).filter(Boolean);
}
// --- END DUPLICATE_POLICY_V11_20261008_FRONTEND ---------------------------

// --- DUPLICATE REVIEW VIEW ---
async function initDuplicatesPage() {
  const select = document.getElementById("duplicate-doc-select");
  select.innerHTML = `<option value="">Loading documents...</option>`;
  document.getElementById("duplicate-results-panel").style.display = "none";

  try {
    const docsResponse = await apiFetch("/documents?limit=100");
    const ownedDocs = Array.isArray(docsResponse) ? docsResponse : [];
    let receivedDocs = [];
    try {
      const receivedResponse = await apiFetch("/shares/received");
      const byUuid = new Map();
      for (const share of (Array.isArray(receivedResponse) ? receivedResponse : [])) {
        const uuid = String(share && share.document_uuid || "");
        const keyReady = !share.share_key_required || !!share.share_key_verified;
        if (!uuid || !share.active || !share.access_activated || !keyReady) continue;
        if (!byUuid.has(uuid)) byUuid.set(uuid, {
          uuid, document_uuid: uuid, id: Number(share.document_id),
          display_name: share.document_name || "Received document",
          original_name: share.document_name || "Received document",
          version_number: Number(share.version_number) || 1,
          is_recipient_shared: true,
          access_locked: !!share.access_locked,
          unlocked_in_session: !share.access_locked || !!lockTokens[uuid]
        });
      }
      receivedDocs = Array.from(byUuid.values());
    } catch (receivedError) {
      console.warn("[Duplicates] Could not load activated received documents:", receivedError);
    }
    const duplicateDocs = new Map(ownedDocs.filter(d => d && d.uuid).map(d => [String(d.uuid), d]));
    for (const d of receivedDocs) if (!duplicateDocs.has(String(d.uuid))) duplicateDocs.set(String(d.uuid), d);
    window.intellidocsReceivedSharedDocumentUuids = new Set(receivedDocs.map(d => String(d.uuid)));
    window.intellidocsDuplicateDocumentStates = new Map(receivedDocs.map(d => [String(d.uuid), d]));
    select.innerHTML = `<option value="">Select a document...</option>` + Array.from(duplicateDocs.values()).map(d => {
      const lockLabel = d.is_recipient_shared && d.access_locked && !lockTokens[d.uuid] ? "🔒 Unlock required · " : "";
      const receivedLabel = d.is_recipient_shared && !(d.access_locked && !lockTokens[d.uuid]) ? "📩 Received · " : "";
      return `<option value="${d.uuid}" data-recipient-shared="${d.is_recipient_shared ? "1" : "0"}" data-access-locked="${d.access_locked ? "1" : "0"}">${lockLabel}${receivedLabel}${escapeHtml(d.display_name || d.original_name)} (v${Number(d.version_number) || 1})</option>`;
    }).join("");

    const overview = document.getElementById("duplicate-alerts-overview");
    if (overview) {
      const alertData = await apiFetch("/duplicates/alerts", {
        headers: getDocumentLockTokenHeaders()
      });
      const alertCandidates = (alertData && Array.isArray(alertData.alerts)) ? alertData.alerts : [];
      const filteredAlerts = duplicatePolicyV11Filter(alertCandidates);
      const lockedAwaitingUnlock = receivedDocs.filter(d => d.access_locked && !lockTokens[d.uuid]).length;
      if (filteredAlerts.length === 0) {
        overview.innerHTML = `<div class="empty-state" style="padding:8px 0;">✅ No actionable duplicate candidates are currently flagged.${lockedAwaitingUnlock ? `<p style="margin-top:10px;color:var(--warning-text);">🔒 ${lockedAwaitingUnlock} received document(s) are Access-Locked and were not analyzed yet. Unlock them from Received by Me, then refresh this page.</p>` : ""}</div>`;
      } else {
        overview.innerHTML = filteredAlerts.map(a => `
          <div class="duplicate-alert-row">
            <div>
              <strong>${escapeHtml(a.document_name)}</strong>
              <span class="text-muted">↔</span>
              <strong>${escapeHtml(a.candidate_name)}</strong>
              <div class="text-muted" style="margin-top:3px;">${(a.confidence * 100).toFixed(1)}% · ${escapeHtml(a.relation_type.replaceAll('_', ' '))} · ${escapeHtml((a.detection_methods || []).join(', ') || 'analysis')}</div>
            </div>
            <button class="btn btn-secondary btn-sm" onclick="document.getElementById('duplicate-doc-select').value='${a.document_uuid}'; inspectSelectedDuplicates();">Review</button>
          </div>
        `).join("");
      }
      const badgeD = document.getElementById("badge-duplicates");
      if (filteredAlerts.length > 0) {
        badgeD.innerText = String(filteredAlerts.length);
        badgeD.style.display = "inline-block";
      } else {
        badgeD.style.display = "none";
      }
    }
  } catch (err) {
    showToast("Error loading document list: " + err.message, "error");
  }
}

async function inspectSelectedDuplicates() {
  const uuid = document.getElementById("duplicate-doc-select").value;
  if (!uuid) {
    showToast("Please select a document.", "warning");
    return;
  }

  const panel = document.getElementById("duplicate-results-panel");
  const listContainer = document.getElementById("duplicate-candidates-list");
  panel.style.display = "block";
  const selectedState = (window.intellidocsDuplicateDocumentStates || new Map()).get(String(uuid));
  if (selectedState && selectedState.access_locked && !lockTokens[uuid]) {
    listContainer.innerHTML = `<div class="empty-state" role="status">🔒 This received document is Access-Locked. Open it from <strong>Groups → Received by Me</strong>, unlock it with the valid access key, then return here and refresh the duplicate list.</div>`;
    return;
  }
  listContainer.innerHTML = `<div class="empty-state"><div class="spinner"></div> Analyzing duplicate candidates...</div>`;

  try {
    const duplicateToken = lockTokens[uuid] || "";
    const res = await apiFetch(`/duplicates/${uuid}`, { headers: getDocumentLockTokenHeaders(uuid) });
    if (!res.has_duplicates || res.candidates.length === 0) {
      listContainer.innerHTML = `<div class="empty-state">✅ No duplicates or similar candidates found for this document.</div>`;
      return;
    }

    const filteredCandidates = duplicatePolicyV11Filter(res.candidates || []);
    if (filteredCandidates.length === 0) {
      listContainer.innerHTML = `<div class="empty-state">✅ No duplicates or similar candidates above the 65% threshold.</div>`;
      return;
    }

    const sharedUuids = window.intellidocsReceivedSharedDocumentUuids || new Set();
    const selectedIsShared = sharedUuids.has(String(uuid));
    listContainer.innerHTML = filteredCandidates.map(c => {
      const candidateIsShared = sharedUuids.has(String(c.document_uuid));
      const decisionActions = (selectedIsShared || candidateIsShared)
        ? '<span class="text-muted" role="note">Read-only review: shared documents cannot be deleted or altered from the recipient account.</span>'
        : `<button class="btn btn-primary btn-sm" onclick="handleDuplicateDecision('${uuid}', '${c.document_uuid}', 'keep_both')">Keep Both</button><button class="btn btn-danger btn-sm" onclick="handleDuplicateDecision('${uuid}', '${c.document_uuid}', 'trash_new')">Trash Candidate</button>`;
      return `
      <div class="card" style="margin-bottom:0; border:1px solid #cbd5e1;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
          <div>
            <span class="badge badge-warning">Similarity Confidence: ${(c.confidence * 100).toFixed(0)}%</span>
            <span style="font-size:12px; color:var(--text-muted); margin-left:8px;">Relation: ${escapeHtml(c.relation_type)}</span>
          </div>
          <div style="display:flex; gap:8px; flex-wrap:wrap;">${decisionActions}</div>
        </div>

        <!-- Side by Side Details -->
        <div class="review-grid">
          <div class="review-card">
            <div style="font-weight:700; color:var(--text-primary);">Selected Document</div>
            <div style="font-size:12px; color:var(--text-muted); margin-top:4px;">UUID: ${uuid}</div>
          </div>

          <div class="review-card">
            <div style="font-weight:700; color:var(--text-primary);">${escapeHtml(c.original_name)}</div>
            <div style="font-size:12px; color:var(--text-muted); margin-top:4px;">Candidate UUID: ${c.document_uuid}</div>
          </div>
        </div>

        <!-- Detection evidence -->
        <div style="margin-top:12px; font-size:12.5px; background:#f8fafc; padding:10px; border-radius:var(--radius-sm);">
          <div><strong>Detection Methods:</strong> ${(c.detection_methods || []).join(", ")}</div>
          <div style="margin-top:4px;"><strong>Evidence:</strong> ${(c.supporting_evidence || []).join(" | ")}</div>
        </div>
      </div>
      `;
    }).join("");

  } catch (err) {
    listContainer.innerHTML = `<div class="empty-state">Error: ${escapeHtml(err.message)}</div>`;
  }
}

async function handleDuplicateDecision(newUuid, existingUuid, action) {
  try {
    const res = await apiFetch("/duplicates/decide", {
      method: "POST",
      body: JSON.stringify({
        new_doc_uuid: newUuid,
        existing_doc_uuid: existingUuid,
        action: action
      })
    });
    showToast(res.detail || "Decision recorded.", "success");
    inspectSelectedDuplicates();
  } catch (err) {
    showToast("Decision failed: " + err.message, "error");
  }
}

// --- FOLDERS / CATEGORIES / TAGS ORGANIZATION VIEW ---
function loadOrganizationView() {
  switchOrgTab("folders");
}

function switchOrgTab(tabName) {
  const tabs = ["folders", "categories", "tags"];
  tabs.forEach(t => {
    const el = document.getElementById(`org-tab-${t}`);
    if (el) el.style.display = (t === tabName) ? "block" : "none";
  });

  if (tabName === "folders") loadFoldersTab();
  else if (tabName === "categories") loadCategoriesTab();
  else if (tabName === "tags") loadTagsTab();
}

async function loadFoldersTab() {
  const tbody = document.getElementById("folders-tbody");
  tbody.innerHTML = `<tr><td colspan="4" class="empty-state">Loading folders...</td></tr>`;
  try {
    foldersList = await apiFetch("/folders");
    if (foldersList.length === 0) {
      tbody.innerHTML = `<tr><td colspan="4" class="empty-state">No custom folders created yet. Click "+ Create Folder" to get started.</td></tr>`;
      return;
    }

    let allDocs = [];
    try { allDocs = await apiFetch("/documents?limit=100"); } catch (e) {}
    const counts = {};
    allDocs.forEach(d => {
      if (d.folder_id) counts[d.folder_id] = (counts[d.folder_id] || 0) + 1;
    });

    tbody.innerHTML = foldersList.map(f => {
      const docCount = counts[f.id] || 0;
      return `
        <tr>
          <td>📁 <strong>${escapeHtml(f.name)}</strong></td>
          <td><span class="badge badge-info">${docCount} docs</span></td>
          <td>${formatDate(f.created_at)}</td>
          <td style="text-align:right;">
            <button class="btn btn-secondary btn-sm" onclick="filterLibraryByFolder(${f.id})">🔍 View Documents</button>
            <button class="btn btn-secondary btn-sm" onclick="renameFolder(${f.id}, '${escapeHtml(f.name)}')">✏️ Rename</button>
            <button class="btn btn-danger btn-sm" onclick="deleteFolder(${f.id})">🗑️ Delete</button>
          </td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty-state">Error: ${escapeHtml(err.message)}</td></tr>`;
  }
}

async function renameFolder(id, currentName) {
  const name = prompt("Enter new folder name:", currentName);
  if (name === null) return;
  const trimmed = name.trim();
  if (!trimmed) return showToast("Folder name cannot be empty", "warning");

  try {
    await apiFetch(`/folders/${id}`, {
      method: "PUT",
      body: JSON.stringify({ name: trimmed })
    });
    showToast("Folder renamed successfully.", "success");
    loadFoldersTab();
    loadMetadataDropdowns();
  } catch (err) {
    showToast("Rename folder failed: " + err.message, "error");
  }
}

function filterLibraryByFolder(folderId) {
  navigateTo("library");
  setTimeout(() => {
    const folderSelect = document.getElementById("filter-folder");
    if (folderSelect) {
      folderSelect.value = folderId;
      loadLibraryDocuments();
    }
  }, 100);
}

function filterLibraryByCategory(categoryName) {
  navigateTo("library");
  setTimeout(() => {
    const catSelect = document.getElementById("filter-category");
    if (catSelect) {
      catSelect.value = categoryName;
      loadLibraryDocuments();
    }
  }, 100);
}

async function loadCategoriesTab() {
  const tbody = document.getElementById("categories-tbody");
  tbody.innerHTML = `<tr><td colspan="4" class="empty-state">Loading categories...</td></tr>`;
  try {
    categoriesList = await apiFetch("/categories");

    let allDocs = [];
    try { allDocs = await apiFetch("/documents?limit=100"); } catch (e) {}
    const counts = {};
    allDocs.forEach(d => {
      if (d.category) counts[d.category] = (counts[d.category] || 0) + 1;
    });

    tbody.innerHTML = categoriesList.map(c => {
      const docCount = counts[c.name] || 0;
      return `
        <tr>
          <td><strong>${escapeHtml(c.name)}</strong></td>
          <td>${escapeHtml(c.description || '-')}</td>
          <td>${c.is_system ? '<span class="badge badge-neutral">System</span>' : '<span class="badge badge-info">Custom</span>'} • <span class="badge badge-neutral">${docCount} docs</span></td>
          <td style="text-align:right;">
            <button class="btn btn-secondary btn-sm" onclick="filterLibraryByCategory('${escapeHtml(c.name)}')">🔍 View Documents</button>
          </td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty-state">Error: ${escapeHtml(err.message)}</td></tr>`;
  }
}

async function loadTagsTab() {
  const tbody = document.getElementById("tags-tbody");
  tbody.innerHTML = `<tr><td colspan="3" class="empty-state">Loading tags...</td></tr>`;
  try {
    tagsList = await apiFetch("/tags");
    if (tagsList.length === 0) {
      tbody.innerHTML = `<tr><td colspan="3" class="empty-state">No tags created yet.</td></tr>`;
      return;
    }
    tbody.innerHTML = tagsList.map(t => `
      <tr>
        <td><span class="tag-pill" style="background:${t.color}; padding:6px 12px; font-size:12px;">${escapeHtml(t.name)}</span></td>
        <td><strong>${t.document_count || 0}</strong> documents</td>
        <td style="text-align:right;">
          ${currentUser && t.created_by === currentUser.id ? `
            <button class="btn btn-secondary btn-sm" onclick="editTag(${t.id}, '${escapeHtml(t.name)}', '${escapeHtml(t.color)}')">Edit</button>
            <button class="btn btn-danger btn-sm" onclick="deleteTag(${t.id}, '${escapeHtml(t.name)}')">Delete</button>
          ` : `<span class="text-muted" style="font-size:11px;">Protected/shared</span>`}
        </td>
      </tr>
    `).join("");
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="3" class="empty-state">Error: ${escapeHtml(err.message)}</td></tr>`;
  }
}

// Create Modals Submit Handlers
function openCreateFolderModal() { openModal("modal-create-folder"); }
async function submitCreateFolder(e) {
  e.preventDefault();
  const name = document.getElementById("create-folder-name").value.trim();
  try {
    await apiFetch("/folders", {
      method: "POST",
      body: JSON.stringify({ name })
    });
    showToast("Folder created!", "success");
    closeModal("modal-create-folder");
    loadFoldersTab();
    loadMetadataDropdowns();
  } catch (err) {
    showToast("Create folder failed: " + err.message, "error");
  }
}

async function deleteFolder(id) {
  if (!confirm("Are you sure you want to delete this folder?")) return;
  try {
    await apiFetch(`/folders/${id}`, { method: "DELETE" });
    showToast("Folder deleted.", "success");
    loadFoldersTab();
    loadMetadataDropdowns();
  } catch (err) {
    showToast("Delete folder failed: " + err.message, "error");
  }
}

function openCreateCategoryModal() { openModal("modal-create-category"); }
async function submitCreateCategory(e) {
  e.preventDefault();
  const name = document.getElementById("create-cat-name").value.trim();
  const desc = document.getElementById("create-cat-desc").value.trim();
  try {
    await apiFetch("/categories", {
      method: "POST",
      body: JSON.stringify({ name, description: desc || null })
    });
    showToast("Category created!", "success");
    closeModal("modal-create-category");
    loadCategoriesTab();
    loadMetadataDropdowns();
  } catch (err) {
    showToast("Create category failed: " + err.message, "error");
  }
}

function openCreateTagModal() { openModal("modal-create-tag"); }
async function editTag(id, currentName, currentColor) {
  const name = prompt("Tag name:", currentName);
  if (name === null) return;
  const trimmed = name.trim();
  if (!trimmed) return showToast("Tag name cannot be empty", "error");
  const color = prompt("Tag color (CSS value or hex):", currentColor);
  if (color === null) return;
  try {
    await apiFetch(`/tags/${id}`, { method: "PUT", body: JSON.stringify({ name: trimmed, color: color.trim() || currentColor }) });
    showToast("Tag updated.", "success");
    loadTagsTab();
    loadMetadataDropdowns();
  } catch (err) {
    showToast("Update tag failed: " + err.message, "error");
  }
}

async function deleteTag(id, name) {
  if (!confirm(`Delete tag '${name}'? This removes the label from your documents.`)) return;
  try {
    await apiFetch(`/tags/${id}`, { method: "DELETE" });
    showToast("Tag deleted.", "success");
    loadTagsTab();
    loadMetadataDropdowns();
  } catch (err) {
    showToast("Delete tag failed: " + err.message, "error");
  }
}

async function submitCreateTag(e) {
  e.preventDefault();
  const name = document.getElementById("create-tag-name").value.trim();
  const color = document.getElementById("create-tag-color").value;
  try {
    await apiFetch("/tags", {
      method: "POST",
      body: JSON.stringify({ name, color })
    });
    showToast("Tag created!", "success");
    closeModal("modal-create-tag");
    loadTagsTab();
  } catch (err) {
    showToast("Create tag failed: " + err.message, "error");
  }
}

// --- RELATIONSHIP & HISTORY EXPLORER GRAPH CONTROLLER ---
let explorerState = {
  rawNodes: [],
  rawEdges: [],
  nodes: [],
  edges: [],
  nodeMap: {},
  selectedNodeId: null,
  selectedEdge: null,
  hoveredNode: null,
  relationFilter: "all",
  hideUnrelated: false,
  zoomScale: 1.0,
  panX: 0,
  panY: 0,
  isDragging: false,
  dragStartX: 0,
  dragStartY: 0,
  dragNode: null,
  isSidePanelOpen: true,
  searchQuery: "",
  listenersAttached: false,
  width: 900,
  height: 500
};

async function loadExplorerGraph() {
  const container = document.getElementById("explorer-canvas-container");
  const canvas = document.getElementById("explorer-graph-canvas");
  if (!canvas || !container) return;

  const ctx = canvas.getContext("2d");
  updateExplorerCanvasSize();

  ctx.clearRect(0, 0, explorerState.width, explorerState.height);
  ctx.fillStyle = "var(--text-muted)";
  ctx.font = "14px sans-serif";
  ctx.fillText("⚡ Fetching document graph & relationship intelligence...", 30, 40);

  try {
    const graphData = await apiFetch("/explorer/graph");
    explorerState.rawNodes = graphData.nodes || [];
    explorerState.rawEdges = graphData.edges || [];

    initExplorerGraphLayout();
    attachExplorerCanvasListeners();
    applyExplorerFilters();
    explorerFitToView();
    requestAnimationFrame(renderExplorerGraphCanvas);
  } catch (err) {
    ctx.clearRect(0, 0, explorerState.width, explorerState.height);
    ctx.fillStyle = "var(--danger-text)";
    ctx.fillText("Failed to load graph: " + err.message, 30, 40);
    showToast("Explorer graph load failed: " + err.message, "error");
  }
}

function updateExplorerCanvasSize() {
  const container = document.getElementById("explorer-canvas-container");
  const canvas = document.getElementById("explorer-graph-canvas");
  if (!container || !canvas) return;

  const rect = container.getBoundingClientRect();
  const dpr = window.devicePixelRatio || 1;
  explorerState.width = rect.width;
  explorerState.height = rect.height;

  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  canvas.style.width = `${rect.width}px`;
  canvas.style.height = `${rect.height}px`;

  const ctx = canvas.getContext("2d");
  ctx.scale(dpr, dpr);
}

function initExplorerGraphLayout() {
  const nodes = explorerState.rawNodes;
  explorerState.nodeMap = {};

  if (nodes.length === 0) return;

  // Hierarchical Cluster Strategy:
  // Layer 0 (Top): Folders & Categories
  // Layer 1 (Middle): Documents
  // Layer 2 (Bottom): Tags, Versions, Users
  const foldersAndCats = nodes.filter(n => n.type === "Folder" || n.type === "Category");
  const documents = nodes.filter(n => n.type === "Document");
  const tagsAndUsers = nodes.filter(n => n.type === "Tag" || n.type === "User");

  const width = Math.max(explorerState.width, 800);
  const height = Math.max(explorerState.height, 500);

  // Layout Folders & Categories along top layer
  const fcY = height * 0.2;
  foldersAndCats.forEach((node, idx) => {
    const step = width / (foldersAndCats.length + 1);
    node.x = step * (idx + 1);
    node.y = fcY + (idx % 2 === 0 ? -20 : 20);
    node.vx = 0; node.vy = 0;
    explorerState.nodeMap[node.id] = node;
  });

  // Layout Documents in middle grid/cluster layer
  const docY = height * 0.5;
  const cols = Math.ceil(Math.sqrt(documents.length)) || 1;
  documents.forEach((node, idx) => {
    const row = Math.floor(idx / cols);
    const col = idx % cols;
    const colStep = width / (cols + 1);
    const rowStep = 100;
    node.x = colStep * (col + 1);
    node.y = docY + (row * rowStep) - ((documents.length / cols * rowStep) / 2);
    node.vx = 0; node.vy = 0;
    explorerState.nodeMap[node.id] = node;
  });

  // Layout Tags & Users along bottom layer
  const tuY = height * 0.8;
  tagsAndUsers.forEach((node, idx) => {
    const step = width / (tagsAndUsers.length + 1);
    node.x = step * (idx + 1);
    node.y = tuY + (idx % 2 === 0 ? -15 : 15);
    node.vx = 0; node.vy = 0;
    explorerState.nodeMap[node.id] = node;
  });

  // Fallback for any unmapped nodes
  nodes.forEach((node, idx) => {
    if (!explorerState.nodeMap[node.id]) {
      node.x = width / 2 + Math.cos(idx) * 150;
      node.y = height / 2 + Math.sin(idx) * 150;
      node.vx = 0; node.vy = 0;
      explorerState.nodeMap[node.id] = node;
    }
  });

  // Iterative relaxation pass to ensure minimum distance (no overlapping labels/nodes)
  const minDist = 90;
  for (let iter = 0; iter < 40; iter++) {
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const n1 = nodes[i];
        const n2 = nodes[j];
        const dx = n2.x - n1.x;
        const dy = n2.y - n1.y;
        const dist = Math.hypot(dx, dy) || 1;
        if (dist < minDist) {
          const force = (minDist - dist) / dist * 0.3;
          const fx = dx * force;
          const fy = dy * force;
          n1.x -= fx;
          n1.y -= fy;
          n2.x += fx;
          n2.y += fy;
        }
      }
    }
  }
}

function applyExplorerFilters() {
  const filter = explorerState.relationFilter;
  const hideUnrelated = explorerState.hideUnrelated;
  const selId = explorerState.selectedNodeId;

  // Filter edges based on relation type
  let filteredEdges = explorerState.rawEdges.filter(e => {
    if (filter === "all") return true;
    if (filter === "belongs_to") return e.relation === "belongs_to";
    if (filter === "categorized_as") return e.relation === "categorized_as";
    if (filter === "has_tag") return e.relation === "has_tag";
    if (filter === "version_of") return e.relation === "version_of";
    if (filter === "duplicate") return e.relation === "duplicate" || e.relation === "near_duplicate" || e.relation === "exact_duplicate";
    if (filter === "related") return e.relation === "related" || e.relation === "semantic_similar";
    if (filter === "sharing") return e.relation === "owns" || e.relation === "shared_access" || e.relation === "shared_with";
    return true;
  });

  if (hideUnrelated && selId) {
    const connectedIds = new Set([selId]);
    filteredEdges.forEach(e => {
      if (e.source === selId) connectedIds.add(e.target);
      if (e.target === selId) connectedIds.add(e.source);
    });
    filteredEdges = filteredEdges.filter(e => connectedIds.has(e.source) && connectedIds.has(e.target));
    explorerState.nodes = explorerState.rawNodes.filter(n => connectedIds.has(n.id));
  } else {
    explorerState.nodes = explorerState.rawNodes;
  }

  explorerState.edges = filteredEdges;
  requestAnimationFrame(renderExplorerGraphCanvas);
}

function setExplorerRelationFilter(filterType, chipEl) {
  explorerState.relationFilter = filterType;
  const chips = document.querySelectorAll(".explorer-filter-chip");
  chips.forEach(c => c.classList.remove("active"));
  if (chipEl) chipEl.classList.add("active");
  applyExplorerFilters();
}

function toggleExplorerHideUnrelated(checked) {
  explorerState.hideUnrelated = checked;
  applyExplorerFilters();
}

function explorerZoom(factor) {
  explorerState.zoomScale = Math.max(0.3, Math.min(3.5, explorerState.zoomScale * factor));
  requestAnimationFrame(renderExplorerGraphCanvas);
}

function explorerResetView() {
  explorerState.zoomScale = 1.0;
  explorerState.panX = 0;
  explorerState.panY = 0;
  explorerState.selectedNodeId = null;
  explorerState.selectedEdge = null;
  explorerState.hideUnrelated = false;
  const hideCheck = document.getElementById("explorer-hide-unrelated-check");
  if (hideCheck) hideCheck.checked = false;
  applyExplorerFilters();
  explorerFitToView();
}

function explorerFitToView() {
  const nodes = explorerState.nodes;
  if (nodes.length === 0) return;

  let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
  nodes.forEach(n => {
    if (n.x < minX) minX = n.x;
    if (n.x > maxX) maxX = n.x;
    if (n.y < minY) minY = n.y;
    if (n.y > maxY) maxY = n.y;
  });

  const graphW = maxX - minX || 1;
  const graphH = maxY - minY || 1;
  const padding = 60;

  const scaleX = (explorerState.width - padding * 2) / graphW;
  const scaleY = (explorerState.height - padding * 2) / graphH;
  explorerState.zoomScale = Math.max(0.4, Math.min(1.4, Math.min(scaleX, scaleY)));

  const centerX = (minX + maxX) / 2;
  const centerY = (minY + maxY) / 2;
  explorerState.panX = (explorerState.width / 2) - (centerX * explorerState.zoomScale);
  explorerState.panY = (explorerState.height / 2) - (centerY * explorerState.zoomScale);

  requestAnimationFrame(renderExplorerGraphCanvas);
}

function explorerFocusSelected() {
  if (!explorerState.selectedNodeId) {
    return showToast("Select a node in the graph first to focus.", "info");
  }
  const node = explorerState.nodeMap[explorerState.selectedNodeId];
  if (node) {
    explorerState.zoomScale = 1.3;
    explorerState.panX = (explorerState.width / 2) - (node.x * explorerState.zoomScale);
    explorerState.panY = (explorerState.height / 2) - (node.y * explorerState.zoomScale);
    requestAnimationFrame(renderExplorerGraphCanvas);
  }
}

function renderExplorerGraphCanvas() {
  const canvas = document.getElementById("explorer-graph-canvas");
  if (!canvas) return;

  updateExplorerCanvasSize();
  const ctx = canvas.getContext("2d");
  const width = explorerState.width;
  const height = explorerState.height;

  const isDark = document.documentElement.getAttribute("data-theme") === "dark";

  // Background surface
  ctx.fillStyle = isDark ? "#0b0f19" : "#f8fafc";
  ctx.fillRect(0, 0, width, height);

  // Background Grid Pattern
  ctx.strokeStyle = isDark ? "rgba(255, 255, 255, 0.04)" : "rgba(0, 0, 0, 0.04)";
  ctx.lineWidth = 1;
  const gridSize = 40 * explorerState.zoomScale;
  const startX = (explorerState.panX % gridSize);
  const startY = (explorerState.panY % gridSize);

  for (let x = startX; x < width; x += gridSize) {
    ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, height); ctx.stroke();
  }
  for (let y = startY; y < height; y += gridSize) {
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(width, y); ctx.stroke();
  }

  ctx.save();
  ctx.translate(explorerState.panX, explorerState.panY);
  ctx.scale(explorerState.zoomScale, explorerState.zoomScale);

  const selId = explorerState.selectedNodeId;
  const selEdge = explorerState.selectedEdge;

  // Determine neighborhood set for focus subduing
  const neighborhood = new Set();
  if (selId) {
    neighborhood.add(selId);
    explorerState.edges.forEach(e => {
      if (e.source === selId) neighborhood.add(e.target);
      if (e.target === selId) neighborhood.add(e.source);
    });
  }

  // Draw Edges
  explorerState.edges.forEach(e => {
    const s = explorerState.nodeMap[e.source];
    const t = explorerState.nodeMap[e.target];
    if (!s || !t) return;

    const isConnectedToSel = selId ? (e.source === selId || e.target === selId) : true;
    const isSelectedEdge = selEdge && selEdge.source === e.source && selEdge.target === e.target;

    ctx.beginPath();
    ctx.moveTo(s.x, s.y);
    ctx.lineTo(t.x, t.y);

    if (isSelectedEdge) {
      ctx.strokeStyle = "#f59e0b";
      ctx.lineWidth = 3 / explorerState.zoomScale;
    } else if (e.relation === "duplicate" || e.relation === "near_duplicate") {
      ctx.strokeStyle = "#ef4444";
      ctx.lineWidth = (isConnectedToSel ? 2.5 : 1.5) / explorerState.zoomScale;
    } else if (e.relation === "version_of") {
      ctx.strokeStyle = "#10b981";
      ctx.lineWidth = (isConnectedToSel ? 2 : 1.2) / explorerState.zoomScale;
    } else {
      ctx.strokeStyle = isDark ? (isConnectedToSel ? "#475569" : "#1e293b") : (isConnectedToSel ? "#94a3b8" : "#e2e8f0");
      ctx.lineWidth = (isConnectedToSel ? 1.8 : 1) / explorerState.zoomScale;
    }

    if (!isConnectedToSel && selId) {
      ctx.globalAlpha = 0.2;
    } else {
      ctx.globalAlpha = 1.0;
    }

    ctx.stroke();
    ctx.globalAlpha = 1.0;
  });

  // Semantic Node Colors
  const typeColors = {
    "Document": "#6366f1",
    "Folder": "#06b6d4",
    "Category": "#a855f7",
    "Tag": "#f59e0b",
    "User": "#ec4899"
  };

  // Draw Nodes
  explorerState.nodes.forEach(node => {
    const isSel = node.id === selId;
    const isHov = explorerState.hoveredNode && explorerState.hoveredNode.id === node.id;
    const isInNeighbors = selId ? neighborhood.has(node.id) : true;

    ctx.globalAlpha = isInNeighbors ? 1.0 : 0.25;

    let baseRadius = node.type === "Document" ? 18 : node.type === "User" ? 20 : 15;
    if (isSel) baseRadius += 4;

    // Outer Selection / Focus Ring
    if (isSel || isHov) {
      ctx.beginPath();
      ctx.arc(node.x, node.y, baseRadius + 5, 0, 2 * Math.PI);
      ctx.fillStyle = isSel ? "rgba(99, 102, 241, 0.3)" : "rgba(245, 158, 11, 0.25)";
      ctx.fill();
    }

    // Node Circle
    ctx.beginPath();
    ctx.arc(node.x, node.y, baseRadius, 0, 2 * Math.PI);
    ctx.fillStyle = typeColors[node.type] || "#64748b";
    ctx.fill();

    ctx.strokeStyle = isSel ? "#ffffff" : (isDark ? "#1e293b" : "#ffffff");
    ctx.lineWidth = isSel ? 3 : 2;
    ctx.stroke();

    // Node Icon / Short Symbol inside circle
    ctx.fillStyle = "#ffffff";
    ctx.font = "bold 11px sans-serif";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    const symbol = ({
      Document: "📄",
      Folder: "📁",
      Category: "🏷️",
      Tag: "🔖",
      User: "👤"
    })[node.type] || "•";
    ctx.fillText(symbol, node.x, node.y);

    // Node Label Pill & High-Contrast Text
    ctx.textBaseline = "top";
    ctx.font = isSel ? "bold 12px sans-serif" : "11px sans-serif";
    const labelStr = node.label.length > 22 ? node.label.substring(0, 19) + "..." : node.label;
    const textWidth = ctx.measureText(labelStr).width;

    const pillX = node.x - (textWidth / 2) - 6;
    const pillY = node.y + baseRadius + 6;
    const pillW = textWidth + 12;
    const pillH = 18;

    // Label Pill Background
    ctx.fillStyle = isDark ? "rgba(15, 23, 42, 0.85)" : "rgba(255, 255, 255, 0.95)";
    ctx.strokeStyle = isSel ? "#6366f1" : (isDark ? "#273549" : "#e2e8f0");
    ctx.lineWidth = 1;

    ctx.beginPath();
    if (ctx.roundRect) ctx.roundRect(pillX, pillY, pillW, pillH, 4);
    else ctx.rect(pillX, pillY, pillW, pillH);
    ctx.fill();
    ctx.stroke();

    // Label Text
    ctx.fillStyle = isDark ? "#f8fafc" : "#0f172a";
    ctx.fillText(labelStr, node.x, pillY + 3);

    ctx.globalAlpha = 1.0;
  });

  ctx.restore();
}

// Canvas Listeners (Pan, Zoom, Hover, Click)
function attachExplorerCanvasListeners() {
  if (explorerState.listenersAttached) return;
  const canvas = document.getElementById("explorer-graph-canvas");
  if (!canvas) return;

  explorerState.listenersAttached = true;

  function getCanvasCoords(e) {
    const rect = canvas.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;
    const graphX = (mouseX - explorerState.panX) / explorerState.zoomScale;
    const graphY = (mouseY - explorerState.panY) / explorerState.zoomScale;
    return { mouseX, mouseY, graphX, graphY };
  }

  function findNodeAt(graphX, graphY) {
    for (let i = explorerState.nodes.length - 1; i >= 0; i--) {
      const node = explorerState.nodes[i];
      const radius = node.type === "Document" ? 22 : 18;
      const dist = Math.hypot(node.x - graphX, node.y - graphY);
      if (dist <= radius) return node;
    }
    return null;
  }

  function findEdgeAt(graphX, graphY) {
    for (const e of explorerState.edges) {
      const s = explorerState.nodeMap[e.source];
      const t = explorerState.nodeMap[e.target];
      if (!s || !t) continue;
      const l2 = Math.hypot(t.x - s.x, t.y - s.y) ** 2;
      if (l2 === 0) continue;
      let t_param = ((graphX - s.x) * (t.x - s.x) + (graphY - s.y) * (t.y - s.y)) / l2;
      t_param = Math.max(0, Math.min(1, t_param));
      const projX = s.x + t_param * (t.x - s.x);
      const projY = s.y + t_param * (t.y - s.y);
      const dist = Math.hypot(graphX - projX, graphY - projY);
      if (dist <= 8 / explorerState.zoomScale) return e;
    }
    return null;
  }

  canvas.addEventListener("mousedown", (e) => {
    const { graphX, graphY } = getCanvasCoords(e);
    const clickedNode = findNodeAt(graphX, graphY);
    if (clickedNode) {
      explorerState.dragNode = clickedNode;
    } else {
      explorerState.isDragging = true;
      explorerState.dragStartX = e.clientX - explorerState.panX;
      explorerState.dragStartY = e.clientY - explorerState.panY;
    }
  });

  canvas.addEventListener("mousemove", (e) => {
    const { mouseX, mouseY, graphX, graphY } = getCanvasCoords(e);

    if (explorerState.dragNode) {
      explorerState.dragNode.x = graphX;
      explorerState.dragNode.y = graphY;
      requestAnimationFrame(renderExplorerGraphCanvas);
      return;
    }

    if (explorerState.isDragging) {
      explorerState.panX = e.clientX - explorerState.dragStartX;
      explorerState.panY = e.clientY - explorerState.dragStartY;
      requestAnimationFrame(renderExplorerGraphCanvas);
      return;
    }

    // Hover Node Check
    const hoverNode = findNodeAt(graphX, graphY);
    explorerState.hoveredNode = hoverNode;

    const hoverCard = document.getElementById("explorer-hover-card");
    if (hoverNode && hoverCard) {
      renderExplorerHoverCard(hoverNode, mouseX, mouseY);
    } else if (hoverCard) {
      hoverCard.style.display = "none";
    }

    requestAnimationFrame(renderExplorerGraphCanvas);
  });

  canvas.addEventListener("mouseup", () => {
    explorerState.isDragging = false;
    explorerState.dragNode = null;
  });

  canvas.addEventListener("mouseleave", () => {
    explorerState.isDragging = false;
    explorerState.dragNode = null;
    explorerState.hoveredNode = null;
    const hoverCard = document.getElementById("explorer-hover-card");
    if (hoverCard) hoverCard.style.display = "none";
  });

  canvas.addEventListener("wheel", (e) => {
    e.preventDefault();
    const factor = e.deltaY < 0 ? 1.15 : 0.85;
    const { mouseX, mouseY } = getCanvasCoords(e);

    const oldScale = explorerState.zoomScale;
    const newScale = Math.max(0.3, Math.min(3.5, oldScale * factor));

    explorerState.panX = mouseX - (mouseX - explorerState.panX) * (newScale / oldScale);
    explorerState.panY = mouseY - (mouseY - explorerState.panY) * (newScale / oldScale);
    explorerState.zoomScale = newScale;

    requestAnimationFrame(renderExplorerGraphCanvas);
  }, { passive: false });

  canvas.addEventListener("click", (e) => {
    const { graphX, graphY } = getCanvasCoords(e);
    const clickedNode = findNodeAt(graphX, graphY);

    if (clickedNode) {
      explorerState.selectedNodeId = clickedNode.id;
      explorerState.selectedEdge = null;
      applyExplorerFilters();
      renderExplorerSidePanelForNode(clickedNode);
      return;
    }

    const clickedEdge = findEdgeAt(graphX, graphY);
    if (clickedEdge) {
      explorerState.selectedEdge = clickedEdge;
      explorerState.selectedNodeId = null;
      renderExplorerSidePanelForEdge(clickedEdge);
      requestAnimationFrame(renderExplorerGraphCanvas);
      return;
    }

    // Clicked empty canvas
    explorerState.selectedNodeId = null;
    explorerState.selectedEdge = null;
    applyExplorerFilters();
  });
}

function renderExplorerHoverCard(node, mouseX, mouseY) {
  const card = document.getElementById("explorer-hover-card");
  if (!card) return;

  const details = node.details || {};
  let html = `<h4>${escapeHtml(node.label)}</h4>`;

  if (node.type === "Document") {
    const typeStr = (details.file_type || "document").toUpperCase();
    const sensBadge = renderSensitivityBadge(details.sensitivity);

    html += `
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
        <span class="badge badge-info">${escapeHtml(typeStr)}</span>
        ${sensBadge}
      </div>
      <div style="margin-bottom:6px; color:var(--text-secondary);">
        <strong>Category:</strong> ${escapeHtml(details.category || "Uncategorized")}
        ${details.folder_name ? ` • 📁 ${escapeHtml(details.folder_name)}` : ""}
      </div>
      ${details.summary ? `<div style="font-size:11.5px; color:var(--text-secondary); margin-bottom:8px; line-height:1.3; background:var(--bg-neutral); padding:6px; border-radius:4px;">${escapeHtml(details.summary.length > 130 ? details.summary.substring(0, 125) + "..." : details.summary)}</div>` : ""}
      <div style="font-size:11px; color:var(--text-muted); margin-top:4px;">
        Uploaded: ${formatDate(details.uploaded_at)} • ${formatBytes(details.size_bytes)}
      </div>
    `;
  } else {
    html += `
      <div style="color:var(--text-secondary); margin-top:4px;">
        Entity Type: <strong>${escapeHtml(node.type)}</strong>
      </div>
    `;
  }

  card.innerHTML = html;
  card.style.display = "block";

  // Keep hover card inside container bounds
  const container = document.getElementById("explorer-canvas-container");
  const rect = container.getBoundingClientRect();

  let posX = mouseX + 15;
  let posY = mouseY + 15;

  if (posX + 300 > rect.width) posX = mouseX - 305;
  if (posY + 220 > rect.height) posY = mouseY - 225;

  card.style.left = `${Math.max(10, posX)}px`;
  card.style.top = `${Math.max(10, posY)}px`;
}

// Live Search Input Handler
function handleExplorerSearchInput(val) {
  const dropdown = document.getElementById("explorer-search-dropdown");
  if (!dropdown) return;

  const query = val.trim().toLowerCase();
  explorerState.searchQuery = query;

  if (!query || query.length < 2) {
    dropdown.classList.remove("active");
    return;
  }

  // Real data matching across display name, original name, category, folder, subcategory, tags
  const matches = explorerState.rawNodes.filter(n => {
    const label = (n.label || "").toLowerCase();
    const details = n.details || {};
    const cat = (details.category || "").toLowerCase();
    const folder = (details.folder_name || "").toLowerCase();
    const orig = (details.original_name || "").toLowerCase();
    const subcat = (details.subcategory || "").toLowerCase();
    const tagNames = (details.tags || []).map(t => t.name.toLowerCase()).join(" ");

    return label.includes(query) || orig.includes(query) || cat.includes(query) || folder.includes(query) || subcat.includes(query) || tagNames.includes(query);
  });

  if (matches.length === 0) {
    dropdown.innerHTML = `<div class="autocomplete-item" style="color:var(--text-muted);">No graph nodes match "${escapeHtml(val)}"</div>`;
    dropdown.classList.add("active");
    return;
  }

  dropdown.innerHTML = matches.slice(0, 10).map(m => `
    <div class="autocomplete-item" onclick="selectExplorerSearchMatch('${m.id}')">
      <span>${m.type === "Document" ? "📄" : m.type === "Folder" ? "📁" : m.type === "Category" ? "🏷️" : "🔖"}</span>
      <strong>${escapeHtml(m.label)}</strong>
      <span style="font-size:11px; color:var(--text-muted); margin-left:auto;">${escapeHtml(m.type)}</span>
    </div>
  `).join("");
  dropdown.classList.add("active");
}

function selectExplorerSearchMatch(nodeId) {
  const dropdown = document.getElementById("explorer-search-dropdown");
  if (dropdown) dropdown.classList.remove("active");

  const node = explorerState.nodeMap[nodeId];
  if (!node) return;

  explorerState.selectedNodeId = nodeId;
  explorerState.selectedEdge = null;
  toggleExplorerSidePanel(true);
  applyExplorerFilters();
  explorerFocusSelected();
  renderExplorerSidePanelForNode(node);
}

function toggleExplorerSidePanel(open) {
  const panel = document.getElementById("explorer-side-panel");
  const resizer = document.getElementById("explorer-panel-resizer");
  if (!panel) return;

  explorerState.isSidePanelOpen = open;

  if (open) {
    panel.classList.remove("collapsed");
    if (resizer) resizer.classList.remove("is-hidden");
  } else {
    panel.classList.add("collapsed");
    if (resizer) resizer.classList.add("is-hidden");
  }

  setTimeout(updateExplorerCanvasSize, 220);
}

function renderExplorerSidePanelForNode(node) {
  toggleExplorerSidePanel(true);
  const titleEl = document.getElementById("explorer-panel-title");
  const bodyEl = document.getElementById("explorer-side-panel-body");
  if (!titleEl || !bodyEl) return;

  titleEl.innerText = `${node.type}: ${node.label}`;
  const details = node.details || {};

  if (node.type === "Document") {
    const uuid = details.uuid;
    const tagHtml = (details.tags || []).map(t => `<span class="tag-pill" style="background:${t.color}">${escapeHtml(t.name)}</span>`).join(" ");

    bodyEl.innerHTML = `
      <div style="display:flex; flex-direction:column; gap:12px;">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <span class="badge badge-info">${escapeHtml((details.file_type || "FILE").toUpperCase())}</span>
          ${renderSensitivityBadge(details.sensitivity)}
        </div>

        <div class="card" style="margin-bottom:0; padding:12px; background:var(--bg-neutral);">
          <div style="font-size:12px; font-weight:700; color:var(--text-primary); margin-bottom:4px;">🧠 AI Document Summary</div>
          <div style="font-size:12.5px; color:var(--text-secondary); line-height:1.4;">
            ${escapeHtml(details.summary || "Summary processing pending or unavailable for this document.")}
          </div>
        </div>

        ${details.key_topics ? `
          <div>
            <div style="font-size:12px; font-weight:600; color:var(--text-secondary); margin-bottom:4px;">Key Topics</div>
            <div style="font-size:12px; color:var(--text-primary); font-family:monospace; background:var(--bg-neutral); padding:6px; border-radius:4px;">${escapeHtml(typeof details.key_topics === 'string' ? details.key_topics : JSON.stringify(details.key_topics))}</div>
          </div>
        ` : ""}

        <div style="display:flex; flex-direction:column; gap:6px; font-size:12.5px; border-top:1px solid var(--border-color); padding-top:10px;">
          <div><strong>Original File:</strong> ${escapeHtml(details.original_name)}</div>
          <div><strong>Category:</strong> ${escapeHtml(details.category || "Uncategorized")}</div>
          ${details.subcategory ? `<div><strong>Subcategory:</strong> ${escapeHtml(details.subcategory)}</div>` : ""}
          ${details.folder_name ? `<div><strong>Folder:</strong> 📁 ${escapeHtml(details.folder_name)}</div>` : ""}
          <div><strong>Size:</strong> ${formatBytes(details.size_bytes)}</div>
          <div><strong>Version:</strong> v${details.version_number || 1}</div>
          <div><strong>Access Lock:</strong> ${details.is_access_locked ? '🔒 Enabled' : '🔓 Unlocked'}</div>
          <div><strong>Uploaded:</strong> ${formatDate(details.uploaded_at)}</div>
        </div>

        ${tagHtml ? `<div><div style="font-size:12px; font-weight:600; color:var(--text-secondary); margin-bottom:4px;">Tags</div>${tagHtml}</div>` : ""}

        <!-- Document Action Buttons -->
        <div style="display:flex; flex-direction:column; gap:8px; border-top:1px solid var(--border-color); padding-top:12px; margin-top:4px;">
          <button class="btn btn-primary" onclick="openDocumentDetail('${uuid}')">📄 Open Document Detail</button>
          <button class="btn btn-secondary" onclick="loadExplorerDocumentTimeline('${uuid}')">📜 View History Timeline</button>
          <button class="btn btn-secondary" onclick="inspectSelectedDuplicatesWithUuid('${uuid}')">👥 Check Duplicates</button>
        </div>

        <!-- Document History Timeline Box -->
        <div id="explorer-timeline-box" style="margin-top:10px; border-top:1px solid var(--border-color); padding-top:10px;"></div>
      </div>
    `;
  } else {
    // Other node types (Folder, Category, Tag, User)
    const connectedDocs = explorerState.rawEdges.filter(e => e.source === node.id || e.target === node.id);
    bodyEl.innerHTML = `
      <div style="display:flex; flex-direction:column; gap:12px;">
        <div style="font-size:13px; color:var(--text-secondary);">
          Entity Type: <strong>${escapeHtml(node.type)}</strong>
        </div>
        <div style="font-size:13px; color:var(--text-secondary);">
          Connected Documents: <strong>${connectedDocs.length}</strong>
        </div>
        <div style="border-top:1px solid var(--border-color); padding-top:10px;">
          <div style="font-size:12px; font-weight:600; color:var(--text-secondary); margin-bottom:8px;">Associated Graph Items</div>
          <div style="display:flex; flex-direction:column; gap:6px;">
            ${connectedDocs.map(e => {
              const otherId = e.source === node.id ? e.target : e.source;
              const otherNode = explorerState.nodeMap[otherId];
              if (!otherNode) return "";
              return `
                <div class="clickable-row" onclick="selectExplorerSearchMatch('${otherNode.id}')" style="padding:6px; border-radius:4px; font-size:12px; display:flex; justify-content:space-between;">
                  <span>${otherNode.type === "Document" ? "📄" : "•"} ${escapeHtml(otherNode.label)}</span>
                  <span style="color:var(--text-muted);">${escapeHtml(e.relation)}</span>
                </div>
              `;
            }).join("")}
          </div>
        </div>
      </div>
    `;
  }
}

function renderExplorerSidePanelForEdge(edge) {
  toggleExplorerSidePanel(true);
  const titleEl = document.getElementById("explorer-panel-title");
  const bodyEl = document.getElementById("explorer-side-panel-body");
  if (!titleEl || !bodyEl) return;

  const srcNode = explorerState.nodeMap[edge.source];
  const tgtNode = explorerState.nodeMap[edge.target];

  titleEl.innerText = "Why Connected?";

  const relationLabels = {
    "belongs_to": "Folder Assignment",
    "categorized_as": "Category Classifier",
    "has_tag": "Shared Tag Label",
    "version_of": "Document Version Chain",
    "duplicate": "Duplicate Detection",
    "near_duplicate": "Near-Duplicate Similarity",
    "semantic_similar": "Semantic Content Match",
    "owns": "Owner Access",
    "shared_access": "Shared Access Permission",
    "shared_with": "Target Share Grant"
  };

  const label = relationLabels[edge.relation] || edge.relation;
  const scorePct = edge.score ? `${Math.round(edge.score * 100)}%` : "N/A";

  bodyEl.innerHTML = `
    <div style="display:flex; flex-direction:column; gap:12px;">
      <div class="card" style="margin-bottom:0; padding:12px; background:var(--bg-neutral);">
        <div style="font-size:12px; font-weight:700; color:var(--text-primary); margin-bottom:4px;">🔗 Relationship Reason</div>
        <div style="font-size:14px; font-weight:600; color:var(--primary);">${escapeHtml(label)}</div>
        <div style="font-size:12px; color:var(--text-muted); margin-top:2px;">Relation Type: <code>${escapeHtml(edge.relation)}</code></div>
      </div>

      <div style="display:flex; flex-direction:column; gap:8px; font-size:12.5px;">
        <div><strong>Source Node:</strong> ${srcNode ? escapeHtml(srcNode.label) + ' (' + srcNode.type + ')' : edge.source}</div>
        <div><strong>Target Node:</strong> ${tgtNode ? escapeHtml(tgtNode.label) + ' (' + tgtNode.type + ')' : edge.target}</div>
        ${edge.score ? `<div><strong>Similarity Score:</strong> <span class="badge badge-info">${scorePct}</span></div>` : ""}
        ${edge.extra && edge.extra.detected_by ? `<div><strong>Detection Method:</strong> ${escapeHtml(edge.extra.detected_by)}</div>` : ""}
        ${edge.extra && edge.extra.permission ? `<div><strong>Share Permission:</strong> ${escapeHtml(edge.extra.permission)}</div>` : ""}
      </div>

      ${(edge.relation === "duplicate" || edge.relation === "near_duplicate") ? `
        <div style="margin-top:8px;">
          <button class="btn btn-primary" style="width:100%;" onclick="navigateTo('duplicates')">👥 Review Duplicate Candidates</button>
        </div>
      ` : ""}
    </div>
  `;
}

// History Timeline Renderer inside Explorer Side Panel
async function loadExplorerDocumentTimeline(uuid) {
  const box = document.getElementById("explorer-timeline-box");
  if (!box) return;

  box.innerHTML = `<div class="empty-state" style="padding:10px;"><div class="spinner"></div> Loading chronological event history...</div>`;

  try {
    const historyData = await apiFetch(`/explorer/history/${uuid}`);
    const events = historyData.events || [];

    if (events.length === 0) {
      box.innerHTML = `<div class="empty-state" style="padding:10px;">No audit timeline history recorded.</div>`;
      return;
    }

    box.innerHTML = `
      <div style="font-size:12px; font-weight:700; color:var(--text-primary); margin-bottom:8px;">📜 Chronological Event History</div>
      <div class="timeline">
        ${events.map(ev => `
          <div class="timeline-item">
            <div class="timeline-date">${formatDate(ev.timestamp)}</div>
            <div class="timeline-content">
              <strong>${escapeHtml(ev.action.replaceAll('_', ' '))}</strong>
              ${ev.detail ? `<div style="font-size:11px; color:var(--text-secondary); margin-top:2px;">${escapeHtml(typeof ev.detail === 'object' ? JSON.stringify(ev.detail) : String(ev.detail))}</div>` : ""}
            </div>
          </div>
        `).join("")}
      </div>
    `;
  } catch (err) {
    box.innerHTML = `<div class="empty-state" style="padding:10px; color:var(--danger-text);">Error loading history: ${escapeHtml(err.message)}</div>`;
  }
}

function inspectSelectedDuplicatesWithUuid(uuid) {
  navigateTo("duplicates");
  setTimeout(() => {
    const select = document.getElementById("duplicate-doc-select");
    if (select) {
      select.value = uuid;
      inspectSelectedDuplicates();
    }
  }, 150);
}

// --- TRASH VIEW ---
async function loadTrashDocuments() {
  const tbody = document.getElementById("trash-tbody");
  tbody.innerHTML = `<tr><td colspan="5" class="empty-state">Loading trash...</td></tr>`;

  try {
    const items = await apiFetch("/trash");
    // INTELLIDOCS_TRASH_BADGE_REFRESH_ON_LOAD
    setSidebarCountBadge("badge-trash", Array.isArray(items) ? items.length : 0);
    if (items.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" class="empty-state">Trash is empty.</td></tr>`;
      return;
    }

    tbody.innerHTML = items.map(item => `
      <tr>
        <td>📄 <strong>${escapeHtml(item.display_name || item.original_name)}</strong></td>
        <td>${escapeHtml(item.category || 'Uncategorized')}</td>
        <td>${formatBytes(item.size_bytes)}</td>
        <td>${formatDate(item.uploaded_at)}</td>
        <td style="text-align:right;">
          <button class="btn btn-secondary btn-sm" onclick="restoreTrashDoc('${item.uuid}')">Restore</button>
          <button class="btn btn-danger btn-sm" onclick="purgeTrashDoc('${item.uuid}')">Permanently Purge</button>
        </td>
      </tr>
    `).join("");

  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="5" class="empty-state">Error: ${escapeHtml(err.message)}</td></tr>`;
  }
}

async function restoreTrashDoc(uuid) {
  try {
    await apiFetch(`/trash/${uuid}/restore`, { method: "POST" });
    showToast("Document restored from Trash.", "success");
    loadTrashDocuments();
    fetchBadges();
  } catch (err) {
    showToast("Restore failed: " + err.message, "error");
  }
}

async function purgeTrashDoc(uuid) {
  if (!confirm("PERMANENT DELETE: This will delete the physical file permanently. Continue?")) return;
  try {
    await apiFetch(`/trash/${uuid}/purge`, { method: "DELETE" });
    showToast("Document permanently deleted.", "info");
    loadTrashDocuments();
  } catch (err) {
    showToast("Purge failed: " + err.message, "error");
  }
}


// --- UTILITY FUNCTIONS ---
function formatBytes(bytes) {
  if (!bytes || bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

function formatDate(isoStr) {
  if (!isoStr) return "";
  try {
    const d = new Date(isoStr);
    return d.toLocaleDateString() + " " + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  } catch (e) {
    return isoStr;
  }
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function renderStatusBadge(status) {
  if (!status) return `<span class="badge badge-neutral">UNKNOWN</span>`;
  const s = status.toUpperCase();
  if (s === "COMPLETED" || s === "PROCESSED") return `<span class="badge badge-success">${s}</span>`;
  if (s === "PENDING" || s === "PROCESSING") return `<span class="badge badge-warning">${s}</span>`;
  return `<span class="badge badge-danger">${s}</span>`;
}

function renderSensitivityBadge(level) {
  const normalized = String(level || "public").trim().toLowerCase();
  if (normalized === "public") return `<span class="badge badge-success">Public</span>`;
  if (normalized === "internal") return `<span class="badge badge-warning">Internal</span>`;
  if (normalized === "pii" || normalized === "confidential" || normalized === "restricted") {
    return `<span class="badge badge-danger">Confidential</span>`;
  }
  return `<span class="badge badge-neutral">${escapeHtml(level || "Needs Review")}</span>`;
}

function renderTagPills(tags) {
  if (!tags || tags.length === 0) return `<span style="color:var(--text-muted); font-size:11px;">-</span>`;
  return tags.map(t => `<span class="tag-pill" style="background:${t.color}">${escapeHtml(t.name)}</span>`).join("");
}

// --- SETTINGS & SECURITY ---
async function loadSettings() {
  if (currentUser) {
    const uEl = document.getElementById("settings-acc-username");
    if (uEl) uEl.innerText = currentUser.username || "-";
    const eEl = document.getElementById("settings-acc-email");
    if (eEl) eEl.innerText = currentUser.email || "-";
    const rEl = document.getElementById("settings-acc-role");
    if (rEl) rEl.innerText = (currentUser.role || "user").toUpperCase();
  }
  loadMfaStatus();
  loadActiveSessions();
  loadNotificationSettings();
}

function switchSettingsTab(tabName) {
  const tabs = ["account", "security", "notifications"];
  tabs.forEach(t => {
    const btn = document.getElementById(`tab-btn-settings-${t}`);
    const content = document.getElementById(`settings-tab-${t}`);
    if (btn) {
      if (t === tabName) btn.classList.add("active");
      else btn.classList.remove("active");
    }
    if (content) {
      content.style.display = t === tabName ? "block" : "none";
    }
  });

  if (tabName === "security") {
    loadMfaStatus();
    loadActiveSessions();
  } else if (tabName === "notifications") {
    loadNotificationSettings();
  }
}

async function submitSettingsChangePassword(e) {
  e.preventDefault();
  const current_password = document.getElementById("settings-curr-pwd").value;
  const new_password = document.getElementById("settings-new-pwd").value;

  try {
    await apiFetch("/auth/change-password", {
      method: "POST",
      body: JSON.stringify({ current_password, new_password })
    });
    showToast("Password updated successfully!", "success");
    document.getElementById("form-settings-change-password").reset();
  } catch (err) {
    showToast(err.message || "Failed to change password", "error");
  }
}

async function loadMfaStatus() {
  try {
    const statusData = await apiFetch("/auth/mfa/status");
    const badge = document.getElementById("settings-mfa-badge");
    const btnEnable = document.getElementById("btn-mfa-enable");
    const btnDisable = document.getElementById("btn-mfa-disable");
    const btnRegen = document.getElementById("btn-mfa-regen");
    const info = document.getElementById("settings-mfa-recovery-info");
    const countEl = document.getElementById("settings-mfa-codes-count");

    if (statusData.is_enabled) {
      if (badge) {
        badge.innerText = "ENABLED";
        badge.className = "badge badge-success";
      }
      if (btnEnable) btnEnable.style.display = "none";
      if (btnDisable) btnDisable.style.display = "inline-block";
      if (btnRegen) btnRegen.style.display = "inline-block";
      if (info) info.style.display = "block";
      if (countEl) countEl.innerText = statusData.remaining_recovery_codes;
    } else {
      if (badge) {
        badge.innerText = "DISABLED";
        badge.className = "badge badge-secondary";
      }
      if (btnEnable) btnEnable.style.display = "inline-block";
      if (btnDisable) btnDisable.style.display = "none";
      if (btnRegen) btnRegen.style.display = "none";
      if (info) info.style.display = "none";
    }
  } catch (err) {
    showToast("Failed to load MFA status", "error");
  }
}

function openMfaSetupModal() {
  document.getElementById("mfa-setup-step-1").style.display = "block";
  document.getElementById("mfa-setup-step-2").style.display = "none";
  document.getElementById("mfa-setup-step-3").style.display = "none";
  document.getElementById("form-mfa-setup-init").reset();
  openModal("modal-mfa-setup");
}

async function submitMfaSetupInitiate(e) {
  e.preventDefault();
  const password = document.getElementById("mfa-setup-pwd").value;

  try {
    const res = await apiFetch("/auth/mfa/setup/initiate", {
      method: "POST",
      body: JSON.stringify({ password })
    });
    document.getElementById("mfa-qr-img").src = res.qr_code_base64;
    document.getElementById("mfa-secret-text").innerText = res.secret;
    document.getElementById("mfa-confirm-code").value = "";

    document.getElementById("mfa-setup-step-1").style.display = "none";
    document.getElementById("mfa-setup-step-2").style.display = "block";
  } catch (err) {
    showToast(err.message || "Password verification failed", "error");
  }
}

async function submitMfaSetupConfirm(e) {
  e.preventDefault();
  const code = document.getElementById("mfa-confirm-code").value.trim();

  try {
    const res = await apiFetch("/auth/mfa/setup/confirm", {
      method: "POST",
      body: JSON.stringify({ code })
    });

    const box = document.getElementById("mfa-recovery-codes-box");
    box.innerHTML = res.recovery_codes.map(c => `<div>${escapeHtml(c)}</div>`).join("");

    document.getElementById("mfa-setup-step-2").style.display = "none";
    document.getElementById("mfa-setup-step-3").style.display = "block";
    showToast("MFA enabled successfully!", "success");
    loadMfaStatus();
  } catch (err) {
    showToast(err.message || "Verification code failed", "error");
  }
}

function openMfaDisableModal() {
  document.getElementById("form-mfa-disable").reset();
  openModal("modal-mfa-disable");
}

async function submitMfaDisable(e) {
  e.preventDefault();
  const password = document.getElementById("mfa-disable-pwd").value;
  const inputCode = document.getElementById("mfa-disable-code").value.trim();

  let code = null;
  let recovery_code = null;
  if (inputCode.includes("-") || inputCode.length > 6) {
    recovery_code = inputCode;
  } else {
    code = inputCode;
  }

  try {
    await apiFetch("/auth/mfa/disable", {
      method: "POST",
      body: JSON.stringify({ password, code, recovery_code })
    });
    closeModal("modal-mfa-disable");
    showToast("MFA disabled successfully", "info");
    loadMfaStatus();
    loadActiveSessions();
  } catch (err) {
    showToast(err.message || "Failed to disable MFA", "error");
  }
}

function openMfaRegenModal() {
  document.getElementById("mfa-regen-form-box").style.display = "block";
  document.getElementById("mfa-regen-result-box").style.display = "none";
  document.getElementById("form-mfa-regen").reset();
  openModal("modal-mfa-regen");
}

async function submitMfaRegen(e) {
  e.preventDefault();
  const password = document.getElementById("mfa-regen-pwd").value;
  const code = document.getElementById("mfa-regen-code").value.trim();

  try {
    const res = await apiFetch("/auth/mfa/recovery-codes/regenerate", {
      method: "POST",
      body: JSON.stringify({ password, code })
    });

    const box = document.getElementById("mfa-new-recovery-codes-box");
    box.innerHTML = res.recovery_codes.map(c => `<div>${escapeHtml(c)}</div>`).join("");

    document.getElementById("mfa-regen-form-box").style.display = "none";
    document.getElementById("mfa-regen-result-box").style.display = "block";
    showToast("New recovery codes generated!", "success");
    loadMfaStatus();
  } catch (err) {
    showToast(err.message || "Regeneration failed", "error");
  }
}

async function loadActiveSessions() {
  try {
    const sessions = await apiFetch("/auth/sessions");
    const tbody = document.getElementById("active-sessions-tbody");
    if (!tbody) return;

    if (!sessions || sessions.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" class="empty-state">No active sessions found</td></tr>`;
      return;
    }

    tbody.innerHTML = sessions.map(s => {
      let issuedStr = s.issued_at;
      try { issuedStr = new Date(s.issued_at).toLocaleString(); } catch(e){}
      let expiresStr = s.expires_at;
      try { expiresStr = new Date(s.expires_at).toLocaleString(); } catch(e){}

      return `
        <tr>
          <td><strong>${escapeHtml(s.ip_address || "Unknown IP")}</strong></td>
          <td>${escapeHtml(issuedStr)}</td>
          <td>${escapeHtml(expiresStr)}</td>
          <td>
            ${s.is_current ? `<span class="badge badge-success">CURRENT SESSION</span>` : `<span class="badge badge-secondary">ACTIVE</span>`}
          </td>
          <td style="text-align: right;">
            ${s.is_current ? `<span style="font-size: 11px; color: var(--text-muted);">(This device)</span>` : `<button class="btn btn-danger btn-sm" onclick="revokeSession('${escapeHtml(s.jti)}')">Revoke Session</button>`}
          </td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    showToast("Failed to load active sessions", "error");
  }
}

async function revokeSession(jti) {
  try {
    await apiFetch(`/auth/sessions/${jti}/revoke`, { method: "POST" });
    showToast("Session revoked successfully!", "success");
    loadActiveSessions();
  } catch (err) {
    showToast(err.message || "Failed to revoke session", "error");
  }
}

async function loadNotificationSettings() {
  try {
    const s = await apiFetch("/notifications/settings");
    document.getElementById("notif-email").checked = s.email_notifications;
    document.getElementById("notif-inapp").checked = s.in_app_notifications;
    document.getElementById("notif-suggestions").checked = s.suggestion_alerts;
    document.getElementById("notif-duplicates").checked = s.duplicate_alerts;
    document.getElementById("notif-security").checked = s.security_alerts;
  } catch (err) {
    showToast("Failed to load notification preferences", "error");
  }
}

async function submitNotificationSettings(e) {
  e.preventDefault();
  const body = {
    email_notifications: document.getElementById("notif-email").checked,
    in_app_notifications: document.getElementById("notif-inapp").checked,
    suggestion_alerts: document.getElementById("notif-suggestions").checked,
    duplicate_alerts: document.getElementById("notif-duplicates").checked,
    security_alerts: document.getElementById("notif-security").checked
  };

  try {
    await apiFetch("/notifications/settings", {
      method: "PUT",
      body: JSON.stringify(body)
    });
    showToast("Notification preferences saved!", "success");
  } catch (err) {
    showToast(err.message || "Failed to save preferences", "error");
  }
}

// --- DOCUMENT SHARING & ACCESS CONTROL FRONTEND ---
let currentShareDocUuid = null;
let currentAddMemberGroupId = null;
let selectedShareRecipients = [];
let shareUserSearchDebounceTimer = null;
let currentSharedDocumentsTab = "received";
let sharedDocumentsCache = [];
let currentSharedDocumentsPage = 1;
const SHARED_DOCUMENTS_PAGE_SIZE = 4;
let currentGroupSharePickerId = null;
let currentReceivedShareKey = null;
let pendingShareActivation = null;
let pendingShareSecurityReport = null;
let lastIssuedShareKeys = [];

function resetShareModalState() {
  // Drop any previous one-time key secrets whenever this form resets.
  lastIssuedShareKeys = [];
  const issuedKeysBox = document.getElementById("issued-share-keys-list");
  if (issuedKeysBox) issuedKeysBox.innerHTML = "";
  selectedShareRecipients = [];
  const searchInput = document.getElementById("share-user-search-input");
  if (searchInput) searchInput.value = "";
  const dropdown = document.getElementById("share-user-search-dropdown");
  if (dropdown) {
    dropdown.innerHTML = "";
    dropdown.style.display = "none";
  }
  const protectWithKey = document.getElementById("share-protect-with-key");
  if (protectWithKey) protectWithKey.checked = false;
  renderSelectedShareRecipients();
}

async function openShareModal(uuid) {
  currentShareDocUuid = uuid || currentDetailUuid;
  if (!currentShareDocUuid) return;

  resetShareModalState();
  openModal("modal-share");
  switchShareTab("users");

  // Load groups for dropdown
  try {
    const groups = await apiFetch("/groups");
    const select = document.getElementById("share-group-select");
    if (select) {
      if (!groups || groups.length === 0) {
        select.innerHTML = `<option value="">No groups created yet. Create one in Groups tab.</option>`;
      } else {
        select.innerHTML = groups.map(g => `<option value="${g.id}">${escapeHtml(g.name)} (${g.member_count} members)</option>`).join("");
      }
    }
  } catch (e) {}

  // Load lock status
  loadAccessLockStatus();
}

function switchShareTab(tab) {
  const tabs = ["users", "group", "active", "lock"];
  tabs.forEach(t => {
    const content = document.getElementById(`tab-share-${t}`);
    const btn = document.getElementById(`tab-btn-share-${t}`);
    if (content) content.style.display = (t === tab) ? "block" : "none";
    if (btn) {
      if (t === tab) btn.classList.add("active");
      else btn.classList.remove("active");
    }
  });

  if (tab === "active") loadActiveShares();
  else if (tab === "lock") loadAccessLockStatus();
}

function handleShareUserSearch(val) {
  clearTimeout(shareUserSearchDebounceTimer);
  const dropdown = document.getElementById("share-user-search-dropdown");
  if (!dropdown) return;

  const query = (val || "").trim();
  if (query.length < 1) {
    dropdown.innerHTML = "";
    dropdown.style.display = "none";
    return;
  }

  shareUserSearchDebounceTimer = setTimeout(async () => {
    try {
      dropdown.innerHTML = `<div class="autocomplete-item text-muted" style="cursor:default;"><div class="spinner"></div> Searching users...</div>`;
      dropdown.style.display = "block";

      const users = await apiFetch(`/users/search?q=${encodeURIComponent(query)}`);

      // Exclude currentUser and already selected recipients
      const available = (users || []).filter(u => {
        if (currentUser && u.id === currentUser.id) return false;
        if (selectedShareRecipients.some(s => s.id === u.id || s.username.toLowerCase() === u.username.toLowerCase())) return false;
        return true;
      });

      if (available.length === 0) {
        dropdown.innerHTML = `<div class="autocomplete-item text-muted" style="cursor:default;">No matching registered users found.</div>`;
      } else {
        dropdown.innerHTML = available.map(u => `
          <div class="autocomplete-item" onclick="selectShareRecipient(${u.id}, '${escapeHtml(u.username)}', '${escapeHtml(u.email)}')">
            👤 <strong>${escapeHtml(u.username)}</strong>
            <span class="text-muted" style="font-size:11.5px; margin-left:6px;">(${escapeHtml(u.email)})</span>
          </div>
        `).join("");
      }
      dropdown.style.display = "block";
    } catch (e) {
      dropdown.innerHTML = `<div class="autocomplete-item text-muted" style="cursor:default;">Search failed.</div>`;
    }
  }, 200);
}

function selectShareRecipient(id, username, email) {
  if (currentUser && id === currentUser.id) {
    showToast("You cannot share a document with yourself.", "warning");
    return;
  }
  if (selectedShareRecipients.length >= 5) {
    showToast("You can share with up to 5 people at a time.", "warning");
    return;
  }
  if (selectedShareRecipients.some(u => u.id === id || u.username.toLowerCase() === username.toLowerCase())) {
    showToast(`User '${username}' is already selected.`, "info");
    return;
  }

  selectedShareRecipients.push({ id, username, email });

  const searchInput = document.getElementById("share-user-search-input");
  if (searchInput) searchInput.value = "";
  const dropdown = document.getElementById("share-user-search-dropdown");
  if (dropdown) {
    dropdown.innerHTML = "";
    dropdown.style.display = "none";
  }

  renderSelectedShareRecipients();
}

function removeShareRecipient(id) {
  selectedShareRecipients = selectedShareRecipients.filter(u => u.id !== id);
  renderSelectedShareRecipients();
}

function renderSelectedShareRecipients() {
  const box = document.getElementById("share-selected-recipients-box");
  const countEl = document.getElementById("share-recipient-count");
  const submitBtn = document.getElementById("btn-submit-share-users");

  if (countEl) {
    countEl.innerText = `Selected: ${selectedShareRecipients.length}/5`;
  }

  if (box) {
    if (selectedShareRecipients.length === 0) {
      box.innerHTML = `<span class="text-muted" style="font-size:12px; padding:4px;" id="share-recipients-placeholder">No recipients selected yet. Search and select users above.</span>`;
    } else {
      box.innerHTML = selectedShareRecipients.map(u => `
        <span class="tag-pill" style="background:#eef2ff; color:var(--primary); font-size:12.5px; padding:4px 10px; border-radius:14px; display:inline-flex; align-items:center; gap:6px; border:1px solid #c7d2fe;">
          👤 <strong>${escapeHtml(u.username)}</strong>
          <span style="cursor:pointer; font-weight:bold; color:var(--text-muted);" onclick="removeShareRecipient(${u.id})" title="Remove recipient">&times;</span>
        </span>
      `).join("");
    }
  }

  if (submitBtn) {
    submitBtn.disabled = (selectedShareRecipients.length === 0 || selectedShareRecipients.length > 5);
  }
}

async function handleShareSubmit(e) {
  e.preventDefault();
  if (selectedShareRecipients.length === 0) {
    showToast("Please select at least one recipient to share with.", "warning");
    return;
  }

  if (selectedShareRecipients.length > 5) {
    showToast("You can share with up to 5 people at a time.", "warning");
    return;
  }

  const permission = document.getElementById("share-permission-select").value;
  const protectWithKey = !!document.getElementById("share-protect-with-key")?.checked;
  const submitBtn = document.getElementById("btn-submit-share-users");
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.innerText = "Sharing Document...";
  }

  const targetUsers = selectedShareRecipients.map(u => u.username);

  try {
    const createdShares = await apiFetch(`/documents/${currentShareDocUuid}/shares`, {
      method: "POST",
      body: JSON.stringify({
        target_users: targetUsers,
        permission: permission,
        protect_with_key: protectWithKey
      })
    });

    showToast(`Document shared with ${targetUsers.length} recipient(s) (${permission})!`, "success");
    resetShareModalState();
    switchShareTab("active");
    if (protectWithKey) {
      lastIssuedShareKeys = (createdShares || []).filter(s => !!s.share_key).map(s => ({
        username: s.target_username || "Recipient",
        email: s.target_email || "",
        key: s.share_key
      }));
      renderIssuedShareKeys();
      if (lastIssuedShareKeys.length) openModal("modal-share-key-issued");
    }
    if (currentView === "groups") loadSharedDocuments();
  } catch (err) {
    showToast(err.message || "Failed to share document", "error");
  } finally {
    if (submitBtn) {
      submitBtn.innerText = "Share Document";
      renderSelectedShareRecipients();
    }
  }
}

async function handleGroupShareSubmit(e) {
  e.preventDefault();
  const groupId = document.getElementById("share-group-select").value;
  const permission = document.getElementById("share-group-permission-select").value;

  if (!groupId) {
    showToast("Please select a group", "error");
    return;
  }

  try {
    await apiFetch(`/groups/${groupId}/shares`, {
      method: "POST",
      body: JSON.stringify({
        document_uuid: currentShareDocUuid,
        permission: permission
      })
    });

    showToast("Document shared with group successfully!", "success");
    switchShareTab("active");
  } catch (err) {
    showToast(err.message || "Failed to share with group", "error");
  }
}

async function loadActiveShares() {
  const tbody = document.getElementById("active-shares-tbody");
  if (!tbody || !currentShareDocUuid) return;
  tbody.innerHTML = `<tr><td colspan="4" class="empty-state">Loading active shares...</td></tr>`;

  try {
    const shares = await apiFetch(`/documents/${currentShareDocUuid}/shares`);
    if (!shares || shares.length === 0) {
      tbody.innerHTML = `<tr><td colspan="4" class="empty-state">No active shares for this document yet.</td></tr>`;
      return;
    }

    tbody.innerHTML = shares.map(s => `
      <tr>
        <td>
          <strong>${escapeHtml(s.target_username)}</strong>
          <div style="font-size:11px; color:var(--text-muted);">${escapeHtml(s.target_email || '')}</div>
        </td>
        <td>
          <select class="form-control" style="padding:2px 6px; font-size:11px; width:90px;" onchange="updateSharePermission(${s.id}, this.value, '${s.source}')">
            <option value="READ" ${s.permission === 'READ' ? 'selected' : ''}>READ</option>
            <option value="APPEND" ${s.permission === 'APPEND' ? 'selected' : ''}>APPEND</option>
            <option value="WRITE" ${s.permission === 'WRITE' ? 'selected' : ''}>WRITE</option>
          </select>
        </td>
        <td><span class="badge ${s.source === 'group' ? 'badge-info' : 'badge-neutral'}">${s.source === 'group' ? 'Group: ' + escapeHtml(s.group_name || '') : 'Direct'}</span></td>
        <td style="text-align:right;">
          <button class="btn btn-danger btn-sm" style="padding:2px 8px; font-size:11px;" onclick="revokeShare(${s.id}, '${s.source === 'group' ? 'group' : 'direct'}')">Revoke</button>
        </td>
      </tr>
    `).join("");
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty-state">Error: ${escapeHtml(err.message)}</td></tr>`;
  }
}

async function updateSharePermission(shareId, newPermission, source) {
  try {
    if (source === "group") {
      const shares = await apiFetch(`/documents/${currentShareDocUuid}/shares`);
      const groupShare = (shares || []).find(s => s.id === shareId && s.source === "group");
      if (!groupShare) throw new Error("Group share not found");
      const groupId = groupShare.group_id || (await apiFetch("/groups")).find(g => g.name === groupShare.group_name)?.id;
      if (!groupId) throw new Error("Group not found");
      await apiFetch(`/groups/${groupId}/shares/${shareId}`, {
        method: "PUT",
        body: JSON.stringify({ permission: newPermission })
      });
    } else {
      await apiFetch(`/documents/${currentShareDocUuid}/shares/${shareId}`, {
      method: "PUT",
        body: JSON.stringify({ permission: newPermission })
      });
    }
    showToast(`Permission updated to ${newPermission}!`, "success");
    loadActiveShares();
  } catch (err) {
    showToast(err.message || "Failed to update permission", "error");
  }
}

async function revokeShare(shareId, source) {
  if (!confirm("Are you sure you want to revoke access for this user/group?")) return;
  const shareSource = source === "group" ? "group" : (source === "direct" ? "direct" : "");
  if (!shareSource) {
    showToast("Share source is missing. Refresh and try again.", "error");
    return;
  }
  try {
    await apiFetch(`/documents/${currentShareDocUuid}/shares/${shareId}?source=${encodeURIComponent(shareSource)}`, {
      method: "DELETE"
    });
    showToast("Access revoked successfully.", "success");
    loadActiveShares();
  } catch (err) {
    showToast(err.message || "Failed to revoke share", "error");
  }
}

// --- ACCESS LOCK HANDLERS ---
async function loadAccessLockStatus() {
  const box = document.getElementById("access-lock-status-box");
  const form = document.getElementById("form-enable-lock");
  const actionsBox = document.getElementById("lock-actions-box");
  if (!box || !currentShareDocUuid) return;

  try {
    const doc = await apiFetch(`/documents/${currentShareDocUuid}`);
    if (doc.is_access_locked) {
      box.innerHTML = `
        <div style="color:var(--success); font-weight:600;">🔒 Document Access Lock is ENABLED</div>
        <div style="color:var(--text-muted); font-size:12px; margin-top:2px;">Non-owner recipients must enter the secret access key to view content.</div>
      `;
      if (form) form.style.display = "none";
      if (actionsBox) actionsBox.style.display = "block";
    } else {
      box.innerHTML = `
        <div style="color:var(--text-main); font-weight:600;">🔓 Document Access Lock is DISABLED</div>
        <div style="color:var(--text-muted); font-size:12px; margin-top:2px;">Set a secret key to require an additional unlock step for shared users.</div>
      `;
      if (form) form.style.display = "block";
      if (actionsBox) actionsBox.style.display = "none";
    }
  } catch (err) {
    box.innerText = "Error loading lock status.";
  }
}

async function handleEnableAccessLock(e) {
  e.preventDefault();
  const key = document.getElementById("lock-key-input").value;
  const confirmKey = document.getElementById("lock-key-confirm-input").value;

  if (key !== confirmKey) {
    showToast("Access key and confirmation do not match.", "error");
    return;
  }

  try {
    await apiFetch(`/documents/${currentShareDocUuid}/access-lock/enable`, {
      method: "POST",
      body: JSON.stringify({ access_key: key, confirm_access_key: confirmKey })
    });

    showToast("Document Access Lock enabled successfully!", "success");
    document.getElementById("lock-key-input").value = "";
    document.getElementById("lock-key-confirm-input").value = "";
    loadAccessLockStatus();
  } catch (err) {
    showToast(err.message || "Failed to enable access lock", "error");
  }
}

async function handleChangeAccessLock(e) {
  e.preventDefault();
  const currentKey = document.getElementById("lock-current-key-input").value;
  const newKey = document.getElementById("lock-new-key-input").value;
  const confirmNewKey = document.getElementById("lock-new-key-confirm-input").value;
  const form = document.getElementById("form-change-lock");
  const submitBtn = form ? form.querySelector('button[type="submit"]') : null;

  if (newKey !== confirmNewKey) {
    showToast("New access key and confirmation do not match.", "error");
    return;
  }

  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.innerText = "Changing Key...";
  }

  try {
    await apiFetch(`/documents/${currentShareDocUuid}/access-lock/change`, {
      method: "POST",
      body: JSON.stringify({
        current_key: currentKey,
        new_key: newKey,
        confirm_new_key: confirmNewKey
      })
    });

    showToast("Access Lock key changed successfully. Previous unlock authorizations are no longer valid.", "success");
    if (form) form.reset();
    loadAccessLockStatus();
  } catch (err) {
    showToast(err.message || "Failed to change access lock key", "error");
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.innerText = "Change Access Key";
    }
  }
}

async function handleRemoveAccessLock() {
  if (!confirm("Are you sure you want to remove the Access Lock from this document?")) return;
  try {
    await apiFetch(`/documents/${currentShareDocUuid}/access-lock`, {
      method: "DELETE"
    });
    showToast("Access Lock removed.", "success");
    loadAccessLockStatus();
  } catch (err) {
    showToast(err.message || "Failed to remove access lock", "error");
  }
}

async function submitUnlockDocument(e) {
  e.preventDefault();
  const key = document.getElementById("unlock-key-input").value;
  if (!key) return;

  try {
    const res = await apiFetch(`/documents/${currentDetailUuid}/access-lock/unlock`, {
      method: "POST",
      body: JSON.stringify({ access_key: key })
    });

    if (res.lock_token) {
      lockTokens[currentDetailUuid] = res.lock_token;
    }

    closeModal("modal-access-lock-unlock");
    document.getElementById("unlock-key-input").value = "";
    if (pendingShareActivation && pendingShareActivation.documentUuid === currentDetailUuid) {
      showToast("Access Lock verified. Review the security report to activate this share.", "success");
      await showReceivedShareSecurityReport();
      return;
    }
    showToast("Document unlocked!", "success");
    openDocumentDetail(currentDetailUuid);
  } catch (err) {
    showToast(err.message || "Incorrect access key", "error");
  }
}

// --- SHARED DOCUMENTS INBOX / SENT VIEW ---
function setSharedDocumentsTab(tab) {
  if (!['received', 'sent'].includes(tab)) return;
  currentSharedDocumentsTab = tab;
  currentSharedDocumentsPage = 1;
  const search = document.getElementById('shared-documents-search');
  if (search) search.value = '';
  const receivedButton = document.getElementById('shared-doc-tab-received');
  const sentButton = document.getElementById('shared-doc-tab-sent');
  if (receivedButton) {
    receivedButton.classList.toggle('btn-primary', tab === 'received');
    receivedButton.classList.toggle('btn-secondary', tab !== 'received');
    receivedButton.setAttribute('aria-selected', tab === 'received' ? 'true' : 'false');
  }
  if (sentButton) {
    sentButton.classList.toggle('btn-primary', tab === 'sent');
    sentButton.classList.toggle('btn-secondary', tab !== 'sent');
    sentButton.setAttribute('aria-selected', tab === 'sent' ? 'true' : 'false');
  }
  loadSharedDocuments();
}

function handleSharedDocumentsSearch(value) {
  currentSharedDocumentsPage = 1;
  renderSharedDocumentsList();
}

function changeSharedDocumentsPage(delta) {
  currentSharedDocumentsPage = Math.max(1, currentSharedDocumentsPage + Number(delta || 0));
  renderSharedDocumentsList();
}

function sharedSecurityLabel(item) {
  const status = String(item.security_status || 'NOT_ASSESSED').toUpperCase();
  const labels = {
    PASSED: 'Upload checks passed',
    LIMITED: 'Limited checks',
    QUARANTINED: 'Quarantined',
    BLOCKED: 'Blocked',
    REVIEW: 'Review required',
    NOT_ASSESSED: 'Not assessed'
  };
  const safeStatus = ['PASSED', 'LIMITED', 'QUARANTINED', 'BLOCKED', 'REVIEW', 'NOT_ASSESSED'].includes(status) ? status : 'REVIEW';
  const detail = item.security_scanner_status ? ` · scanner ${String(item.security_scanner_status).toLowerCase()}` : '';
  return `<span class="shared-security-badge shared-security-${safeStatus.toLowerCase()}" title="Status from the source document upload assessment">${labels[safeStatus]}${escapeHtml(detail)}</span>`;
}

function renderSharedDocumentCard(item, tab) {
  const isReceived = tab === 'received';
  const isGroup = item.source === 'group';
  const actor = isReceived
    ? `From ${escapeHtml(item.owner_username || 'Unknown sender')}`
    : (isGroup ? `Shared with group ${escapeHtml(item.group_name || item.target_username || 'Unknown')}` : `Shared with ${escapeHtml(item.target_username || 'Unknown recipient')}`);
  const sourceLabel = isGroup ? `Group · ${escapeHtml(item.group_name || 'Unknown group')}` : 'Direct share';
  const keyRequired = !isGroup && !!item.share_key_required;
  const keyVerified = !!item.share_key_verified;
  const lockLine = item.access_locked ? '<span class="shared-protection-pill">🔒 Access Lock enabled</span>' : '';
  const shareKeyLine = keyRequired
    ? `<span class="shared-protection-pill">${keyVerified ? '🔑 Share Key verified' : (isReceived ? '🔑 Share Key required' : '🔑 Share Key pending recipient verification')}</span>`
    : '';
  const dateLabel = item.updated_at || item.created_at || '';
  const dateText = dateLabel ? escapeHtml(formatDate(dateLabel)) : 'Date unavailable';
  const permission = escapeHtml(String(item.permission || 'READ').toUpperCase());
  let actions = '';
  if (isReceived) {
    if (!item.access_activated) {
      actions = `<button type="button" class="btn btn-primary btn-sm" onclick="beginReceivedShareActivation('${escapeHtml(item.document_uuid)}', ${Number(item.id)}, '${isGroup ? 'group' : 'direct'}', ${!!item.access_locked}, ${keyRequired}, ${keyVerified})">Review &amp; Activate</button>`;
    } else if (keyRequired && !keyVerified) {
      actions = `<button type="button" class="btn btn-primary btn-sm" onclick="openReceivedShareKeyModal('${escapeHtml(item.document_uuid)}', ${Number(item.id)})">Verify Share Key</button>`;
    } else {
      actions = `<button type="button" class="btn btn-primary btn-sm" onclick="openSharedReceivedDocument('${escapeHtml(item.document_uuid)}')">${item.access_locked ? '🔓 Unlock &amp; Open' : 'Open Document'}</button>`;
    }
  } else {
    actions = `<button type="button" class="btn btn-secondary btn-sm" onclick="changeSharedSharePermission('${escapeHtml(item.document_uuid)}', ${Number(item.id)}, '${isGroup ? 'group' : 'direct'}', ${Number(item.group_id || 0)}, '${permission}')">Change Permission</button>
      <button type="button" class="btn btn-secondary btn-sm" onclick="manageSharedDocumentAccess('${escapeHtml(item.document_uuid)}')">Manage Access</button>
      <button type="button" class="btn btn-danger btn-sm" onclick="revokeSharedDocument('${escapeHtml(item.document_uuid)}', ${Number(item.id)}, '${isGroup ? 'group' : 'direct'}', ${Number(item.group_id || 0)})">Revoke Share</button>`;
  }
  const keyStateText = isReceived && !item.access_activated
    ? `<p class="shared-document-warning">Pending access: review the source security assessment${keyRequired && !keyVerified ? ', verify the recipient-specific Share Key' : ''}${item.access_locked ? ', and unlock Access Lock' : ''} before this document appears in your Documents and Explorer Graph.</p>`
    : (isReceived && keyRequired && !keyVerified
      ? '<p class="shared-document-warning">The Share Key must be re-verified before this document can be opened.</p>'
      : '');
  // Security assessment details belong to the recipient's review flow, not the sender's Sent list.
  const securityFacts = isReceived && item.security_status && item.security_status !== 'NOT_ASSESSED'
    ? `<p class="shared-security-facts">${item.security_risk_level ? `Risk: ${escapeHtml(item.security_risk_level)}` : ''}${item.security_confidence ? ` · Confidence: ${escapeHtml(item.security_confidence)}` : ''}${item.security_assessed_at ? ` · Assessed: ${escapeHtml(formatDate(item.security_assessed_at))}` : ''}</p>`
    : '';
  const assessmentWarning = !isReceived ? '' : ((!item.security_status || item.security_status === 'NOT_ASSESSED')
    ? '<p class="shared-document-warning">No linked upload security assessment was found. Do not treat this as a clean scan.</p>'
    : (item.security_status === 'LIMITED'
      ? '<p class="shared-document-warning">The malware scanner was unavailable or partial; only limited checks are recorded.</p>'
      : ''));
  return `
    <article class="shared-document-card">
      <div class="shared-document-card-top">
        <div class="shared-document-title-wrap">
          <h4>📄 ${escapeHtml(item.document_name || 'Untitled document')}</h4>
          <p>${actor}</p>
        </div>
        ${isReceived ? sharedSecurityLabel(item) : '<span class="shared-security-badge" title="Share status. Security review is shown to the recipient.">Shared</span>'}
      </div>
      <div class="shared-document-metadata">
        <span><strong>Permission:</strong> ${permission}</span>
        <span><strong>Route:</strong> ${sourceLabel}</span>
        <span><strong>Updated:</strong> ${dateText}</span>
      </div>
      <div class="shared-document-protections">${lockLine}${shareKeyLine}</div>
      ${keyStateText}
      ${assessmentWarning}
      ${securityFacts}
      <div class="shared-document-actions">${actions}</div>
    </article>`;
}

function renderSharedDocumentsList() {
  const container = document.getElementById('shared-documents-list-container');
  const count = document.getElementById('shared-documents-count');
  const pager = document.getElementById('shared-documents-pagination');
  const search = document.getElementById('shared-documents-search');
  if (!container) return;
  const tab = currentSharedDocumentsTab === 'sent' ? 'sent' : 'received';
  const allItems = Array.isArray(sharedDocumentsCache) ? sharedDocumentsCache : [];
  const query = String(search ? search.value : '').trim().toLowerCase();
  const items = allItems.filter(item => {
    if (!query) return true;
    const fields = [item.document_name, item.owner_username, item.target_username, item.target_email, item.group_name, item.permission, item.source];
    return fields.some(value => String(value || '').toLowerCase().includes(query));
  });
  if (count) count.textContent = `${items.length} ${items.length === 1 ? 'document' : 'documents'}`;
  if (!allItems.length) {
    container.innerHTML = tab === 'received'
      ? '<div class="empty-state"><p>No documents have been shared with you yet.</p><small>Documents shared directly with you or with one of your groups will appear here.</small></div>'
      : '<div class="empty-state"><p>0 shared documents.</p><small>When you share a document with a person or group, it will appear here. You can revoke access at any time.</small></div>';
    if (pager) pager.innerHTML = '';
    return;
  }
  if (!items.length) {
    container.innerHTML = '<div class="empty-state"><p>No matching documents.</p><small>Try another search term or clear the search box.</small></div>';
    if (pager) pager.innerHTML = '';
    return;
  }
  const pageCount = Math.max(1, Math.ceil(items.length / SHARED_DOCUMENTS_PAGE_SIZE));
  currentSharedDocumentsPage = Math.min(Math.max(1, currentSharedDocumentsPage), pageCount);
  const startIndex = (currentSharedDocumentsPage - 1) * SHARED_DOCUMENTS_PAGE_SIZE;
  const pageItems = items.slice(startIndex, startIndex + SHARED_DOCUMENTS_PAGE_SIZE);
  container.innerHTML = pageItems.map(item => renderSharedDocumentCard(item, tab)).join('');
  if (pager) {
    pager.innerHTML = pageCount > 1 ? `
      <span>Showing ${startIndex + 1}–${Math.min(startIndex + pageItems.length, items.length)} of ${items.length}</span>
      <div class="shared-documents-page-actions">
        <button type="button" class="btn btn-secondary btn-sm" onclick="changeSharedDocumentsPage(-1)" ${currentSharedDocumentsPage <= 1 ? 'disabled' : ''}>Previous</button>
        <span>Page ${currentSharedDocumentsPage} of ${pageCount}</span>
        <button type="button" class="btn btn-secondary btn-sm" onclick="changeSharedDocumentsPage(1)" ${currentSharedDocumentsPage >= pageCount ? 'disabled' : ''}>Next</button>
      </div>` : `<span>Showing ${items.length} ${items.length === 1 ? 'document' : 'documents'}</span>`;
  }
}

async function loadSharedDocuments() {
  const container = document.getElementById('shared-documents-list-container');
  if (!container) return;
  const tab = currentSharedDocumentsTab === 'sent' ? 'sent' : 'received';
  container.innerHTML = '<div class="empty-state"><div class="spinner"></div> Loading shared documents...</div>';
  try {
    const items = await apiFetch(`/shares/${tab}`);
    if (tab !== currentSharedDocumentsTab) return;
    sharedDocumentsCache = Array.isArray(items) ? items : [];
    // INTELLIDOCS_RECEIVED_BADGE_REFRESH_ON_LOAD
    if (tab === 'received') {
      setSidebarCountBadge("badge-shared-received", countUniqueReceivedDocuments(sharedDocumentsCache));
    }
    currentSharedDocumentsPage = 1;
    renderSharedDocumentsList();
  } catch (err) {
    if (tab !== currentSharedDocumentsTab) return;
    sharedDocumentsCache = [];
    container.innerHTML = `<div class="empty-state shared-documents-error">Could not load ${tab === 'received' ? 'received' : 'sent'} shares: ${escapeHtml(err.message || 'Unknown error')}</div>`;
    const pager = document.getElementById('shared-documents-pagination');
    if (pager) pager.innerHTML = '';
  }
}

function openSharedReceivedDocument(documentUuid) {
  // Only activated shares can reach this content-opening path.
  openDocumentDetail(documentUuid);
}

function beginReceivedShareActivation(documentUuid, shareId, source, accessLocked, keyRequired, keyVerified) {
  pendingShareActivation = {
    documentUuid: String(documentUuid),
    shareId: Number(shareId),
    source: source === 'group' ? 'group' : 'direct',
    accessLocked: !!accessLocked,
    keyRequired: !!keyRequired,
    keyVerified: !!keyVerified
  };
  pendingShareSecurityReport = null;
  currentDetailUuid = String(documentUuid);

  if (pendingShareActivation.source === 'direct' && pendingShareActivation.keyRequired && !pendingShareActivation.keyVerified) {
    openReceivedShareKeyModal(documentUuid, shareId);
    showToast('Verify the sender-provided Share Key first.', 'info');
    return;
  }
  continueReceivedShareActivation();
}

async function continueReceivedShareActivation() {
  if (!pendingShareActivation) return;
  currentDetailUuid = pendingShareActivation.documentUuid;
  // Load the sanitized security report first. Access Lock protects document content,
  // not the recipient-only security metadata needed to make an informed decision.
  // The activation button remains disabled until a valid unlock token is available.
  await showReceivedShareSecurityReport();
}

function promptShareActivationUnlock() {
  if (!pendingShareActivation) return;
  currentDetailUuid = pendingShareActivation.documentUuid;
  const input = document.getElementById('unlock-key-input');
  if (input) input.value = '';
  closeModal('modal-share-security-review');
  openModal('modal-access-lock-unlock');
  if (input) setTimeout(() => input.focus(), 0);
}

async function showReceivedShareSecurityReport() {
  // V2: security report remains readable when optional refresh is blocked by Access Lock.
  if (!pendingShareActivation) return;
  currentDetailUuid = pendingShareActivation.documentUuid;
  const content = document.getElementById('share-security-report-content');
  const statusMessage = document.getElementById('share-activation-state-message');
  const submitButton = document.getElementById('received-share-activate-submit');
  const ackWrap = document.getElementById('share-limited-ack-wrap');
  const ackCheckbox = document.getElementById('share-limited-ack');
  if (content) content.innerHTML = '<div class="empty-state"><div class="spinner"></div> Loading source security assessment…</div>';
  if (statusMessage) statusMessage.textContent = '';
  if (submitButton) submitButton.disabled = true;
  if (ackWrap) ackWrap.style.display = 'none';
  if (ackCheckbox) ackCheckbox.checked = false;
  openModal('modal-share-security-review');
  let securityRefreshWarning = '';
  try {
    const p = pendingShareActivation;
    // The stored security report is metadata-only. Access Lock must still gate
    // content access and activation, but it must not hide the assessment itself.
    // Refresh is best-effort: an Access Lock response or scanner outage must not
    // prevent the recipient from seeing the existing, clearly-labelled report.
    try {
      await apiFetch(`/shares/${encodeURIComponent(p.source)}/${p.shareId}/refresh-security`, { method: 'POST' });
    } catch (refreshErr) {
      const refreshMessage = String((refreshErr && refreshErr.message) || 'Security refresh failed');
      // Never use a refresh failure to bypass a recipient Share Key or login gate.
      if (/share key|not authorized|unauthorized|authentication required|not authenticated|active received share|recipient-specific/i.test(refreshMessage)) {
        throw refreshErr;
      }
      securityRefreshWarning = refreshMessage.slice(0, 240);
    }

    // This endpoint returns only the sanitized source assessment, not file contents.
    // Forward an existing lock token for compatibility, but report visibility does not depend on it.
    const lockToken = lockTokens[p.documentUuid];
const lockQuery = lockToken ? `?lock_token=${encodeURIComponent(lockToken)}` : '';
const report = await apiFetch(`/shares/${encodeURIComponent(p.source)}/${p.shareId}/security-report${lockQuery}`);
    pendingShareSecurityReport = report;
    // Refresh the inbox status after loading the report; a list refresh is not a gate.
    try { await loadSharedDocuments(); } catch (_) { /* keep the loaded report visible */ }
    // The lock may have been enabled/rotated since the Received list was rendered.
    pendingShareActivation.accessLocked = !!report.access_locked;
    const unlockButton = document.getElementById('received-share-unlock-for-activation');
    if (unlockButton) unlockButton.style.display = (report.access_locked && !lockTokens[p.documentUuid]) ? '' : 'none';
    const facts = [
      ['Security status', report.security_status || 'NOT_ASSESSED'],
      ['Verdict', report.security_verdict || 'Unknown'],
      ['Quarantine status', report.security_quarantine_status || 'Unknown'],
      ['Risk', report.security_risk_level || 'Unknown'],
      ['Risk score', report.security_risk_score == null ? 'Unknown' : `${report.security_risk_score}/100`],
      ['Scanner', report.security_scanner_status || 'Unavailable / unknown'],
      ['Confidence', report.security_confidence == null ? 'Unknown' : report.security_confidence],
      ['Data sensitivity', report.data_sensitivity || 'Unknown'],
      ['PII detected', report.pii_detected ? 'Yes — sensitive details are not shown here' : 'No'],
      ['Assessment date', report.security_assessed_at ? formatDate(report.security_assessed_at) : 'Unavailable']
    ];
    const checkStates = report.check_states && typeof report.check_states === 'object' ? report.check_states : {};
    const scannerDiagnostic = typeof checkStates.malware_scan_detail === 'string' ? checkStates.malware_scan_detail : '';
    const checks = Object.entries(checkStates)
      .filter(([name]) => name !== 'malware_scan_detail')
      .map(([name, value]) => `<li><strong>${escapeHtml(name.replace(/_/g, ' '))}</strong>: ${escapeHtml(typeof value === 'string' ? value : JSON.stringify(value))}</li>`).join('')
      + (scannerDiagnostic ? `<li role="note"><strong>Malware scanner diagnostic:</strong> ${escapeHtml(scannerDiagnostic)}</li>` : '');
    const scannerState = String(report.security_scanner_status || '').toUpperCase();
    const scannerDetail = report.security_scanner_detail
      ? `<p class="shared-document-warning"><strong>Scanner detail:</strong> ${escapeHtml(report.security_scanner_detail)}</p>`
      : '';
    const findings = Array.isArray(report.findings) && report.findings.length
      ? `<ul class="share-security-findings">${report.findings.map(f => `<li><strong>${escapeHtml(f.severity || 'INFO')}</strong> · ${escapeHtml(f.check_name || 'Security check')}: ${escapeHtml(f.title || 'Finding')}</li>`).join('')}</ul>`
      : (scannerState === 'AVAILABLE'
        ? '<p>No findings were recorded by the completed source assessment.</p>'
        : '<p>No findings were recorded by the checks that completed. The malware scan did not complete, so this is not a malware-free result.</p>');
    if (content) {
      content.innerHTML = `
        <h4>${escapeHtml(report.document_name || 'Shared document')}</h4>
        <p class="shared-document-warning">This share grants access to the original stored document; it does not create a second physical copy.</p>
        <p><strong>Permission being granted:</strong> ${escapeHtml(String(report.permission || 'READ').toUpperCase())}</p>
        <div class="share-security-facts-grid">${facts.map(([label, value]) => `<div class="share-security-fact"><strong>${escapeHtml(label)}</strong><span>${escapeHtml(value)}</span></div>`).join('')}</div>
        ${scannerDetail}
        <h4>Checks recorded</h4>${checks ? `<ul class="share-security-checks">${checks}</ul>` : '<p>No check-state summary is available.</p>'}
        <h4>Finding summary</h4>${findings}
        <h4>Recommended action</h4><p>${escapeHtml(report.recommended_action || 'Review the assessment before activating access.')}</p>`;
    }
    if (ackWrap) ackWrap.style.display = report.limited_checks_ack_required ? 'block' : 'none';
    if (statusMessage) {
      if (!report.can_activate) statusMessage.textContent = `Activation blocked: security status is ${report.security_status || 'NOT_ASSESSED'}. Ask the owner to resolve the assessment before sharing.`;
      else if (report.access_locked && !lockTokens[p.documentUuid]) statusMessage.textContent = 'Security report loaded. Access Lock still protects the document; verify the owner-provided Access Key before activating and opening it.';
      else if (report.limited_checks_ack_required) statusMessage.textContent = 'The scanner was unavailable or partial. You must explicitly acknowledge the limitation before activation.';
      else statusMessage.textContent = 'Review complete. Activate only if you trust the sender and accept the reported assessment.';
    }
    if (securityRefreshWarning && statusMessage) {
      const refreshNote = `Stored assessment displayed, but automatic reassessment did not complete: ${securityRefreshWarning}. Review the status above; a failed refresh is not a clean scan result.`;
      statusMessage.textContent = `${statusMessage.textContent} ${refreshNote}`.trim();
    }
    updateShareActivationButtonState();
  } catch (err) {
    pendingShareSecurityReport = null;
    if (content) content.innerHTML = `<p class="shared-document-warning">Could not load the security assessment: ${escapeHtml(err.message || 'Unknown error')}</p>`;
    if (statusMessage) statusMessage.textContent = 'Access remains pending. The report must load successfully before activation.';
    if (submitButton) submitButton.disabled = true;
  }
}

function updateShareActivationButtonState() {
  const button = document.getElementById('received-share-activate-submit');
  const unlockButton = document.getElementById('received-share-unlock-for-activation');
  const ackCheckbox = document.getElementById('share-limited-ack');
  if (!button) return;
  const report = pendingShareSecurityReport;
  const documentUuid = pendingShareActivation && pendingShareActivation.documentUuid;
  const lockRequired = !!(pendingShareActivation && pendingShareActivation.accessLocked) || !!(report && report.access_locked);
  const hasUnlockToken = !!(documentUuid && lockTokens[documentUuid]);
  const needsUnlock = lockRequired && !hasUnlockToken;
  if (unlockButton) unlockButton.style.display = needsUnlock ? '' : 'none';
  button.disabled = !pendingShareActivation || !report || !report.can_activate || needsUnlock ||
    (!!report.limited_checks_ack_required && !(ackCheckbox && ackCheckbox.checked));
}

async function submitReceivedShareActivation() {
  if (!pendingShareActivation || !pendingShareSecurityReport) return;
  updateShareActivationButtonState();
  const button = document.getElementById('received-share-activate-submit');
  if (button && button.disabled) return;
  if (button) { button.disabled = true; button.textContent = 'Activating…'; }
  try {
    const p = pendingShareActivation;
    const payload = {
      assessment_id: pendingShareSecurityReport.assessment_id,
      acknowledge_limited: !!(document.getElementById('share-limited-ack') && document.getElementById('share-limited-ack').checked)
    };
    const lockToken = lockTokens[p.documentUuid];
    const lockQuery = lockToken ? `?lock_token=${encodeURIComponent(lockToken)}` : '';
    await apiFetch(`/shares/${encodeURIComponent(p.source)}/${p.shareId}/activate${lockQuery}`, {
      method: 'POST', body: JSON.stringify(payload)
    });
    const uuid = p.documentUuid;
    closeModal('modal-share-security-review');
    pendingShareActivation = null;
    pendingShareSecurityReport = null;
    currentDetailUuid = uuid;
    showToast('Shared access activated. Running your personal document analysis…', 'success');
    const receiverAnalysis = { suggestions: 0, groups: 0, related: 0, failures: [] };
    let receiverDocumentId = 0;
    try {
      const activatedDocument = await apiFetch(`/documents/${encodeURIComponent(uuid)}`);
      receiverDocumentId = Number(activatedDocument && activatedDocument.id);
      if (!Number.isFinite(receiverDocumentId) || receiverDocumentId <= 0) {
        throw new Error('Activated document ID was not returned by the library API.');
      }
      try { sessionStorage.setItem('intellidocs_suggestion_focus_document_id', String(receiverDocumentId)); } catch (_) {}
      try {
        const plan = await apiFetch(`/suggestions/analyze?document_id=${encodeURIComponent(receiverDocumentId)}`, { method: 'POST' });
        receiverAnalysis.suggestions = Array.isArray(plan && plan.suggestions) ? plan.suggestions.length : 0;
      } catch (analysisError) {
        receiverAnalysis.failures.push('personal AI suggestions');
        console.warn('[Recipient analysis] Per-document suggestion analysis failed:', analysisError);
      }
      try {
        const groupRows = await apiFetch('/suggestions/analyze-groups', {
          method: 'POST', headers: getDocumentLockTokenHeaders(uuid)
        });
        receiverAnalysis.groups = Array.isArray(groupRows) ? groupRows.length : 0;
      } catch (groupError) {
        receiverAnalysis.failures.push('folder grouping');
        console.warn('[Recipient analysis] Group analysis failed:', groupError);
      }
    } catch (documentError) {
      receiverAnalysis.failures.push('document analysis setup');
      console.warn('[Recipient analysis] Could not resolve the activated library document:', documentError);
    }
    await loadSharedDocuments();
    await fetchBadges();
    await openDocumentDetail(uuid);
    // Pre-populate the Related Documents table on the detail page. This invokes the
    // existing recipient-aware duplicate/related evaluator using the active lock token.
    const relatedResult = await loadRelatedDocuments();
    receiverAnalysis.related = Array.isArray(relatedResult && relatedResult.related_documents)
      ? relatedResult.related_documents.length : 0;
    if (!relatedResult) receiverAnalysis.failures.push('duplicate/related analysis');
    if (receiverAnalysis.failures.length) {
      showToast(`Access is active, but analysis was partial (${receiverAnalysis.failures.join(', ')}). The document remains shared; open Suggestions to retry/review.`, 'warning');
    } else {
      showToast(`Receiver analysis finished: ${receiverAnalysis.suggestions} file suggestion(s), ${receiverAnalysis.groups} grouping recommendation(s), and ${receiverAnalysis.related} related/duplicate candidate(s).`, 'success');
    }
    // Show the newly focused personal recommendations immediately instead of
    // leaving the recipient on the document overview with no visible suggestions.
    navigateTo('suggestions');
    // INTELLIDOCS_RECIPIENT_ANALYSIS_PIPELINE_V1
  } catch (err) {
    const message = String((err && err.message) || 'Could not activate shared access');
    if (/access lock is enabled|unlock the document before activating/i.test(message) && pendingShareActivation) {
      const uuid = pendingShareActivation.documentUuid;
      delete lockTokens[uuid]; // A previously cached token may be stale after key rotation/re-locking.
      pendingShareActivation.accessLocked = true;
      const statusMessage = document.getElementById('share-activation-state-message');
      if (statusMessage) statusMessage.textContent = 'The Access Lock key must be verified again before activation. The security report remains available.';
      showToast('Access Lock must be verified again before activating this share.', 'warning');
      promptShareActivationUnlock();
    } else {
      showToast(message, 'error');
      if (button) button.disabled = false;
    }
  } finally {
    if (button) button.textContent = 'Activate Access & Open';
    updateShareActivationButtonState();
  }
}

function cancelReceivedShareActivation() {
  closeModal('modal-share-security-review');
  pendingShareActivation = null;
  pendingShareSecurityReport = null;
  currentReceivedShareKey = null;
}

async function changeSharedSharePermission(documentUuid, shareId, source, groupId, currentPermission) {
  const allowed = ['READ', 'APPEND', 'WRITE'];
  const entered = window.prompt(
    'Choose permission: READ, APPEND, or WRITE.\nREAD = view only; APPEND = add content while preserving prior content where supported; WRITE = edit under the app\'s versioning rules.',
    String(currentPermission || 'READ').toUpperCase()
  );
  if (entered === null) return;
  const permission = String(entered).trim().toUpperCase();
  if (!allowed.includes(permission)) {
    showToast('Invalid permission. Choose READ, APPEND, or WRITE.', 'error');
    return;
  }
  if (permission === String(currentPermission || 'READ').toUpperCase()) {
    showToast('Permission is unchanged.', 'info');
    return;
  }
  try {
    if (source === 'group') {
      if (!Number(groupId)) throw new Error('Group identity is missing. Refresh and try again.');
      await apiFetch(`/groups/${Number(groupId)}/shares/${Number(shareId)}`, {
        method: 'PUT',
        body: JSON.stringify({ permission })
      });
    } else {
      await apiFetch(`/documents/${encodeURIComponent(documentUuid)}/shares/${Number(shareId)}`, {
        method: 'PUT',
        body: JSON.stringify({ permission })
      });
    }
    showToast(`Share permission changed to ${permission}.`, 'success');
    await loadSharedDocuments();
    fetchBadges();
  } catch (err) {
    showToast(err.message || 'Could not update share permission.', 'error');
  }
}

async function manageSharedDocumentAccess(documentUuid) {
  await openShareModal(documentUuid);
  switchShareTab('lock');
}

async function revokeSharedDocument(documentUuid, shareId, source, groupId) {
  const what = source === 'group' ? 'this group share' : 'this recipient share';
  if (!confirm(`Revoke ${what}? The document will remain in your library; only shared access will be removed.`)) return;
  try {
    if (source === 'group') {
      if (!Number(groupId)) throw new Error('Group identity is missing. Please refresh and try again.');
      await apiFetch(`/groups/${Number(groupId)}/shares/${Number(shareId)}`, { method: 'DELETE' });
    } else {
      await apiFetch(`/documents/${encodeURIComponent(documentUuid)}/shares/${Number(shareId)}`, { method: 'DELETE' });
    }
    showToast('Share revoked. The original document was not deleted.', 'success');
    await loadSharedDocuments();
    loadGroups();
    fetchBadges();
  } catch (err) {
    showToast(err.message || 'Could not revoke this share.', 'error');
  }
}

function openReceivedShareKeyModal(documentUuid, shareId) {
  currentReceivedShareKey = { documentUuid, shareId };
  const input = document.getElementById('received-share-key-input');
  if (input) input.value = '';
  openModal('modal-share-key-verify');
  if (input) setTimeout(() => input.focus(), 0);
}

async function submitReceivedShareKey(event) {
  event.preventDefault();
  if (!currentReceivedShareKey) return;
  const input = document.getElementById('received-share-key-input');
  const submitButton = document.getElementById('received-share-key-submit');
  const key = input ? input.value : '';
  if (!key) return;
  if (submitButton) { submitButton.disabled = true; submitButton.innerText = 'Verifying...'; }
  try {
    await apiFetch(`/documents/${encodeURIComponent(currentReceivedShareKey.documentUuid)}/shares/${currentReceivedShareKey.shareId}/verify-key`, {
      method: 'POST',
      body: JSON.stringify({ key })
    });
    const documentUuid = currentReceivedShareKey.documentUuid;
    const verifiedShareId = Number(currentReceivedShareKey.shareId);
    closeModal('modal-share-key-verify');
    currentReceivedShareKey = null;
    if (input) input.value = '';
    showToast('Share Key verified.', 'success');
    await loadSharedDocuments();
    fetchBadges();
    if (pendingShareActivation && pendingShareActivation.documentUuid === documentUuid && pendingShareActivation.shareId === verifiedShareId) {
      pendingShareActivation.keyVerified = true;
      await continueReceivedShareActivation();
    } else {
      // Preserve the existing key re-verification behavior outside the pending-activation flow.
      await openDocumentDetail(documentUuid);
    }
  } catch (err) {
    showToast(err.message || 'Share Key verification failed', 'error');
  } finally {
    if (submitButton) { submitButton.disabled = false; submitButton.innerText = 'Verify & Continue'; }
  }
}

function renderIssuedShareKeys() {
  const box = document.getElementById('issued-share-keys-list');
  if (!box) return;
  if (!lastIssuedShareKeys.length) {
    box.innerHTML = '<div class="empty-state">No Share Keys were returned by the server.</div>';
    return;
  }
  box.innerHTML = lastIssuedShareKeys.map((entry, index) => `
    <div class="issued-share-key-row">
      <div><strong>${escapeHtml(entry.username)}</strong><small>${escapeHtml(entry.email)}</small></div>
      <div class="issued-share-key-control">
        <input type="text" id="issued-share-key-${index}" class="form-control" value="${escapeHtml(entry.key)}" readonly aria-label="Share Key for ${escapeHtml(entry.username)}">
        <button type="button" class="btn btn-secondary btn-sm" onclick="copyIssuedShareKey(${index})">Copy</button>
      </div>
    </div>`).join('');
}

function closeIssuedShareKeysModal() {
  closeModal('modal-share-key-issued');
  lastIssuedShareKeys = [];
  const box = document.getElementById('issued-share-keys-list');
  if (box) box.innerHTML = '';
}

async function copyIssuedShareKey(index) {
  const entry = lastIssuedShareKeys[index];
  if (!entry || !entry.key) return;
  try {
    await navigator.clipboard.writeText(entry.key);
    showToast(`Share Key copied for ${entry.username}. Deliver it securely.`, 'success');
  } catch (err) {
    const input = document.getElementById(`issued-share-key-${index}`);
    if (input) { input.focus(); input.select(); }
    showToast('Clipboard unavailable. The key is selected; copy it manually.', 'warning');
  }
}

// --- GROUPS FRONTEND HANDLERS ---
async function loadGroups() {
  const container = document.getElementById("groups-list-container");
  if (!container) return;
  container.innerHTML = `<div class="empty-state"><div class="spinner"></div> Loading groups...</div>`;

  try {
    const groups = await apiFetch("/groups");
    if (!groups || groups.length === 0) {
      container.innerHTML = `
        <div class="empty-state" style="grid-column: 1/-1;">
          <p>No sharing groups created yet.</p>
          <button class="btn btn-primary btn-sm" onclick="openModal('modal-group-create')">+ Create Your First Group</button>
        </div>
      `;
      return;
    }

    container.innerHTML = groups.map(g => {
      const isOwner = currentUser && (g.owner_id === currentUser.id);
      const membersList = (g.members || []).map(m => `
        <li style="display:flex; justify-content:space-between; align-items:center; font-size:12.5px; padding:4px 0;">
          <span>👤 <strong>${escapeHtml(m.username)}</strong> ${m.role === 'owner' ? '<span class="badge badge-neutral">Owner</span>' : ''}</span>
          ${isOwner && m.role !== 'owner' ? `<button class="btn btn-danger btn-sm" style="padding:1px 6px; font-size:10px;" onclick="removeGroupMember(${g.id}, ${m.user_id})">Remove</button>` : ''}
        </li>
      `).join("");

      return `
        <div class="card" style="display:flex; flex-direction:column; justify-content:space-between;">
          <div>
            <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:12px;">
              <div>
                <h3 style="margin:0; font-size:16px;">${escapeHtml(g.name)}</h3>
                <span class="text-muted" style="font-size:12px;">Created by ${escapeHtml(g.owner_username)}</span>
              </div>
              <span class="badge badge-info">${g.member_count}/7 Members</span>
            </div>
            <ul style="list-style:none; padding:0; margin:0 0 16px 0; border-top:1px solid var(--border-color); padding-top:8px;">
              ${membersList}
            </ul>
          </div>
          <div class="sharing-group-actions" style="display:flex; gap:8px; justify-content:flex-end; flex-wrap:wrap; border-top:1px solid var(--border-color); padding-top:12px;">
            ${isOwner ? `<button class="btn btn-primary btn-sm" onclick="openGroupDocumentPicker(${g.id})">Share Document</button>` : ''}
            ${isOwner && g.member_count < 7 ? `<button class="btn btn-secondary btn-sm" onclick="openAddGroupMemberModal(${g.id})">+ Add Member</button>` : ''}
            ${isOwner ? `<button class="btn btn-danger btn-sm" onclick="deleteGroup(${g.id})">Delete Group</button>` : ''}
          </div>
        </div>
      `;
    }).join("");
  } catch (err) {
    container.innerHTML = `<div class="empty-state" style="grid-column: 1/-1;">Error loading groups: ${escapeHtml(err.message)}</div>`;
  }
}

let groupSharePickerDocuments = [];

async function openGroupDocumentPicker(groupId) {
  currentGroupSharePickerId = Number(groupId) || null;
  if (!currentGroupSharePickerId) return;
  const title = document.getElementById('group-share-picker-title');
  const select = document.getElementById('group-share-document-select');
  const hint = document.getElementById('group-share-picker-hint');
  const submit = document.getElementById('group-share-picker-submit');
  if (title) title.textContent = 'Share a Document with Group';
  if (select) select.innerHTML = '<option value="">Loading your documents...</option>';
  if (hint) hint.textContent = 'Select a document you own and choose the access permission.';
  if (submit) submit.disabled = true;
  openModal('modal-group-share-document');
  try {
    const [groups, docs] = await Promise.all([
      apiFetch('/groups'),
      apiFetch('/documents?limit=100&sort_by=uploaded_at&order=desc')
    ]);
    const group = (Array.isArray(groups) ? groups : []).find(g => Number(g.id) === currentGroupSharePickerId);
    if (!group) throw new Error('Group not found or no longer available.');
    if (title) title.textContent = `Share a Document with ${group.name}`;
    // Only list documents owned by the current user. Do not offer files merely shared with the user.
    groupSharePickerDocuments = (Array.isArray(docs) ? docs : []).filter(d =>
      d && d.uuid && currentUser && Number(d.owner_id) === Number(currentUser.id) && !d.is_deleted
    );
    if (!select) return;
    if (!groupSharePickerDocuments.length) {
      select.innerHTML = '<option value="">No documents you own are available</option>';
      if (hint) hint.textContent = 'Upload or select a document in your own library first. This action shares individual documents, not whole folders.';
      if (submit) submit.disabled = true;
      return;
    }
    select.innerHTML = '<option value="">Choose a document...</option>' + groupSharePickerDocuments.map(d => {
      const name = escapeHtml(d.display_name || d.original_name || 'Untitled document');
      const folder = d.folder_name ? ` · ${escapeHtml(d.folder_name)}` : '';
      return `<option value="${escapeHtml(d.uuid)}">${name}${folder}</option>`;
    }).join('');
    if (submit) submit.disabled = false;
  } catch (err) {
    if (select) select.innerHTML = '<option value="">Could not load documents</option>';
    if (hint) hint.textContent = err.message || 'Could not load your documents.';
    if (submit) submit.disabled = true;
  }
}

async function submitGroupDocumentPicker(event) {
  event.preventDefault();
  const groupId = Number(currentGroupSharePickerId) || 0;
  const select = document.getElementById('group-share-document-select');
  const submit = document.getElementById('group-share-picker-submit');
  const documentUuid = select ? select.value : '';
  const permissionEl = document.getElementById('group-share-document-permission');
  const permission = permissionEl ? permissionEl.value : 'READ';
  if (!groupId || !documentUuid) {
    showToast('Choose a document first.', 'warning');
    return;
  }
  if (submit) { submit.disabled = true; submit.textContent = 'Sharing...'; }
  try {
    await apiFetch(`/groups/${groupId}/shares`, {
      method: 'POST',
      body: JSON.stringify({ document_uuid: documentUuid, permission })
    });
    closeModal('modal-group-share-document');
    currentGroupSharePickerId = null;
    showToast('Document shared with the group.', 'success');
    setSharedDocumentsTab('sent');
    loadGroups();
  } catch (err) {
    showToast(err.message || 'Could not share this document with the group.', 'error');
  } finally {
    if (submit) { submit.disabled = false; submit.textContent = 'Share with Group'; }
  }
}

async function submitCreateGroup(e) {
  e.preventDefault();
  const name = document.getElementById("create-group-name-input").value.trim();
  const membersStr = document.getElementById("create-group-members-input").value.trim();
  const members = membersStr ? membersStr.split(",").map(s => s.trim()).filter(Boolean) : [];

  if (members.length > 6) {
    showToast("Groups can contain up to 7 members total.", "warning");
    return;
  }

  try {
    await apiFetch("/groups", {
      method: "POST",
      body: JSON.stringify({ name, member_usernames: members })
    });

    showToast(`Group '${name}' created successfully!`, "success");
    closeModal("modal-group-create");
    document.getElementById("create-group-name-input").value = "";
    document.getElementById("create-group-members-input").value = "";
    loadGroups();
  } catch (err) {
    showToast(err.message || "Failed to create group", "error");
  }
}

function openAddGroupMemberModal(groupId) {
  currentAddMemberGroupId = groupId;
  openModal("modal-group-add-member");
}

async function submitAddGroupMember(e) {
  e.preventDefault();
  const inputVal = document.getElementById("add-group-member-input").value.trim();
  if (!inputVal || !currentAddMemberGroupId) return;

  try {
    await apiFetch(`/groups/${currentAddMemberGroupId}/members`, {
      method: "POST",
      body: JSON.stringify({ username_or_email: inputVal })
    });

    showToast("Member added to group!", "success");
    closeModal("modal-group-add-member");
    document.getElementById("add-group-member-input").value = "";
    loadGroups();
  } catch (err) {
    showToast(err.message || "Failed to add member", "error");
  }
}

async function removeGroupMember(groupId, userId) {
  if (!confirm("Are you sure you want to remove this member from the group?")) return;
  try {
    await apiFetch(`/groups/${groupId}/members/${userId}`, {
      method: "DELETE"
    });
    showToast("Member removed from group.", "success");
    loadGroups();
  } catch (err) {
    showToast(err.message || "Failed to remove member", "error");
  }
}

async function deleteGroup(groupId) {
  if (!confirm("Are you sure you want to delete this group? Group-derived document access will be revoked.")) return;
  try {
    await apiFetch(`/groups/${groupId}`, {
      method: "DELETE"
    });
    showToast("Group deleted.", "success");
    loadGroups();
  } catch (err) {
    showToast(err.message || "Failed to delete group", "error");
  }
}

/* --- Explorer resizable details panel --- */
function initExplorerSidePanelResize() {
  const workspace = document.querySelector(".explorer-workspace");
  const panel = document.getElementById("explorer-side-panel");
  const resizer = document.getElementById("explorer-panel-resizer");

  if (!workspace || !panel || !resizer) return;
  if (resizer.dataset.initialized === "1") return;

  resizer.dataset.initialized = "1";

  const STORAGE_KEY = "intellidocs_explorer_panel_width";
  const MIN_WIDTH = 280;
  const MAX_WIDTH = 560;

  const getSavedWidth = () => {
    const value = Number.parseInt(localStorage.getItem(STORAGE_KEY) || "", 10);
    return Number.isFinite(value)
      ? Math.min(MAX_WIDTH, Math.max(MIN_WIDTH, value))
      : 350;
  };

  panel.style.setProperty("--explorer-side-panel-width", `${getSavedWidth()}px`);

  let dragging = false;

  const setPanelWidth = (clientX) => {
    const rect = workspace.getBoundingClientRect();
    const width = Math.round(rect.right - clientX);
    const clamped = Math.min(MAX_WIDTH, Math.max(MIN_WIDTH, width));

    panel.style.width = `${clamped}px`;
    panel.style.setProperty("--explorer-side-panel-width", `${clamped}px`);

    localStorage.setItem(STORAGE_KEY, String(clamped));

    if (typeof updateExplorerCanvasSize === "function") {
      updateExplorerCanvasSize();
    }

    if (typeof renderExplorerGraphCanvas === "function") {
      requestAnimationFrame(() => {
        try {
          renderExplorerGraphCanvas();
        } catch (_) {}
      });
    }
  };

  const stopDragging = () => {
    if (!dragging) return;

    dragging = false;
    resizer.classList.remove("is-dragging");
    document.body.style.cursor = "";
    document.body.style.userSelect = "";
  };

  resizer.addEventListener("pointerdown", (event) => {
    if (window.innerWidth <= 900) return;
    if (panel.classList.contains("collapsed")) return;

    dragging = true;
    resizer.classList.add("is-dragging");
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";

    event.preventDefault();
    event.stopPropagation();
  });

  document.addEventListener("pointermove", (event) => {
    if (!dragging) return;
    setPanelWidth(event.clientX);
    event.preventDefault();
  }, { passive: false });

  document.addEventListener("pointerup", stopDragging);
  document.addEventListener("pointercancel", stopDragging);
  window.addEventListener("blur", stopDragging);

  if (panel.classList.contains("collapsed")) {
    resizer.classList.add("is-hidden");
  } else {
    resizer.classList.remove("is-hidden");
  }
}

function ensureExplorerSidePanelResize() {
  if (typeof initExplorerSidePanelResize === "function") {
    initExplorerSidePanelResize();
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", ensureExplorerSidePanelResize);
} else {
  ensureExplorerSidePanelResize();
}
/* --- Full IntelliDocs sidebar resize --- */
function initSidebarResize() {
  const appLayout = document.querySelector(".app-layout");
  const sidebar = document.querySelector(".sidebar");
  const resizer = document.getElementById("sidebar-resizer");

  if (!appLayout || !sidebar || !resizer) return;
  if (resizer.dataset.initialized === "1") return;

  resizer.dataset.initialized = "1";

  const STORAGE_KEY = "intellidocs_sidebar_width";
  const MIN_WIDTH = 200;
  const MAX_WIDTH = 380;

  const clampWidth = (value) =>
    Math.min(MAX_WIDTH, Math.max(MIN_WIDTH, value));

  const applyWidth = (value) => {
    const width = clampWidth(value);

    appLayout.style.setProperty("--sidebar-width", `${width}px`);
    sidebar.style.setProperty("--sidebar-width", `${width}px`);

    localStorage.setItem(STORAGE_KEY, String(width));

    window.dispatchEvent(new Event("resize"));
  };

  const savedWidth = Number.parseInt(
    localStorage.getItem(STORAGE_KEY) || "",
    10
  );

  applyWidth(Number.isFinite(savedWidth) ? savedWidth : 250);

  let dragging = false;

  const updateWidthFromPointer = (clientX) => {
    const layoutRect = appLayout.getBoundingClientRect();
    const width = Math.round(clientX - layoutRect.left);

    applyWidth(width);
  };

  const stopDragging = () => {
    if (!dragging) return;

    dragging = false;
    resizer.classList.remove("is-dragging");

    document.body.style.cursor = "";
    document.body.style.userSelect = "";
  };

  resizer.addEventListener("pointerdown", (event) => {
    if (window.innerWidth <= 900) return;

    dragging = true;
    resizer.classList.add("is-dragging");

    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";

    try {
      resizer.setPointerCapture(event.pointerId);
    } catch (_) {}

    event.preventDefault();
    event.stopPropagation();
  });

  resizer.addEventListener("pointermove", (event) => {
    if (!dragging) return;

    updateWidthFromPointer(event.clientX);
    event.preventDefault();
  }, { passive: false });

  resizer.addEventListener("pointerup", stopDragging);
  resizer.addEventListener("pointercancel", stopDragging);

  document.addEventListener("pointermove", (event) => {
    if (!dragging) return;

    updateWidthFromPointer(event.clientX);
    event.preventDefault();
  }, { passive: false });

  document.addEventListener("pointerup", stopDragging);
  document.addEventListener("pointercancel", stopDragging);
  window.addEventListener("blur", stopDragging);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initSidebarResize);
} else {
  initSidebarResize();
}
/* --- IntelliDocs Sidebar Toggle --- */

function initSidebarToggle() {

  const appLayout = document.querySelector(".app-layout");
  const sidebar = document.querySelector(".sidebar");
  const toggle = document.getElementById("sidebar-toggle");

  if (!appLayout || !sidebar || !toggle) return;

  const STORAGE_KEY = "intellidocs_sidebar_collapsed";

  const applyState = (collapsed) => {

    appLayout.classList.toggle("sidebar-collapsed", collapsed);

    toggle.setAttribute(
      "aria-expanded",
      collapsed ? "false" : "true"
    );

    toggle.setAttribute(
      "aria-label",
      collapsed ? "Expand sidebar" : "Collapse sidebar"
    );

    toggle.setAttribute(
      "title",
      collapsed ? "Expand sidebar" : "Collapse sidebar"
    );
  };

  const saved =
    localStorage.getItem(STORAGE_KEY) === "true";

  applyState(saved);

  toggle.addEventListener("click", () => {

    const collapsed =
      !appLayout.classList.contains("sidebar-collapsed");

    applyState(collapsed);

    localStorage.setItem(
      STORAGE_KEY,
      String(collapsed)
    );

    window.dispatchEvent(new Event("resize"));
  });
}

if (document.readyState === "loading") {

  document.addEventListener(
    "DOMContentLoaded",
    initSidebarToggle
  );

} else {
  initSidebarToggle();
}

// --- HELP & SUPPORT CONTROLLER ---
async function loadHelpSupportView() {
  const userDisplay = document.getElementById("support-user-display");
  if (userDisplay && currentUser) {
    userDisplay.innerText = `Logged in as: ${currentUser.username}`;
  }

  // Populate reference document select for support form
  const docSelect = document.getElementById("support-doc-select");
  if (docSelect) {
    try {
      const docs = await apiFetch("/documents?limit=100");
      docSelect.innerHTML = `<option value="">None / General</option>` + docs.map(d => `
        <option value="${d.uuid}">${escapeHtml(d.display_name || d.original_name)} (v${d.version_number})</option>
      `).join("");
    } catch (e) {
      docSelect.innerHTML = `<option value="">None / General</option>`;
    }
  }

  switchHelpTab("faq");
}

function switchHelpTab(tabName) {
  const tabs = ["faq", "contact", "history"];
  tabs.forEach(t => {
    const content = document.getElementById(`help-tab-${t}`);
    const btn = document.getElementById(`help-tab-btn-${t}`);
    if (content) content.style.display = (t === tabName) ? "block" : "none";
    if (btn) {
      if (t === tabName) btn.classList.add("active");
      else btn.classList.remove("active");
    }
  });

  if (tabName === "history") loadUserSupportTickets();
}

function filterFaqItems(val) {
  const query = (val || "").trim().toLowerCase();
  const items = document.querySelectorAll("#faq-accordion-list .faq-item");

  items.forEach(item => {
    const text = item.innerText.toLowerCase();
    const keywords = (item.dataset.keywords || "").toLowerCase();
    if (!query || text.includes(query) || keywords.includes(query)) {
      item.style.display = "block";
    } else {
      item.style.display = "none";
    }
  });
}

function toggleFaqAccordion(headerEl) {
  const item = headerEl.closest(".faq-item");
  if (!item) return;
  const answer = item.querySelector(".faq-answer");
  const arrow = headerEl.querySelector("span:last-child");

  if (answer) {
    const isOpen = answer.style.display !== "none";
    answer.style.display = isOpen ? "none" : "block";
    if (arrow) arrow.innerText = isOpen ? "▼" : "▲";
  }
}

function updateSupportCharCount() {
  const textarea = document.getElementById("support-message");
  const counter = document.getElementById("support-char-count");
  if (textarea && counter) {
    counter.innerText = `${textarea.value.length} / 3000`;
  }
}

function resetSupportForm() {
  const form = document.getElementById("form-contact-support");
  if (form) form.reset();
  updateSupportCharCount();
}

async function submitContactSupport(e) {
  e.preventDefault();
  const submitBtn = document.getElementById("btn-submit-support");
  const issueType = document.getElementById("support-issue-type").value;
  const subject = document.getElementById("support-subject").value.trim();
  const docUuid = document.getElementById("support-doc-select").value || null;
  const message = document.getElementById("support-message").value.trim();

  if (!issueType) return showToast("Please select an issue category", "warning");
  if (subject.length < 3) return showToast("Subject must be at least 3 characters", "warning");
  if (message.length < 10) return showToast("Message details must be at least 10 characters", "warning");

  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.innerText = "⏳ Submitting Request...";
  }

  try {
    const payload = {
      issue_type: issueType,
      subject: subject,
      message: message,
      document_uuid: docUuid
    };

    const res = await apiFetch("/support/tickets", {
      method: "POST",
      body: JSON.stringify(payload)
    });

    showToast("Support request submitted successfully. Your request reference has been recorded.", "success");
    resetSupportForm();
    switchHelpTab("history");
  } catch (err) {
    showToast("Support submission failed: " + err.message, "error");
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.innerText = "✉️ Submit Support Request";
    }
  }
}

async function loadUserSupportTickets() {
  const tbody = document.getElementById("support-tickets-tbody");
  if (!tbody) return;
  tbody.innerHTML = `<tr><td colspan="5" class="empty-state"><div class="spinner"></div> Loading your support requests...</td></tr>`;

  try {
    const tickets = await apiFetch("/support/tickets");
    if (tickets.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" class="empty-state">You have not submitted any support requests yet.</td></tr>`;
      return;
    }

    tbody.innerHTML = tickets.map(t => `
      <tr>
        <td><strong>#${t.id}</strong></td>
        <td><span class="badge badge-info">${escapeHtml(t.issue_type.toUpperCase())}</span></td>
        <td><strong>${escapeHtml(t.subject)}</strong></td>
        <td style="color:var(--text-muted); font-size:12px;">${formatDate(t.created_at)}</td>
        <td>
          <span class="badge ${t.status === 'open' ? 'badge-warning' : 'badge-success'}">${escapeHtml(t.status.toUpperCase())}</span>
        </td>
      </tr>
    `).join("");
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="5" class="empty-state">Error: ${escapeHtml(err.message)}</td></tr>`;
  }
}

let editDocOrgUuid = null;
async function openEditDocOrgModal(uuid) {
  editDocOrgUuid = uuid;
  try {
    const doc = await apiFetch(`/documents/${uuid}`);

    // Populate Folder options
    const folderSelect = document.getElementById("edit-doc-folder-select");
    if (folderSelect) {
      const folders = await apiFetch("/folders");
      folderSelect.innerHTML = `<option value="">No Folder (Root)</option>` + folders.map(f => `
        <option value="${f.id}" ${doc.folder_id === f.id ? 'selected' : ''}>📁 ${escapeHtml(f.name)}</option>
      `).join("");
    }

    // Populate Category options
    const catSelect = document.getElementById("edit-doc-category-select");
    if (catSelect) {
      const cats = await apiFetch("/categories");
      catSelect.innerHTML = `<option value="">Uncategorized</option>` + cats.map(c => `
        <option value="${escapeHtml(c.name)}" ${doc.category === c.name ? 'selected' : ''}>${escapeHtml(c.name)}</option>
      `).join("");
    }

    document.getElementById("edit-doc-display-name").value = doc.display_name || doc.original_name;
    document.getElementById("edit-doc-subcategory-input").value = doc.subcategory || "";
    document.getElementById("edit-doc-sensitivity-select").value = doc.sensitivity || "public";

    openModal("modal-edit-doc-org");
  } catch (err) {
    showToast("Error preparing edit modal: " + err.message, "error");
  }
}

async function submitEditDocOrg(e) {
  e.preventDefault();
  if (!editDocOrgUuid) return;

  const displayName = document.getElementById("edit-doc-display-name").value.trim();
  const folderVal = document.getElementById("edit-doc-folder-select").value;
  const folderId = folderVal ? parseInt(folderVal, 10) : null;
  const category = document.getElementById("edit-doc-category-select").value || null;
  const subcategory = document.getElementById("edit-doc-subcategory-input").value.trim() || null;
  const sensitivity = document.getElementById("edit-doc-sensitivity-select").value;

  try {
    await apiFetch(`/documents/${editDocOrgUuid}`, {
      method: "PUT",
      body: JSON.stringify({
        display_name: displayName,
        folder_id: folderId,
        category: category,
        subcategory: subcategory,
        sensitivity: sensitivity
      })
    });

    showToast("Document organization updated.", "success");
    closeModal("modal-edit-doc-org");
    if (currentView === "detail") openDocumentDetail(editDocOrgUuid);
    else if (currentView === "library") loadLibraryDocuments();
  } catch (err) {
    showToast("Update failed: " + err.message, "error");
  }
}

/* === IntelliDocs AI Organization V6 === */
(function(){
  function esc(v){return typeof escapeHtml==='function'?escapeHtml(v==null?'':String(v)):String(v==null?'':v)}
  function e(s){return s&&s.evidence?s.evidence:{}}
  async function refresh(){const jobs=[];try{if(typeof loadDashboard==='function')jobs.push(loadDashboard())}catch(_){} try{if(typeof loadDocuments==='function')jobs.push(loadDocuments())}catch(_){} try{if(typeof loadFolders==='function')jobs.push(loadFolders())}catch(_){} try{if(typeof loadExplorer==='function')jobs.push(loadExplorer())}catch(_){} await Promise.allSettled(jobs)}
  function idV10StorageGet(key) { try { return sessionStorage.getItem(key); } catch (_) { return null; } }
  function idV10StorageSet(key, value) { try { if (value === null) sessionStorage.removeItem(key); else sessionStorage.setItem(key, String(value)); } catch (_) {} }
  window.toggleLegacyDocSuggestions = function(showAll) {
    idV10StorageSet("intellidocs_suggestion_focus_document_id", null);
    idV10StorageSet("intellidocs_show_all_doc_suggestions", showAll ? "1" : "0");
    window.loadSuggestions();
  };
  window.clearSuggestionDocumentFocus = function() {
    idV10StorageSet("intellidocs_suggestion_focus_document_id", null);
    idV10StorageSet("intellidocs_show_all_doc_suggestions", "0");
    window.loadSuggestions();
  };
  window.loadSuggestions = async function(analysisData = null) {
    const container = document.getElementById("suggestions-list-container");
    if (!container) return;
    container.innerHTML = '<div class="empty-state"><div class="spinner"></div> Loading name and folder suggestions...</div>';

    const rawFocus = Number(idV10StorageGet("intellidocs_suggestion_focus_document_id") || 0);
    const focusId = Number.isFinite(rawFocus) && rawFocus > 0 ? rawFocus : 0;
    const showAllDocs = !focusId && idV10StorageGet("intellidocs_show_all_doc_suggestions") === "1";
    const bulkSummary = document.getElementById("bulk-suggestions-summary-card");
    if (bulkSummary) bulkSummary.style.display = focusId ? "none" : "";

    try {
      const endpoint = focusId ? `/suggestions?document_id=${encodeURIComponent(focusId)}` : "/suggestions";
      const response = await apiFetch(endpoint);
      const rawList = Array.isArray(response) ? response : [];
      const list = rawList.filter(s => s && (s.suggestion_type === "rename" || s.suggestion_type === "create_folder_group"));
      const groupItems = focusId ? [] : list.filter(s => s.suggestion_type === "create_folder_group");
      const otherItems = focusId
        ? list.filter(s => Number(s.document_id) === focusId && s.suggestion_type === "rename")
        : (showAllDocs ? list.filter(s => s.suggestion_type === "rename") : []);

      const visibleCount = groupItems.length + otherItems.length;
      const summaryDetails = document.getElementById("bulk-summary-details");
      if (summaryDetails) summaryDetails.textContent = focusId
        ? "Only the selected upload is shown. Accept applies its suggested name and destination folder together."
        : (showAllDocs
          ? `Showing ${visibleCount} pending filename/folder or library-group proposal(s). Tags and category cards are hidden here.`
          : `Showing ${groupItems.length} library-level folder group(s). Older document rename suggestions are hidden by default.`);

      const labels = { rename: "Smart Name + Destination Folder" };
      const escValue = (v, fallback = "Not specified") => esc(v == null || v === "" ? fallback : String(v));
      const cardCheck = (s) => {
        if (focusId) return "";
        const id = Number(s.id);
        const checked = typeof selectedSuggestionIds !== "undefined" && selectedSuggestionIds.has(id) ? "checked" : "";
        return `<input type="checkbox" class="suggestion-select-checkbox" value="${id}" ${checked} onchange="updateBulkSelectionUI()" aria-label="Select suggestion ${id}" style="margin-right:9px;cursor:pointer;">`;
      };
      const scopeBanner = focusId
        ? `<div class="id-v10-scope" style="padding:12px 14px;border:1px solid var(--border-color);border-radius:10px;background:var(--surface-secondary,rgba(127,127,127,.06));margin-bottom:12px;display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap"><span>📄 Reviewing suggestions for uploaded document #${focusId}. Other files are not shown.</span><button class="btn btn-secondary btn-sm" onclick="clearSuggestionDocumentFocus()">Show library groups</button></div>`
        : `<div class="id-v10-scope" style="padding:12px 14px;border:1px solid var(--border-color);border-radius:10px;margin-bottom:12px;display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap"><span>${showAllDocs ? "Older document name suggestions are visible by request." : "Older document name suggestions are hidden to avoid repeated proposals after uploads."}</span><button class="btn btn-secondary btn-sm" onclick="toggleLegacyDocSuggestions(${showAllDocs ? "false" : "true"})">${showAllDocs ? "Hide older filename suggestions" : "Show older filename suggestions"}</button></div>`;

      const otherHtml = otherItems.map(s => {
        const id = Number(s.id);
        const evidence = s.evidence && typeof s.evidence === "object" ? s.evidence : {};
        const confidence = Math.max(0, Math.min(100, Math.round((Number(s.confidence) || 0) * 100)));
        const current = s.current_value == null || s.current_value === "" ? "Current name unavailable" : s.current_value;
        const suggested = s.suggested_value == null ? "Needs review" : s.suggested_value;
        const destination = evidence.destination_folder_path || evidence.target_folder_path || "Destination will be selected after review";
        const mode = evidence.destination_mode || evidence.target_mode || "review";
        const destinationState = mode === "create" || mode === "new"
          ? "A new folder will be created only after approval."
          : (mode === "keep_current" ? "Already in this folder; location will stay unchanged." : "The document will be moved to this existing folder after approval.");
        const reason = s.reason || evidence.reason || "Review the proposed filename and destination before applying.";
        return `<article class="id-v6-card id-v6-name id-v10-document-card" data-suggestion-id="${id}">
          <div class="id-v6-head"><span>${cardCheck(s)}✨ ${esc(labels.rename)}</span><small>${confidence}% confidence</small></div>
          <div class="id-v6-current">Document: ${escValue(evidence.document_name, "Uploaded document")}</div>
          <div class="id-v6-current">Current name: ${escValue(current)}</div>
          <div class="id-v6-title">${escValue(suggested)}</div>
          <div style="margin:12px 0;padding:12px;border:1px solid var(--border-color);border-radius:8px;display:flex;flex-direction:column;gap:4px"><small style="color:var(--text-muted)">DESTINATION FOLDER</small><strong>${escValue(destination)}</strong><small style="color:var(--text-muted)">${esc(destinationState)}</small></div>
          <div class="id-v6-reason">${esc(reason)}</div>
          <div class="id-v6-actions">
            <button class="btn btn-primary btn-sm" onclick="acceptSuggestion(${id}, this)">Apply Name &amp; Folder</button>
            <button class="btn btn-secondary btn-sm" onclick="promptEditSuggestion(${id}, '', this)">Edit Name</button>
            <button class="btn btn-secondary btn-sm" onclick="keepSuggestion(${id}, this)">Keep Current</button>
            <button class="btn btn-secondary btn-sm" onclick="rejectSuggestion(${id}, this)">Reject</button>
          </div>
        </article>`;
      }).join("");

      const groupHtml = groupItems.map(s => {
        const id = Number(s.id);
        const x = s.evidence && typeof s.evidence === "object" ? s.evidence : {};
        const existing = x.target_mode === "existing";
        const documentIds = Array.isArray(x.document_ids) ? x.document_ids : [];
        const documentNames = Array.isArray(x.document_names) ? x.document_names : [];
        const confidence = Math.max(0, Math.min(100, Math.round((Number(s.confidence) || 0) * 100)));
        const destination = x.target_folder_path || s.suggested_value || "Suggested folder";
        const reason = x.reason || s.reason || "The documents share contextual signals. Review before organizing.";
        return `<article class="id-v6-card id-v6-group" data-suggestion-id="${id}">
          <div class="id-v6-head"><span>${cardCheck(s)}📁 Library Folder Group</span><small>${confidence}% confidence</small></div>
          <div class="id-v6-group-title">${documentIds.length || documentNames.length || 2} related document(s)</div>
          <div class="id-v6-dest"><small>${existing ? "Use existing folder" : "Create new smart folder"}</small><strong>${esc(destination)}</strong></div>
          ${documentNames.length ? `<div class="id-v6-docs">${documentNames.map(name => `<div>• ${esc(name)}</div>`).join("")}</div>` : ""}
          ${x.category ? `<div class="id-v6-meta">Category: ${esc(x.category)}</div>` : ""}
          <div class="id-v6-reason">${esc(reason)}</div>
          <div class="id-v6-actions">
            <button class="btn btn-primary btn-sm" onclick="acceptSuggestion(${id}, this)">${existing ? "Use This Folder & Organize" : "Create Folder & Organize"}</button>
            <button class="btn btn-secondary btn-sm" onclick="keepSuggestion(${id}, this)">Keep As-Is</button>
            <button class="btn btn-secondary btn-sm" onclick="rejectSuggestion(${id}, this)">Reject</button>
          </div>
        </article>`;
      }).join("");

      const nameEmpty = focusId
        ? '<div class="id-v6-empty">This file has no pending name/folder action. It may already be approved, kept, rejected, or its current name is already suitable.</div>'
        : (showAllDocs ? '<div class="id-v6-empty">No older pending filename suggestions.</div>' : '<div class="id-v6-empty">Upload a file and use “Review AI Name &amp; Folder” to see one recommendation for that file.</div>');
      const groupSection = focusId ? "" : `<section class="id-v6-section"><div class="id-v6-section-title">📁 Library Folder Groups</div><div class="id-v6-section-sub">These are separate multi-document proposals. A single-file recommendation is shown after selecting a recent upload.</div>${groupHtml || '<div class="id-v6-empty">No meaningful multi-document folder group is pending.</div>'}</section>`;
      container.innerHTML = `${scopeBanner}<section class="id-v6-section"><div class="id-v6-section-title">✨ Smart Name &amp; Destination Folder</div><div class="id-v6-section-sub">One approval applies this document’s filename and folder together. Tags and category proposals are not shown here.</div>${otherHtml || nameEmpty}</section>${groupSection}`;
      if (typeof updateBulkSelectionUI === "function") updateBulkSelectionUI();
      if (typeof fetchBadges === "function") await fetchBadges();
    } catch (err) {
      container.innerHTML = `<div class="empty-state">Unable to load AI name/folder suggestions: ${esc(err && err.message ? err.message : err)}</div>`;
    }
  };  async function runSuggestionAction(id, action, buttonEl) {
    const card = buttonEl?.closest(".suggestion-card, .id-v6-card");
    const buttons = card ? Array.from(card.querySelectorAll("button")) : [];
    buttons.forEach(button => { button.disabled = true; });
    const labels = {
      accept: ["Suggestion applied successfully.", "Apply failed: "],
      keep: ["Kept as-is. IntelliDocs will not change this document.", "Keep as-is failed: "],
      reject: ["Suggestion rejected.", "Reject failed: "]
    };
    try {
      await apiFetch(`/suggestions/${Number(id)}/${action}`, { method: "POST" });
      showToast(labels[action][0], action === "reject" || action === "keep" ? "info" : "success");
      await Promise.allSettled([
        typeof window.loadSuggestions === "function" ? window.loadSuggestions() : Promise.resolve(),
        refresh()
      ]);
    } catch (err) {
      buttons.forEach(button => { button.disabled = false; });
      showToast(labels[action][1] + (err && err.message ? err.message : String(err)), "error");
    }
  }
  window.acceptSuggestion = (id, buttonEl) => runSuggestionAction(id, "accept", buttonEl);
  window.keepSuggestion = (id, buttonEl) => runSuggestionAction(id, "keep", buttonEl);
  window.rejectSuggestion = (id, buttonEl) => runSuggestionAction(id, "reject", buttonEl);
  window.IntelliDocsAIOrganizationV9=true;
})();

/* === IntelliDocs AI Organization V9 Audit Hardening === */
// Edit action restored; duplicate reload wrapper removed; partial bulk results retained.

/* === IntelliDocs Single-Document Suggestion Focus V10 === */

// Focus the Suggestions view on the latest uploaded document; only name + folder is shown.

// intellidocs_single_doc_analyze_v10



/* === IntelliDocs Smart Filing V12 === */
(function(){
  const FOCUS_KEY = "intellidocs_suggestion_focus_document_id";
  const SHOW_ALL_KEY = "intellidocs_show_all_doc_suggestions";
  const esc = (value) => typeof escapeHtml === "function" ? escapeHtml(value == null ? "" : String(value)) : String(value == null ? "" : value);
  const getFocus = () => { try { return Number(sessionStorage.getItem(FOCUS_KEY) || 0); } catch (_) { return 0; } };
  const setFocus = (id) => { try { sessionStorage.setItem(FOCUS_KEY, String(Number(id) || 0)); sessionStorage.setItem(SHOW_ALL_KEY, "0"); } catch (_) {} };
  const parseEvidence = (value) => {
    if (value && typeof value === "object") return value;
    if (typeof value === "string") { try { const parsed = JSON.parse(value); return parsed && typeof parsed === "object" ? parsed : {}; } catch (_) {} }
    return {};
  };
  async function getRecentDocuments(){
    const response = await apiFetch("/documents?limit=100&sort_by=uploaded_at&order=desc");
    return Array.isArray(response) ? response.filter(d => d && Number(d.id) > 0) : [];
  }
  async function getAllFolders(){
    const result = [], seen = new Set();
    async function visit(parentId, prefix, depth){
      if (depth > 20) return;
      const endpoint = parentId == null ? "/folders" : `/folders?parent_id=${encodeURIComponent(parentId)}`;
      const rows = await apiFetch(endpoint);
      for (const folder of (Array.isArray(rows) ? rows : [])){
        const id = Number(folder.id);
        if (!id || seen.has(id)) continue;
        seen.add(id);
        const path = prefix ? `${prefix} / ${folder.name}` : String(folder.name || "");
        result.push({ ...folder, path, depth });
        await visit(id, path, depth + 1);
      }
    }
    await visit(null, "", 0);
    return result;
  }
  async function getAllDocumentsForCounts(){
    const docs = [];
    for (let page = 1; page <= 100; page++){
      const rows = await apiFetch(`/documents?limit=100&page=${page}&sort_by=uploaded_at&order=desc`);
      if (!Array.isArray(rows)) break;
      docs.push(...rows);
      if (rows.length < 100) break;
    }
    return docs;
  }
  // Keep every folder level available in upload filters and manual metadata editing.
  window.loadMetadataDropdowns = async function(){
    try {
      const [cats, folders, tags] = await Promise.all([apiFetch("/categories"), getAllFolders(), apiFetch("/tags")]);
      categoriesList = Array.isArray(cats) ? cats : [];
      foldersList = Array.isArray(folders) ? folders : [];
      tagsList = Array.isArray(tags) ? tags : [];
      const categorySelect = document.getElementById("filter-category");
      if (categorySelect) categorySelect.innerHTML = '<option value="">All Categories</option>' + categoriesList.map(c => `<option value="${esc(c.name)}">${esc(c.name)}</option>`).join("");
      const folderSelect = document.getElementById("filter-folder");
      if (folderSelect) folderSelect.innerHTML = '<option value="">All Folders</option>' + foldersList.map(f => `<option value="${Number(f.id)}">${esc(f.path)}</option>`).join("");
      const uploadFolderSelect = document.getElementById("upload-target-folder");
      if (uploadFolderSelect) uploadFolderSelect.innerHTML = '<option value="">(Root / Unorganized)</option>' + foldersList.map(f => `<option value="${Number(f.id)}">${esc(f.path)}</option>`).join("");
    } catch (err) { console.warn("Could not refresh folder/category dropdowns:", err); }
  };
  const _idV12OriginalOpenEditDocOrgModal = window.openEditDocOrgModal;
  if (typeof _idV12OriginalOpenEditDocOrgModal === "function") {
    window.openEditDocOrgModal = async function(uuid){
      await _idV12OriginalOpenEditDocOrgModal(uuid);
      try {
        const [doc, folders] = await Promise.all([apiFetch(`/documents/${encodeURIComponent(uuid)}`), getAllFolders()]);
        const select = document.getElementById("edit-doc-folder-select");
        if (select) {
          select.innerHTML = '<option value="">No Folder (Root)</option>' + folders.map(f => `<option value="${Number(f.id)}" ${Number(doc.folder_id) === Number(f.id) ? "selected" : ""}>📁 ${esc(f.path)}</option>`).join("");
          select.value = doc.folder_id == null ? "" : String(doc.folder_id);
        }
      } catch (err) { showToast("Could not load nested folder paths: " + (err.message || err), "error"); }
    };
  }
  function selectedOptionText(doc){
    const name = doc.display_name || doc.original_name || `Document #${doc.id}`;
    const cat = doc.category || "General";
    return `${name} — ${cat}`;
  }
  window.v12ReviewDocument = async function(documentId){
    const id = Number(documentId);
    if (!Number.isFinite(id) || id <= 0) return;
    setFocus(id);
    await window.loadSuggestions();
  };
  window.clearSuggestionDocumentFocus = function(){
    try { sessionStorage.removeItem(FOCUS_KEY); sessionStorage.setItem(SHOW_ALL_KEY, "0"); } catch (_) {}
    window.loadSuggestions();
  };
  window.toggleLegacyDocSuggestions = function(){
    showToast("Older file suggestions are intentionally not shown in this focused review.", "info");
    window.loadSuggestions();
  };
  window.triggerAnalyzeLibrarySuggestions = async function(buttonEl){
    const button = buttonEl || document.getElementById("btn-re-evaluate-suggestions");
    if (button){ button.disabled = true; button.dataset.v12OldText = button.innerText; button.innerText = "Analyzing selected document…"; }
    try { await window.loadSuggestions(); }
    finally { if (button){ button.disabled = false; button.innerText = "Analyze Selected Document"; } }
  };

  window.loadSuggestions = async function(){
    const container = document.getElementById("suggestions-list-container");
    if (!container) return;
    const bulkSummary = document.getElementById("bulk-suggestions-summary-card");
    if (bulkSummary) bulkSummary.style.display = "none";
    const bulkCard = document.getElementById("bulk-suggestions-toolbar-card");
    if (bulkCard) bulkCard.style.display = "none";
    container.innerHTML = '<div class="id-v12-loading">Loading document and folder recommendation…</div>';
    try {
      const docs = await getRecentDocuments();
      if (!docs.length){
        container.innerHTML = '<div class="id-v12-empty"><h3>No documents uploaded yet</h3><p>Upload a file first. IntelliDocs will recommend one meaningful filename and one category-based destination folder for that file.</p><button class="btn btn-primary" onclick="navigateTo(\'upload\')">Upload a Document</button></div>';
        return;
      }
      const storedFocus = getFocus();
      const selectedDoc = docs.find(d => Number(d.id) === storedFocus) || docs[0];
      const focusId = Number(selectedDoc.id);
      if (focusId !== storedFocus) setFocus(focusId);

      // The selected document is the only document analyzed and rendered here.
      await apiFetch(`/suggestions/analyze?document_id=${encodeURIComponent(focusId)}`, { method: "POST" });
      const suggestionsResponse = await apiFetch(`/suggestions?document_id=${encodeURIComponent(focusId)}`);
      const suggestions = Array.isArray(suggestionsResponse) ? suggestionsResponse : [];
      const suggestion = suggestions.find(s => s && s.suggestion_type === "rename" && s.status === "pending")
        || suggestions.find(s => s && s.suggestion_type === "rename");

      const options = docs.map(d => `<option value="${Number(d.id)}" ${Number(d.id) === focusId ? "selected" : ""}>${esc(selectedOptionText(d))}</option>`).join("");
      const selector = `<div class="id-v12-selector"><div><label for="v12-document-select">Document to review</label><p>Select one file. No other document's name suggestion is shown.</p></div><select id="v12-document-select" class="form-control" onchange="v12ReviewDocument(this.value)">${options}</select></div>`;

      if (!suggestion || suggestion.status !== "pending"){
        const currentPath = selectedDoc.folder_id ? `Stored in folder #${Number(selectedDoc.folder_id)}` : "Not assigned to a folder yet";
        container.innerHTML = `<div class="id-v12-shell">${selector}<div class="id-v12-empty"><h3>No pending change for this document</h3><p><strong>${esc(selectedDoc.display_name || selectedDoc.original_name || "Selected document")}</strong></p><p>${esc(currentPath)}. This file may already have been approved, kept or rejected. Its previous decision is not recreated automatically.</p><button class="btn btn-secondary" onclick="navigateTo(\'upload\')">Upload Another File</button></div></div>`;
        if (typeof fetchBadges === "function") await fetchBadges();
        return;
      }

      const evidence = parseEvidence(suggestion.evidence);
      const currentName = suggestion.current_value || selectedDoc.display_name || selectedDoc.original_name || "Current name unavailable";
      const suggestedName = evidence.generated_filename || suggestion.suggested_value || currentName;
      const path = evidence.destination_folder_path || evidence.target_folder_path || "General / To Review";
      const category = evidence.destination_category || "General";
      const mode = evidence.destination_mode || "create";
      const destinationNote = mode === "existing"
        ? "This folder already exists. Approval will move the file there."
        : mode === "keep_current"
          ? "This file already has a folder. Approval keeps its current location."
          : "On approval, IntelliDocs creates the category folder and meaningful subfolder if missing; no empty folder tree is pre-created.";
      const reason = suggestion.reason || "The recommendation uses the document's title and extracted text. Review both sides before applying.";
      const confidence = Math.max(0, Math.min(100, Math.round((Number(suggestion.confidence) || 0) * 100)));
      container.innerHTML = `<div class="id-v12-shell">
        ${selector}
        <div class="id-v12-fileline"><span class="id-v12-file-icon">PDF/DOC</span><div class="id-v12-file-meta"><strong>${esc(selectedDoc.display_name || selectedDoc.original_name || `Document #${focusId}`)}</strong><small>${esc(selectedDoc.file_type || "file")} · ${esc(category)} category · ${confidence}% context confidence</small></div></div>
        <div class="id-v12-grid">
          <section class="id-v12-panel id-v12-name-panel">
            <div class="id-v12-panel-kicker">01 · FILE NAME</div>
            <h3>Recommended name</h3>
            <div class="id-v12-current"><small>Current name</small><div>${esc(currentName)}</div></div>
            <div class="id-v12-proposed"><small>AI recommendation</small><code class="id-v6-title">${esc(suggestedName)}</code></div>
            <p class="id-v12-help">The recommendation removes repeated/noisy terms and keeps the document's meaningful subject. You can edit it before applying.</p>
          </section>
          <section class="id-v12-panel id-v12-folder-panel">
            <div class="id-v12-panel-kicker">02 · DESTINATION</div>
            <h3>Where this file will live</h3>
            <div class="id-v12-category-chip">Category: ${esc(category)}</div>
            <div class="id-v12-path">📁 ${esc(path)}</div>
            <p class="id-v12-help">${esc(destinationNote)}</p>
            <p class="id-v12-help">Categories describe <em>what</em> a document is. Folders describe <em>where</em> it is stored. The approved category folder and document-specific subfolder will appear in Folders; counts will appear under Categories.</p>
          </section>
        </div>
        <div class="id-v12-reason"><strong>Why this recommendation?</strong><p>${esc(reason)}</p></div>
        <div class="id-v12-actions">
          <button class="btn btn-primary" onclick="acceptSuggestion(${Number(suggestion.id)}, this)">Apply Name &amp; Folder</button>
          <button class="btn btn-secondary" onclick="promptEditSuggestion(${Number(suggestion.id)}, '', this)">Edit Name &amp; Apply</button>
          <button class="btn btn-secondary" onclick="keepSuggestion(${Number(suggestion.id)}, this)">Keep Current</button>
          <button class="btn btn-secondary" onclick="rejectSuggestion(${Number(suggestion.id)}, this)">Reject</button>
        </div>
      </div>`;
      if (typeof fetchBadges === "function") await fetchBadges();
    } catch (err) {
      container.innerHTML = `<div class="id-v12-empty"><h3>Could not load this recommendation</h3><p>${esc(err && err.message ? err.message : err)}</p><button class="btn btn-secondary" onclick="window.loadSuggestions()">Retry</button></div>`;
    }
  };

  window.loadFoldersTab = async function(){
    const tbody = document.getElementById("folders-tbody");
    if (!tbody) return;
    tbody.innerHTML = '<tr><td colspan="4" class="empty-state">Loading category-based folder tree…</td></tr>';
    try {
      const [folders, docs] = await Promise.all([getAllFolders(), getAllDocumentsForCounts()]);
      const counts = {};
      docs.forEach(d => { const id = Number(d.folder_id || 0); if (id) counts[id] = (counts[id] || 0) + 1; });
      // Roll child document totals up to parent/category folders so root counts are useful.
      folders.slice().sort((a, b) => Number(b.depth || 0) - Number(a.depth || 0)).forEach(f => {
        const parent = Number(f.parent_id || 0);
        if (parent) counts[parent] = (counts[parent] || 0) + (counts[Number(f.id)] || 0);
      });
      foldersList = folders;
      window.foldersList = folders;
      if (!folders.length){
        tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No folders created yet. Approve an AI destination to create only the category folder and useful subfolder needed for that document. You can also create a folder manually.</td></tr>';
        return;
      }
      tbody.innerHTML = folders.map(f => {
        const count = counts[Number(f.id)] || 0;
        const nameArg = esc(JSON.stringify(String(f.name || "")));
        return `<tr><td><strong>📁 ${esc(f.path)}</strong>${f.depth ? `<small class="id-v12-folder-level">Subfolder · level ${f.depth + 1}</small>` : `<small class="id-v12-folder-level">Category root</small>`}</td><td><span class="badge badge-info">${count} docs</span></td><td>${typeof formatDate === "function" ? formatDate(f.created_at) : esc(f.created_at || "—")}</td><td style="text-align:right"><button class="btn btn-secondary btn-sm" onclick="filterLibraryByFolder(${Number(f.id)})">View Documents</button> <button class="btn btn-secondary btn-sm" onclick="renameFolder(${Number(f.id)}, ${nameArg})">Rename</button> <button class="btn btn-danger btn-sm" onclick="deleteFolder(${Number(f.id)})">Delete</button></td></tr>`;
      }).join("");
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="4" class="empty-state">Could not load folders: ${esc(err && err.message ? err.message : err)}</td></tr>`;
    }
  };

  window.loadCategoriesTab = async function(){
    const tbody = document.getElementById("categories-tbody");
    if (!tbody) return;
    tbody.innerHTML = '<tr><td colspan="4" class="empty-state">Loading categories…</td></tr>';
    try {
      const [cats, docs] = await Promise.all([apiFetch("/categories"), getAllDocumentsForCounts()]);
      categoriesList = Array.isArray(cats) ? cats : [];
      window.categoriesList = categoriesList;
      const counts = {};
      docs.forEach(d => { const name = String(d.category || "General"); counts[name] = (counts[name] || 0) + 1; });
      if (!window.categoriesList.length){ tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No categories available.</td></tr>'; return; }
      tbody.innerHTML = window.categoriesList.map(c => {
        const nameArg = esc(JSON.stringify(String(c.name || "")));
        return `<tr><td><strong>${esc(c.name)}</strong></td><td>${esc(c.description || "—")}</td><td>${c.is_system ? '<span class="badge badge-neutral">System</span>' : '<span class="badge badge-info">Custom</span>'} · <span class="badge badge-neutral">${counts[c.name] || 0} docs</span></td><td style="text-align:right"><button class="btn btn-secondary btn-sm" onclick="filterLibraryByCategory(${nameArg})">View Documents</button></td></tr>`;
      }).join("");
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="4" class="empty-state">Could not load categories: ${esc(err && err.message ? err.message : err)}</td></tr>`;
    }
  };

  window.switchOrgTab = function(tabName){
    const safeTab = tabName === "categories" ? "categories" : "folders";
    ["folders", "categories", "tags"].forEach(t => {
      const element = document.getElementById(`org-tab-${t}`);
      if (element) element.style.display = t === safeTab ? "block" : "none";
    });
    document.querySelectorAll("#view-organization .page-tabs .tab-button").forEach((button, index) => button.classList.toggle("active", index === (safeTab === "folders" ? 0 : 1)));
    if (safeTab === "folders") window.loadFoldersTab(); else window.loadCategoriesTab();
  };
  window.loadOrganizationView = function(){ window.switchOrgTab("folders"); };
  window.IntelliDocsSmartFilingV12 = true;
})();

/* === IntelliDocs Suggestions Split View V13 === */
(function () {
  "use strict";
  const FOCUS_KEY = "intellidocs_suggestion_focus_document_id";
  const SHOW_ALL_KEY = "intellidocs_show_all_doc_suggestions";
  const esc = (value) => typeof window.escapeHtml === "function"
    ? window.escapeHtml(value == null ? "" : String(value))
    : String(value == null ? "" : value).replace(/[&<>"']/g, ch => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[ch]));
  const readFocus = () => { try { return Number(sessionStorage.getItem(FOCUS_KEY) || 0); } catch (_) { return 0; } };
  const writeFocus = (id) => { try { sessionStorage.setItem(FOCUS_KEY, String(Number(id) || 0)); sessionStorage.setItem(SHOW_ALL_KEY, "0"); } catch (_) {} };
  const evidenceOf = (s) => {
    const e = s && s.evidence;
    if (e && typeof e === "object") return e;
    if (typeof e === "string") { try { const parsed = JSON.parse(e); return parsed && typeof parsed === "object" ? parsed : {}; } catch (_) {} }
    return {};
  };
  const pct = (s) => Math.max(0, Math.min(100, Math.round((Number(s && s.confidence) || 0) * 100)));
  const meaningfulGroup = (s) => {
    const e = evidenceOf(s);
    const label = String(e.suggested_folder_name || e.label || String(e.target_folder_path || s.suggested_value || "").split("/").pop() || "")
      .toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
    // Filter stale low-quality group suggestions already persisted before V9 hardening.
    const allowed = new Set(["college fees", "fees", "bank statements", "bills invoices", "dsa assignments", "academic assignments", "certificates", "career documents", "identity documents", "legal documents"]);
    return (e.v14_strong_group === true || allowed.has(label)) && (Array.isArray(e.document_ids) ? e.document_ids.length : Array.isArray(e.document_names) ? e.document_names.length : 0) >= 2;
  };
  window.intelliDocsV13MeaningfulGroup = meaningfulGroup;

  async function recentDocs() {
    const result = await apiFetch("/documents?limit=100&sort_by=uploaded_at&order=desc");
    return Array.isArray(result) ? result.filter(d => d && Number(d.id) > 0) : [];
  }
  function selectedDocLabel(d) {
    const name = d.display_name || d.original_name || `Document #${d.id}`;
    return `${name} — ${d.category || "General"}`;
  }
  function cardCheckbox(s) {
    const id = Number(s.id);
    const checked = typeof selectedSuggestionIds !== "undefined" && selectedSuggestionIds instanceof Set && selectedSuggestionIds.has(id) ? "checked" : "";
    return `<input type="checkbox" class="suggestion-select-checkbox" value="${id}" ${checked} onchange="updateBulkSelectionUI()" aria-label="Select suggestion ${id}" style="margin-right:9px;cursor:pointer;">`;
  }
  function renderNameCard(s) {
    const id = Number(s.id), ev = evidenceOf(s);
    const current = s.current_value || ev.document_name || "Current name unavailable";
    const suggested = ev.generated_filename || s.suggested_value || current;
    const dest = ev.destination_folder_path || ev.target_folder_path || "Folder destination needs review";
    const category = ev.destination_category || ev.category || "General";
    const mode = ev.destination_mode || "create";
    const destinationNote = mode === "existing" ? "Uses an existing folder after approval."
      : mode === "keep_current" ? "Keeps the current folder."
      : "The category folder and specific subfolder are created only after approval.";
    const reason = s.reason || ev.destination_reason || "Suggested from this document's title and extracted content.";
    return `<article class="id-v6-card id-v6-name id-v13-name-card" data-suggestion-id="${id}">
      <div class="id-v6-head"><span>${cardCheckbox(s)}✨ Smart Name</span><small>${pct(s)}% confidence</small></div>
      <div class="id-v6-current"><strong>Document</strong> ${esc(ev.document_name || current)}</div>
      <div class="id-v6-current"><strong>Current name</strong><div>${esc(current)}</div></div>
      <div class="id-v6-title id-v13-proposed-name">${esc(suggested)}</div>
      <div class="id-v13-destination"><small>DESTINATION FOLDER</small><strong>📁 ${esc(dest)}</strong><span>Category: ${esc(category)} · ${esc(destinationNote)}</span></div>
      <div class="id-v6-reason">${esc(reason)}</div>
      <div class="id-v6-actions">
        <button class="btn btn-primary btn-sm" onclick="acceptSuggestion(${id}, this)">Apply Name &amp; Folder</button>
        <button class="btn btn-secondary btn-sm" onclick="promptEditSuggestion(${id}, '', this)">Edit Name &amp; Apply</button>
        <button class="btn btn-secondary btn-sm" onclick="keepSuggestion(${id}, this)">Keep Current</button>
        <button class="btn btn-secondary btn-sm" onclick="rejectSuggestion(${id}, this)">Reject</button>
      </div>
    </article>`;
  }
  function renderGroupCard(s) {
    const id = Number(s.id), ev = evidenceOf(s);
    const path = ev.target_folder_path || ev.folder_path || s.suggested_value || "Suggested folder";
    const existing = String(ev.target_mode || ev.destination_mode || "").toLowerCase() === "existing";
    const names = Array.isArray(ev.document_names) ? ev.document_names : [];
    const ids = Array.isArray(ev.document_ids) ? ev.document_ids : [];
    const reason = s.reason || ev.reason || "These documents share a meaningful document type or context.";
    return `<article class="id-v6-card id-v6-group id-v13-group-card" data-suggestion-id="${id}">
      <div class="id-v6-head"><span>${cardCheckbox(s)}📁 Smart Organization &amp; Grouping</span><small>${pct(s)}% confidence</small></div>
      <div class="id-v6-group-title">${Math.max(names.length, ids.length, 2)} related documents</div>
      <div class="id-v6-dest"><small>${existing ? "Use existing folder" : "Create new smart folder"}</small><strong>${esc(path)}</strong></div>
      ${names.length ? `<div class="id-v6-docs">${names.map(n => `<div>• ${esc(n)}</div>`).join("")}</div>` : ""}
      ${ev.category ? `<div class="id-v6-meta">Category: ${esc(ev.category)}</div>` : ""}
      <div class="id-v6-reason">${esc(reason)}</div>
      <div class="id-v6-actions">
        <button class="btn btn-primary btn-sm" onclick="acceptSuggestion(${id}, this)">${existing ? "Use This Folder &amp; Organize" : "Create Folder &amp; Organize"}</button>
        <button class="btn btn-secondary btn-sm" onclick="keepSuggestion(${id}, this)">Keep As-Is</button>
        <button class="btn btn-secondary btn-sm" onclick="rejectSuggestion(${id}, this)">Reject</button>
      </div>
    </article>`;
  }
  function setScopeHint(text) {
    const el = document.getElementById("v13-suggestions-scope-hint");
    if (el) el.textContent = text;
  }

  window.v13ReviewDocument = async function (rawId) {
    const id = Number(rawId);
    if (!Number.isFinite(id) || id <= 0) return;
    writeFocus(id);
    const select = document.getElementById("v13-document-select");
    if (select) select.value = String(id);
    const button = document.getElementById("btn-re-evaluate-suggestions");
    try {
      if (button) { button.disabled = true; button.dataset.v13Text = button.textContent; button.textContent = "Analyzing selected document…"; }
      // Analyze only the explicitly selected document; never regenerate the entire library's rename proposals.
      await apiFetch(`/suggestions/analyze?document_id=${encodeURIComponent(id)}`, { method: "POST" });
      await window.loadSuggestions();
      if (typeof window.fetchBadges === "function") await window.fetchBadges();
    } catch (err) {
      showToast("Could not analyze selected document: " + (err && err.message ? err.message : err), "error");
      await window.loadSuggestions();
    } finally {
      if (button) { button.disabled = false; button.textContent = button.dataset.v13Text || "⚡ Re-evaluate AI Insights"; }
    }
  };

  window.triggerAnalyzeLibrarySuggestions = async function (buttonEl) {
    const button = buttonEl || document.getElementById("btn-re-evaluate-suggestions");
    if (button) { button.disabled = true; button.dataset.v13Text = button.textContent; button.textContent = "Re-evaluating name + groups…"; }
    try {
      const docs = await recentDocs();
      const savedFocus = readFocus();
      const doc = docs.find(d => Number(d.id) === savedFocus) || docs[0];
      if (doc) {
        writeFocus(Number(doc.id));
        // Scoped endpoint is crucial: don't recreate old rename suggestions for every upload.
        await apiFetch(`/suggestions/analyze?document_id=${encodeURIComponent(Number(doc.id))}`, { method: "POST" });
      }
      // Dedicated groups-only endpoint does not regenerate per-document name/tag/sensitivity proposals.
      await apiFetch("/suggestions/analyze-groups", { method: "POST" });
      showToast("Selected document name and library folder groups re-evaluated.", "success");
      await window.loadSuggestions();
      if (typeof window.fetchBadges === "function") await window.fetchBadges();
    } catch (err) {
      showToast("Re-evaluation failed: " + (err && err.message ? err.message : err), "error");
      await window.loadSuggestions();
    } finally {
      if (button) { button.disabled = false; button.textContent = button.dataset.v13Text || "⚡ Re-evaluate AI Insights"; }
    }
  };

  window.loadSuggestions = async function () {
    const container = document.getElementById("suggestions-list-container");
    if (!container) return;
    container.style.display = "block";
    container.innerHTML = '<div class="id-v13-loading">Loading smart name and folder-group suggestions…</div>';
    const bulk = document.getElementById("bulk-suggestions-summary-card");
    try {
      const docs = await recentDocs();
      if (!docs.length) {
        if (bulk) bulk.style.display = "none";
        container.innerHTML = `<div class="id-v13-scope"><div><strong>Document to review</strong><p id="v13-suggestions-scope-hint">Upload a document to get one smart filename recommendation.</p></div></div><div class="id-v13-layout"><section class="id-v13-section"><h3>✨ Smart Name Suggestions</h3><div class="id-v13-empty">No documents uploaded yet. Upload a file to start.</div></section><section class="id-v13-section"><h3>📁 Smart Organization &amp; Grouping</h3><div class="id-v13-empty">No multi-document groups are available yet.</div></section></div>`;
        return;
      }
      const currentFocus = readFocus();
      const selected = docs.find(d => Number(d.id) === currentFocus) || docs[0];
      const focusId = Number(selected.id);
      if (focusId !== currentFocus) writeFocus(focusId);

      const [focusedResponse, allResponse] = await Promise.all([
        apiFetch(`/suggestions?document_id=${encodeURIComponent(focusId)}`),
        apiFetch("/suggestions")
      ]);
      const focused = Array.isArray(focusedResponse) ? focusedResponse : [];
      const all = Array.isArray(allResponse) ? allResponse : [];
      const nameSuggestion = focused.find(s => s && s.suggestion_type === "rename" && s.status === "pending") || null;
      const groups = all.filter(s => s && s.suggestion_type === "create_folder_group" && s.status === "pending" && meaningfulGroup(s));
      const visible = [...(nameSuggestion ? [nameSuggestion] : []), ...groups];

      const options = docs.map(d => `<option value="${Number(d.id)}" ${Number(d.id) === focusId ? "selected" : ""}>${esc(selectedDocLabel(d))}</option>`).join("");
      const selectedName = selected.display_name || selected.original_name || `Document #${focusId}`;
      const scope = `<div class="id-v13-scope"><div><strong>Document to review</strong><p id="v13-suggestions-scope-hint">Only this file’s smart-name recommendation is shown. Library grouping stays separate on the right.</p></div><select id="v13-document-select" class="form-control" aria-label="Document to review" onchange="v13ReviewDocument(this.value)">${options}</select></div>`;
      const nameContent = nameSuggestion
        ? renderNameCard(nameSuggestion)
        : `<div class="id-v13-empty"><strong>No pending smart-name suggestion for this file.</strong><p>${esc(selectedName)}. Its previous approval/keep/reject decision is preserved. Choose a different document above or use Re-evaluate AI Insights for this file.</p><button class="btn btn-secondary btn-sm" onclick="v13ReviewDocument(${focusId})">Analyze This Document</button></div>`;
      const groupContent = groups.length
        ? groups.map(renderGroupCard).join("")
        : `<div class="id-v13-empty"><strong>No meaningful multi-document group is pending.</strong><p>Grouping proposals appear here separately after at least two documents share a strong document-type context. Legacy weak/person-name groups are hidden.</p></div>`;

      container.innerHTML = `${scope}<div class="id-v13-layout">
        <section class="id-v13-section id-v13-name-section"><div class="id-v13-section-heading"><div><h3>✨ Smart Name Suggestions</h3><p>Content-based filename for the selected document only. The proposed destination is shown on the same card; nothing changes until approval.</p></div><span class="id-v13-count">${nameSuggestion ? "1 proposal" : "0 proposals"}</span></div>${nameContent}</section>
        <section class="id-v13-section id-v13-group-section"><div class="id-v13-section-heading"><div><h3>📁 Smart Organization &amp; Grouping</h3><p>Independent library-level proposals for multiple related documents. No tags or sensitivity cards are shown here.</p></div><span class="id-v13-count">${groups.length} group${groups.length === 1 ? "" : "s"}</span></div>${groupContent}</section>
      </div>`;

      if (bulk) {
        bulk.style.display = visible.length ? "" : "none";
        const details = document.getElementById("bulk-summary-details");
        if (details) details.textContent = `${nameSuggestion ? "1 selected-document name/folder proposal" : "No pending name proposal for selected file"} · ${groups.length} meaningful library folder group(s). Tags and sensitivity are not part of this review.`;
        const title = document.getElementById("bulk-summary-title");
        if (title) title.textContent = "Review Name & Folder-Group Proposals";
      }
      if (typeof updateBulkSelectionUI === "function") updateBulkSelectionUI();
      setScopeHint(`Currently reviewing: ${selectedName}. Older documents' name cards are not shown automatically.`);
      if (typeof window.fetchBadges === "function") await window.fetchBadges();
    } catch (err) {
      container.innerHTML = `<div class="id-v13-empty"><strong>Could not load AI suggestions.</strong><p>${esc(err && err.message ? err.message : err)}</p><button class="btn btn-secondary" onclick="window.loadSuggestions()">Retry</button></div>`;
      if (bulk) bulk.style.display = "none";
    }
  };

  // Keep the sidebar badge aligned with this view: focused filename + meaningful grouping cards.
  const originalFetchBadges = window.fetchBadges;
  if (typeof originalFetchBadges === "function") {
    window.fetchBadges = async function () {
      await originalFetchBadges.apply(this, arguments);
      try {
        const [rows] = await Promise.all([apiFetch("/suggestions")]);
        const focusId = readFocus();
        const visibleCount = (Array.isArray(rows) ? rows : []).filter(s =>
          (s && s.suggestion_type === "create_folder_group" && s.status === "pending" && meaningfulGroup(s)) ||
          (s && s.suggestion_type === "rename" && s.status === "pending" && focusId > 0 && Number(s.document_id) === focusId)
        ).length;
        const badge = document.getElementById("badge-suggestions");
        if (badge) {
          badge.textContent = String(visibleCount);
          badge.style.display = visibleCount ? "inline-block" : "none";
        }
      } catch (_) {}
    };
  }
  window.IntelliDocsSuggestionsSplitV13 = true;
})();
/* === End IntelliDocs Suggestions Split View V13 === */

/* === IntelliDocs Simple Two-Panel Suggestions V16 === */
(function () {
  "use strict";
  const FOCUS_KEY = "intellidocs_suggestion_focus_document_id";
  const esc = (value) => typeof window.escapeHtml === "function"
    ? window.escapeHtml(value == null ? "" : String(value))
    : String(value == null ? "" : value).replace(/[&<>"']/g, ch => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[ch]));
  const evidenceOf = (s) => {
    const v = s && s.evidence;
    if (v && typeof v === "object") return v;
    if (typeof v === "string") { try { const p = JSON.parse(v); return p && typeof p === "object" ? p : {}; } catch (_) {} }
    return {};
  };
  const pct = (s) => Math.max(0, Math.min(100, Math.round((Number(s && s.confidence) || 0) * 100)));
  const readFocus = () => { try { return Number(sessionStorage.getItem(FOCUS_KEY) || 0); } catch (_) { return 0; } };
  const writeFocus = (id) => { try { sessionStorage.setItem(FOCUS_KEY, String(Number(id) || 0)); sessionStorage.setItem("intellidocs_show_all_doc_suggestions", "0"); } catch (_) {} };

  async function recentDocuments() {
    const rows = await apiFetch("/documents?limit=100&sort_by=uploaded_at&order=desc");
    return Array.isArray(rows) ? rows.filter(d => d && Number(d.id) > 0) : [];
  }
  function isMeaningfulGroup(s) {
    if (!s || s.suggestion_type !== "create_folder_group" || s.status !== "pending") return false;
    if (typeof window.intelliDocsV13MeaningfulGroup === "function") {
      try { return !!window.intelliDocsV13MeaningfulGroup(s); } catch (_) { return false; }
    }
    const ev = evidenceOf(s);
    const count = Math.max(Array.isArray(ev.document_ids) ? ev.document_ids.length : 0,
      Array.isArray(ev.document_names) ? ev.document_names.length : 0);
    return count >= 2 && ev.v14_strong_group === true;
  }
  function renderNameCard(s) {
    const id = Number(s.id), ev = evidenceOf(s);
    const current = s.current_value || ev.document_name || "Current name unavailable";
    const proposed = ev.generated_filename || s.suggested_value || current;
    const destination = ev.destination_folder_path || ev.target_folder_path || "Destination folder needs review";
    const category = ev.destination_category || ev.category || "General";
    const mode = ev.destination_mode || ev.target_mode || "create";
    const note = mode === "existing" ? "Uses an existing folder after approval."
      : mode === "keep_current" ? "Keeps the file in its current location."
      : "The category folder and meaningful subfolder are created only after approval.";
    const reason = s.reason || ev.destination_reason || "Suggested from this file's title and extracted content.";
    return `<article class="id-v6-card id-v6-name id-v13-name-card" data-suggestion-id="${id}">
      <div class="id-v6-head"><span>✨ Smart Name</span><small>${pct(s)}% confidence</small></div>
      <div class="id-v6-current"><strong>Current name</strong><div>${esc(current)}</div></div>
      <div class="id-v6-title id-v13-proposed-name">${esc(proposed)}</div>
      <div class="id-v13-destination"><small>DESTINATION FOLDER</small><strong>📁 ${esc(destination)}</strong><span>Category: ${esc(category)} · ${esc(note)}</span></div>
      <div class="id-v6-reason">${esc(reason)}</div>
      <div class="id-v6-actions">
        <button class="btn btn-primary btn-sm" onclick="acceptSuggestion(${id}, this)">Apply Name &amp; Folder</button>
        <button class="btn btn-secondary btn-sm" onclick="promptEditSuggestion(${id}, '', this)">Edit Name &amp; Apply</button>
        <button class="btn btn-secondary btn-sm" onclick="keepSuggestion(${id}, this)">Keep Current</button>
        <button class="btn btn-secondary btn-sm" onclick="rejectSuggestion(${id}, this)">Reject</button>
      </div>
    </article>`;
  }
  function renderGroupCard(s) {
    const id = Number(s.id), ev = evidenceOf(s);
    const path = ev.target_folder_path || ev.folder_path || s.suggested_value || "Suggested folder";
    const mode = String(ev.target_mode || ev.destination_mode || "").toLowerCase();
    const existing = mode === "existing";
    const names = Array.isArray(ev.document_names) ? ev.document_names : [];
    const ids = Array.isArray(ev.document_ids) ? ev.document_ids : [];
    const reason = s.reason || ev.reason || "These files share a strong document type or content context.";
    return `<article class="id-v6-card id-v6-group id-v13-group-card" data-suggestion-id="${id}">
      <div class="id-v6-head"><span>📁 Smart Organization &amp; Grouping</span><small>${pct(s)}% confidence</small></div>
      <div class="id-v6-group-title">${Math.max(names.length, ids.length, 2)} related documents</div>
      <div class="id-v6-dest"><small>${existing ? "Use existing folder" : "Create new smart folder"}</small><strong>${esc(path)}</strong></div>
      ${names.length ? `<div class="id-v6-docs">${names.map(n => `<div>• ${esc(n)}</div>`).join("")}</div>` : ""}
      ${ev.category ? `<div class="id-v6-meta">Category: ${esc(ev.category)}</div>` : ""}
      <div class="id-v6-reason">${esc(reason)}</div>
      <div class="id-v6-actions">
        <button class="btn btn-primary btn-sm" onclick="acceptSuggestion(${id}, this)">${existing ? "Use This Folder &amp; Organize" : "Create Folder &amp; Organize"}</button>
        <button class="btn btn-secondary btn-sm" onclick="keepSuggestion(${id}, this)">Keep As-Is</button>
        <button class="btn btn-secondary btn-sm" onclick="rejectSuggestion(${id}, this)">Reject</button>
      </div>
    </article>`;
  }

  // Replace the previous renderer. Focus is picked silently from upload state; no selector or per-card analyze button.
  window.loadSuggestions = async function () {
    const container = document.getElementById("suggestions-list-container");
    if (!container) return;
    container.style.display = "block";
    container.innerHTML = '<div class="id-v13-loading">Loading smart name and folder-group suggestions…</div>';
    for (const id of ["bulk-suggestions-summary-card", "bulk-suggestions-toolbar-card"]) {
      const el = document.getElementById(id); if (el) el.style.display = "none";
    }
    try {
      const docs = await recentDocuments();
      const allResponse = await apiFetch("/suggestions");
      const all = Array.isArray(allResponse) ? allResponse : [];
      if (!docs.length) {
        container.innerHTML = `<div class="id-v13-layout">
          <section class="id-v13-section id-v13-name-section"><div class="id-v13-section-heading"><div><h3>✨ Smart Name Suggestions</h3><p>One content-based filename and destination for each new upload.</p></div><span class="id-v13-count">0 proposals</span></div><div class="id-v13-empty">Upload a document to receive its smart filename and destination recommendation.</div></section>
          <section class="id-v13-section id-v13-group-section"><div class="id-v13-section-heading"><div><h3>📁 Smart Organization &amp; Grouping</h3><p>Related documents are grouped separately.</p></div><span class="id-v13-count">0 groups</span></div><div class="id-v13-empty">A grouping proposal appears when at least two documents share a strong document-type or content context.</div></section>
        </div>`;
        if (typeof window.fetchBadges === "function") await window.fetchBadges();
        return;
      }
      const savedFocus = readFocus();
      const focusedDoc = docs.find(d => Number(d.id) === savedFocus) || docs[0];
      const focusId = Number(focusedDoc.id);
      if (focusId !== savedFocus) writeFocus(focusId);
      const focusRowsRaw = await apiFetch(`/suggestions?document_id=${encodeURIComponent(focusId)}`);
      const focusRows = Array.isArray(focusRowsRaw) ? focusRowsRaw : [];
      // Only a still-pending rename for the current upload is displayed. Resolved decisions are not resurrected.
      const nameSuggestion = focusRows.find(s => s && s.suggestion_type === "rename" && s.status === "pending") || null;
      const groups = all.filter(isMeaningfulGroup);
      const nameContent = nameSuggestion
        ? renderNameCard(nameSuggestion)
        : '<div class="id-v13-empty"><strong>No pending smart-name suggestion.</strong><p>Upload a new file to see one smart filename and destination suggestion here. Previous decisions stay saved.</p></div>';
      const groupContent = groups.length
        ? groups.map(renderGroupCard).join("")
        : `<div class="id-v13-empty"><strong>No meaningful multi-document group is pending.</strong><p>When another document shares a strong category or content context, one folder-group proposal will appear here and update as matching files arrive.</p></div>`;
      container.innerHTML = `<div class="id-v13-layout">
        <section class="id-v13-section id-v13-name-section"><div class="id-v13-section-heading"><div><h3>✨ Smart Name Suggestions</h3><p>Smart filename and destination for the latest upload. Nothing changes without approval.</p></div><span class="id-v13-count">${nameSuggestion ? "1 proposal" : "0 proposals"}</span></div>${nameContent}</section>
        <section class="id-v13-section id-v13-group-section"><div class="id-v13-section-heading"><div><h3>📁 Smart Organization &amp; Grouping</h3><p>Independent multi-document folder proposals. No tag or sensitivity cards.</p></div><span class="id-v13-count">${groups.length} group${groups.length === 1 ? "" : "s"}</span></div>${groupContent}</section>
      </div>`;
      if (typeof window.fetchBadges === "function") await window.fetchBadges();
    } catch (err) {
      container.innerHTML = `<div class="id-v13-empty"><strong>Could not load AI suggestions.</strong><p>${esc(err && err.message ? err.message : err)}</p><button class="btn btn-secondary" onclick="window.loadSuggestions()">Retry</button></div>`;
    }
  };
  window.IntelliDocsSimpleSuggestionsV16 = true;
})();
/* === End IntelliDocs Simple Two-Panel Suggestions V16 === */

/* === IntelliDocs Smart Filing Lifecycle V18 === */
(function () {
  "use strict";
  const FOCUS_KEY = "intellidocs_suggestion_focus_document_id";
  const esc = (v) => typeof window.escapeHtml === "function" ? window.escapeHtml(v == null ? "" : String(v)) : String(v == null ? "" : v).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const evidence = (s) => { const e=s&&s.evidence; if(e&&typeof e==="object") return e; if(typeof e==="string"){try{return JSON.parse(e)||{};}catch(_){}} return {}; };
  const confidence = s => Math.max(0, Math.min(100, Math.round((Number(s&&s.confidence)||0)*100)));
  const focus = () => { try { return Number(sessionStorage.getItem(FOCUS_KEY)||0); } catch (_) { return 0; } };
  const putFocus = id => { try { sessionStorage.setItem(FOCUS_KEY,String(Number(id)||0)); } catch (_) {} };
  const normalized = v => String(v||"").toLowerCase().replace(/[^a-z0-9]+/g," ").trim();
  const escapeAttr = v => esc(v).replace(/`/g,"&#96;");

  async function refreshViews() {
    const work=[];
    for (const fn of ["loadSuggestions","fetchBadges","loadDocuments","loadDashboard","loadFolders","loadExplorerGraph"]) {
      try { if (typeof window[fn] === "function") work.push(Promise.resolve(window[fn]())); } catch (_) {}
    }
    await Promise.allSettled(work);
  }
  async function act(id, action, extra={}) {
    const card = document.querySelector(`[data-suggestion-id="${Number(id)}"]`);
    const buttons = card ? Array.from(card.querySelectorAll("button")) : [];
    buttons.forEach(b=>b.disabled=true);
    try {
      const payload = action === "edit" ? {method:"POST", body:JSON.stringify({custom_value:extra.custom_value})} : {method:"POST"};
      await apiFetch(`/suggestions/${Number(id)}/${action === "accept" ? "accept" : action === "keep" ? "keep" : action === "reject" ? "reject" : "edit"}`, payload);
      if (typeof window.showToast === "function") window.showToast(action === "accept" ? (extra.message || "Applied successfully.") : action === "edit" ? "Edited recommendation applied." : action === "keep" ? "Kept as-is. Your decision is saved." : "Suggestion rejected.", action === "accept" || action === "edit" ? "success" : "info");
      await refreshViews();
    } catch (err) {
      buttons.forEach(b=>b.disabled=false);
      if (typeof window.showToast === "function") window.showToast((action.charAt(0).toUpperCase()+action.slice(1))+" failed: "+(err&&err.message||err),"error");
    }
  }
  window.v18AcceptSuggestion = (id, button) => act(id,"accept");
  window.v18KeepSuggestion = (id, button) => act(id,"keep");
  window.v18RejectSuggestion = (id, button) => act(id,"reject");
  window.v18EditName = (id, button) => {
    const card=button&&button.closest("[data-suggestion-id]");
    const suggested=card&&card.querySelector(".id-v18-suggested-name")&&card.querySelector(".id-v18-suggested-name").textContent.trim();
    const value=prompt("Edit the suggested filename:",suggested||"");
    if(value===null||!value.trim()) return;
    return act(id,"edit",{custom_value:value.trim()});
  };
  window.v18EditFolder = (id, button) => {
    const card=button&&button.closest("[data-suggestion-id]");
    const suggested=card&&card.querySelector(".id-v18-folder-path")&&card.querySelector(".id-v18-folder-path").textContent.trim();
    const value=prompt("Edit destination path (Category / Folder):",suggested||"");
    if(value===null||!value.trim()) return;
    // The backend treats an edited value as an explicit destination path.
    return act(id,"edit",{custom_value:value.trim()});
  };

  function isGroup(s) {
    if(!s||s.suggestion_type!=="create_folder_group"||s.status!=="pending") return false;
    const ev=evidence(s), ids=Array.isArray(ev.document_ids)?ev.document_ids:[];
    return ids.length>=2 && (ev.v14_strong_group===true || !!ev.v14_group_key);
  }
  // Single source of truth for counts shown by the sidebar and dashboard.
  // Hidden tag/category/sensitivity proposals are intentionally excluded from this page's count.
  window.intelliDocsVisibleSuggestionRows = function(inputRows) {
    const rows = Array.isArray(inputRows) ? inputRows : [];
    const pending = rows.filter(s => s && s.status === "pending");
    const groups = pending.filter(s => s && s.suggestion_type === "create_folder_group" && isGroup(s));
    const groupedDocIds = new Set();
    groups.forEach(g => {
      const ids = Array.isArray(evidence(g).document_ids) ? evidence(g).document_ids : [];
      ids.forEach(id => groupedDocIds.add(Number(id)));
    });
    const names = pending.filter(s => s.suggestion_type === "rename");
    const routes = pending.filter(s => s.suggestion_type === "route_folder" && !groupedDocIds.has(Number(s.document_id)));
    const combined = [...names, ...routes, ...groups];
    const seen = new Set();
    return combined.filter(s => {
      const id = Number(s.id);
      if (!Number.isFinite(id) || seen.has(id)) return false;
      seen.add(id); return true;
    });
  };
  function renderName(s) {
    const ev=evidence(s), id=Number(s.id);
    const current=s.current_value||ev.document_name||"Current filename";
    const proposed=ev.generated_filename||s.suggested_value||current;
    const reason="Suggested from this document's text, OCR, and visual content where available.";
    return `<article class="id-v6-card id-v18-name-card" data-suggestion-id="${id}">
      <div class="id-v6-head"><span>✨ Smart Name</span><small>${confidence(s)}% confidence</small></div>
      <div class="id-v6-current"><strong>Current name</strong><div>${esc(current)}</div></div>
      <div class="id-v6-title id-v18-suggested-name">${esc(proposed)}</div>
      <div class="id-v6-reason">${esc(reason)}</div>
      <div class="id-v6-actions">
        <button class="btn btn-primary btn-sm" onclick="v18AcceptSuggestion(${id}, this)">Apply Name</button>
        <button class="btn btn-secondary btn-sm" onclick="v18EditName(${id}, this)">Edit</button>
        <button class="btn btn-secondary btn-sm" onclick="v18KeepSuggestion(${id}, this)">Keep Current</button>
        <button class="btn btn-secondary btn-sm" onclick="v18RejectSuggestion(${id}, this)">Reject</button>
      </div>
    </article>`;
  }
  function renderRoute(s) {
    const ev=evidence(s), id=Number(s.id), path=ev.destination_folder_path||s.suggested_value||"Suggested folder";
    const mode=String(ev.destination_mode||"create").toLowerCase();
    const category=ev.destination_category||"General";
    const label=mode==="existing"?"Use existing folder":"Create folder if needed";
    const reason=s.reason||ev.destination_reason||"Suggested from the file's category and extracted text, OCR, or local image description.";
    return `<article class="id-v6-card id-v18-route-card" data-suggestion-id="${id}">
      <div class="id-v6-head"><span>📁 Where this file belongs</span><small>${confidence(s)}% confidence</small></div>
      <div class="id-v6-dest"><small>${esc(label)}</small><strong class="id-v18-folder-path">${esc(path)}</strong></div>
      <div class="id-v18-meta">Category: ${esc(category)}</div>
      <div class="id-v6-reason">${esc(reason)}</div>
      <div class="id-v6-actions">
        <button class="btn btn-primary btn-sm" onclick="v18AcceptSuggestion(${id}, this)">Apply Folder</button>
        <button class="btn btn-secondary btn-sm" onclick="v18EditFolder(${id}, this)">Edit</button>
        <button class="btn btn-secondary btn-sm" onclick="v18KeepSuggestion(${id}, this)">Keep Current</button>
        <button class="btn btn-secondary btn-sm" onclick="v18RejectSuggestion(${id}, this)">Reject</button>
      </div>
    </article>`;
  }
  function renderGroup(s) {
    const ev=evidence(s), id=Number(s.id), path=ev.target_folder_path||s.suggested_value||"Suggested folder";
    const mode=String(ev.target_mode||"new").toLowerCase(), existing=mode==="existing";
    const names=Array.isArray(ev.document_names)?ev.document_names:[], ids=Array.isArray(ev.document_ids)?ev.document_ids:[];
    const reason=s.reason||"These documents share a document type or clear content context.";
    return `<article class="id-v6-card id-v18-group-card" data-suggestion-id="${id}">
      <div class="id-v6-head"><span>📂 Related documents</span><small>${confidence(s)}% confidence</small></div>
      <div class="id-v6-group-title">${Math.max(names.length,ids.length)} related documents</div>
      <div class="id-v6-dest"><small>${existing?"Use existing folder":"Create folder if needed"}</small><strong>${esc(path)}</strong></div>
      ${names.length?`<div class="id-v6-docs">${names.map(n=>`<div>• ${esc(n)}</div>`).join("")}</div>`:""}
      ${ev.category?`<div class="id-v18-meta">Category: ${esc(ev.category)}</div>`:""}
      <div class="id-v6-reason">${esc(reason)}</div>
      <div class="id-v6-actions">
        <button class="btn btn-primary btn-sm" onclick="v18AcceptSuggestion(${id}, this)">${existing?"Use Folder &amp; Organize":"Create Folder &amp; Organize"}</button>
        <button class="btn btn-secondary btn-sm" onclick="v18EditFolder(${id}, this)">Edit</button>
        <button class="btn btn-secondary btn-sm" onclick="v18KeepSuggestion(${id}, this)">Keep Current</button>
        <button class="btn btn-secondary btn-sm" onclick="v18RejectSuggestion(${id}, this)">Reject</button>
      </div>
    </article>`;
  }

  const _v18OriginalFetchBadges = window.fetchBadges;
  window.fetchBadges = async function(...args) {
    if (typeof _v18OriginalFetchBadges === "function") {
      try { await _v18OriginalFetchBadges.apply(this,args); } catch (_) {}
    }
    try {
      const response = await apiFetch("/suggestions");
      const rows = Array.isArray(response) ? response : [];
      const visible = typeof window.intelliDocsVisibleSuggestionRows === "function"
        ? window.intelliDocsVisibleSuggestionRows(rows)
        : rows.filter(s => s && s.status === "pending" && ["rename", "route_folder", "create_folder_group"].includes(s.suggestion_type));
      const badge = document.getElementById("badge-suggestions");
      if (badge) { badge.textContent = String(visible.length); badge.style.display = visible.length ? "inline-block" : "none"; }
    } catch (_) {}
  };

  window.loadSuggestions = async function() {
    const container = document.getElementById("suggestions-list-container");
    if (!container) return;
    for (const id of ["bulk-suggestions-summary-card", "bulk-suggestions-toolbar-card"]) {
      const el = document.getElementById(id); if (el) el.style.display = "none";
    }
    container.innerHTML = '<div class="id-v13-loading">Loading all pending smart filing recommendations…</div>';
    try {
      const savedFocus = focus();
      const docsResponse = await apiFetch("/documents?limit=100&sort_by=uploaded_at&order=desc");
      const ownedDocs = Array.isArray(docsResponse) ? docsResponse.filter(d => d && Number(d.id) > 0) : [];
      let receivedDocs = [];
      try {
        const sharesResponse = await apiFetch("/shares/received");
        const shares = Array.isArray(sharesResponse) ? sharesResponse : [];
        const byDocumentId = new Map();
        for (const share of shares) {
          const id = Number(share && share.document_id);
          const uuid = String(share && share.document_uuid || "");
          const keyReady = !share.share_key_required || !!share.share_key_verified;
          // Pending/not-yet-activated shares must never enter recipient analysis.
          if (!id || !uuid || !share.active || !share.access_activated || !keyReady) continue;
          if (!byDocumentId.has(id)) byDocumentId.set(id, {
            id, uuid, document_uuid: uuid,
            original_name: share.document_name || "Received document",
            display_name: share.document_name || "Received document",
            version_number: Number(share.version_number) || 1,
            uploaded_at: share.created_at || share.updated_at || "",
            is_recipient_shared: true,
            access_locked: !!share.access_locked,
            share_source: share.source || "direct",
            share_id: Number(share.id) || 0,
            share_key_required: !!share.share_key_required,
            share_key_verified: !!share.share_key_verified,
            owner_username: share.owner_username || "Unknown"
          });
        }
        receivedDocs = Array.from(byDocumentId.values());
      } catch (receivedError) {
        // A sharing API hiccup must not hide the recipient's normal own-library suggestions.
        console.warn("[Suggestions] Could not load activated received documents:", receivedError);
      }
      const mergedDocs = new Map(ownedDocs.map(d => [Number(d.id), d]));
      // Do not replace an owner's canonical document row with a recipient projection.
      for (const d of receivedDocs) if (!mergedDocs.has(Number(d.id))) mergedDocs.set(Number(d.id), d);
      const docs = Array.from(mergedDocs.values());
      const docById = new Map(docs.map(d => [Number(d.id), d]));
      let fid = savedFocus;
      if (!docById.has(fid)) {
        // When opened from Received by Me, the newest activated received item is
        // the natural first focus; otherwise retain the normal newest-owned-file behavior.
        const defaultDoc = receivedDocs[0] || docs[0] || null;
        fid = defaultDoc ? Number(defaultDoc.id) : 0;
        putFocus(fid);
      }
      // Resolve lock context from the actual focused document, including received shares.
      const focusedDoc = docById.get(Number(fid));
      const focusedUuid = String(focusedDoc && (focusedDoc.uuid || focusedDoc.document_uuid) || "");
      const focusedLockToken = focusedUuid && lockTokens[focusedUuid] ? lockTokens[focusedUuid] : "";
      // An explicit empty token prevents apiFetch from accidentally attaching a token
      // belonging to another document currently open in the detail panel.
      const focusedHeaders = getDocumentLockTokenHeaders(focusedUuid);
      const analysisWarnings = [];
      if (fid > 0 && focusedDoc) {
        if (focusedDoc.access_locked && !focusedLockToken) {
          analysisWarnings.push("This received document is Access-Locked. Open it from Received by Me and unlock it before running private analysis.");
        } else {
          try {
            await apiFetch(`/suggestions/analyze?document_id=${encodeURIComponent(fid)}`, {
              method: "POST", headers: focusedHeaders
            });
          } catch (analysisError) {
            analysisWarnings.push(`Document analysis did not complete: ${analysisError && analysisError.message ? analysisError.message : analysisError}`);
            console.warn("[Suggestions] Focused-document analysis did not complete:", analysisError);
          }
        }
      }
      // Group analysis is explicitly refreshed for receiver-side documents too. The
      // backend applies per-share activation and Access Lock checks to each candidate.
      try {
        await apiFetch("/suggestions/analyze-groups", { method: "POST", headers: focusedHeaders });
      } catch (groupError) {
        analysisWarnings.push(`Folder grouping could not be refreshed: ${groupError && groupError.message ? groupError.message : groupError}`);
        console.warn("[Suggestions] Group analysis did not complete:", groupError);
      }
      const analysisBanner = analysisWarnings.length
        ? `<div class="id-v13-empty" role="status" style="margin-bottom:12px;border-style:solid;">${analysisWarnings.map(w => `<p>${esc(w)}</p>`).join("")}</div>`
        : "";
      const response = await apiFetch("/suggestions", { headers: focusedHeaders });
      const all = Array.isArray(response) ? response : [];
      const pending = all.filter(s => s && s.status === "pending");
      const names = pending.filter(s => s.suggestion_type === "rename");
      const groups = pending.filter(isGroup);
      const groupedDocIds = new Set();
      groups.forEach(g => {
        const ids = Array.isArray(evidence(g).document_ids) ? evidence(g).document_ids : [];
        ids.forEach(id => groupedDocIds.add(Number(id)));
      });
      const routes = pending.filter(s => s.suggestion_type === "route_folder" && !groupedDocIds.has(Number(s.document_id)));
      const docLabel = s => {
        const d = docById.get(Number(s && s.document_id));
        const ev = evidence(s);
        return (d && (d.display_name || d.original_name)) || ev.document_name || ev.original_filename || s.current_value || `Document #${s.document_id || "?"}`;
      };
      const order = id => { const i = docs.findIndex(d => Number(d.id) === Number(id)); return i < 0 ? Number.MAX_SAFE_INTEGER - Number(id || 0) : i; };
      names.sort((a,b) => order(a.document_id)-order(b.document_id) || Number(a.id)-Number(b.id));
      routes.sort((a,b) => order(a.document_id)-order(b.document_id) || Number(a.id)-Number(b.id));
      const nameCards = names.map(s => `<div class="id-v19-suggestion-stack-item"><div class="id-v19-document-label">📄 ${esc(docLabel(s))}</div>${renderName(s)}</div>`).join("");
      const routeCards = routes.map(s => `<div class="id-v19-suggestion-stack-item"><div class="id-v19-document-label">📄 ${esc(docLabel(s))}</div>${renderRoute(s)}</div>`).join("");
      const groupCards = groups.map(renderGroup).join("");
      const leftContent = nameCards || '<div class="id-v13-empty"><strong>No pending filename suggestions.</strong><p>New uploads appear here without replacing earlier unresolved recommendations.</p></div>';
      const rightContent = (routeCards + groupCards) || '<div class="id-v13-empty"><strong>No pending folder recommendations.</strong><p>Document destinations and meaningful multi-document groups stay here until you decide.</p></div>';
      const rightCount = routes.length + groups.length;
      container.innerHTML = `${analysisBanner}<div class="id-v19-stack-layout">
        <section class="id-v13-section id-v18-name-section"><div class="id-v13-section-heading"><div><h3>✨ Smart Name Suggestions</h3><p>All unresolved filename recommendations remain visible until you apply, keep, or reject them.</p></div><span class="id-v13-count">${names.length} proposal${names.length===1?"":"s"}</span></div><div class="id-v19-stack">${leftContent}</div></section>
        <section class="id-v13-section id-v18-folder-section"><div class="id-v13-section-heading"><div><h3>📁 Smart Organization &amp; Grouping</h3><p>Unresolved destinations and meaningful multi-document groups are shown together.</p></div><span class="id-v13-count">${rightCount} recommendation${rightCount===1?"":"s"}</span></div><div class="id-v19-stack">${rightContent}</div></section>
      </div>`;
      if (typeof window.fetchBadges === "function") await window.fetchBadges();
    } catch (err) {
      container.innerHTML = `<div class="id-v13-empty"><strong>Could not load filing suggestions.</strong><p>${esc(err && err.message ? err.message : err)}</p><button class="btn btn-secondary" onclick="window.loadSuggestions()">Retry</button></div>`;
    }
  };

  window.triggerAnalyzeLibrarySuggestions = async function(button) {
    const el = button || document.getElementById("btn-re-evaluate-suggestions");
    const old = el ? el.innerText : "";
    if (el) { el.disabled = true; el.innerText = "Re-evaluating…"; }
    try {
      await window.loadSuggestions();
      if (typeof window.showToast === "function") window.showToast("Document suggestions and accessible folder groups refreshed.", "success");
    } catch (err) {
      if (typeof window.showToast === "function") window.showToast("Re-evaluation failed: " + (err && err.message || err), "error");
    } finally {
      if (el) { el.disabled = false; el.innerText = old || "⚡ Re-evaluate AI Insights"; }
    }
  };
  // INTELLIDOCS_RECEIVER_DOCUMENT_INTELLIGENCE_FIX_V1
  window.IntelliDocsSmartFilingLifecycleV18 = true;
})();
/* === End IntelliDocs Smart Filing Lifecycle V18 === */



/* INTELLIDOCS_V19_PERSISTENT_SUGGESTIONS_DUPLICATE_REPAIR */
