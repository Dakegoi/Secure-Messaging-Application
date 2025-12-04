const API_BASE = "/api";
// Use cookies instead of localStorage for session token
let currentUser = null;

const homePage = document.getElementById("home-page");
const signupPage = document.getElementById("signup-page");
const loginPage = document.getElementById("login-page");
const forgotPage = document.getElementById("forgot-page");
const totpSetupPage = document.getElementById("totp-setup-page");
const appPage = document.getElementById("app-page");
const sessionUser = document.getElementById("session-user");
const recipientSelect = document.getElementById("recipient-select");
const inboxEl = document.getElementById("inbox");
const toast = document.getElementById("toast");

const registerForm = document.getElementById("register-form");
const loginForm = document.getElementById("login-form");
const sendForm = document.getElementById("send-form");
const groupSendForm = document.getElementById("group-send-form");
const groupRecipientsInput = document.getElementById("group-recipients");
const groupMessageInput = document.getElementById("group-message-input");
const logoutBtn = document.getElementById("logout-btn");
const getStartedBtn = document.getElementById("get-started-btn");
const goLoginBtnHome = document.getElementById("go-login-btn-home");
const goLoginBtn = document.getElementById("go-login-btn");
const goSignupBtn = document.getElementById("go-signup-btn");
const goForgotBtn = document.getElementById("go-forgot-btn");
const goLoginFromForgotBtn = document.getElementById("go-login-from-forgot");
const forgotForm = document.getElementById("forgot-form");
const totpSection = document.getElementById("totp-section");
const setupTotpBtn = document.getElementById("setup-totp-btn");
const disableTotpBtn = document.getElementById("disable-totp-btn");
const totpSetupDoneBtn = document.getElementById("totp-setup-done-btn");
const registerPasswordInput = document.getElementById("register-password");

// Password validation regex
const passwordRegex = {
  minLength: /.{8,}/,
  hasLetter: /[a-zA-Z]/,
  hasNumber: /[0-9]/,
  hasSpecial: /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/
};

function showToast(message, isError = false) {
  toast.textContent = message;
  toast.classList.remove("hidden", "error");
  if (isError) toast.classList.add("error");
  setTimeout(() => toast.classList.add("hidden"), 5000);
}

async function api(path, { method = "GET", body, credentials = "include" } = {}) {
  // credentials: "include" ensures cookies are sent with requests
  const headers = { "Content-Type": "application/json" };
  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers,
    credentials,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}));
    throw new Error(detail.detail || detail.message || "Request failed");
  }
  return res.json();
}

function showPage(page) {
  homePage.classList.add("hidden");
  signupPage.classList.add("hidden");
  loginPage.classList.add("hidden");
  forgotPage.classList.add("hidden");
  totpSetupPage.classList.add("hidden");
  appPage.classList.add("hidden");
  if (page === "home") homePage.classList.remove("hidden");
  if (page === "signup") signupPage.classList.remove("hidden");
  if (page === "login") loginPage.classList.remove("hidden");
  if (page === "forgot") forgotPage.classList.remove("hidden");
  if (page === "totp-setup") totpSetupPage.classList.remove("hidden");
  if (page === "app") appPage.classList.remove("hidden");
}

function validatePassword(password) {
  if (!passwordRegex.minLength.test(password)) {
    return { valid: false, message: "Password must be at least 8 characters long" };
  }
  if (!passwordRegex.hasLetter.test(password)) {
    return { valid: false, message: "Password must contain at least one letter" };
  }
  if (!passwordRegex.hasNumber.test(password)) {
    return { valid: false, message: "Password must contain at least one number" };
  }
  if (!passwordRegex.hasSpecial.test(password)) {
    return { valid: false, message: "Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)" };
  }
  return { valid: true, message: "" };
}

function setAuthenticated(username) {
  currentUser = username;
  if (username) {
    showPage("app");
    sessionUser.textContent = `Logged in as ${username}`;
    refreshData();
  } else {
    showPage("home");
    recipientSelect.innerHTML = "";
    inboxEl.innerHTML = "";
  }
}

async function refreshData() {
  try {
    const users = await api("/users");
    renderUsers(users);
    const inbox = await api("/messages");
    renderInbox(inbox);
  } catch (error) {
    showToast(error.message, true);
  }
}

function renderUsers(users) {
  recipientSelect.innerHTML = "";
  users
    .filter((user) => user !== currentUser)
    .forEach((user) => {
      const option = document.createElement("option");
      option.value = user;
      option.textContent = user;
      recipientSelect.appendChild(option);
    });
  if (!recipientSelect.value) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = users.length ? "Select recipient" : "No users";
    option.disabled = true;
    option.selected = true;
    recipientSelect.appendChild(option);
  }
}

function renderInbox(messages) {
  if (!messages.length) {
    inboxEl.innerHTML = "<p>No messages yet.</p>";
    return;
  }
  inboxEl.innerHTML = "";
  messages.forEach((msg) => {
    const container = document.createElement("div");
    container.className = "message";
    const status = msg.signature_valid ? "valid" : "invalid";
    container.innerHTML = `
      <strong>From ${msg.from}</strong>
      <small>${msg.timestamp} · signature ${status}</small>
      <p>${msg.message}</p>
    `;
    inboxEl.appendChild(container);
  });
}

// Password validation on input
if (registerPasswordInput) {
  registerPasswordInput.addEventListener("input", (e) => {
    const validation = validatePassword(e.target.value);
    const hint = document.getElementById("password-hint");
    if (e.target.value.length > 0) {
      if (!validation.valid) {
        hint.textContent = validation.message;
        hint.style.color = "#dc2626";
      } else {
        hint.textContent = "Password meets requirements ✓";
        hint.style.color = "#16a34a";
      }
    } else {
      hint.textContent = "Password must be at least 8 characters with at least one letter, one number, and one special character";
      hint.style.color = "";
    }
  });
}

registerForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(registerForm));
  
  // Client-side password validation
  const validation = validatePassword(data.password);
  if (!validation.valid) {
    showToast(validation.message, true);
    return;
  }
  
  try {
    await api("/register", { method: "POST", body: data });
    showToast("Registration successful");
    registerForm.reset();
    showPage("login");
  } catch (error) {
    showToast(error.message, true);
  }
});

let pendingUsername = null;
let pendingPassword = null;

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(loginForm));
  
  // Store credentials for TOTP verification
  if (!totpSection.classList.contains("hidden")) {
    // TOTP verification step
    try {
      const response = await api("/login", { method: "POST", body: data });
      setAuthenticated(response.username);
      loginForm.reset();
      totpSection.classList.add("hidden");
      pendingUsername = null;
      pendingPassword = null;
    } catch (error) {
      showToast(error.message, true);
    }
  } else {
    // Initial login attempt
    pendingUsername = data.username;
    pendingPassword = data.password;
    try {
      const response = await api("/login", { method: "POST", body: { username: data.username, password: data.password } });
      if (response.requires_totp) {
        // Show TOTP input
        totpSection.classList.remove("hidden");
        showToast("TOTP code required. Enter the 6-digit code from your authenticator app.");
      } else {
        // Login successful
        setAuthenticated(response.username);
        loginForm.reset();
      }
    } catch (error) {
      showToast(error.message, true);
    }
  }
});

sendForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const recipient = recipientSelect.value;
  const message = document.getElementById("message-input").value.trim();
  if (!recipient || !message) {
    showToast("Recipient and message required", true);
    return;
  }
  try {
    await api("/messages", { method: "POST", body: { recipient, message } });
    showToast("Message sent");
    document.getElementById("message-input").value = "";
    refreshData();
  } catch (error) {
    showToast(error.message, true);
  }
});

groupSendForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const rawRecipients = groupRecipientsInput.value || "";
  const recipients = rawRecipients
    .split(",")
    .map((r) => r.trim())
    .filter((r) => r.length > 0);
  const message = groupMessageInput.value.trim();
  if (!recipients.length || !message) {
    showToast("Recipients and message required", true);
    return;
  }
  try {
    await api("/group-messages", { method: "POST", body: { recipients, message } });
    showToast(`Group message sent to ${recipients.length} users`);
    groupMessageInput.value = "";
    refreshData();
  } catch (error) {
    showToast(error.message, true);
  }
});

logoutBtn.addEventListener("click", async () => {
  try {
    await api("/logout", { method: "POST" });
  } catch (error) {
    console.warn(error);
  }
  setAuthenticated(null);
});

getStartedBtn.addEventListener("click", () => {
  showPage("signup");
});

goLoginBtnHome.addEventListener("click", () => {
  showPage("login");
});

goLoginBtn.addEventListener("click", () => {
  showPage("login");
  totpSection.classList.add("hidden");
});

goSignupBtn.addEventListener("click", () => {
  showPage("signup");
});

goForgotBtn.addEventListener("click", () => {
  showPage("forgot");
});

goLoginFromForgotBtn.addEventListener("click", () => {
  showPage("login");
});

forgotForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(forgotForm));
  if (!data.email) {
    showToast("Email required", true);
    return;
  }
  try {
    const response = await api("/forgot-password", { method: "POST", body: data });
    // Show user-friendly message (token is sent via email, not returned)
    showToast(response.message || "Reset token generated. Please check your email.");
    // Clear form
    forgotForm.reset();
    // Optionally redirect to login page after a delay
    setTimeout(() => {
      showPage("login");
    }, 2000);
  } catch (error) {
    // Handle network errors or other issues
    showToast(error.message || "Failed to process reset request. Please try again.", true);
  }
});

setupTotpBtn.addEventListener("click", async () => {
  try {
    const response = await api("/totp/setup", { method: "POST" });
    document.getElementById("totp-qr-code").src = response.qr_code;
    document.getElementById("totp-secret").textContent = response.secret;
    showPage("totp-setup");
  } catch (error) {
    showToast(error.message, true);
  }
});

totpSetupDoneBtn.addEventListener("click", () => {
  showPage("app");
  showToast("TOTP enabled. You'll be asked for a code on next login.");
});

disableTotpBtn.addEventListener("click", async () => {
  if (!confirm("Are you sure you want to disable two-factor authentication?")) {
    return;
  }
  try {
    await api("/totp/disable", { method: "POST" });
    showToast("TOTP disabled");
    disableTotpBtn.classList.add("hidden");
    setupTotpBtn.classList.remove("hidden");
  } catch (error) {
    showToast(error.message, true);
  }
});

async function bootstrap() {
  // Check if user is authenticated by trying to fetch user data
  try {
    const users = await api("/users");
    // If we get here, we're authenticated
    // Try to get username from a user endpoint or session
    // For now, we'll just show the app page
    showPage("app");
    refreshData();
  } catch {
    // Not authenticated
    setAuthenticated(null);
  }
}

bootstrap();
