const API_BASE = "/api";
let authToken = localStorage.getItem("token");
let currentUser = localStorage.getItem("username");

const homePage = document.getElementById("home-page");
const signupPage = document.getElementById("signup-page");
const loginPage = document.getElementById("login-page");
const forgotPage = document.getElementById("forgot-page");
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

function showToast(message, isError = false) {
  toast.textContent = message;
  toast.classList.remove("hidden", "error");
  if (isError) toast.classList.add("error");
  setTimeout(() => toast.classList.add("hidden"), 2500);
}

async function api(path, { method = "GET", body } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (authToken) headers.Authorization = `Bearer ${authToken}`;
  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}));
    throw new Error(detail.detail || "Request failed");
  }
  return res.json();
}

function showPage(page) {
  homePage.classList.add("hidden");
  signupPage.classList.add("hidden");
  loginPage.classList.add("hidden");
  forgotPage.classList.add("hidden");
  appPage.classList.add("hidden");
  if (page === "home") homePage.classList.remove("hidden");
  if (page === "signup") signupPage.classList.remove("hidden");
  if (page === "login") loginPage.classList.remove("hidden");
  if (page === "forgot") forgotPage.classList.remove("hidden");
  if (page === "app") appPage.classList.remove("hidden");
}

function setAuthenticated(username, token) {
  currentUser = username;
  authToken = token;
  if (token) {
    localStorage.setItem("token", token);
    localStorage.setItem("username", username);
    showPage("app");
    sessionUser.textContent = `Logged in as ${username}`;
    refreshData();
  } else {
    localStorage.removeItem("token");
    localStorage.removeItem("username");
    recipientSelect.innerHTML = "";
    inboxEl.innerHTML = "";
    showPage("home");
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

registerForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(registerForm));
  try {
    await api("/register", { method: "POST", body: data });
    showToast("Registration successful");
    registerForm.reset();
  } catch (error) {
    showToast(error.message, true);
  }
});

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(loginForm));
  try {
    const response = await api("/login", { method: "POST", body: data });
    setAuthenticated(response.username, response.token);
    loginForm.reset();
  } catch (error) {
    showToast(error.message, true);
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
  setAuthenticated(null, null);
});

getStartedBtn.addEventListener("click", () => {
  showPage("signup");
});

goLoginBtnHome.addEventListener("click", () => {
  showPage("login");
});

goLoginBtn.addEventListener("click", () => {
  showPage("login");
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
    showToast("Reset code generated. See alert (demo) and open reset page.");
    alert(`Your reset code (demo only, would be emailed): ${response.code}`);
    window.location.href = `/reset_password.html?email=${encodeURIComponent(data.email)}`;
  } catch (error) {
    showToast(error.message, true);
  }
});

async function bootstrap() {
  if (!authToken) return;
  try {
    await refreshData();
    showPage("app");
    sessionUser.textContent = `Logged in as ${currentUser}`;
  } catch {
    setAuthenticated(null, null);
  }
}

bootstrap();
