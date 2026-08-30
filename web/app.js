/*
 * app.js
 * ------
 * What this is: all the browser-side logic for CyberShield AI — switching
 * between pages, sending the analyzer form to the server, and rendering
 * the results screen.
 *
 * Why it's built this way: no framework (React, Vue, etc.) is used,
 * only plain DOM APIs, to satisfy the zero-third-party-dependency rule.
 * Everything here is native browser JavaScript.
 */

const state = {
  currentType: "message",
  currentTab: "simple",
  lastResult: null,
};

const CHAR_LIMITS = { message: 5000, url: 2048 };

// ---------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------

function showView(name) {
  document.querySelectorAll(".view").forEach((el) => el.classList.remove("active"));
  document.querySelectorAll("nav.tabs button").forEach((el) => el.classList.remove("active"));

  const view = document.getElementById(`view-${name}`);
  if (view) view.classList.add("active");

  const navBtn = document.querySelector(`nav.tabs button[data-view="${name}"]`);
  if (navBtn) navBtn.classList.add("active");

  window.scrollTo({ top: 0, behavior: "smooth" });
}

document.querySelectorAll("nav.tabs button").forEach((btn) => {
  btn.addEventListener("click", () => showView(btn.dataset.view));
});

document.querySelectorAll("[data-goto]").forEach((btn) => {
  btn.addEventListener("click", () => showView(btn.dataset.goto));
});

// ---------------------------------------------------------------------
// Analyzer: type selector + char count
// ---------------------------------------------------------------------

const contentInput = document.getElementById("content-input");
const charCountEl = document.getElementById("char-count");
const charMaxEl = document.getElementById("char-max");
const errorBanner = document.getElementById("error-banner");

document.querySelectorAll(".type-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".type-btn").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    state.currentType = btn.dataset.type;

    const limit = CHAR_LIMITS[state.currentType];
    charMaxEl.textContent = limit;
    updateCharCount();

    contentInput.placeholder =
      state.currentType === "url"
        ? "Paste the suspicious URL here, e.g. http://secure-login-paypal.verify-account.xyz"
        : "Paste the suspicious message here, e.g. 'Your bank account will be blocked today. Verify your account immediately by clicking this link.'";

    hideError();
  });
});

function updateCharCount() {
  charCountEl.textContent = contentInput.value.length;
}

contentInput.addEventListener("input", updateCharCount);

function showError(message) {
  errorBanner.textContent = message;
  errorBanner.classList.add("show");
}

function hideError() {
  errorBanner.classList.remove("show");
}

// ---------------------------------------------------------------------
// Analyze button
// ---------------------------------------------------------------------

const analyzeBtn = document.getElementById("analyze-btn");

analyzeBtn.addEventListener("click", async () => {
  const content = contentInput.value.trim();
  hideError();

  if (!content) {
    showError(
      state.currentType === "url"
        ? "Please enter a URL to analyze."
        : "Please enter a message to analyze."
    );
    return;
  }

  analyzeBtn.disabled = true;
  analyzeBtn.textContent = "Analyzing…";

  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: state.currentType, content }),
    });

    const data = await response.json();

    if (!data.ok) {
      showError(data.error || "Something went wrong. Please try again.");
      return;
    }

    state.lastResult = data;
    renderResults(data);
    showView("results");
  } catch (err) {
    showError(
      "Couldn't reach the analysis engine. Check that the server is running and try again."
    );
  } finally {
    analyzeBtn.disabled = false;
    analyzeBtn.textContent = "Analyze →";
  }
});

// ---------------------------------------------------------------------
// Results rendering
// ---------------------------------------------------------------------

const RISK_COLORS = {
  CRITICAL: "#ff3b5c",
  HIGH: "#ff8a3d",
  MEDIUM: "#ffd23f",
  LOW: "#2de6a6",
};

const RISK_ICONS = {
  CRITICAL: "🔴",
  HIGH: "🟠",
  MEDIUM: "🟡",
  LOW: "🟢",
};

const CIRCLE_CIRCUMFERENCE = 351.86; // 2 * PI * 56

function renderResults(data) {
  document.getElementById("results-empty").style.display = "none";
  document.getElementById("results-content").style.display = "block";

  const color = RISK_COLORS[data.level] || RISK_COLORS.LOW;

  // Risk ring
  const ringFg = document.getElementById("risk-ring-fg");
  const offset = CIRCLE_CIRCUMFERENCE - (data.score / 100) * CIRCLE_CIRCUMFERENCE;
  ringFg.style.stroke = color;
  // Reset then animate on next frame so the transition actually plays.
  ringFg.style.strokeDashoffset = CIRCLE_CIRCUMFERENCE;
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      ringFg.style.strokeDashoffset = offset;
    });
  });

  document.getElementById("risk-score-num").textContent = data.score;
  document.getElementById("risk-score-num").style.color = color;

  const badge = document.getElementById("risk-badge");
  badge.textContent = `${RISK_ICONS[data.level] || ""} ${data.level} RISK`;
  badge.style.background = `${color}22`;
  badge.style.color = color;
  badge.style.border = `1px solid ${color}55`;

  document.getElementById("risk-category").textContent = toTitleCase(data.category);
  document.getElementById("risk-confidence").textContent = data.confidence;

  // Indicators
  const indicatorList = document.getElementById("indicator-list");
  indicatorList.innerHTML = "";
  if (data.contributing_indicators.length === 0) {
    indicatorList.innerHTML = "<li>No warning signs detected from the current rule set.</li>";
  } else {
    data.contributing_indicators.forEach((item) => {
      const li = document.createElement("li");
      li.innerHTML = `<span>✓ ${escapeHtml(item.label)}</span><span class="weight">+${item.points}</span>`;
      indicatorList.appendChild(li);
    });
  }

  // Recommended actions
  const avoidList = document.getElementById("avoid-list");
  const doList = document.getElementById("do-list");
  avoidList.innerHTML = "";
  doList.innerHTML = "";

  (data.recommended_actions.avoid || []).forEach((text) => {
    const li = document.createElement("li");
    li.innerHTML = `<span>❌</span><span>${escapeHtml(text)}</span>`;
    avoidList.appendChild(li);
  });

  (data.recommended_actions.do || []).forEach((text) => {
    const li = document.createElement("li");
    li.innerHTML = `<span>✅</span><span>${escapeHtml(text)}</span>`;
    doList.appendChild(li);
  });

  // Explanations
  document.getElementById("ai-note-text").textContent = data.ai_context;
  state.currentTab = "simple";
  renderExplanationTab(data);
}

function renderExplanationTab(data) {
  document.querySelectorAll(".explanation-tabs button").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.tab === state.currentTab);
  });

  const body = document.getElementById("explanation-body");
  body.textContent =
    state.currentTab === "simple" ? data.simple_explanation : data.technical_explanation;
}

document.querySelectorAll(".explanation-tabs button").forEach((btn) => {
  btn.addEventListener("click", () => {
    state.currentTab = btn.dataset.tab;
    if (state.lastResult) renderExplanationTab(state.lastResult);
  });
});

// ---------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------

function toTitleCase(str) {
  return str
    .toLowerCase()
    .split(" ")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}