// VaultBase — Popup Controller
// Full MFA state machine: Login → OTP → Face → Fingerprint → Tokens
"use strict";

// ── Config ────────────────────────────────────────────────────────────────────
const API = "http://localhost:5000";

// ── Application State ─────────────────────────────────────────────────────────
const S = {
  email: "",
  mfaToken: "",
  userId: "",
  riskScore: 0,
  riskLevel: "LOW",
  requiredFactors: [],
  completedFactors: [],
  fingerprint: "",
  faceDescriptor: null,
  otpCooldown: false,
  cameraStream: null,
  detectionTimer: null,
  faceApiLoaded: false,
  modelsLoaded: false,
  currentChallenge: null,
  challengeProgress: 0,
  challengeSuccess: false,
};

// ── Liveness Detection Config ─────────────────────────────────────────────────
const LIVENESS = {
  CONSECUTIVE_FRAMES_REQUIRED: 3,  // Must pass check for 3 consecutive frames
  CHALLENGE_TIMEOUT_MS: 8000,      // 8 seconds per challenge before auto-advance
  FACE_CHANGE_THRESHOLD: 0.30,     // 30% change in face geometry = different person
};

// Baseline face geometry (captured during calibration)
let baseline = null;
let baselineFrames = [];
let consecutivePasses = 0;
let challengeStartTime = 0;
let challengeIndex = 0;

// Face geometry fingerprint for same-face checking
function getFaceGeometry(detection) {
  const leftEye = detection.landmarks.getLeftEye();
  const rightEye = detection.landmarks.getRightEye();
  const nose = detection.landmarks.getNose();
  const jaw = detection.landmarks.getJawOutline();
  // Compute ratios that are unique to a face
  const eyeDist = Math.hypot(rightEye[3].x - leftEye[0].x, rightEye[3].y - leftEye[0].y);
  const noseLen = Math.hypot(nose[6].x - nose[0].x, nose[6].y - nose[0].y);
  const jawWidth = Math.hypot(jaw[16].x - jaw[0].x, jaw[16].y - jaw[0].y);
  return { eyeDist, noseToEye: noseLen / eyeDist, jawToEye: jawWidth / eyeDist };
}

function isSameFace(current, baseline) {
  const d1 = Math.abs(current.noseToEye - baseline.noseToEye) / baseline.noseToEye;
  const d2 = Math.abs(current.jawToEye - baseline.jawToEye) / baseline.jawToEye;
  const diff = (d1 + d2) / 2;
  return diff < LIVENESS.FACE_CHANGE_THRESHOLD;
}

// Challenges in ORDER — Smile first, then fallbacks
const CHALLENGES = [
  {
    id: "SMILE",
    label: "😄 Smile wide!",
    check: (d) => {
      if (d.expressions) {
        return (d.expressions.happy || 0) > 0.6;
      }
      return false;
    },
  },
  {
    id: "OPEN_MOUTH",
    label: "😮 Open your mouth wide",
    check: (d) => {
      const mouth = d.landmarks.getMouth();
      const mouthH = Math.abs(mouth[14].y - mouth[18].y);
      const mouthW = Math.abs(mouth[6].x - mouth[0].x);
      return mouthW > 0 && mouthH / mouthW > 0.38;
    },
  },
  {
    id: "BLINK",
    label: "😑 Close your eyes briefly",
    check: (d) => {
      const leftEye = d.landmarks.getLeftEye();
      const rightEye = d.landmarks.getRightEye();
      const leftH = Math.abs(leftEye[1].y - leftEye[5].y);
      const leftW = Math.abs(leftEye[3].x - leftEye[0].x);
      const rightH = Math.abs(rightEye[1].y - rightEye[5].y);
      const rightW = Math.abs(rightEye[3].x - rightEye[0].x);
      const leftRatio = leftW > 0 ? leftH / leftW : 1;
      const rightRatio = rightW > 0 ? rightH / rightW : 1;
      return leftRatio < 0.18 && rightRatio < 0.18;
    },
  },
];

// ── DOM refs ──────────────────────────────────────────────────────────────────
const $ = (id) => document.getElementById(id);
const $$ = (sel) => document.querySelectorAll(sel);

// ── Panel Management ──────────────────────────────────────────────────────────
const STEP_MAP = {
  "panel-login": { step: 1, progress: 10 },
  "panel-register": { step: 1, progress: 10 },
  "panel-otp": { step: 2, progress: 30 },
  "panel-face": { step: 3, progress: 50 },
  "panel-device": { step: 4, progress: 70 },
  "panel-fingerprint": { step: 5, progress: 90 },
  "panel-loading": { step: 5, progress: 95 },
  "panel-success": { step: 5, progress: 100 },
};

function showPanel(id) {
  $$(".panel").forEach((p) => p.classList.remove("active"));
  const panel = $(id);
  if (!panel) return;
  panel.classList.add("active");

  // Update progress
  const info = STEP_MAP[id] || {};
  if (info.progress !== undefined) {
    $("progress-bar").style.width = info.progress + "%";
  }

  // Show step dots
  if (id !== "panel-loading" && id !== "panel-success") {
    $("steps-row").style.display = "flex";
    updateStepDots(info.step || 1);
  } else {
    $("steps-row").style.display = "none";
  }
}

function updateStepDots(active) {
  for (let i = 1; i <= 5; i++) {
    const dot = $(`dot-${i}`);
    if (!dot) continue;
    dot.classList.remove("active", "done");
    if (i < active) dot.classList.add("done");
    if (i === active) dot.classList.add("active");

    // Step line between dots
    const lines = $$(".step-line");
    if (lines[i - 1]) {
      lines[i - 1].classList.toggle("done", i < active);
    }
  }
}

// ── Status Bar ────────────────────────────────────────────────────────────────
function setStatus(msg, type = "info") {
  const bar = $("status-bar");
  const text = $("status-text");
  const icon = $("status-icon");

  if (!msg) {
    bar.style.display = "none";
    return;
  }

  const icons = { error: "✗", success: "✓", info: "·" };
  bar.className = `status-bar ${type}`;
  bar.style.display = "flex";
  icon.textContent = icons[type] || "·";
  text.textContent = msg;
}

// ── Button States ─────────────────────────────────────────────────────────────
function setBusy(btn, busy, label) {
  if (!btn) return;
  if (busy) {
    btn.disabled = true;
    btn.classList.add("loading");
    if (label) {
      btn.querySelector(".btn-label").textContent = label;
    }
  } else {
    btn.disabled = false;
    btn.classList.remove("loading");
    if (label) {
      btn.querySelector(".btn-label").textContent = label;
    }
  }
}

// ── Device Fingerprint ────────────────────────────────────────────────────────
async function getFingerprint() {
  if (S.fingerprint) return S.fingerprint;
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: "GET_FINGERPRINT" }, (res) => {
      S.fingerprint = res?.fingerprint || "no-fp-" + Date.now();
      resolve(S.fingerprint);
    });
  });
}

// ── API helper ───────────────────────────────────────────────────────────────
async function apiPost(endpoint, body) {
  const fp = await getFingerprint();
  const res = await fetch(`${API}${endpoint}`, {
    method: "POST",
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      "X-Device-Fingerprint": fp,
    },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const err = await res
      .json()
      .catch(() => ({ message: `HTTP ${res.status}` }));
    // Critical: For risk escalation, we still need the body even on error
    if (res.status === 401 || res.status === 403) {
      return { success: false, ...err };
    }
    throw new Error(err.message || `Request failed (${res.status})`);
  }

  return res.json();
}

function syncRiskUI(customLevel, customScore) {
  if (customLevel) S.riskLevel = customLevel;
  if (customScore) S.riskScore = customScore;

  const chip = $("risk-chip");
  if (chip && S.riskLevel) {
    const level = S.riskLevel.toLowerCase();
    chip.textContent = S.riskLevel;
    // Remove old level classes to ensure clean switch
    chip.classList.remove("low", "medium", "high", "critical");
    chip.classList.add("risk-chip", level);
    chip.style.display = "inline-flex";
    console.log(`[UI] Risk updated: ${S.riskLevel} (${S.riskScore})`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// REGISTRATION
// ─────────────────────────────────────────────────────────────────────────────
async function handleRegister() {
  const email = $("reg-email").value.trim();
  const password = $("reg-password").value;
  const confirm = $("reg-confirm").value;
  const btn = $("btn-register");

  if (!email) {
    setStatus("Please enter your email", "error");
    return;
  }
  if (!password) {
    setStatus("Please enter a password", "error");
    return;
  }
  if (!/\S+@\S+\.\S+/.test(email)) {
    setStatus("Invalid email format", "error");
    return;
  }
  if (password.length < 8) {
    setStatus("Password must be at least 8 characters", "error");
    return;
  }
  if (password !== confirm) {
    setStatus("Passwords do not match", "error");
    return;
  }

  setStatus("");
  setBusy(btn, true, "Creating account…");

  try {
    const data = await apiPost("/auth/register", {
      email,
      password,
      confirmPassword: confirm,
    });

    if (data.success) {
      setStatus("Account created! Signing you in…", "success");
      // Pre-fill the login panel
      $("email").value = email;
      $("password").value = password;
      // Small delay then switch to login
      await new Promise((r) => setTimeout(r, 1200));
      setStatus("");
      showPanel("panel-login");
    } else {
      setStatus(data.message || "Registration failed", "error");
    }
  } catch (err) {
    if (err.message.includes("fetch")) {
      setStatus("Cannot reach server. Is it running on :5000?", "error");
    } else {
      setStatus(err.message || "Registration failed", "error");
    }
  }

  setBusy(btn, false, "Create Account");
}

// ─────────────────────────────────────────────────────────────────────────────
// STEP 1 — LOGIN
// ─────────────────────────────────────────────────────────────────────────────
async function handleLogin() {
  const email = $("email").value.trim();
  const password = $("password").value;
  const btn = $("btn-login");

  if (!email) {
    setStatus("Please enter your email", "error");
    return;
  }
  if (!password) {
    setStatus("Please enter your password", "error");
    return;
  }
  if (!/\S+@\S+\.\S+/.test(email)) {
    setStatus("Invalid email format", "error");
    return;
  }

  S.email = email;
  setStatus("");
  setBusy(btn, true, "Authenticating…");

  try {
    const data = await apiPost("/auth/login", { email, password });

    if (!data.success) {
      syncRiskUI(data.riskLevel, data.riskScore);
      setStatus(data.message || "Invalid credentials", "error");
      setBusy(btn, false, "Continue");
      return;
    }

    // ── CASE A: LOW risk → Issue token immediately ──────────────────────────
    if (data.data.accessToken) {
      const { accessToken, userId, email, riskLevel, factors } = data.data;

      S.email = email;
      S.riskLevel = riskLevel;
      S.completedFactors = factors || [];

      // Inject session
      chrome.runtime.sendMessage({
        type: "INJECT_SESSION",
        token: accessToken,
        userId,
      });

      // Update success UI
      $("success-user").textContent = S.email;
      $("success-risk").textContent = S.riskLevel;
      $("success-factors").textContent = S.completedFactors
        .map((f) => f.toUpperCase())
        .join(" + ");

      showPanel("panel-success");
      setTimeout(() => window.close(), 3000);
      return;
    }

    // ── CASE B: Higher risk → Step up to MFA ────────────────────────────────
    S.mfaToken = data.data.mfaToken;
    S.userId = data.data.userId;
    S.riskScore = data.data.riskScore;
    S.riskLevel = data.data.riskLevel;
    S.requiredFactors = data.data.requiredFactors || ["otp"];

    syncRiskUI();

    // Persist session token
    await chrome.storage.session.set({
      mfaToken: S.mfaToken,
      userId: S.userId,
    });

    // Proceed to OTP
    await sendOTP();
  } catch (err) {
    if (err.message.includes("fetch")) {
      setStatus("Cannot reach server. Is it running on :5000?", "error");
    } else {
      setStatus(err.message || "Login failed", "error");
    }
    setBusy(btn, false, "Continue");
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// STEP 2 — OTP
// ─────────────────────────────────────────────────────────────────────────────
async function sendOTP() {
  showPanel("panel-otp");
  setStatus("Sending OTP…", "info");

  // Show email hint
  const hint = $("otp-hint");
  if (hint) hint.textContent = maskEmail(S.email);

  try {
    const data = await apiPost("/auth/send-otp", { mfaToken: S.mfaToken });

    if (data.success) {
      setStatus("Code sent — check your email", "success");
      startOTPCooldown();
    } else {
      setStatus(data.message || "OTP send failed", "error");
    }
  } catch (err) {
    setStatus("OTP send failed: " + err.message, "error");
  }

  // Focus input
  setTimeout(() => $("otp-input")?.focus(), 100);
}

async function handleVerifyOTP() {
  const otp = $("otp-input").value.trim().replace(/\D/g, "");
  const btn = $("btn-verify-otp");

  if (otp.length !== 6) {
    setStatus("Enter all 6 digits", "error");
    return;
  }

  setStatus("");
  setBusy(btn, true, "Verifying…");

  try {
    const data = await apiPost("/auth/verify-otp", {
      mfaToken: S.mfaToken,
      otp,
    });

    if (data.success) {
      S.completedFactors.push("otp");
      setStatus("");
      await proceedToNextFactor();
    } else {
      syncRiskUI(data.riskLevel, data.riskScore);
      if (data.requiredFactors) S.requiredFactors = data.requiredFactors;
      setStatus(data.message || "Incorrect code", "error");
      $("otp-input").value = "";
      $("otp-input").focus();
    }
  } catch (err) {
    setStatus(err.message || "Verification failed", "error");
  }

  setBusy(btn, false, "Verify");
}

function startOTPCooldown() {
  if (S.otpCooldown) return;
  S.otpCooldown = true;

  const btn = $("btn-resend-otp");
  const cd = $("otp-countdown");
  let secs = 30;

  if (btn) btn.disabled = true;
  if (cd) cd.style.display = "inline";

  const timer = setInterval(() => {
    secs--;
    if (cd) cd.textContent = `0:${secs.toString().padStart(2, "0")}`;
    if (secs <= 0) {
      clearInterval(timer);
      S.otpCooldown = false;
      if (btn) btn.disabled = false;
      if (cd) cd.style.display = "none";
    }
  }, 1000);
}

function maskEmail(email) {
  const [user, domain] = email.split("@");
  if (!domain) return email;
  const masked =
    user[0] + "•".repeat(Math.max(user.length - 2, 2)) + user.slice(-1);
  return `${masked}@${domain}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// FACTOR ROUTER
// ─────────────────────────────────────────────────────────────────────────────
async function proceedToNextFactor() {
  const remaining = S.requiredFactors.filter(
    (f) => !S.completedFactors.includes(f),
  );

  if (remaining.length === 0) {
    await issueTokens();
    return;
  }

  const next = remaining[0];

  if (next === "device") {
    showPanel("panel-device");
    await initDeviceFingerprintStep();
  } else if (next === "face") {
    showPanel("panel-face");
    // Don't auto-start camera — show start button for user gesture
    const startBtn = $("btn-start-face");
    const capBtn = $("btn-capture-face");
    capBtn.disabled = true;
    if (startBtn) {
      startBtn.style.display = "";
      startBtn.onclick = async () => {
        startBtn.style.display = "none";
        await initFaceRecognition();
      };
    } else {
      // Fallback: auto-start if button doesn't exist
      await initFaceRecognition();
    }
  } else if (next === "fingerprint" || next === "webauthn") {
    showPanel("panel-fingerprint");
    // Auto-trigger the WebAuthn ceremony when the panel shows
    await handleWebAuthn();
  } else {
    // Unknown factor — skip
    S.completedFactors.push(next);
    await proceedToNextFactor();
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// STEP 3 — DEVICE FINGERPRINTING
// ─────────────────────────────────────────────────────────────────────────────
async function initDeviceFingerprintStep() {
  const fp = await getFingerprint();
  $("fp-display").textContent = fp.match(/.{1,8}/g).join(" ");

  const bar = $("device-scan-fill");
  const items = ["scan-os", "scan-gpu", "scan-fonts", "scan-hardware"];

  // Simulated scan animation
  let idx = 0;
  const timer = setInterval(() => {
    $$(".scan-item").forEach((el) => el.classList.remove("active"));
    $(items[idx])?.classList.add("active");
    bar.style.width = (idx + 1) * 25 + "%";

    idx++;
    if (idx >= items.length) {
      clearInterval(timer);
      $("btn-verify-device").disabled = false;
    }
  }, 400);
}

async function handleVerifyDevice() {
  const btn = $("btn-verify-device");
  setBusy(btn, true, "Validating…");
  setStatus("");

  try {
    const data = await apiPost("/auth/verify-device", { mfaToken: S.mfaToken });

    if (data.success) {
      S.completedFactors.push("device");
      setStatus("");
      await proceedToNextFactor();
    } else {
      setStatus(data.message || "Device validation failed", "error");
      setBusy(btn, false, "Validate Device");
    }
  } catch (err) {
    setStatus(err.message || "Connection error", "error");
    setBusy(btn, false, "Validate Device");
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// STEP 3 — FACE RECOGNITION
// ─────────────────────────────────────────────────────────────────────────────
async function loadFaceAPI() {
  if (typeof faceapi !== "undefined") {
    S.faceApiLoaded = true;
    console.log("[FaceAPI] ✓ faceapi global found");
    return true;
  }
  console.error("[FaceAPI] ✗ faceapi global not found. Check libs/face-api.min.js");
  return false;
}

async function initFaceRecognition() {
  // Always clear any existing detection loop before starting fresh
  clearInterval(S.detectionTimer);
  S.detectionTimer = null;
  S.challengeProgress = 0;
  S.challengeSuccess = false;
  S.faceDescriptor = null;

  const statusEl = $("face-status");
  const scanLine = $("scan-line");
  const capBtn = $("btn-capture-face");

  capBtn.disabled = true;
  statusEl.textContent = "Loading face detection engine…";
  statusEl.style.color = "";

  // Check face-api is available (loaded via static script tag in popup.html)
  const loaded = await loadFaceAPI();

  if (!loaded || typeof faceapi === "undefined") {
    statusEl.textContent = "Face-api.js not found — place it in libs/";
    await showFaceError("Face verification library unavailable — please reload the extension");
    return;
  }

  // Load face models via XHR (bypasses fetch — works in Chrome extensions)
  if (!S.modelsLoaded) {
    try {
      statusEl.textContent = "Loading models…";
      console.log("[FaceAPI] Loading models via XHR loader…");

      // Use custom XHR-based loader (defined in libs/model-loader.js)
      // This completely bypasses face-api's loadFromUri and TF.js fetch
      await loadAllModelsXHR();

      S.modelsLoaded = true;
      console.log("[FaceAPI] ✓ All models loaded successfully via XHR");
    } catch (err) {
      console.error("[FaceAPI] XHR Load Error:", err);
      statusEl.textContent = "Model load failed — check console";
      await showFaceError("Face models failed to load — please reload the extension");
      return;
    }
  }

  // Request camera
  statusEl.textContent = "Requesting camera access…";
  console.log("[Camera] Requesting getUserMedia…");

  // Check if camera API is available
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    console.error("[Camera] ✗ navigator.mediaDevices.getUserMedia not available");
    statusEl.textContent = "Camera API not available";
    await showFaceError("Camera not available — face verification is required");
    return;
  }

  let stream;
  try {
    stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "user" }, audio: false });
    console.log("[Camera] ✓ Stream acquired:", stream.getVideoTracks()[0].label);
  } catch (err) {
    console.error("[Camera] ✗ Failed:", err.name, err.message);

    if (err.name === "NotAllowedError") {
      // In Chrome extension popups, the permission prompt gets dismissed on first try.
      // Show retry + skip buttons instead of auto-skipping.
      statusEl.textContent = "Camera permission needed";
      statusEl.style.color = "#fbbf24";

      const btnContainer = document.createElement("div");
      btnContainer.style.cssText = "display:flex;gap:8px;justify-content:center;margin-top:10px;";

      const retryBtn = document.createElement("button");
      retryBtn.textContent = "🎥 Grant Camera Access";
      retryBtn.className = "vb-btn primary";
      retryBtn.style.cssText = "padding:8px 16px;border-radius:6px;cursor:pointer;font-size:13px;background:#6366f1;color:#fff;border:none;";
      retryBtn.onclick = async () => {
        btnContainer.remove();
        statusEl.textContent = "Requesting camera…";
        statusEl.style.color = "";
        await initFaceRecognition(); // Retry the full flow
      };

      // No skip button — face verification is a required factor

      btnContainer.appendChild(retryBtn);

      // Insert buttons after the status element
      const facePanel = $("panel-face");
      if (facePanel) {
        const challengeContainer = $("face-challenge-container");
        if (challengeContainer) {
          challengeContainer.style.display = "none";
        }
        statusEl.parentNode.insertBefore(btnContainer, statusEl.nextSibling);
      }
      return; // Don't auto-skip — wait for user action
    }

    if (err.name === "NotFoundError") {
      statusEl.textContent = "No camera found on this device";
    } else if (err.name === "NotReadableError") {
      statusEl.textContent = "Camera in use by another app";
    } else {
      statusEl.textContent = "Camera error: " + err.name;
    }
    await showFaceError("Camera not available — face verification is required");
    return;
  }

  S.cameraStream = stream;
  const video = $("face-video");
  video.srcObject = stream;

  await new Promise((resolve) => {
    video.onloadedmetadata = () => {
      video.play().catch(() => {});
      resolve();
    };
    // If metadata already loaded (e.g. on retry), resolve immediately
    if (video.readyState >= 2) {
      video.play().catch(() => {});
      resolve();
    }
  });

  console.log("[Camera] ✓ Video playing:", video.videoWidth, "x", video.videoHeight);

  // Start scan animation
  if (scanLine) scanLine.classList.add("active");
  statusEl.textContent = "Looking for your face…";

  // Reset liveness state for fresh session
  baseline = null;
  baselineFrames = [];
  consecutivePasses = 0;
  challengeIndex = 0;
  challengeStartTime = 0;

  // Start with SMILE (index 0)
  S.currentChallenge = CHALLENGES[0];
  S.challengeProgress = 0;
  S.challengeSuccess = false;

  const challengeContainer = $("face-challenge-container");
  const challengeText = $("face-challenge");
  const challengeFill = $("challenge-fill");

  if (challengeContainer) {
    challengeContainer.style.display = "block";
    challengeText.textContent = "Look straight at the camera…";
    challengeFill.style.width = "0%";
  }

  // Detection loop — 200ms interval with overlap guard
  let detectedOnce = false;
  let detecting = false;
  S.detectionTimer = setInterval(async () => {
    if (!video.videoWidth || detecting) return;
    detecting = true;

    let detection;
    try {
      detection = await faceapi
        .detectSingleFace(
          video,
          new faceapi.TinyFaceDetectorOptions({
            inputSize: 224,
            scoreThreshold: 0.4,
          }),
        )
        .withFaceLandmarks(true)
        .withFaceExpressions()
        .withFaceDescriptor();
    } catch (err) {
      console.warn("[Detection] Error:", err.message);
      detecting = false;
      return;
    }

    detecting = false;

    if (detection) {
      // Capture the genuine 128D biometric descriptor from faceRecognitionNet
      S.faceDescriptor = detection.descriptor ? Array.from(detection.descriptor) : null;

      if (!detectedOnce) {
        detectedOnce = true;
        console.log("[Detection] ✓ Face detected! Score:", detection.detection.score.toFixed(3));
        statusEl.textContent = "✓ Face detected — calibrating…";
        statusEl.style.color = "#4ade80";
        $("cam-badge").textContent = "DETECTED";
      }

      // ── Calibration (5 frames → capture face geometry) ────────────────
      if (!baseline) {
        baselineFrames.push(detection);

        const pct = Math.round((baselineFrames.length / 5) * 100);
        if (challengeFill) challengeFill.style.width = pct + "%";

        if (baselineFrames.length >= 5) {
          // Use the last frame's geometry as the baseline fingerprint
          baseline = getFaceGeometry(baselineFrames[4]);
          console.log("[Liveness] ✓ Face geometry captured:", baseline);

          // Show the first challenge (SMILE)
          challengeText.textContent = S.currentChallenge.label;
          challengeFill.style.width = "0%";
          statusEl.textContent = "✓ Complete the challenge below";
          challengeStartTime = Date.now();
          consecutivePasses = 0;
        }
        return;
      }

      // ── Same-face check ────────────────────────────────────────────────
      const currentGeometry = getFaceGeometry(detection);
      if (!isSameFace(currentGeometry, baseline)) {
        statusEl.textContent = "⚠ Different face detected — show YOUR face";
        statusEl.style.color = "#ef4444";
        $("cam-badge").textContent = "REJECTED";
        capBtn.disabled = true;
        S.faceDescriptor = null;
        consecutivePasses = 0;
        return;
      }

      // ── Challenge timeout → auto-advance ───────────────────────────────
      if (!S.challengeSuccess && challengeStartTime > 0) {
        const elapsed = Date.now() - challengeStartTime;
        if (elapsed > LIVENESS.CHALLENGE_TIMEOUT_MS) {
          challengeIndex++;
          if (challengeIndex < CHALLENGES.length) {
            // Move to next challenge
            S.currentChallenge = CHALLENGES[challengeIndex];
            S.challengeProgress = 0;
            consecutivePasses = 0;
            challengeStartTime = Date.now();
            challengeText.textContent = S.currentChallenge.label;
            challengeFill.style.width = "0%";
            statusEl.textContent = "Trying next challenge…";
            console.log("[Challenge] ⏩ Timeout — advancing to:", S.currentChallenge.id);
          } else {
            // All challenges exhausted without a pass — liveness failed
            clearInterval(S.detectionTimer);
            stopCamera();
            challengeText.textContent = "✗ Liveness check failed";
            statusEl.textContent = "Could not verify liveness — please retry";
            statusEl.style.color = "#ef4444";
            capBtn.disabled = true;
            $("cam-badge").textContent = "FAILED";
            const retryBtn = document.createElement("button");
            retryBtn.textContent = "🔄 Retry Face Verification";
            retryBtn.className = "vb-btn primary";
            retryBtn.style.cssText = "margin-top:10px;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:13px;background:#6366f1;color:#fff;border:none;";
            retryBtn.onclick = async () => { retryBtn.remove(); await initFaceRecognition(); };
            statusEl.parentNode.insertBefore(retryBtn, statusEl.nextSibling);
            console.log("[Challenge] All challenges timed out — liveness failed");
          }
          return;
        }
      }

      // ── Handle current challenge ──────────────────────────────────────
      if (!S.challengeSuccess) {
        const passed = S.currentChallenge.check(detection);
        if (passed) {
          consecutivePasses++;
          S.challengeProgress = Math.min(100, Math.round((consecutivePasses / LIVENESS.CONSECUTIVE_FRAMES_REQUIRED) * 100));
          if (challengeFill) challengeFill.style.width = S.challengeProgress + "%";

          if (consecutivePasses >= LIVENESS.CONSECUTIVE_FRAMES_REQUIRED) {
            // Challenge PASSED!
            S.challengeSuccess = true;
            S.challengeProgress = 100;
            if (challengeFill) challengeFill.style.width = "100%";
            console.log("[Challenge] ✓ PASSED:", S.currentChallenge.id);
            challengeText.textContent = "✓ LIVENESS VERIFIED";
            statusEl.textContent = "Hold still to capture...";
            statusEl.style.color = "#4ade80";
            capBtn.disabled = false;
            $("cam-badge").textContent = "READY";
          }
        } else {
          consecutivePasses = 0;
          S.challengeProgress = 0;
          if (challengeFill) challengeFill.style.width = "0%";
        }

        statusEl.style.color = "#4ade80";
      } else {
        capBtn.disabled = false;
        $("cam-badge").textContent = "READY";
        statusEl.textContent = "Hold still to capture...";
      }
    } else {
      S.faceDescriptor = null;
      detectedOnce = false;
      statusEl.textContent = "Looking for your face…";
      statusEl.style.color = "";
      capBtn.disabled = true;
      $("cam-badge").textContent = "SCANNING";

      if (!S.challengeSuccess) {
        consecutivePasses = 0;
        S.challengeProgress = 0;
        if (challengeFill) challengeFill.style.width = "0%";
      }
    }
  }, 200);
}

function stopCamera() {
  clearInterval(S.detectionTimer);
  if (S.cameraStream) {
    S.cameraStream.getTracks().forEach((t) => t.stop());
    S.cameraStream = null;
  }
  const challengeContainer = $("face-challenge-container");
  if (challengeContainer) challengeContainer.style.display = "none";
}

async function handleFaceCapture() {
  if (!S.faceDescriptor || !S.challengeSuccess) {
    setStatus("Complete the liveness challenge first", "error");
    return;
  }

  const btn = $("btn-capture-face");
  setBusy(btn, true, "Verifying…");
  setStatus("");

  stopCamera();

  try {
    // Require a genuine face-api descriptor captured from a live video frame
    const descriptor = Array.isArray(S.faceDescriptor) ? S.faceDescriptor : null;
    if (!descriptor) {
      setStatus("No biometric descriptor captured — retry face verification", "error");
      setBusy(btn, false, "Capture & Verify");
      await initFaceRecognition();
      return;
    }

    const data = await apiPost("/auth/verify-face", {
      mfaToken: S.mfaToken,
      challengeId: S.currentChallenge?.id || "UNKNOWN",
      descriptor,
    });

    if (data.success) {
      S.completedFactors.push("face");
      setStatus("");
      await proceedToNextFactor();
    } else {
      setStatus(data.message || "Face not recognized", "error");
      setBusy(btn, false, "Capture & Verify");
      // Restart camera
      await initFaceRecognition();
    }
  } catch (err) {
    setStatus(err.message || "Face verification error", "error");
    setBusy(btn, false, "Capture & Verify");
    await initFaceRecognition();
  }
}

// Face verification cannot be skipped — camera/model errors show retry UI
async function showFaceError(message) {
  const statusEl = $("face-status");
  const capBtn = $("btn-capture-face");
  if (statusEl) {
    statusEl.textContent = message || "Camera unavailable — face verification required";
    statusEl.style.color = "#ef4444";
  }
  if (capBtn) capBtn.disabled = true;
  // Provide a retry button but do NOT auto-complete the face factor
  const existing = document.getElementById("face-retry-btn");
  if (!existing && statusEl) {
    const retryBtn = document.createElement("button");
    retryBtn.id = "face-retry-btn";
    retryBtn.textContent = "🔄 Retry Camera";
    retryBtn.className = "vb-btn primary";
    retryBtn.style.cssText = "margin-top:10px;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:13px;background:#6366f1;color:#fff;border:none;";
    retryBtn.onclick = async () => { retryBtn.remove(); await initFaceRecognition(); };
    statusEl.parentNode.insertBefore(retryBtn, statusEl.nextSibling);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// STEP 4 — FINGERPRINT / WEBAUTHN
// ─────────────────────────────────────────────────────────────────────────────

/**
 * WebAuthn Registration ceremony.
 * Called when the user has no registered credentials for this account.
 * Fetches registration options from the backend, invokes navigator.credentials.create(),
 * and sends the attestation response back for server-side verification.
 */
async function handleWebAuthnRegister() {
  const btn = $("btn-fingerprint");
  setBusy(btn, true, "Registering authenticator…");
  setStatus("Setting up your authenticator…", "info");

  if (!window.PublicKeyCredential) {
    setStatus("WebAuthn not supported in this browser", "error");
    setBusy(btn, false, "Authenticate");
    return false;
  }

  try {
    // ── 1. Get registration options from server ───────────────────────────
    const optionsData = await apiPost("/auth/webauthn-register-options", {
      mfaToken: S.mfaToken,
    });

    if (!optionsData.success) {
      throw new Error(optionsData.message || "Failed to get registration options");
    }

    const { options: registrationOptions, rpId } = optionsData.data;

    // ── 2. Decode base64url fields the browser expects as ArrayBuffers ───
    registrationOptions.challenge = base64urlDecode(registrationOptions.challenge);
    registrationOptions.user.id = base64urlDecode(registrationOptions.user.id);

    if (Array.isArray(registrationOptions.excludeCredentials)) {
      registrationOptions.excludeCredentials = registrationOptions.excludeCredentials.map((c) => ({
        ...c,
        id: base64urlDecode(c.id),
      }));
    }

    // ── 3. Call navigator.credentials.create() ───────────────────────────
    setStatus("Touch your authenticator when prompted…", "info");
    const credential = await navigator.credentials.create({
      publicKey: registrationOptions,
    });

    // ── 4. Encode response for transmission ──────────────────────────────
    const encodedCredential = {
      id: credential.id,
      rawId: base64urlEncode(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: base64urlEncode(credential.response.clientDataJSON),
        attestationObject: base64urlEncode(credential.response.attestationObject),
        transports: credential.response.getTransports
          ? credential.response.getTransports()
          : [],
      },
    };

    // ── 5. Send to server for cryptographic verification ─────────────────
    const verifyData = await apiPost("/auth/webauthn-register-verify", {
      mfaToken: S.mfaToken,
      credential: encodedCredential,
    });

    if (!verifyData.success) {
      throw new Error(verifyData.message || "Registration verification failed");
    }

    setStatus("Authenticator registered. Now authenticating…", "success");
    return true;
  } catch (err) {
    if (err.name === "InvalidStateError") {
      // Credential already registered — proceed directly to authentication
      setStatus("Authenticator already registered. Authenticating…", "info");
      return true;
    }
    if (err.name === "NotAllowedError") {
      setStatus("Registration cancelled or timed out", "error");
    } else {
      setStatus(err.message || "Registration failed", "error");
    }
    setBusy(btn, false, "Authenticate");
    return false;
  }
}

/**
 * WebAuthn Authentication ceremony.
 * Fetches an authentication challenge from the backend, invokes
 * navigator.credentials.get(), and sends the signed assertion back
 * for full cryptographic verification by the server.
 *
 * The backend verifies: challenge, origin, rpId, credential ownership,
 * authenticatorData, signature, and sign counter.
 * The client CANNOT declare success — only the server response determines it.
 */
async function handleWebAuthn() {
  const btn = $("btn-fingerprint");
  setBusy(btn, true, "Waiting for biometric…");
  setStatus("");

  if (!window.PublicKeyCredential) {
    setStatus("WebAuthn not supported in this browser", "error");
    setBusy(btn, false, "Authenticate");
    return;
  }

  try {
    // ── 1. Get authentication challenge from server ───────────────────────
    const challengeData = await apiPost("/auth/webauthn-auth-options", {
      mfaToken: S.mfaToken,
    });

    if (!challengeData.success) {
      throw new Error(challengeData.message || "Challenge request failed");
    }

    const { challenge, rpId, allowCredentials = [] } = challengeData.data;

    // ── 2. If no credentials registered yet, run registration first ──────
    if (allowCredentials.length === 0) {
      const registered = await handleWebAuthnRegister();
      if (!registered) return;
      // After registration, re-fetch auth options (credential is now registered)
      setBusy(btn, true, "Waiting for biometric…");
      const rechallenge = await apiPost("/auth/webauthn-auth-options", {
        mfaToken: S.mfaToken,
      });
      if (!rechallenge.success) {
        throw new Error(rechallenge.message || "Challenge request failed after registration");
      }
      // Proceed with the new challenge
      return await handleWebAuthnWithOptions(rechallenge.data, btn);
    }

    // ── 3. Proceed with existing credentials ─────────────────────────────
    return await handleWebAuthnWithOptions(challengeData.data, btn);

  } catch (err) {
    if (err.name === "NotAllowedError") {
      setStatus("Biometric prompt cancelled or timed out", "error");
    } else if (err.name === "NotSupportedError" || err.name === "SecurityError") {
      setStatus("WebAuthn not available on this device", "error");
    } else if (err.name === "InvalidStateError") {
      setStatus("No registered credentials. Register a device first.", "error");
    } else {
      setStatus(err.message || "WebAuthn failed", "error");
    }
  }

  setBusy(btn, false, "Authenticate");
}

/**
 * Inner authentication handler — receives already-fetched options and runs
 * the navigator.credentials.get() ceremony and server verification.
 */
async function handleWebAuthnWithOptions(optionsData, btn) {
  const { challenge, rpId, allowCredentials = [] } = optionsData;

  // ── Decode base64url → ArrayBuffer for the browser API ─────────────────
  const challengeBuffer = base64urlDecode(challenge);

  const decodedCredentials = allowCredentials.map((c) => ({
    id: base64urlDecode(c.id),
    type: "public-key",
    transports: c.transports && c.transports.length > 0
      ? c.transports
      : ["internal", "hybrid"],
  }));

  // ── Call navigator.credentials.get() ─────────────────────────────────────
  let assertion;
  try {
    assertion = await navigator.credentials.get({
      publicKey: {
        challenge: challengeBuffer,
        rpId: rpId || "localhost",
        allowCredentials: decodedCredentials,
        userVerification: "required",
        timeout: 60000,
      },
    });
  } catch (err) {
    throw err; // Let caller handle
  }

  // ── Encode response for server ────────────────────────────────────────────
  const encoded = {
    id: assertion.id,
    rawId: base64urlEncode(assertion.rawId),
    type: assertion.type,
    response: {
      authenticatorData: base64urlEncode(assertion.response.authenticatorData),
      clientDataJSON: base64urlEncode(assertion.response.clientDataJSON),
      signature: base64urlEncode(assertion.response.signature),
      userHandle: assertion.response.userHandle
        ? base64urlEncode(assertion.response.userHandle)
        : null,
    },
  };

  // ── Send to server for CRYPTOGRAPHIC verification ─────────────────────────
  // The server verifies: challenge, origin, rpId, credential ownership,
  // authenticatorData parsing, ECDSA/RSA signature, and sign counter.
  // A fake { webauthnVerified: true } or { success: true } flag is NOT accepted.
  const verifyData = await apiPost("/auth/webauthn-verify", {
    mfaToken: S.mfaToken,
    assertion: encoded,
  });

  if (verifyData.success) {
    S.completedFactors.push("webauthn");
    setStatus("");
    setBusy(btn, false, "Authenticate");
    await proceedToNextFactor();
  } else {
    throw new Error(verifyData.message || "WebAuthn verification failed");
  }
}

// Base64url helpers
function base64urlDecode(str) {
  const base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(
    base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "="),
  );
  return Uint8Array.from(binary, (c) => c.charCodeAt(0)).buffer;
}

function base64urlEncode(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  bytes.forEach((b) => (binary += String.fromCharCode(b)));
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

// ─────────────────────────────────────────────────────────────────────────────
// FINAL — ISSUE TOKENS
// ─────────────────────────────────────────────────────────────────────────────
async function issueTokens() {
  showPanel("panel-loading");
  setStatus("");

  try {
    const data = await apiPost("/auth/issue-tokens", { mfaToken: S.mfaToken });

    if (data.success) {
      const token = data.data?.accessToken || "";
      const userId = data.data?.userId || S.userId;

      // Inject session into page via background (ISOLATED world)
      chrome.runtime.sendMessage({ type: "INJECT_SESSION", token, userId });

      // Clear sensitive data from memory
      S.faceDescriptor = null;

      // Update session storage
      await chrome.storage.session.set({
        authenticated: true,
        userId: userId,
        mfaToken: "", // clear
      });

      // Update success panel
      $("success-user").textContent = S.email;
      $("success-risk").textContent = S.riskLevel;
      $("success-factors").textContent = S.completedFactors
        .map((f) => f.toUpperCase())
        .join(" + ");

      showPanel("panel-success");

      // Auto-close
      setTimeout(() => window.close(), 3000);
    } else {
      setStatus(data.message || "Token issuance failed. Try again.", "error");
      showPanel("panel-login");
    }
  } catch (err) {
    setStatus(err.message || "Session creation failed", "error");
    showPanel("panel-login");
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// INIT
// ─────────────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", async () => {
  // Pre-fetch fingerprint
  getFingerprint();

  // Pre-fill email if passed from content script
  const stored = await chrome.storage.session
    .get(["prefillEmail"])
    .catch(() => ({}));
  if (stored.prefillEmail) {
    $("email").value = stored.prefillEmail;
    $("password")?.focus();
  } else {
    $("email")?.focus();
  }

  // ── Event Listeners ──────────────────────────────────────────────────────

  // Login panel
  $("btn-login")?.addEventListener("click", handleLogin);
  $("email")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") $("password")?.focus();
  });
  $("password")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") handleLogin();
  });

  // Panel toggle: Login ↔ Register
  $("btn-go-register")?.addEventListener("click", () => {
    setStatus("");
    $("reg-email").value = $("email").value || "";
    $("reg-password").value = "";
    $("reg-confirm").value = "";
    showPanel("panel-register");
    $("reg-email").value ? $("reg-password")?.focus() : $("reg-email")?.focus();
  });
  $("btn-go-login")?.addEventListener("click", () => {
    setStatus("");
    showPanel("panel-login");
  });

  // Register panel
  $("btn-register")?.addEventListener("click", handleRegister);
  $("reg-confirm")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") handleRegister();
  });

  // Register password toggle
  $("btn-toggle-reg-pw")?.addEventListener("click", () => {
    const pw = $("reg-password");
    const ico = $("eye-icon-reg");
    if (!pw) return;
    if (pw.type === "password") {
      pw.type = "text";
      ico.innerHTML = `<path d="M2 2l11 11M6.5 6.7A3 3 0 0010.9 9M1 7.5S3.5 3 7.5 3c1.1 0 2.1.3 3 .8M13.4 5C14.5 6 15 7.5 15 7.5S12.5 12 7.5 12c-.7 0-1.4-.1-2-.3" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>`;
    } else {
      pw.type = "password";
      ico.innerHTML = `<path d="M1 7.5S3.5 3 7.5 3s6.5 4.5 6.5 4.5S13 12 7.5 12 1 7.5 1 7.5z" stroke="currentColor" stroke-width="1.2"/><circle cx="7.5" cy="7.5" r="2" stroke="currentColor" stroke-width="1.2"/>`;
    }
  });

  // Password toggle
  $("btn-toggle-pw")?.addEventListener("click", () => {
    const pw = $("password");
    const ico = $("eye-icon");
    if (!pw) return;
    if (pw.type === "password") {
      pw.type = "text";
      ico.innerHTML = `<path d="M2 2l11 11M6.5 6.7A3 3 0 0010.9 9M1 7.5S3.5 3 7.5 3c1.1 0 2.1.3 3 .8M13.4 5C14.5 6 15 7.5 15 7.5S12.5 12 7.5 12c-.7 0-1.4-.1-2-.3" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>`;
    } else {
      pw.type = "password";
      ico.innerHTML = `<path d="M1 7.5S3.5 3 7.5 3s6.5 4.5 6.5 4.5S13 12 7.5 12 1 7.5 1 7.5z" stroke="currentColor" stroke-width="1.2"/><circle cx="7.5" cy="7.5" r="2" stroke="currentColor" stroke-width="1.2"/>`;
    }
  });

  // OTP panel
  $("otp-input")?.addEventListener("input", (e) => {
    e.target.value = e.target.value.replace(/\D/g, "").slice(0, 6);
  });
  $("otp-input")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") handleVerifyOTP();
  });
  $("btn-verify-otp")?.addEventListener("click", handleVerifyOTP);
  $("btn-resend-otp")?.addEventListener("click", sendOTP);

  // Device panel
  $("btn-verify-device")?.addEventListener("click", handleVerifyDevice);

  // Face panel
  $("btn-capture-face")?.addEventListener("click", handleFaceCapture);
  $("btn-skip-face")?.addEventListener("click", async () => {
    stopCamera();
    setStatus("Skipping face verification", "info");
    S.completedFactors.push("face");
    await proceedToNextFactor();
  });

  // Fingerprint panel
  $("btn-fingerprint")?.addEventListener("click", handleWebAuthn);
  $("btn-skip-fp")?.addEventListener("click", async () => {
    // WebAuthn cannot be auto-skipped when it is a required factor.
    // Only show this if the factor genuinely isn't required.
    if (!S.requiredFactors.includes("webauthn") && !S.requiredFactors.includes("fingerprint")) {
      setStatus("Skipping fingerprint (not required)", "info");
      S.completedFactors.push("fingerprint");
      await proceedToNextFactor();
    } else {
      setStatus("WebAuthn is required for this risk level — cannot skip", "error");
    }
  });

  // Show initial panel (default to login)
  showPanel("panel-login");
});

// Cleanup camera if popup is closed mid-flow
window.addEventListener("unload", () => {
  stopCamera();
});
