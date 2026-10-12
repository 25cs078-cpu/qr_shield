(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const fileInput = $("fileInput");
  const dropZone = $("dropZone");
  const workCanvas = $("workCanvas");
  const ctx = workCanvas.getContext("2d", { willReadFrequently: true });
  const state = { payload: "", stream: null, cameraFrame: null, currentDemo: "", lastFileUrl: null };

  const suspiciousWords = [
    { re: /login|signin|verify|verification|account|password|credential/i, title: "Account-related wording", detail: "The URL contains words often used in account verification or credential-harvesting lures.", points: 12 },
    { re: /urgent|suspend|limited|claim|prize|winner|gift|free/i, title: "Urgency or reward wording", detail: "The URL contains urgency or reward-related wording sometimes used to pressure users.", points: 10 },
    { re: /payment|banking|wallet|refund|upi|paytm/i, title: "Payment-related wording", detail: "The URL contains payment-related terms. Confirm the destination independently before entering financial details.", points: 8 }
  ];

  function showToast(message) {
    const toast = $("toast");
    toast.textContent = message;
    toast.classList.add("show");
    clearTimeout(showToast.timer);
    showToast.timer = setTimeout(() => toast.classList.remove("show"), 2500);
  }

  function isLikelyUrl(payload) {
    const s = payload.trim();
    return /^(https?:\/\/|www\.)/i.test(s) || /^[a-z0-9-]+(\.[a-z0-9-]+)+([/:?#]|$)/i.test(s);
  }

  function normalizeUrl(payload) {
    const s = payload.trim();
    if (/^www\./i.test(s)) return "https://" + s;
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s) && isLikelyUrl(s)) return "https://" + s;
    return s;
  }

  function analyzePayload(payload) {
    const raw = payload.trim();
    const findings = [];
    let score = 0;
    const add = (level, title, detail, points = 0) => {
      findings.push({ level, title, detail });
      score += points;
    };

    if (!raw) {
      return { type: "UNKNOWN", score: 0, label: "Unreadable QR code", level: "medium", findings: [{ level: "warn", title: "No content decoded", detail: "Try a sharper, brighter image with the full QR code visible." }] };
    }

    if (!isLikelyUrl(raw)) {
      const type = /^(WIFI:|WIFI;)/i.test(raw) ? "WI-FI" :
        /^(mailto:)/i.test(raw) ? "EMAIL" :
        /^(tel:)/i.test(raw) ? "PHONE" :
        /^(upi:|paytmmp:|phonepe:)/i.test(raw) ? "PAYMENT" : "TEXT";
      add("good", "Non-URL content", "This QR code contains text or structured data rather than a standard web URL. Review it before acting.", 0);
      return { type, score: 0, label: "Content decoded — review before use", level: "low", findings };
    }

    const normalized = normalizeUrl(raw);
    let url;
    try {
      url = new URL(normalized);
    } catch (_) {
      add("bad", "Malformed URL", "The decoded content resembles a URL but could not be parsed correctly.", 35);
      return finalize("URL", score, findings);
    }

    if (url.protocol !== "https:") {
      if (url.protocol === "http:") add("warn", "Unencrypted HTTP connection", "This destination does not use HTTPS, so data sent to it may not be protected in transit.", 15);
      else add("bad", "Unusual URL protocol", "The link uses a protocol other than HTTP or HTTPS. Do not open it unless you understand why.", 35);
    } else {
      add("good", "HTTPS connection", "The URL uses HTTPS. This protects the connection but does not prove the site itself is trustworthy.", 0);
    }

    const host = url.hostname.toLowerCase();
    const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host);
    const ipv6 = host.startsWith("[") && host.endsWith("]");
    if (ipv4 || ipv6) add("bad", "IP address used as host", "The destination points directly to an IP address instead of a typical domain name. This can be suspicious; it is not proof of abuse.", 25);

    if (host.includes("xn--")) add("warn", "Internationalized domain encoding", "The hostname contains punycode. Check carefully for look-alike characters or a misleading domain.", 18);

    const labels = host.split(".");
    if (labels.length >= 5) add("warn", "Many subdomains", "The hostname contains several subdomain levels. Check which domain actually owns the site.", 12);

    if (host.length > 45) add("warn", "Unusually long hostname", "Long hostnames can hide misleading words or make the real destination harder to recognize.", 10);

    if (/@/.test(raw.split("://").slice(1).join("://").split("/")[0] || "")) add("bad", "Misleading user-info section", "The URL contains an @ symbol in its authority section, which can disguise the actual hostname.", 25);

    if (/%[0-9a-f]{2}/i.test(url.pathname + url.search)) add("warn", "Encoded URL characters", "The URL includes percent-encoded characters. This can be normal, but review unfamiliar destinations carefully.", 5);

    const shorteners = ["bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "ow.ly", "rb.gy", "shorturl.at", "rebrand.ly", "buff.ly", "lnkd.in"];
    if (shorteners.includes(host) || shorteners.some((domain) => host.endsWith("." + domain))) {
      add("warn", "Shortened link", "The final destination is hidden behind a URL shortener and cannot be confirmed by this offline check.", 22);
    }

    if (raw.length > 180) add("warn", "Very long URL", "The URL is unusually long. Long URLs can contain tracking or confusing parameters, although length alone is not proof of risk.", 8);

    for (const rule of suspiciousWords) {
      if (rule.re.test(url.hostname + url.pathname + url.search)) {
        add("warn", rule.title, rule.detail, rule.points);
      }
    }

    const riskyTld = /\.(zip|mov|click|top|work|country|gq|tk)$/i.test(host);
    if (riskyTld) add("warn", "TLD worth reviewing", "This top-level domain is sometimes used in abuse, but a domain ending alone cannot determine whether a site is malicious.", 8);

    if (findings.every((f) => f.level === "good")) {
      add("good", "No basic risk indicators found", "These simple checks did not identify obvious warning signs. This is not a reputation check and does not guarantee safety.", 0);
    }
    return finalize("URL", score, findings);
  }

  function finalize(type, score, findings) {
    score = Math.max(0, Math.min(100, score));
    let level = "low";
    let label = "No obvious risks detected";
    if (score >= 50) { level = "high"; label = "High risk — avoid opening"; }
    else if (score >= 20) { level = "medium"; label = "Suspicious — review carefully"; }
    else if (findings.some((f) => f.level === "warn")) { level = "low"; label = "Some caution advised"; }
    return { type, score, label, level, findings };
  }

  function renderReport(payload) {
    state.payload = payload;
    const result = analyzePayload(payload);
    $("emptyState").classList.add("hidden");
    $("reportContent").classList.remove("hidden");
    $("resultTitle").textContent = result.level === "high" ? "Potential threat detected" : result.level === "medium" ? "Needs careful review" : "Analysis complete";
    $("riskScore").textContent = result.score;
    $("meterFill").style.width = result.score + "%";
    $("meterFill").style.background = result.level === "high" ? "var(--red)" : result.level === "medium" ? "var(--yellow)" : "var(--green)";
    $("classification").className = "classification" + (result.level === "medium" ? " medium" : result.level === "high" ? " high" : "");
    $("classificationText").textContent = result.label;
    $("resultIcon").className = "result-icon " + result.level;
    $("resultIcon").textContent = result.level === "high" ? "!" : result.level === "medium" ? "⚠" : "✓";
    $("decodedPayload").textContent = payload;
    $("payloadType").textContent = result.type;
    $("findingCount").textContent = result.findings.length + (result.findings.length === 1 ? " finding" : " findings");
    $("findingsList").replaceChildren();

    for (const finding of result.findings) {
      const row = document.createElement("div");
      row.className = "finding";
      const icon = document.createElement("span");
      icon.className = "finding-icon " + (finding.level === "good" ? "good" : finding.level === "bad" ? "bad" : "warn");
      icon.textContent = finding.level === "good" ? "✓" : finding.level === "bad" ? "!" : "⚠";
      const copy = document.createElement("div");
      const title = document.createElement("strong");
      title.textContent = finding.title;
      const detail = document.createElement("p");
      detail.textContent = finding.detail;
      copy.append(title, detail);
      row.append(icon, copy);
      $("findingsList").append(row);
    }
    $("copyStatus").textContent = "";
    $("resultPanel").scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  function decodeImage(image) {
    if (!window.jsQR) {
      showToast("QR decoder did not load. Check your internet connection and refresh.");
      return;
    }
    const maxSide = 1800;
    const ratio = Math.min(1, maxSide / Math.max(image.naturalWidth || image.width, image.naturalHeight || image.height));
    workCanvas.width = Math.max(1, Math.round((image.naturalWidth || image.width) * ratio));
    workCanvas.height = Math.max(1, Math.round((image.naturalHeight || image.height) * ratio));
    ctx.clearRect(0, 0, workCanvas.width, workCanvas.height);
    ctx.drawImage(image, 0, 0, workCanvas.width, workCanvas.height);
    const imageData = ctx.getImageData(0, 0, workCanvas.width, workCanvas.height);
    const code = window.jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: "attemptBoth" });
    if (!code) {
      showToast("No QR code detected. Try a clearer image with the full code visible.");
      return;
    }
    stopCamera();
    renderReport(code.data);
  }

  function handleFile(file) {
    if (!file) return;
    if (!file.type.startsWith("image/")) { showToast("Please choose an image file."); return; }
    const img = new Image();
    const objectUrl = URL.createObjectURL(file);
    if (state.lastFileUrl) URL.revokeObjectURL(state.lastFileUrl);
    state.lastFileUrl = objectUrl;
    img.onload = () => decodeImage(img);
    img.onerror = () => showToast("Could not read that image. Please try another file.");
    img.src = objectUrl;
  }

  function stopCamera() {
    if (state.cameraFrame) cancelAnimationFrame(state.cameraFrame);
    state.cameraFrame = null;
    if (state.stream) state.stream.getTracks().forEach((track) => track.stop());
    state.stream = null;
    $("cameraVideo").srcObject = null;
    $("cameraWrap").classList.add("hidden");
    $("cameraBtn").textContent = "Start camera";
  }

  async function startCamera() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      showToast("Camera access requires localhost or HTTPS in a supported browser.");
      return;
    }
    try {
      state.stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: "environment" } }, audio: false });
      const video = $("cameraVideo");
      video.srcObject = state.stream;
      $("cameraWrap").classList.remove("hidden");
      $("cameraBtn").textContent = "Camera active";
      await video.play();
      const scanFrame = () => {
        if (!state.stream || video.readyState < 2) {
          if (state.stream) state.cameraFrame = requestAnimationFrame(scanFrame);
          return;
        }
        const w = video.videoWidth, h = video.videoHeight;
        if (w && h && window.jsQR) {
          workCanvas.width = w; workCanvas.height = h;
          ctx.drawImage(video, 0, 0, w, h);
          const data = ctx.getImageData(0, 0, w, h);
          const code = window.jsQR(data.data, data.width, data.height, { inversionAttempts: "dontInvert" });
          if (code) {
            $("cameraStatus").textContent = "QR code detected";
            renderReport(code.data);
            stopCamera();
            return;
          }
        }
        state.cameraFrame = requestAnimationFrame(scanFrame);
      };
      scanFrame();
    } catch (err) {
      stopCamera();
      showToast(err && err.name === "NotAllowedError" ? "Camera permission was denied." : "Could not start camera. Try image upload instead.");
    }
  }

  function generateDemo(kind) {
    if (!window.QRCode) {
      showToast("Demo QR generator did not load. Check your internet connection and refresh.");
      return;
    }
    const demos = {
      safe: { value: "https://www.wikipedia.org/", title: "Example URL", description: "A familiar HTTPS URL for demonstrating a low-risk result." },
      suspicious: { value: "http://192.168.1.25/login-verify-account", title: "Suspicious URL", description: "A deliberately synthetic example containing multiple warning indicators. It is not a real phishing site." },
      text: { value: "Product Demo: Batch ID QRS-2026-014. Verify details with the seller.", title: "Plain text QR", description: "A non-URL QR payload. The scanner displays it without treating it as a web destination." }
    };
    const demo = demos[kind];
    state.currentDemo = demo.value;
    $("demoQr").replaceChildren();
    new QRCode($("demoQr"), { text: demo.value, width: 116, height: 116, colorDark: "#07111e", colorLight: "#ffffff", correctLevel: QRCode.CorrectLevel.M });
    $("demoTitle").textContent = demo.title;
    $("demoDescription").textContent = demo.description;
    $("demoStage").classList.remove("hidden");
    $("demoStage").scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  $("chooseFileBtn").addEventListener("click", (e) => { e.stopPropagation(); fileInput.click(); });
  dropZone.addEventListener("click", () => fileInput.click());
  dropZone.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fileInput.click(); } });
  fileInput.addEventListener("change", () => { handleFile(fileInput.files[0]); fileInput.value = ""; });
  ["dragenter", "dragover"].forEach((name) => dropZone.addEventListener(name, (e) => { e.preventDefault(); dropZone.classList.add("dragover"); }));
  ["dragleave", "drop"].forEach((name) => dropZone.addEventListener(name, (e) => { e.preventDefault(); dropZone.classList.remove("dragover"); }));
  dropZone.addEventListener("drop", (e) => handleFile(e.dataTransfer.files[0]));
  $("cameraBtn").addEventListener("click", () => state.stream ? stopCamera() : startCamera());
  $("stopCameraBtn").addEventListener("click", stopCamera);
  document.querySelectorAll("[data-demo]").forEach((button) => button.addEventListener("click", () => generateDemo(button.dataset.demo)));
  $("analyzeDemoBtn").addEventListener("click", () => { if (state.currentDemo) renderReport(state.currentDemo); });
  $("closeDemoBtn").addEventListener("click", () => $("demoStage").classList.add("hidden"));
  $("resetBtn").addEventListener("click", () => {
    $("reportContent").classList.add("hidden");
    $("emptyState").classList.remove("hidden");
    $("resultTitle").textContent = "Waiting for a QR code";
    $("resultIcon").className = "result-icon neutral";
    $("resultIcon").textContent = "⌁";
    state.payload = "";
  });
  $("copyBtn").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(state.payload);
      $("copyStatus").textContent = "Copied";
    } catch (_) {
      const textArea = document.createElement("textarea");
      textArea.value = state.payload;
      textArea.style.position = "fixed"; textArea.style.opacity = "0";
      document.body.append(textArea); textArea.select();
      const ok = document.execCommand("copy"); textArea.remove();
      $("copyStatus").textContent = ok ? "Copied" : "Select the content to copy";
    }
  });

  window.addEventListener("beforeunload", () => {
    stopCamera();
    if (state.lastFileUrl) URL.revokeObjectURL(state.lastFileUrl);
  });
})();
