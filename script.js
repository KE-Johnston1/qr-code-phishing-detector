const fileInput = document.getElementById("qr-input");
const decodedTextEl = document.getElementById("decoded-text");
const riskOutputEl = document.getElementById("risk-output");
const resultBox = document.getElementById("result");

const copyBtn = document.getElementById("copy-url-btn");
const downloadBtn = document.getElementById("download-report-btn");
const clearBtn = document.getElementById("clear-btn");
const darkToggle = document.getElementById("dark-toggle");
const dropZone = document.getElementById("drop-zone");

let lastAnalysis = null;

// ---------------- DARK MODE ----------------

darkToggle.addEventListener("click", () => {
    const isLight = document.body.classList.toggle("light-mode");
    darkToggle.setAttribute("aria-pressed", isLight ? "true" : "false");
});

// ---------------- CLEAR SCAN ----------------

clearBtn.addEventListener("click", () => {
    fileInput.value = "";
    decodedTextEl.textContent = "";
    riskOutputEl.textContent = "";
    resultBox.classList.add("hidden");
    lastAnalysis = null;
    copyBtn.disabled = true;
    downloadBtn.disabled = true;
});

// ---------------- COPY URL ----------------

copyBtn.addEventListener("click", () => {
    if (!lastAnalysis) return;
    navigator.clipboard.writeText(lastAnalysis.url).catch(() => {});
});

// ---------------- DOWNLOAD REPORT ----------------

downloadBtn.addEventListener("click", () => {
    if (!lastAnalysis) return;

    const { url, score, level, reasons } = lastAnalysis;

    let text = `QR Code Phishing Detector Report\n\n`;
    text += `Analysed URL: ${url}\n`;
    text += `Risk Level: ${level}\n`;
    text += `Score: ${score}\n\n`;

    if (reasons.length) {
        text += `Indicators:\n`;
        for (const r of reasons) text += `- ${r}\n`;
    } else {
        text += `No obvious phishing indicators detected.\n`;
    }

    text += `\nNote: This tool is heuristic and does not guarantee link safety.\n`;

    const blob = new Blob([text], { type: "text/plain" });
    const urlObj = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = urlObj;
    a.download = "qr_phishing_report.txt";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(urlObj);
});

// ---------------- FILE INPUT HANDLER ----------------

fileInput.addEventListener("change", () => {
    const file = fileInput.files[0];
    if (!file) return;
    handleImageFile(file);
});

// ---------------- DRAG & DROP HANDLERS ----------------

["dragenter", "dragover"].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropZone.classList.add("drag-over");
    });
});

["dragleave", "drop"].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropZone.classList.remove("drag-over");
    });
});

dropZone.addEventListener("drop", (e) => {
    const files = e.dataTransfer.files;
    if (!files || !files.length) return;
    const file = files[0];
    if (!file.type.startsWith("image/")) {
        decodedTextEl.textContent = "Please drop an image file containing a QR code.";
        resultBox.classList.remove("hidden");
        riskOutputEl.textContent = "";
        return;
    }
    handleImageFile(file);
});

// Keyboard activation for drop zone (opens file picker)
dropZone.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        fileInput.click();
    }
});

// ---------------- CORE IMAGE HANDLER ----------------

function handleImageFile(file) {
    decodedTextEl.textContent = "Decoding QR code...";
    riskOutputEl.textContent = "";
    resultBox.classList.remove("hidden");

    copyBtn.disabled = true;
    downloadBtn.disabled = true;
    lastAnalysis = null;

    const reader = new FileReader();
    reader.onload = function () {
        const img = new Image();
        img.onload = function () {
            const canvas = document.createElement("canvas");
            const ctx = canvas.getContext("2d");

            canvas.width = img.width;
            canvas.height = img.height;
            ctx.drawImage(img, 0, 0);

            const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
            const code = jsQR(imageData.data, canvas.width, canvas.height);

            if (code) {
                const decoded = code.data.trim();
                decodedTextEl.textContent = decoded;

                if (isUrl(decoded)) {
                    const analysis = analyseUrlRisk(decoded);
                    lastAnalysis = analysis;
                    riskOutputEl.innerHTML = formatRiskAnalysis(analysis);

                    copyBtn.disabled = false;
                    downloadBtn.disabled = false;
                } else {
                    riskOutputEl.textContent = "No URL detected. Risk analysis is only applied to links.";
                }
            } else {
                decodedTextEl.textContent = "Unable to read QR code. Please try another image.";
                riskOutputEl.textContent = "";
            }
        };
        img.src = reader.result;
    };
    reader.readAsDataURL(file);
}

// ---------------- URL DETECTION ----------------

function isUrl(text) {
    try {
        const url = new URL(text.startsWith("http") ? text : "https://" + text);
        return !!url.hostname;
    } catch {
        return false;
    }
}

// ---------------- RISK ENGINE ----------------

function analyseUrlRisk(rawUrl) {
    const url = normaliseUrl(rawUrl);
    const hostname = url.hostname.toLowerCase();
    const full = url.href.toLowerCase();

    let score = 0;
    const reasons = [];

    // 1. Protocol
    if (url.protocol !== "https:") {
        score += 20;
        reasons.push("Uses HTTP instead of HTTPS.");
    }

    // 2. Suspicious TLDs
    const tld = hostname.split(".").slice(-1)[0];
    const badTlds = ["xyz", "top", "click", "gq", "cf", "ml", "tk", "rest", "monster", "zip", "mov"];
    if (badTlds.includes(tld)) {
        score += 20;
        reasons.push(`Suspicious top-level domain (.${tld}).`);
    }

    // 3. URL shorteners
    const shorteners = [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
        "buff.ly", "cutt.ly", "rebrand.ly", "bit.do"
    ];
    if (shorteners.includes(hostname)) {
        score += 25;
        reasons.push("URL shortener detected (destination may be hidden).");
    }

    // 4. IP-based URLs
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
        score += 25;
        reasons.push("IP address used instead of domain name.");
    }

    // 5. Excessive subdomains
    if (hostname.split(".").length > 4) {
        score += 15;
        reasons.push("Excessive subdomains used (possible obfuscation).");
    }

    // 6. @ symbol
    if (full.includes("@")) {
        score += 20;
        reasons.push("@ symbol present in URL (can hide real destination).");
    }

    // 7. Punycode
    if (hostname.startsWith("xn--")) {
        score += 20;
        reasons.push("Punycode domain detected (possible homograph attack).");
    }

    // 8. Keyword groups
    const keywordGroups = {
        auth: ["login", "verify", "update", "secure", "password", "reset", "signin"],
        finance: ["bank", "wallet", "payment", "invoice", "paypal", "card"],
        urgency: ["urgent", "immediately", "suspend", "locked", "alert", "warning"],
        crypto: ["crypto", "bitcoin", "eth", "airdrop"],
        gov: ["hmrc", "gov.uk", "tax", "fine"]
    };

    let keywordHits = [];
    for (const group in keywordGroups) {
        keywordHits.push(...keywordGroups[group].filter(k => full.includes(k)));
    }
    if (keywordHits.length) {
        score += 20;
        reasons.push("Contains sensitive or urgent keywords: " + keywordHits.join(", ") + ".");
    }

    // 9. Long query
    if (url.search.length > 80) {
        score += 10;
        reasons.push("Very long query string (possible tracking or obfuscation).");
    }

    // 10. Encoded characters
    if (/%[0-9a-f]{2}/i.test(full)) {
        score += 10;
        reasons.push("Encoded characters present in URL.");
    }

    // 11. Suspicious file extensions
    const path = url.pathname.toLowerCase();
    const badExt = [".exe", ".apk", ".zip", ".rar", ".scr", ".js", ".bat", ".cmd"];
    const docExt = [".pdf", ".doc", ".docx", ".xls", ".xlsx"];

    if (badExt.some(ext => path.endsWith(ext))) {
        score += 30;
        reasons.push("Suspicious executable or archive file extension in URL path.");
    } else if (docExt.some(ext => path.endsWith(ext))) {
        score += 10;
        reasons.push("Document download detected (common in phishing campaigns).");
    }

    // 12. Suspicious ports
    const oddPorts = ["8080", "3000", "4443", "1337"];
    if (url.port && oddPorts.includes(url.port)) {
        score += 10;
        reasons.push(`Non-standard port used (:${url.port}).`);
    }

    // 13. Unicode homoglyph heuristic
    if (/[^\x00-\x7F]/.test(hostname)) {
        score += 15;
        reasons.push("Non-ASCII characters in domain (possible homoglyph attack).");
    }

    // Final risk level
    let level = "LOW";
    if (score >= 70) level = "HIGH";
    else if (score >= 35) level = "MEDIUM";

    return { url: url.href, score, level, reasons };
}

function normaliseUrl(raw) {
    try {
        return new URL(raw);
    } catch {
        return new URL("https://" + raw);
    }
}

// ---------------- FORMATTING ----------------

function formatRiskAnalysis(analysis) {
    const { url, score, level, reasons } = analysis;

    let badgeClass = "risk-low";
    let icon = "🟢";

    if (level === "MEDIUM") {
        badgeClass = "risk-medium";
        icon = "🟡";
    }
    if (level === "HIGH") {
        badgeClass = "risk-high";
        icon = "🔴";
    }

    // Only LOW risk URLs are clickable
    let urlDisplay = escapeHtml(url);
    if (level === "LOW") {
        urlDisplay = `<a href="${escapeAttr(url)}" target="_blank" rel="noopener noreferrer" class="safe-link">${escapeHtml(url)}</a>`;
    }

    let html = `
        <div class="risk-badge ${badgeClass}">
            <span>${icon}</span>
            <span>${level} RISK</span>
        </div><br>
        <strong>Analysed URL:</strong> ${urlDisplay}<br>
        <strong>Score:</strong> ${score}<br>
    `;

    if (!reasons.length) {
        html += "No obvious phishing indicators detected. This does not guarantee the link is safe.";
        return html;
    }

    html += "<strong>Indicators:</strong><ul>";
    for (const reason of reasons) {
        html += `<li>${escapeHtml(reason)}</li>`;
    }
    html += "</ul>";
    html += "Treat unexpected links with caution, especially if received via email, SMS, or QR codes in public places.";

    return html;
}

function escapeHtml(str) {
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
}

function escapeAttr(str) {
    return String(str)
        .replace(/"/g, "&quot;")
        .replace(/</g, "&lt;");
}

// ---------------- TEST CASES ----------------

function runTestCases() {
    const tests = [
        {
            label: "Low risk example.com",
            url: "https://example.com/login?session=123"
        },
        {
            label: "Medium risk suspicious TLD + verify",
            url: "http://example.xyz/verify-account"
        },
        {
            label: "High risk IP + encoded + login/update",
            url: "http://192.168.1.50/login/update?session=999&token=%AF%22%9C"
        },
        {
            label: "High risk shortener + payment",
            url: "http://bit.ly/secure-update-payment?invoice=44882&auth=%F0%9F%94%92"
        }
    ];

    console.log("=== QR Phishing Detector Test Cases ===");
    for (const t of tests) {
        const analysis = analyseUrlRisk(t.url);
        console.log(`\n[${t.label}]`);
        console.log("URL:   ", analysis.url);
        console.log("Level: ", analysis.level);
        console.log("Score: ", analysis.score);
        console.log("Reasons:");
        analysis.reasons.forEach(r => console.log(" -", r));
    }
    console.log("\n=== End of tests ===");
}

// Uncomment this line if you want tests to run automatically in the console on load:
// runTestCases();
