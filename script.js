const fileInput = document.getElementById("qr-input");
const decodedTextEl = document.getElementById("decoded-text");
const riskOutputEl = document.getElementById("risk-output");
const resultBox = document.getElementById("result");

const copyBtn = document.getElementById("copy-url-btn");
const downloadBtn = document.getElementById("download-report-btn");
const clearBtn = document.getElementById("clear-btn");
const darkToggle = document.getElementById("dark-toggle");

let lastAnalysis = null;

// Dark mode toggle
darkToggle.addEventListener("click", () => {
    document.body.classList.toggle("light-mode");
});

// Clear scan
clearBtn.addEventListener("click", () => {
    fileInput.value = "";
    decodedTextEl.textContent = "";
    riskOutputEl.textContent = "";
    resultBox.classList.add("hidden");
    lastAnalysis = null;
    copyBtn.disabled = true;
    downloadBtn.disabled = true;
});

// Copy URL
copyBtn.addEventListener("click", () => {
    if (!lastAnalysis) return;
    navigator.clipboard.writeText(lastAnalysis.url).catch(() => {});
});

// Download report
downloadBtn.addEventListener("click", () => {
    if (!lastAnalysis) return;

    const { url, score, level, reasons } = lastAnalysis;
    let text = `QR Code Phishing Detector Report\n\n`;
    text += `Analysed URL: ${url}\n`;
    text += `Risk Level: ${level}\n`;
    text += `Score: ${score}\n\n`;

    if (reasons.length) {
        text += `Indicators:\n`;
        for (const r of reasons) {
            text += `- ${r}\n`;
        }
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

// File input handler
fileInput.addEventListener("change", () => {
    const file = fileInput.files[0];
    if (!file) return;

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
});

// --------- URL detection ---------

function isUrl(text) {
    try {
        const url = new URL(text.startsWith("http") ? text : "https://" + text);
        return !!url.hostname;
    } catch {
        return false;
    }
}

// --------- Risk analysis engine (maximum depth) ---------

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
    if (shorteners.some(s => hostname === s)) {
        score += 25;
        reasons.push("URL shortener detected (destination may be hidden).");
    }

    // 4. IP-based URLs
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
        score += 25;
        reasons.push("IP address used instead of domain name.");
    }

    // 5. Excessive subdomains
    const parts = hostname.split(".");
    if (parts.length > 4) {
        score += 15;
        reasons.push("Excessive subdomains used (possible obfuscation).");
    }

    // 6. @ symbol in URL
    if (full.includes("@")) {
        score += 20;
        reasons.push("@ symbol present in URL (can hide real destination).");
    }

    // 7. Punycode
    if (hostname.startsWith("xn--")) {
        score += 20;
        reasons.push("Punycode domain detected (possible homograph attack).");
    }

    // 8. Suspicious keywords (auth, finance, urgency, crypto, gov)
    const keywordGroups = {
        auth: ["login", "verify", "update", "secure", "password", "reset", "signin"],
        finance: ["bank", "wallet", "payment", "invoice", "paypal", "card"],
        urgency: ["urgent", "immediately", "suspend", "locked", "alert", "warning"],
        crypto: ["crypto", "bitcoin", "eth", "airdrop"],
        gov: ["hmrc", "gov.uk", "tax", "fine"]
    };

    let keywordHits = [];
    for (const group in keywordGroups) {
        const hits = keywordGroups[group].filter(k => full.includes(k));
        if (hits.length) {
            keywordHits = keywordHits.concat(hits);
        }
    }
    if (keywordHits.length > 0) {
        score += 20;
        reasons.push("Contains sensitive or urgent keywords: " + keywordHits.join(", ") + ".");
    }

    // 9. Long query / tracking
    if (url.search && url.search.length > 80) {
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
    const port = url.port;
    const oddPorts = ["8080", "3000", "4443", "1337"];
    if (port && oddPorts.includes(port)) {
        score += 10;
        reasons.push(`Non-standard port used (:${port}).`);
    }

    // 13. Unicode homoglyph heuristic (very rough)
    if (/[^\x00-\x7F]/.test(hostname)) {
        score += 15;
        reasons.push("Non-ASCII characters in domain (possible homoglyph attack).");
    }

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

// --------- Formatting ---------

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

    // Clickable only for LOW risk
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
