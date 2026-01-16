const fileInput = document.getElementById("qr-input");
const decodedTextEl = document.getElementById("decoded-text");
const riskOutputEl = document.getElementById("risk-output");
const resultBox = document.getElementById("result");

fileInput.addEventListener("change", () => {
    const file = fileInput.files[0];
    if (!file) return;

    decodedTextEl.textContent = "Decoding QR code...";
    riskOutputEl.textContent = "";
    resultBox.classList.remove("hidden");

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
                    riskOutputEl.innerHTML = formatRiskAnalysis(analysis);
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

// --------- Risk analysis engine ---------

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

    // 8. Suspicious keywords
    const keywords = [
        "login", "verify", "update", "secure", "account", "bank",
        "wallet", "crypto", "password", "reset", "support", "invoice"
    ];
    const hitKeywords = keywords.filter(k => full.includes(k));
    if (hitKeywords.length > 0) {
        score += 15;
        reasons.push("Contains sensitive keywords: " + hitKeywords.join(", ") + ".");
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

    // Final risk level
    let level = "LOW";
    if (score >= 60) level = "HIGH";
    else if (score >= 30) level = "MEDIUM";

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
    if (level === "MEDIUM") badgeClass = "risk-medium";
    if (level === "HIGH") badgeClass = "risk-high";

    let html = `
        <div class="risk-badge ${badgeClass}">
            ${level} RISK
        </div><br>
        <strong>Analysed URL:</strong> ${escapeHtml(url)}<br>
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
