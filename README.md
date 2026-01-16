📌 QR Code Phishing Detector
A browser‑based security tool that scans QR codes, extracts embedded URLs, and performs a multi‑layer phishing risk analysis.
Designed with a cyber‑security mindset, this project demonstrates practical threat‑detection logic, secure UI patterns, and modern accessibility standards.

🔗 Live Demo:  
https://ke-johnston1.github.io/qr-code-phishing-detector

🖼️ Screenshot
![Screenshot_16-1-2026_18612_ke-johnston1 github io](https://github.com/user-attachments/assets/1c57604f-7c1f-4a59-9ae4-17dd99eb99f9)


Code
![QR Code Phishing Detector Screenshot](screenshot.png)
🛡️ Features
🔍 QR Code Scanning
Upload or drag‑and‑drop QR code images

Automatic decoding using jsQR

Real‑time results with accessible live region updates

🧠 Advanced Phishing Risk Engine
The tool analyses URLs using 13+ detection heuristics, including:

Protocol (HTTP vs HTTPS)

Suspicious TLDs

URL shorteners

IP‑based URLs

Excessive subdomains

Punycode / homoglyph detection

Sensitive keywords (login, verify, payment, etc.)

Urgency keywords (alert, warning, suspended)

Encoded characters

Suspicious file extensions

Non‑standard ports

Document download patterns

Unicode anomalies

Risk levels are scored and displayed as:

🟢 LOW RISK

🟡 MEDIUM RISK

🔴 HIGH RISK

High‑risk URLs are blocked from being clickable.

🎛️ User Interface & UX
Dark cyber‑security dashboard theme

Light mode toggle

Drag‑and‑drop upload zone

Keyboard‑accessible controls

Screen‑reader friendly labels

Clear scan, copy URL, and download report buttons

Clean, responsive layout

♿ Accessibility Enhancements
ARIA labels

Live region updates for scan results

Focus‑visible outlines

Keyboard‑operable drop zone

Screen‑reader‑only text for hidden labels

This makes the tool usable for keyboard‑only and assistive‑technology users.

🧪 Built‑In Test Suite
Developers can run:

js
runTestCases();
…in the browser console to validate the risk engine against known phishing patterns.

🧰 Tech Stack
HTML5

CSS3 (custom cyber‑security theme)

JavaScript (ES6+)

jsQR for QR decoding

No frameworks, no dependencies — fully client‑side

🚀 How to Use
Open the live demo

Upload or drag‑and‑drop a QR code image

View the decoded URL

Review the phishing risk analysis

Copy the URL or download a text‑based report

Clear the scan to test another QR code

🧩 Why This Project Matters
QR codes are increasingly used in:

Public spaces

Restaurants

Parking meters

Delivery scams

Phishing campaigns

Attackers exploit QR codes because:

Users can’t visually inspect the URL

QR codes bypass email filters

Mobile devices hide full URLs by default

This tool demonstrates:

Real‑world threat detection

Secure UI patterns

Practical cyber‑security thinking

Your ability to build tools that solve modern security problems

Perfect for SOC, analyst, and cyber‑adjacent roles.

⚙️ Run Locally
bash
git clone https://github.com/KE-Johnston1/qr-code-phishing-detector
cd qr-code-phishing-detector
open index.html
No build steps. No dependencies. Just open and run.

⚠️ Disclaimer
This tool provides heuristic analysis only.
It does not guarantee that a URL is safe.

👤 Author
K. Johnston  
Cyber‑security & IT Support Professional
Focused on SOC, detection engineering, and practical security tooling.
