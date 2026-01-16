const fileInput = document.getElementById("qr-input");
const decodedTextEl = document.getElementById("decoded-text");
const riskOutputEl = document.getElementById("risk-output");
const resultBox = document.getElementById("result");

fileInput.addEventListener("change", async () => {
    const file = fileInput.files[0];
    if (!file) return;

    decodedTextEl.textContent = "Decoding QR code...";
    riskOutputEl.textContent = "";
    resultBox.classList.remove("hidden");

    try {
        const qrResult = await QrScanner.scanImage(file);
        decodedTextEl.textContent = qrResult;
    } catch (err) {
        decodedTextEl.textContent = "Unable to read QR code. Please try another image.";
    }
});
