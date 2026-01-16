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
                decodedTextEl.textContent = code.data;
            } else {
                decodedTextEl.textContent = "Unable to read QR code. Please try another image.";
            }
        };
        img.src = reader.result;
    };
    reader.readAsDataURL(file);
});
