document.getElementById("qr-input").addEventListener("change", () => {
    document.getElementById("decoded-text").textContent = "Decoding...";
    document.getElementById("risk-output").textContent = "Analysing...";
    document.getElementById("result").classList.remove("hidden");
});

