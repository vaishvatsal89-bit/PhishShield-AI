const HISTORY_KEY = "phishshield-history";

const riskRules = [
    {
        test: (text, url) => Boolean(url && url.protocol !== "https:"),
        points: 18,
        evidence: "The link does not use HTTPS encryption."
    },
    {
        test: (text) => /\b(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd|cutt\.ly|rebrand\.ly)\b/i.test(text),
        points: 18,
        evidence: "A URL shortener is present, which can hide the final destination."
    },
    {
        test: (text) => /\b\d{1,3}(\.\d{1,3}){3}\b/.test(text),
        points: 20,
        evidence: "The message contains an IP address instead of a normal domain."
    },
    {
        test: (text) => /\b(password|otp|pin|ssn|card number|cvv|bank account|seed phrase)\b/i.test(text),
        points: 20,
        evidence: "The message asks for sensitive credentials or financial information."
    },
    {
        test: (text) => /\b(urgent|immediately|locked|suspended|verify now|limited time|final warning|act now)\b/i.test(text),
        points: 15,
        evidence: "Urgent pressure language is used to rush the recipient."
    },
    {
        test: (text) => /\b(prize|reward|bonus|refund|free gift|lottery|claim)\b/i.test(text),
        points: 11,
        evidence: "Reward or prize language appears in the message."
    },
    {
        test: (text, url) => Boolean(url && url.hostname.split(".").length > 4),
        points: 9,
        evidence: "The domain has many subdomains, a common trick for hiding the real host."
    },
    {
        test: (text, url) => Boolean(url && /[-_]{2,}|[0-9]{4,}/.test(url.hostname)),
        points: 8,
        evidence: "The domain contains unusual separators or long number sequences."
    },
    {
        test: (text) => /\b(paypaI|rnicrosoft|g00gle|faceb00k|netfIix|appIe)\b/i.test(text),
        points: 18,
        evidence: "A lookalike brand spelling was detected."
    },
    {
        test: (text) => /\.(zip|exe|scr|bat|cmd|js|iso)\b/i.test(text),
        points: 14,
        evidence: "The message references a risky file type."
    }
];

function readHistory() {
    try {
        return JSON.parse(localStorage.getItem(HISTORY_KEY)) || [];
    } catch {
        return [];
    }
}

function saveHistory(items) {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(items.slice(0, 20)));
}

function extractUrl(input) {
    const match = input.match(/https?:\/\/[^\s<>"']+/i);
    if (!match) return null;

    try {
        return new URL(match[0]);
    } catch {
        return null;
    }
}

function analyzeInput(input, deepScan) {
    const text = input.trim();
    const url = extractUrl(text);
    const evidence = [];
    let score = 0;

    riskRules.forEach((rule) => {
        if (rule.test(text, url)) {
            score += rule.points;
            evidence.push(rule.evidence);
        }
    });

    if (deepScan && text.length < 18) {
        score += 8;
        evidence.push("The submitted content is very short, which limits verification context.");
    }

    if (url && /^[a-z0-9.-]+\.(com|org|net|edu|gov|in)$/i.test(url.hostname) && url.protocol === "https:" && evidence.length === 0) {
        evidence.push("No major phishing indicators were found in the URL structure.");
    }

    const normalizedScore = Math.min(score, 100);
    const label = normalizedScore >= 70 ? "High risk" : normalizedScore >= 35 ? "Suspicious" : "Low risk";
    const color = normalizedScore >= 70 ? "#ff5c7a" : normalizedScore >= 35 ? "#ffb84d" : "#37d67a";

    return {
        input: text,
        score: normalizedScore,
        label,
        color,
        evidence,
        domain: url ? url.hostname : "No URL detected",
        scannedAt: new Date().toISOString()
    };
}

function recommendationsFor(result) {
    if (result.score >= 70) {
        return [
            "Do not open the link or download any attachment.",
            "Report the message to your security team or email provider.",
            "If you already interacted with it, change passwords and revoke active sessions."
        ];
    }

    if (result.score >= 35) {
        return [
            "Verify the sender using an official website, app, or known contact.",
            "Avoid entering credentials until the domain and request are confirmed.",
            "Scan again with the full message if you only pasted a partial link."
        ];
    }

    return [
        "The scan looks low risk, but still confirm unexpected requests.",
        "Use multi-factor authentication for accounts connected to this message.",
        "Keep this result in history for future reference."
    ];
}

function renderResult(result) {
    const panel = document.querySelector("#resultPanel");
    if (!panel) return;

    panel.classList.remove("empty");
    panel.style.setProperty("--score", result.score);
    panel.style.setProperty("--ring-color", result.color);
    panel.style.setProperty("--label-color", result.color);

    const evidenceItems = result.evidence.map((item) => `<li>${escapeHtml(item)}</li>`).join("");
    const recommendationItems = recommendationsFor(result).map((item) => `<li>${escapeHtml(item)}</li>`).join("");

    panel.innerHTML = `
        <div class="result-header">
            <div class="score-ring"><span>${result.score}</span></div>
            <div>
                <span class="label-pill">${result.label}</span>
                <h2>${escapeHtml(result.domain)}</h2>
                <p class="muted">Generated by local heuristic analysis.</p>
            </div>
        </div>
        <div class="result-section">
            <h3>Detected signals</h3>
            <ul class="evidence-list">${evidenceItems}</ul>
        </div>
        <div class="result-section">
            <h3>Recommended action</h3>
            <ul class="recommendations">${recommendationItems}</ul>
        </div>
    `;
}

function renderHistory() {
    const list = document.querySelector("#historyList");
    if (!list) return;

    const history = readHistory();
    if (!history.length) {
        list.innerHTML = `<div class="empty-history">No scans saved yet. Run a scan to build your evidence archive.</div>`;
        return;
    }

    list.innerHTML = history.map((item) => {
        const date = new Date(item.scannedAt).toLocaleString();
        return `
            <article class="history-card" style="--label-color:${item.color}">
                <div>
                    <div class="history-meta">
                        <span class="label-pill">${escapeHtml(item.label)}</span>
                        <span class="muted">${date}</span>
                    </div>
                    <code>${escapeHtml(item.input)}</code>
                    <p>${escapeHtml((item.evidence || [])[0] || "No major phishing indicators were found.")}</p>
                </div>
                <div class="history-score">${item.score}/100</div>
            </article>
        `;
    }).join("");
}

function escapeHtml(value) {
    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function setupScanner() {
    const form = document.querySelector("#scanForm");
    const input = document.querySelector("#scanInput");
    const deepScan = document.querySelector("#deepScan");
    if (!form || !input) return;

    document.querySelectorAll("[data-example]").forEach((button) => {
        button.addEventListener("click", () => {
            input.value = button.dataset.example;
            input.focus();
        });
    });

    form.addEventListener("submit", (event) => {
        event.preventDefault();
        const result = analyzeInput(input.value, Boolean(deepScan && deepScan.checked));
        const history = readHistory();
        saveHistory([result, ...history]);
        renderResult(result);
    });
}

function setupHistoryActions() {
    const clearButton = document.querySelector("#clearHistory");
    if (!clearButton) return;

    clearButton.addEventListener("click", () => {
        saveHistory([]);
        renderHistory();
    });
}

function updateHomeStats() {
    const count = document.querySelector("#homeHistoryCount");
    if (count) count.textContent = readHistory().length;
}

setupScanner();
setupHistoryActions();
renderHistory();
updateHomeStats();
