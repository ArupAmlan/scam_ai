const SCAM_GUARD_ATTRIBUTE = "data-scam-guard-checked";

const DETECTION_RULES = [
  { id: "otp_request", phrases: ["otp", "one time password", "verification code", "verification otp"], score: 4 },
  { id: "bank_details", phrases: ["bank account", "account number", "ifsc", "iban"], score: 4 },
  { id: "card_details", phrases: ["cvv", "pin code", "card number", "debit card", "credit card"], score: 5 },
  { id: "prize_lottery", phrases: ["you have won", "congratulations you won", "lottery winner", "prize money"], score: 4 },
  { id: "urgent_action", phrases: ["urgent action", "limited time", "act now", "immediately", "within 5 minutes"], score: 2 },
  { id: "money_request", phrases: ["send money", "wire money", "transfer money", "pay the fee"], score: 4 },
  { id: "giftcard_crypto", phrases: ["gift card", "google play card", "itunes card", "bitcoin", "crypto"], score: 4 },
  { id: "investment", phrases: ["investment opportunity", "double your money", "guaranteed returns"], score: 3 },
  { id: "inheritance", phrases: ["inheritance", "foreign fund", "unclaimed funds"], score: 3 },
  { id: "keep_secret", phrases: ["do not tell anyone", "keep this confidential"], score: 3 },
  { id: "account_verify", phrases: ["verify your account", "confirm your identity", "kyc update"], score: 3 }
];

function isSuspiciousText(text) {
  const lowered = text.toLowerCase();
  const matchedReasons = [];
  let totalScore = 0;

  for (const rule of DETECTION_RULES) {
    for (const phrase of rule.phrases) {
      if (lowered.includes(phrase)) {
        matchedReasons.push(phrase);
        totalScore += rule.score;
        break;
      }
    }
  }

  const moneyRegex = /(\b(?:rs\.?|inr|₹|usd|\$|eur|£|rupees|dollars?)\s?\d{3,}|\d{3,}\s?(?:rs\.?|inr|₹|\$|eur|£))/i;
  if (moneyRegex.test(text)) {
    matchedReasons.push("large money amount mentioned");
    totalScore += 3;
  }

  const urlRegex = /(https?:\/\/[^\s]+)/gi;
  const urls = text.match(urlRegex) || [];

  const suspiciousShorteners = ["bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co"];

  for (const url of urls) {
    try {
      const u = new URL(url);
      const host = u.hostname.toLowerCase();
      for (const shortener of suspiciousShorteners) {
        if (host === shortener || host.endsWith("." + shortener)) {
          matchedReasons.push("link via url shortener (" + shortener + ")");
          totalScore += 3;
        }
      }
    } catch (e) {
    }
  }

  const suspicious = totalScore >= 3;

  return {
    suspicious,
    reasons: Array.from(new Set(matchedReasons)),
    urls,
    score: totalScore
  };
}

function buildAdviceText(reasons) {
  const baseAdvice = [
    "Do not share OTPs, passwords, PINs, or card details.",
    "Do not click on suspicious links or download unknown attachments.",
    "Do not send money, gift cards, or crypto to unknown people.",
    "Verify requests through official channels (bank app, company website, phone number from their official site).",
    "If unsure, ignore the message and do not reply."
  ];

  const extra = [];

  for (const reason of reasons) {
    if (reason.includes("otp") || reason.includes("password") || reason.includes("pin")) {
      extra.push("Legitimate companies and banks will never ask for OTPs or full passwords over chat.");
    } else if (reason.includes("won") || reason.includes("lottery") || reason.includes("prize")) {
      extra.push("Random messages telling you that you won money or prizes are almost always scams.");
    } else if (reason.includes("send money") || reason.includes("gift card") || reason.includes("bitcoin") || reason.includes("crypto")) {
      extra.push("Never send money or gift cards to someone you only know through chat.");
    } else if (reason.includes("url shortener")) {
      extra.push("Shortened links can hide the real website; open them only if you fully trust the sender.");
    }
  }

  const allAdvice = baseAdvice.concat(extra);

  const uniqueAdvice = Array.from(new Set(allAdvice));

  return uniqueAdvice;
}

function createWarningElement(analysis) {
  const container = document.createElement("div");
  container.style.border = "1px solid #e53935";
  container.style.borderRadius = "6px";
  container.style.padding = "6px 8px";
  container.style.marginTop = "4px";
  container.style.backgroundColor = "rgba(229,57,53,0.08)";
  container.style.fontSize = "12px";
  container.style.color = "#b71c1c";
  container.style.maxWidth = "320px";

  const title = document.createElement("div");
  let riskLabel = "medium risk";
  if (analysis.score >= 7) {
    riskLabel = "high risk";
  } else if (analysis.score < 5) {
    riskLabel = "medium risk";
  }
  title.textContent = "Scam Guard: " + riskLabel + " message";
  title.style.fontWeight = "600";
  title.style.marginBottom = "4px";
  container.appendChild(title);

  if (analysis.reasons.length > 0) {
    const reasonsEl = document.createElement("div");
    reasonsEl.textContent = "Suspicious because: " + analysis.reasons.join(", ");
    reasonsEl.style.marginBottom = "4px";
    container.appendChild(reasonsEl);
  }

  const adviceList = document.createElement("ul");
  adviceList.style.paddingLeft = "18px";
  adviceList.style.margin = "0";

  const adviceItems = buildAdviceText(analysis.reasons);
  for (const advice of adviceItems) {
    const li = document.createElement("li");
    li.textContent = advice;
    adviceList.appendChild(li);
  }

  container.appendChild(adviceList);

  return container;
}

function findMessageTextElements(root) {
  const containers = root.querySelectorAll('div[role="row"] div[data-testid="msg-container"], div.message-in, div.message-out');
  const elements = [];

  for (const container of containers) {
    const spans = container.querySelectorAll('span[dir="ltr"], span[dir="auto"], span.selectable-text');
    for (const span of spans) {
      elements.push(span);
    }
  }

  return elements;
}

function markMessageElement(messageEl, analysis) {
  const bubble =
    messageEl.closest('div[data-testid="msg-container"]') ||
    messageEl.closest("div.message-in, div.message-out") ||
    messageEl.parentElement;
  if (!bubble) return;

  if (bubble.hasAttribute(SCAM_GUARD_ATTRIBUTE)) return;

  bubble.setAttribute(SCAM_GUARD_ATTRIBUTE, "true");

  if (!analysis.suspicious) return;

  bubble.style.border = "2px solid #e53935";
  bubble.style.borderRadius = "8px";

  const warning = createWarningElement(analysis);
  bubble.appendChild(warning);
}

function scanExistingMessages() {
  const root = document.body;
  const messageNodes = findMessageTextElements(root);

  for (const node of messageNodes) {
    const text = node.innerText || node.textContent || "";
    if (!text.trim()) continue;

    const analysis = isSuspiciousText(text);
    if (analysis.suspicious) {
      markMessageElement(node, analysis);
    } else {
      node.closest("div.message-in, div.message-out")?.setAttribute(SCAM_GUARD_ATTRIBUTE, "true");
    }
  }
}

function observeNewMessages() {
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (!(node instanceof HTMLElement)) continue;

        const messageNodes = findMessageTextElements(node);
        for (const msgNode of messageNodes) {
          const text = msgNode.innerText || msgNode.textContent || "";
          if (!text.trim()) continue;

          const analysis = isSuspiciousText(text);
          if (analysis.suspicious) {
            markMessageElement(msgNode, analysis);
          } else {
            msgNode.closest("div.message-in, div.message-out")?.setAttribute(SCAM_GUARD_ATTRIBUTE, "true");
          }
        }
      }
    }
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
}

function showScamGuardActiveBanner() {
  const existing = document.getElementById("scam-guard-active-banner");
  if (existing) return;

  const banner = document.createElement("div");
  banner.id = "scam-guard-active-banner";
  banner.textContent = "Scam Guard is active on this page";
  banner.style.position = "fixed";
  banner.style.bottom = "12px";
  banner.style.right = "12px";
  banner.style.zIndex = "99999";
  banner.style.backgroundColor = "rgba(25,118,210,0.9)";
  banner.style.color = "#ffffff";
  banner.style.padding = "6px 10px";
  banner.style.borderRadius = "4px";
  banner.style.fontSize = "12px";
  banner.style.boxShadow = "0 2px 6px rgba(0,0,0,0.3)";

  document.body.appendChild(banner);

  setTimeout(() => {
    banner.remove();
  }, 5000);
}

function initScamGuard() {
  try {
    showScamGuardActiveBanner();
    scanExistingMessages();
    observeNewMessages();
  } catch (e) {
    console.error("Scam Guard init error:", e);
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initScamGuard);
} else {
  initScamGuard();
}
