// WhatsApp Web Scam Detection
(function() {
  'use strict';

  const SCAM_KEYWORDS = [
    'won', 'prize', 'lottery', 'urgent', 'otp', 'verify', 'suspended',
    'inheritance', 'million', 'bitcoin', 'crypto', 'investment',
    'double your money', 'send money', 'processing fee', 'click here',
    'call now', 'limited time', 'act now', 'congratulations'
  ];

  const SCAM_PATTERNS = [
    /\$\d+/,
    /\d{4,}/,
    /https?:\/\//,
    /\bOTP\b/i,
    /\bUrgent\b/i,
    /\bWon\b/i,
    /\bPrize\b/i
  ];

  function analyzeMessage(text) {
    let score = 0;
    let reasons = [];

    // Check keywords
    SCAM_KEYWORDS.forEach(keyword => {
      if (text.toLowerCase().includes(keyword)) {
        score += 10;
        reasons.push(`Contains "${keyword}"`);
      }
    });

    // Check patterns
    SCAM_PATTERNS.forEach(pattern => {
      if (pattern.test(text)) {
        score += 5;
      }
    });

    // Check for urgency indicators
    if (/\b(urgent|hurry|limited time|act now|immediately)\b/i.test(text)) {
      score += 15;
      reasons.push('Urgency indicators found');
    }

    // Check for money requests
    if (/\b(send money|wire transfer|bitcoin|crypto|payment)\b/i.test(text)) {
      score += 20;
      reasons.push('Money request detected');
    }

    return {
      isScam: score >= 30,
      score: score,
      reasons: reasons
    };
  }

  function addWarningIndicator(messageElement, result) {
    if (messageElement.querySelector('.scam-warning')) return;

    const warning = document.createElement('div');
    warning.className = 'scam-warning';
    warning.style.cssText = `
      background: #ff4444;
      color: white;
      padding: 5px 10px;
      border-radius: 5px;
      font-size: 12px;
      margin-top: 5px;
      display: flex;
      align-items: center;
      gap: 5px;
    `;
    warning.innerHTML = `
      <span>⚠️</span>
      <span><strong>Potential Scam!</strong> Score: ${result.score}</span>
    `;

    const reasonsDiv = document.createElement('div');
    reasonsDiv.style.cssText = `
      background: #ffebee;
      color: #c62828;
      padding: 5px 10px;
      border-radius: 0 0 5px 5px;
      font-size: 11px;
      margin-top: 2px;
    `;
    reasonsDiv.innerHTML = result.reasons.map(r => `• ${r}`).join('<br>');

    messageElement.style.position = 'relative';
    messageElement.appendChild(warning);
    messageElement.appendChild(reasonsDiv);
  }

  function scanMessages() {
    const messages = document.querySelectorAll('[data-testid="msg-container"]');
    
    messages.forEach(message => {
      const textElement = message.querySelector('.copyable-text');
      if (!textElement) return;

      const text = textElement.innerText || textElement.textContent;
      if (!text || text.length < 10) return;

      const result = analyzeMessage(text);
      if (result.isScam) {
        addWarningIndicator(message, result);
      }
    });
  }

  // Scan on load and when new messages appear
  setInterval(scanMessages, 2000);

  // Also scan when DOM changes
  const observer = new MutationObserver(scanMessages);
  observer.observe(document.body, { childList: true, subtree: true });

  console.log('WhatsApp Scam Detector loaded');
})();
