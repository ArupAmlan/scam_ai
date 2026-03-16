// Gmail Scam Detection
(function() {
  'use strict';

  const SCAM_KEYWORDS = [
    'won', 'prize', 'lottery', 'urgent', 'verify', 'suspended',
    'inheritance', 'million', 'bitcoin', 'crypto', 'investment',
    'double your money', 'send money', 'processing fee', 'click here',
    'call now', 'limited time', 'act now', 'congratulations',
    'account locked', 'unusual activity', 'confirm your identity'
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

  const PHISHING_INDICATORS = [
    'verify your account',
    'update your information',
    'suspended',
    'unauthorized access',
    'click the link below',
    'confirm your details'
  ];

  function analyzeEmail(subject, body) {
    let score = 0;
    let reasons = [];
    const fullText = (subject + ' ' + body).toLowerCase();

    // Check keywords
    SCAM_KEYWORDS.forEach(keyword => {
      if (fullText.includes(keyword)) {
        score += 10;
        reasons.push(`Contains "${keyword}"`);
      }
    });

    // Check patterns
    SCAM_PATTERNS.forEach(pattern => {
      if (pattern.test(fullText)) {
        score += 5;
      }
    });

    // Check phishing indicators
    PHISHING_INDICATORS.forEach(indicator => {
      if (fullText.includes(indicator)) {
        score += 15;
        reasons.push(`Phishing: "${indicator}"`);
      }
    });

    // Check for suspicious sender patterns
    const senderElement = document.querySelector('[email]');
    if (senderElement) {
      const sender = senderElement.getAttribute('email');
      if (sender && !sender.includes('@gmail.com') && !sender.includes('@')) {
        score += 10;
        reasons.push('Suspicious sender');
      }
    }

    // Check for urgency
    if (/\b(urgent|immediate action required|respond within|24 hours)\b/i.test(fullText)) {
      score += 20;
      reasons.push('Urgency pressure');
    }

    return {
      isScam: score >= 40,
      score: score,
      reasons: reasons
    };
  }

  function addEmailWarning(emailElement, result) {
    if (emailElement.querySelector('.email-scam-warning')) return;

    const warning = document.createElement('div');
    warning.className = 'email-scam-warning';
    warning.style.cssText = `
      background: #ff4444;
      color: white;
      padding: 8px 12px;
      border-radius: 4px;
      font-size: 13px;
      margin: 10px 0;
      display: flex;
      align-items: center;
      gap: 8px;
    `;
    warning.innerHTML = `
      <span style="font-size: 16px;">⚠️</span>
      <div>
        <strong>Potential Scam Email!</strong>
        <div style="font-size: 11px; margin-top: 2px;">Risk Score: ${result.score}/100</div>
      </div>
    `;

    const reasonsDiv = document.createElement('div');
    reasonsDiv.style.cssText = `
      background: #ffebee;
      color: #c62828;
      padding: 8px 12px;
      border-radius: 0 0 4px 4px;
      font-size: 12px;
      margin: -10px 0 10px 0;
      border-left: 3px solid #ff4444;
    `;
    reasonsDiv.innerHTML = '<strong>Warning signs:</strong><br>' + 
      result.reasons.map(r => `• ${r}`).join('<br>');

    emailElement.insertBefore(warning, emailElement.firstChild);
    emailElement.insertBefore(reasonsDiv, warning.nextSibling);
  }

  function scanEmails() {
    // Scan email list
    const emailRows = document.querySelectorAll('[data-legacy-thread-id]');
    
    emailRows.forEach(row => {
      const subjectElement = row.querySelector('[data-tooltip]');
      if (!subjectElement) return;

      const subject = subjectElement.textContent || '';
      const result = analyzeEmail(subject, '');
      
      if (result.isScam) {
        row.style.backgroundColor = '#ffebee';
        row.style.borderLeft = '3px solid #ff4444';
      }
    });

    // Scan opened email
    const emailBody = document.querySelector('.a3s.aiL');
    const emailSubject = document.querySelector('h2[data-thread-perm-id]');
    
    if (emailBody && emailSubject) {
      const subject = emailSubject.textContent || '';
      const body = emailBody.textContent || '';
      const result = analyzeEmail(subject, body);
      
      if (result.isScam) {
        addEmailWarning(emailBody.parentElement, result);
      }
    }
  }

  // Scan on load and periodically
  setInterval(scanEmails, 3000);

  // Also scan when DOM changes
  const observer = new MutationObserver(scanEmails);
  observer.observe(document.body, { childList: true, subtree: true });

  console.log('Gmail Scam Detector loaded');
})();
