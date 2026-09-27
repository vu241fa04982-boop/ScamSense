/**
 * ScamSense Analysis Engine
 * Pure vanilla JavaScript rule-based pattern matching and educational risk assessment.
 * NOTE: ScamSense highlights patterns and warning indicators for educational review.
 * It never claims to definitively prove whether a message is or is not a scam.
 */

export const RULE_CATEGORIES = {
  URGENCY: 'urgency',
  THREAT: 'threat',
  REWARD: 'reward',
  SENSITIVE_INFO: 'sensitive_info',
  PAYMENT: 'payment',
  SUSPICIOUS_LINK: 'suspicious_link',
  IMPERSONATION: 'impersonation',
  PRESSURE: 'pressure',
  FORMATTING: 'formatting',
  GENERIC_GREETING: 'generic_greeting'
};

export const CATEGORY_DETAILS = {
  [RULE_CATEGORIES.URGENCY]: {
    name: 'Urgency & Deadlines',
    icon: '⚡',
    badge: 'Urgency',
    description: 'Artificial time pressure created to force hasty decisions before you can think or verify.',
    advice: 'Pause, take a breath, and never rush into clicking or responding under deadline pressure.'
  },
  [RULE_CATEGORIES.THREAT]: {
    name: 'Fear or Threat Tactics',
    icon: '🛑',
    badge: 'Threat / Fear',
    description: 'Threats of account suspension, legal penalties, arrest, or service termination.',
    advice: 'Legitimate organizations do not close accounts without formal prior notice. Verify via official channels.'
  },
  [RULE_CATEGORIES.REWARD]: {
    name: 'Unexpected Rewards & Prizes',
    icon: '🎁',
    badge: 'Unsolicited Reward',
    description: 'Prizes, cash lotteries, job windfalls, or free rewards you never entered or applied for.',
    advice: 'If you did not enter a contest or lottery, you cannot win it. Genuine prizes do not demand upfront fees.'
  },
  [RULE_CATEGORIES.SENSITIVE_INFO]: {
    name: 'Sensitive Credential Requests',
    icon: '🔐',
    badge: 'Credential Request',
    description: 'Solicitation of passwords, one-time passwords (OTPs), PINs, or banking credentials.',
    advice: 'Banks and services explicitly state they will NEVER ask for your OTP, password, or PIN.'
  },
  [RULE_CATEGORIES.PAYMENT]: {
    name: 'Unusual Payment Demands',
    icon: '💳',
    badge: 'Payment Request',
    description: 'Demands for money transfers, upfront processing fees, courier release fees, or gift cards.',
    advice: 'Always verify unexpected fee requests directly on the official app or website before sending money.'
  },
  [RULE_CATEGORIES.SUSPICIOUS_LINK]: {
    name: 'Suspicious Links & URLs',
    icon: '🔗',
    badge: 'Suspicious Link',
    description: 'Web addresses with unfamiliar domains, disguised services, URL shorteners, or deceptive paths.',
    advice: 'Do not click the link. Open your browser and navigate directly to the trusted official website.'
  },
  [RULE_CATEGORIES.IMPERSONATION]: {
    name: 'Potential Impersonation',
    icon: '🛡',
    badge: 'Impersonation Pattern',
    description: 'Wording implying an official message from a bank, delivery courier, government, or tech brand.',
    advice: 'Scammers frequently spoof well-known brand names. Independently contact the organization using official contact info.'
  },
  [RULE_CATEGORIES.PRESSURE]: {
    name: 'Secrecy & Pressure Tactics',
    icon: '🤐',
    badge: 'Secrecy & Pressure',
    description: 'Urging you not to consult friends or family, to keep things confidential, or claiming "last chance".',
    advice: 'Legitimate opportunities and genuine support agents never ask you to hide transactions from family or bank staff.'
  },
  [RULE_CATEGORIES.FORMATTING]: {
    name: 'Unusual Formatting & Shouting',
    icon: '🔠',
    badge: 'Suspicious Formatting',
    description: 'Excessive capital letters, erratic exclamation marks, or unnatural punctuation patterns.',
    advice: 'Professional customer communications adhere to proper capitalization, grammar, and typography.'
  },
  [RULE_CATEGORIES.GENERIC_GREETING]: {
    name: 'Generic or Impersonal Greeting',
    icon: '👤',
    badge: 'Impersonal Greeting',
    description: 'Vague salutations like "Dear Customer", "Dear User", or "Valued Client" instead of your actual name.',
    advice: 'Companies you have accounts with almost always address you by your registered name or account number.'
  }
};

/** Known URL shorteners */
const SHORTENER_DOMAINS = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly', 'ow.ly',
  'rb.gy', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'bl.ink', 'v.gd'
];

/** Suspicious or cheap top-level domains commonly abused in spam blasts */
const SUSPICIOUS_TLDS = [
  '.xyz', '.top', '.club', '.work', '.click', '.site', '.loan', '.online',
  '.stream', '.bid', '.racing', '.win', '.download', '.buzz', '.info'
];

/** Brands commonly targeted for impersonation */
const IMPERSONATION_TARGETS = [
  { name: 'Banking / Financial Institution', terms: ['state bank', 'hdfc', 'icici', 'wells fargo', 'chase bank', 'bank of america', 'citi bank', 'barclays', 'paypal', 'venmo', 'cashapp', 'zelle', 'paytm', 'phonepe', 'gpay', 'central bank', 'credit union'] },
  { name: 'Delivery / Courier Service', terms: ['fedex', 'dhl', 'ups', 'usps', 'india post', 'royal mail', 'amazon delivery', 'courier', 'parcel delivery', 'postal service'] },
  { name: 'Government & Tax Authorities', terms: ['irs', 'tax department', 'income tax', 'customs', 'law enforcement', 'police', 'social security', 'aadhaar', 'court summons', 'department of revenue'] },
  { name: 'Tech & Streaming Services', terms: ['netflix', 'apple support', 'icloud', 'microsoft support', 'google security', 'amazon prime', 'meta support', 'whatsapp support', 'instagram team'] },
  { name: 'Telecommunications & Utilities', terms: ['electricity department', 'power board', 'verizon', 'at&t', 't-mobile', 'vodafone', 'jio', 'airtel', 'broadband connection'] }
];

/**
 * Checks text for presence of highly sensitive credentials (PII) before analysis.
 * Used to safeguard users against accidentally pasting real credentials.
 */
export function detectSensitiveCredentials(text) {
  if (!text) return { hasSensitiveData: false, findings: [] };

  const findings = [];
  
  // 16-digit credit card pattern (with or without spaces/dashes)
  const cardRegex = /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|[0-9]{4}[ -][0-9]{4}[ -][0-9]{4}[ -][0-9]{4})\b/g;
  if (cardRegex.test(text)) {
    findings.push('Possible credit or debit card number');
  }

  // 3-4 digit CVV mention
  if (/\b(?:cvv|cvc|security code)\s*[:=]?\s*\d{3,4}\b/i.test(text)) {
    findings.push('Card CVV / security code');
  }

  // Real password mention with secret value
  if (/\b(?:password|passcode|secret pin)\s*[:=]\s*\S{4,}\b/i.test(text)) {
    findings.push('Explicit password or secret PIN text');
  }

  // 6-digit OTP code paired with otp prompt
  if (/\b(?:otp|one-time password|verification code)\s*(?:is|:)?\s*\d{4,8}\b/i.test(text)) {
    findings.push('One-time password (OTP) code');
  }

  return {
    hasSensitiveData: findings.length > 0,
    findings
  };
}

/**
 * Sanitizes / masks any detected sensitive numbers in user text.
 */
export function redactSensitiveData(text) {
  if (!text) return '';
  return text
    .replace(/\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|[0-9]{4}[ -][0-9]{4}[ -][0-9]{4}[ -][0-9]{4})\b/g, '[REDACTED_CARD_NUMBER]')
    .replace(/\b(?:cvv|cvc|security code)\s*[:=]?\s*\d{3,4}\b/gi, 'CVV: [REDACTED]')
    .replace(/\b(?:password|passcode)\s*[:=]\s*\S{4,}\b/gi, 'password: [REDACTED]')
    .replace(/\b((?:otp|one-time password|verification code)\s*(?:is|:)?\s*)\d{4,8}\b/gi, '$1[REDACTED_OTP]');
}

/**
 * Extract and analyze all URLs found in the text
 */
export function extractAndInspectLinks(text) {
  const urlRegex = /(?:https?:\/\/|www\.)[^\s<>"'{}|\\^`]+[^\s<>"'{}|\\^`.,;:!?]/gi;
  const matches = text.match(urlRegex) || [];
  
  const linkReports = [];

  matches.forEach(rawUrl => {
    let normalized = rawUrl;
    if (!normalized.startsWith('http://') && !normalized.startsWith('https://')) {
      normalized = 'http://' + normalized;
    }

    try {
      const parsed = new URL(normalized);
      const hostname = parsed.hostname.toLowerCase();
      const pathname = parsed.pathname;
      const protocol = parsed.protocol;
      const isHttps = protocol === 'https:';

      const flags = [];
      const parts = hostname.split('.');
      const tld = parts.length > 1 ? '.' + parts[parts.length - 1] : '';
      const isShortener = SHORTENER_DOMAINS.some(short => hostname.endsWith(short));
      const hasSuspiciousTld = SUSPICIOUS_TLDS.some(ext => hostname.endsWith(ext));
      const isIpAddress = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
      const excessiveSubdomains = parts.length >= 4;
      const hasHyphens = (hostname.match(/-/g) || []).length >= 2;
      const hasAtSymbol = rawUrl.includes('@');

      if (!isHttps) {
        flags.push({
          type: 'Unencrypted HTTP',
          note: 'Connection uses unencrypted HTTP rather than modern HTTPS.'
        });
      }

      if (isShortener) {
        flags.push({
          type: 'URL Shortening Service',
          note: 'Shortened links conceal the actual destination until clicked.'
        });
      }

      if (isIpAddress) {
        flags.push({
          type: 'Direct IP Address',
          note: 'Legitimate organizations rarely use bare numeric IP addresses for customer portals.'
        });
      }

      if (hasSuspiciousTld) {
        flags.push({
          type: 'High-Risk Domain Extension',
          note: `Domain ends with "${tld}", a domain extension frequently seen in automated spam registrations.`
        });
      }

      if (excessiveSubdomains) {
        flags.push({
          type: 'Excessive Subdomains',
          note: `Complex domain structure (${parts.length} segments) may be masking the real owner domain.`
        });
      }

      if (hasHyphens) {
        flags.push({
          type: 'Multiple Hyphens in Host',
          note: 'Host contains multiple hyphens, often used to create deceptive look-alike names.'
        });
      }

      if (hasAtSymbol) {
        flags.push({
          type: 'Misleading @ Authority Syntax',
          note: 'The @ character in URLs can trick browsers into connecting to the host after the symbol.'
        });
      }

      // Check if domain impersonates well-known names
      const knownBrands = ['paypal', 'amazon', 'apple', 'netflix', 'google', 'microsoft', 'chase', 'wells', 'bank', 'fedex', 'dhl', 'support'];
      const matchedBrand = knownBrands.find(b => hostname.includes(b));
      if (matchedBrand) {
        // Check if not official
        const officialDomains = [
          'paypal.com', 'amazon.com', 'apple.com', 'netflix.com',
          'google.com', 'microsoft.com', 'chase.com', 'wellsfargo.com',
          'fedex.com', 'dhl.com'
        ];
        const isOfficial = officialDomains.some(off => hostname === off || hostname.endsWith('.' + off));
        if (!isOfficial) {
          flags.push({
            type: 'Potential Brand Lookalike Host',
            note: `Domain name contains "${matchedBrand}" but does not belong to the official verified domain.`
          });
        }
      }

      linkReports.push({
        rawUrl,
        normalized,
        protocol,
        hostname,
        pathname,
        isHttps,
        isShortener,
        isIpAddress,
        flags,
        hasConcerns: flags.length > 0
      });
    } catch {
      linkReports.push({
        rawUrl,
        normalized,
        protocol: 'unknown',
        hostname: rawUrl,
        pathname: '',
        isHttps: false,
        isShortener: false,
        isIpAddress: false,
        flags: [{
          type: 'Malformed URL Structure',
          note: 'The link does not conform to standard URL formatting rules.'
        }],
        hasConcerns: true
      });
    }
  });

  return linkReports;
}

/**
 * Main Analysis Engine
 */
export function analyzeMessage(text) {
  if (!text || typeof text !== 'string') {
    return null;
  }

  const cleanText = text.trim();
  const lowerText = cleanText.toLowerCase();

  const detectedFindings = [];
  const highlightedTokens = []; // [{ phrase, category, start, end }]

  // 1. Urgency detection
  const urgencyPatterns = [
    { regex: /\b(?:immediately|urgent|urgently|act now|act immediately|right now)\b/gi, phrase: 'act immediately / urgent' },
    { regex: /\b(?:today only|expires today|valid today|within 24 hours|within \d+ hours|in \d+ minutes|last day)\b/gi, phrase: 'tight countdown / today only' },
    { regex: /\b(?:before it(?:'s| is) too late|don't delay|do not delay|time is running out|clock is ticking)\b/gi, phrase: 'time pressure phrasing' },
    { regex: /\b(?:immediate response required|immediate action required|action required immediately)\b/gi, phrase: 'immediate action required' }
  ];

  urgencyPatterns.forEach(p => {
    let match;
    while ((match = p.regex.exec(cleanText)) !== null) {
      highlightedTokens.push({
        phrase: match[0],
        category: RULE_CATEGORIES.URGENCY,
        index: match.index,
        length: match[0].length
      });
      detectedFindings.push({
        category: RULE_CATEGORIES.URGENCY,
        matchedText: match[0],
        title: 'Urgency & Tight Deadlines',
        whyItMatters: 'Artificial urgency triggers fear of missing out or panic, discouraging you from taking time to double-check details.',
        whatToDo: 'Take a breath and step away from the message. Genuine organizations will not cut you off in minutes or hours.'
      });
    }
  });

  // 2. Fear or threat detection
  const threatPatterns = [
    { regex: /\b(?:account (?:will be|has been) (?:closed|suspended|blocked|terminated|disabled|frozen))\b/gi, phrase: 'account closed / suspended' },
    { regex: /\b(?:legal action|police complaint|arrest warrant|court summons|penalty|fine will be charged)\b/gi, phrase: 'legal / police action threat' },
    { regex: /\b(?:electricity (?:will be|has been) disconnected|power will be cut|service disconnected)\b/gi, phrase: 'utility disconnection threat' },
    { regex: /\b(?:kyc (?:suspended|expired|pending|incomplete)|pan (?:blocked|deactivated)|sim card blocked)\b/gi, phrase: 'KYC / document deactivation threat' },
    { regex: /\b(?:facing legal consequences|fail(?:ure)? to comply will result in)\b/gi, phrase: 'consequence threat' }
  ];

  threatPatterns.forEach(p => {
    let match;
    while ((match = p.regex.exec(cleanText)) !== null) {
      highlightedTokens.push({
        phrase: match[0],
        category: RULE_CATEGORIES.THREAT,
        index: match.index,
        length: match[0].length
      });
      detectedFindings.push({
        category: RULE_CATEGORIES.THREAT,
        matchedText: match[0],
        title: 'Fear & Threat Tactics',
        whyItMatters: 'Threatening account closure, police action, or fines is designed to create anxiety so you obey instructions without question.',
        whatToDo: 'Do not use numbers or links in this message. Log in to your account via the official app or website to view your real status.'
      });
    }
  });

  // 3. Unexpected rewards & prizes
  const rewardPatterns = [
    { regex: /\b(?:congratulations|congrats|you have won|you've won|you won)\b/gi, phrase: 'congratulations / you won' },
    { regex: /\b(?:lucky winner|selected winner|won (?:₹|\$|€|£)?\s*\d+[\d,]*|lottery winner|cash prize)\b/gi, phrase: 'lottery / cash prize' },
    { regex: /\b(?:claim (?:your|the) (?:reward|prize|bonus|gift card|voucher|cashback))\b/gi, phrase: 'claim your reward' },
    { regex: /\b(?:free money|exclusive reward for you|special cashback credited|unclaimed funds)\b/gi, phrase: 'unclaimed funds / free reward' }
  ];

  rewardPatterns.forEach(p => {
    let match;
    while ((match = p.regex.exec(cleanText)) !== null) {
      highlightedTokens.push({
        phrase: match[0],
        category: RULE_CATEGORIES.REWARD,
        index: match.index,
        length: match[0].length
      });
      detectedFindings.push({
        category: RULE_CATEGORIES.REWARD,
        matchedText: match[0],
        title: 'Unexpected Reward or Prize Offer',
        whyItMatters: 'Unsolicited prize notices dangle sudden windfalls to entice victims into paying "release fees" or handing over bank credentials.',
        whatToDo: 'Ask yourself: Did I enter this lottery or contest? If not, ignore the message and never pay any advance fees to claim a prize.'
      });
    }
  });

  // 4. Requests for sensitive information
  const credentialPatterns = [
    { regex: /\b(?:enter|share|provide|send|verify|confirm)\s+(?:your\s+)?(?:password|passcode|secret pin|login details|credentials)\b/gi, phrase: 'request for password / PIN' },
    { regex: /\b(?:share (?:your\s+)?(?:otp|one[- ]time password)|enter (?:the\s+)?otp|send (?:the\s+)?code)\b/gi, phrase: 'request for OTP' },
    { regex: /\b(?:bank (?:account\s+)?details|card number|debit card details|credit card details|cvv|expiry date)\b/gi, phrase: 'bank / card information request' },
    { regex: /\b(?:verification code|security code sent to your phone|authenticator code)\b/gi, phrase: 'verification code request' }
  ];

  credentialPatterns.forEach(p => {
    let match;
    while ((match = p.regex.exec(cleanText)) !== null) {
      highlightedTokens.push({
        phrase: match[0],
        category: RULE_CATEGORIES.SENSITIVE_INFO,
        index: match.index,
        length: match[0].length
      });
      detectedFindings.push({
        category: RULE_CATEGORIES.SENSITIVE_INFO,
        matchedText: match[0],
        title: 'Request for Sensitive Credentials',
        whyItMatters: 'Genuine service providers and bank employees never request your private OTP, password, or PIN. Sharing these allows direct account compromise.',
        whatToDo: 'Never share OTPs, passwords, or PINs with anyone. Real verification codes are strictly private to you.'
      });
    }
  });

  // 5. Payment requests
  const paymentPatterns = [
    { regex: /\b(?:pay now|transfer (?:money|funds)|send payment|make a payment|deposit (?:money|funds|\$|₹|£))\b/gi, phrase: 'pay now / transfer money' },
    { regex: /\b(?:processing fee|reschedule fee|delivery fee|customs fee|clearance fee|registration fee|activation charge)\b/gi, phrase: 'processing / release fee' },
    { regex: /\b(?:pay (?:₹|\$|€|£)\s*\d+[\d,]*|send (?:₹|\$|€|£)\s*\d+[\d,]*)\b/gi, phrase: 'specific payment amount' },
    { regex: /\b(?:gift card|apple gift card|steam card|google play card|crypto|bitcoin|usdt)\b/gi, phrase: 'untraceable payment method' }
  ];

  paymentPatterns.forEach(p => {
    let match;
    while ((match = p.regex.exec(cleanText)) !== null) {
      highlightedTokens.push({
        phrase: match[0],
        category: RULE_CATEGORIES.PAYMENT,
        index: match.index,
        length: match[0].length
      });
      detectedFindings.push({
        category: RULE_CATEGORIES.PAYMENT,
        matchedText: match[0],
        title: 'Payment or Fee Demanded',
        whyItMatters: 'Small unexpected fees (e.g. ₹25 / $2 parcel redelivery) are commonly used to capture debit card details, while large demands seek direct wire transfers.',
        whatToDo: 'Never send money via links provided in unsolicited messages. Inspect pending bills directly in your official banking or merchant app.'
      });
    }
  });

  // 6. Suspicious links
  const linkReports = extractAndInspectLinks(cleanText);
  if (linkReports.length > 0) {
    linkReports.forEach(link => {
      highlightedTokens.push({
        phrase: link.rawUrl,
        category: RULE_CATEGORIES.SUSPICIOUS_LINK,
        index: cleanText.indexOf(link.rawUrl),
        length: link.rawUrl.length
      });

      const concernSummary = link.flags.length > 0 
        ? link.flags.map(f => f.type).join(', ')
        : 'Link present in unverified message';

      detectedFindings.push({
        category: RULE_CATEGORIES.SUSPICIOUS_LINK,
        matchedText: link.rawUrl,
        title: 'Suspicious or Unverified Link',
        whyItMatters: `Links can direct you to clone websites disguised as familiar portals (${concernSummary}).`,
        whatToDo: 'Avoid clicking this link directly. Instead, open a new browser tab and type the organization’s recognized website address manually.'
      });
    });
  }

  // 7. Impersonation detection
  IMPERSONATION_TARGETS.forEach(group => {
    group.terms.forEach(term => {
      const termRegex = new RegExp(`\\b${term}\\b`, 'gi');
      let match;
      while ((match = termRegex.exec(cleanText)) !== null) {
        highlightedTokens.push({
          phrase: match[0],
          category: RULE_CATEGORIES.IMPERSONATION,
          index: match.index,
          length: match[0].length
        });
        detectedFindings.push({
          category: RULE_CATEGORIES.IMPERSONATION,
          matchedText: match[0],
          title: `Apparent Reference to ${group.name}`,
          whyItMatters: 'The message refers to a well-known organization. Fraudulent messages frequently mimic official entities to command unwarranted trust.',
          whatToDo: 'Verify this communication by calling the verified helpline listed on the back of your payment card or on the official website.'
        });
      }
    });
  });

  // 8. Pressure tactics / Secrecy
  const pressurePatterns = [
    { regex: /\b(?:don't tell anyone|do not tell anyone|keep this (?:secret|confidential)|between you and me)\b/gi, phrase: 'secrecy demand' },
    { regex: /\b(?:do not disconnect|stay on the line|do not hang up)\b/gi, phrase: 'call retention pressure' },
    { regex: /\b(?:last chance|final warning|final notice|once-in-a-lifetime opportunity)\b/gi, phrase: 'final notice / last chance' },
    { regex: /\b(?:limited seats|limited spots available|offer expires in|exclusive invitation)\b/gi, phrase: 'artificial scarcity' }
  ];

  pressurePatterns.forEach(p => {
    let match;
    while ((match = p.regex.exec(cleanText)) !== null) {
      highlightedTokens.push({
        phrase: match[0],
        category: RULE_CATEGORIES.PRESSURE,
        index: match.index,
        length: match[0].length
      });
      detectedFindings.push({
        category: RULE_CATEGORIES.PRESSURE,
        matchedText: match[0],
        title: 'Secrecy or Pressure Tactics',
        whyItMatters: 'Demands for confidentiality isolate you from second opinions and knowledgeable family members or advisers.',
        whatToDo: 'Any request instructing you to keep a transaction or message hidden from others is a major warning pattern to discuss with a trusted person.'
      });
    }
  });

  // 9. Suspicious formatting (excessive uppercase, punctuation bursts)
  const words = cleanText.split(/\s+/).filter(Boolean);
  const uppercaseWords = words.filter(w => w.length >= 3 && /^[A-Z0-9!$%?]+$/.test(w) && !/^(URL|SMS|OTP|KYC|PIN|INR|USD|EUR|GBP|HTTP|HTTPS)$/.test(w));
  const isShouting = uppercaseWords.length >= 3 && (uppercaseWords.length / words.length > 0.25);
  const excessivePunctuation = /(?:!{2,}|\?{2,}|\.{4,})/g.test(cleanText);

  if (isShouting || excessivePunctuation) {
    const matchedEx = isShouting ? uppercaseWords.slice(0, 3).join(' ') : 'Excessive punctuation (!/?)';
    detectedFindings.push({
      category: RULE_CATEGORIES.FORMATTING,
      matchedText: matchedEx,
      title: 'Erratic Formatting & Capitalization',
      whyItMatters: 'Excessive capitalization, erratic punctuation, and sensory shouting rarely appear in legitimate corporate customer notifications.',
      whatToDo: 'Pay attention to professional tone. Highly emotional or sensational formatting is a hallmark of unsolicited marketing or phishing.'
    });
  }

  // 10. Generic greetings
  const genericGreetingPatterns = [
    { regex: /\b(?:dear customer|dear user|dear client|valued customer|dear account holder|dear member|congratulations user|attention user)\b/gi, phrase: 'generic greeting' }
  ];

  genericGreetingPatterns.forEach(p => {
    let match;
    while ((match = p.regex.exec(cleanText)) !== null) {
      highlightedTokens.push({
        phrase: match[0],
        category: RULE_CATEGORIES.GENERIC_GREETING,
        index: match.index,
        length: match[0].length
      });
      detectedFindings.push({
        category: RULE_CATEGORIES.GENERIC_GREETING,
        matchedText: match[0],
        title: 'Generic or Impersonal Greeting',
        whyItMatters: 'Mass phishing campaigns dispatch bulk messages without knowing recipients’ personal names, defaulting to impersonal greetings.',
        whatToDo: 'Check if you have an active account with this entity and whether they typically address you by your real name.'
      });
    }
  });

  // Deduplicate findings by category + matched text
  const uniqueFindings = [];
  const seenKeys = new Set();

  detectedFindings.forEach(f => {
    const key = `${f.category}:${(f.matchedText || '').toLowerCase()}`;
    if (!seenKeys.has(key)) {
      seenKeys.add(key);
      uniqueFindings.push(f);
    }
  });

  // Group findings by category
  const categoriesDetected = new Set(uniqueFindings.map(f => f.category));

  // Determine educational warning level
  // LOW: 0-1 mild findings (or 0 findings)
  // MODERATE: 2-3 findings or 2 categories
  // HIGH: 4+ findings, or presence of high-risk combinations (Threat + Link, Credential request + Urgency, Payment + Threat)
  const count = uniqueFindings.length;
  let level = 'LOW';
  let levelTitle = 'NO OBVIOUS WARNING SIGNS FOUND';
  let levelClass = 'status-low';

  const hasHighRiskCombo = (
    (categoriesDetected.has(RULE_CATEGORIES.SENSITIVE_INFO)) ||
    (categoriesDetected.has(RULE_CATEGORIES.THREAT) && categoriesDetected.has(RULE_CATEGORIES.SUSPICIOUS_LINK)) ||
    (categoriesDetected.has(RULE_CATEGORIES.PAYMENT) && categoriesDetected.has(RULE_CATEGORIES.URGENCY)) ||
    (categoriesDetected.has(RULE_CATEGORIES.REWARD) && categoriesDetected.has(RULE_CATEGORIES.SUSPICIOUS_LINK))
  );

  if (count === 0) {
    level = 'LOW';
    levelTitle = 'NO OBVIOUS WARNING SIGNS FOUND';
    levelClass = 'status-low';
  } else if (count >= 4 || hasHighRiskCombo) {
    level = 'HIGH';
    levelTitle = 'WARNING SIGNS FOUND';
    levelClass = 'status-high';
  } else {
    level = 'MODERATE';
    levelTitle = 'FEW WARNING SIGNS FOUND';
    levelClass = 'status-moderate';
  }

  // Generate actionable "What Should I Do?" guidance based on context
  const actionList = generateActionChecklist(categoriesDetected, linkReports);

  // Generate in-message highlighted markup
  const highlightedHtml = generateHighlightedMarkup(cleanText, highlightedTokens);

  // Basic stats
  const charCount = cleanText.length;
  const wordCount = words.length;

  return {
    id: 'scan_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7),
    type: 'message_analysis',
    timestamp: new Date().toISOString(),
    originalText: cleanText,
    charCount,
    wordCount,
    level,
    levelTitle,
    levelClass,
    warningSignCount: count,
    categoriesCount: categoriesDetected.size,
    totalCategoriesChecked: Object.keys(RULE_CATEGORIES).length,
    findings: uniqueFindings,
    categoriesDetected: Array.from(categoriesDetected),
    linkReports,
    actionList,
    highlightedHtml,
    stats: {
      links: linkReports.length,
      urgencyPhrases: countCategoryMatches(uniqueFindings, RULE_CATEGORIES.URGENCY),
      paymentRequests: countCategoryMatches(uniqueFindings, RULE_CATEGORIES.PAYMENT),
      credentialRequests: countCategoryMatches(uniqueFindings, RULE_CATEGORIES.SENSITIVE_INFO),
      threatPhrases: countCategoryMatches(uniqueFindings, RULE_CATEGORIES.THREAT),
      pressurePhrases: countCategoryMatches(uniqueFindings, RULE_CATEGORIES.PRESSURE)
    }
  };
}

function countCategoryMatches(findings, cat) {
  return findings.filter(f => f.category === cat).length;
}

/**
 * Produces prioritized checklist of educational next steps
 */
function generateActionChecklist(categories, linkReports) {
  const steps = [];

  if (linkReports.length > 0 || categories.has(RULE_CATEGORIES.SUSPICIOUS_LINK)) {
    steps.push({
      priority: 'high',
      title: 'Do not click links inside this message',
      detail: 'Opening unverified links may compromise device security or direct you to cloned phishing pages.'
    });
  }

  if (categories.has(RULE_CATEGORIES.SENSITIVE_INFO)) {
    steps.push({
      priority: 'critical',
      title: 'Never share passwords, OTPs, or PINs',
      detail: 'Legitimate banks, delivery staff, and customer support representatives will never ask for your private verification code.'
    });
  }

  if (categories.has(RULE_CATEGORIES.PAYMENT)) {
    steps.push({
      priority: 'high',
      title: 'Do not transfer money or pay advance fees',
      detail: 'Verify any requested fees directly on the official merchant account or registered billing statement.'
    });
  }

  if (categories.has(RULE_CATEGORIES.IMPERSONATION) || categories.has(RULE_CATEGORIES.THREAT)) {
    steps.push({
      priority: 'medium',
      title: 'Contact the organization through official channels only',
      detail: 'Use a customer helpline from your physical payment card, official bill, or established bookmark, not from this text.'
    });
  }

  if (categories.has(RULE_CATEGORIES.URGENCY) || categories.has(RULE_CATEGORIES.PRESSURE)) {
    steps.push({
      priority: 'medium',
      title: 'Take your time before responding',
      detail: 'Artificial urgency is intended to overwhelm your intuition. Disregard arbitrary countdowns.'
    });
  }

  // Universal baseline recommendation
  steps.push({
    priority: 'info',
    title: 'Consult someone you trust if uncertain',
    detail: 'Talking through a strange message with a colleague, friend, or relative almost immediately dissolves high-pressure tactics.'
  });

  return steps;
}

/**
 * Builds HTML with non-destructive, safe inline highlight tags
 */
function generateHighlightedMarkup(text, tokens) {
  if (!tokens || tokens.length === 0) {
    return escapeHtml(text);
  }

  // Filter valid token ranges
  const valid = tokens
    .filter(t => typeof t.index === 'number' && t.index >= 0 && t.length > 0)
    .sort((a, b) => a.index - b.index);

  if (valid.length === 0) return escapeHtml(text);

  // Merge overlapping ranges
  const merged = [];
  let cur = { ...valid[0] };

  for (let i = 1; i < valid.length; i++) {
    const next = valid[i];
    if (next.index < cur.index + cur.length) {
      // Overlap: expand current
      cur.length = Math.max(cur.length, (next.index + next.length) - cur.index);
    } else {
      merged.push(cur);
      cur = { ...next };
    }
  }
  merged.push(cur);

  let result = '';
  let lastIndex = 0;

  merged.forEach(span => {
    // Add text preceding the highlight
    if (span.index > lastIndex) {
      result += escapeHtml(text.substring(lastIndex, span.index));
    }
    // Add highlighted span
    const matchedSegment = text.substring(span.index, span.index + span.length);
    const catDetail = CATEGORY_DETAILS[span.category] || { badge: 'Warning Sign' };
    result += `<mark class="highlight-token highlight-${span.category}" title="${escapeHtml(catDetail.badge)}">${escapeHtml(matchedSegment)}</mark>`;
    lastIndex = span.index + span.length;
  });

  if (lastIndex < text.length) {
    result += escapeHtml(text.substring(lastIndex));
  }

  return result;
}

function escapeHtml(string) {
  if (!string) return '';
  return String(string)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
