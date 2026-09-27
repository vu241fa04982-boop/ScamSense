/**
 * ScamSense Learning Center and Inspection Tools
 */

import { extractAndInspectLinks } from './analyzer.js';

export const LEARN_TOPICS = [
  {
    id: 'urgency',
    title: 'Urgent Messages',
    subtitle: 'Why urgency is the scammer\'s favorite weapon',
    icon: '⚡',
    summary: 'Pressure to act quickly bypasses your rational skepticism.',
    content: `
      <p>When you feel rushed, panicked, or pressured by an impending deadline, your brain switches to fight-or-flight mode. Threat actors exploit this deliberately by giving you arbitrary countdowns like "account suspended in 15 minutes" or "offer expires today."</p>
      <h4>Classic Red Flags:</h4>
      <ul>
        <li>Phrases like <em>"Act immediately"</em>, <em>"Within 2 hours"</em>, or <em>"Final warning"</em></li>
        <li>Claims that immediate inaction will cause sudden financial or legal disaster</li>
        <li>Pressure not to pause, consult family members, or verify</li>
      </ul>
      <h4>Safe Practice:</h4>
      <p>Legitimate organizations rarely make urgent threats via unexpected text or email. Even if a message feels alarming, pause for 10 minutes. Step away from your phone and verify your account status directly in your official banking or service app.</p>
    `
  },
  {
    id: 'rewards',
    title: 'Fake Rewards & Lotteries',
    subtitle: 'Why unexpected prizes deserve extreme verification',
    icon: '🎁',
    summary: 'If you never bought a ticket or entered a contest, you cannot win it.',
    content: `
      <p>Unexpected prize and lottery notifications trigger feelings of excitement and greed. Scammers use this lure to request an upfront "advance fee," "taxes," or "courier clearance charge" to release the funds, or to direct you to a phishing portal.</p>
      <h4>Classic Red Flags:</h4>
      <ul>
        <li>Winning large sums of money (e.g. ₹50,000 or $10,000) from contests you never entered</li>
        <li>Requirement to pay a small "processing charge" or "registration fee" to receive your prize</li>
        <li>Instructions to click a link within a few hours to claim the reward</li>
      </ul>
      <h4>Safe Practice:</h4>
      <p>Remember the golden rule: Genuine rewards and lotteries never charge advance fees to transfer winnings. If someone asks for money to give you money, it is almost certainly a trap.</p>
    `
  },
  {
    id: 'links',
    title: 'Suspicious Links & URLs',
    subtitle: 'How to inspect a link before tapping or clicking',
    icon: '🔗',
    summary: 'The text you see in a message does not always match where the link actually goes.',
    content: `
      <p>Deceptive web links look deceptively similar to trusted brands. Attackers use look-alike domains (e.g. <code>netflix-account-update.xyz</code> instead of <code>netflix.com</code>), URL shortening tools, or numeric IP addresses to deceive victims.</p>
      <h4>Classic Red Flags:</h4>
      <ul>
        <li>Unusual top-level domain extensions like <code>.xyz</code>, <code>.top</code>, <code>.work</code>, or <code>.club</code> for corporate accounts</li>
        <li>Excessive subdomains masking the real host (e.g., <code>paypal.com.customer-verify.site</code> is NOT PayPal)</li>
        <li>Hidden destinations created by URL shorteners (bit.ly, tinyurl) in unverified messages</li>
      </ul>
      <h4>Safe Practice:</h4>
      <p>Never rely on links sent via SMS, chat apps, or unsolicited emails. Open a clean browser window, type the official brand URL yourself, or use your saved browser bookmarks.</p>
    `
  },
  {
    id: 'impersonation',
    title: 'Fake Support & Authority',
    subtitle: 'How actors pretend to be banks, police, or tech support',
    icon: '🛡',
    summary: 'Branding, logos, and caller IDs can be forged or spoofed easily.',
    content: `
      <p>Impersonation scams rely on perceived authority. Attackers pose as police officers, tax inspectors, bank managers, courier staff, or tech support representatives (e.g. Microsoft, Apple, Amazon) to demand obedience.</p>
      <h4>Classic Red Flags:</h4>
      <ul>
        <li>Claims that your identity was involved in money laundering or customs parcel violations</li>
        <li>Demands to stay on an active call and not speak with family or bank branch staff</li>
        <li>Requests to install remote access tools like AnyDesk, TeamViewer, or QuickSupport</li>
      </ul>
      <h4>Safe Practice:</h4>
      <p>Government authorities and reputable companies do not conduct interrogations or request remote access via video calls or messaging apps. Hang up and contact the institution using its public directory number.</p>
    `
  },
  {
    id: 'payments',
    title: 'Payment & Fee Demands',
    subtitle: 'Why unexpected fees should always trigger verification',
    icon: '💳',
    summary: 'Small fees (₹25 or $2) are often bait to steal entire card credentials.',
    content: `
      <p>A very common tactic is claiming a package delivery failed due to an incomplete address or unpaid ₹25 re-delivery fee. When you enter your card details and OTP, the attackers immediately initiate unauthorized high-value debits.</p>
      <h4>Classic Red Flags:</h4>
      <ul>
        <li>Demands for small token payments to unlock packages, accounts, or prizes</li>
        <li>Requests to pay using unconventional channels (cryptocurrency, gift cards, P2P transfer links)</li>
        <li>Sudden changes in bank account details for invoices or vendor payments</li>
      </ul>
      <h4>Safe Practice:</h4>
      <p>Check the courier’s official tracking page using your original order number from the merchant where you purchased the item. Never pay delivery fees via links in SMS notifications.</p>
    `
  },
  {
    id: 'credentials',
    title: 'Personal Information & OTPs',
    subtitle: 'Why passwords, PINs, and OTPs must remain strictly private',
    icon: '🔐',
    summary: 'An OTP is the master key to your digital account. Never speak or send it.',
    content: `
      <p>One-Time Passwords (OTPs) and 2-Factor Authentication codes are intended exclusively for you to authenticate your own actions. Once you recite or send an OTP to another person, you grant them the authority to drain funds or take over your accounts.</p>
      <h4>Classic Red Flags:</h4>
      <ul>
        <li>Caller asking you to "read out the 6-digit code sent to your phone" to cancel a fraudulent transaction</li>
        <li>Messages asking for your ATM PIN, debit card CVV, or net banking password</li>
        <li>Forms asking for your full social security, tax ID, or national ID to "verify identity" on unencrypted pages</li>
      </ul>
      <h4>Safe Practice:</h4>
      <p>Treat your OTP like your house keys. No legitimate company, bank officer, or police agent will ever ask you to tell them your OTP. If someone asks for it, terminate communication immediately.</p>
    `
  }
];

/**
 * Link Inspector Logic
 */
export function inspectSingleUrl(inputUrl) {
  if (!inputUrl || typeof inputUrl !== 'string') {
    return { error: 'Please enter a valid link or web address.' };
  }

  const clean = inputUrl.trim();
  let normalized = clean;
  if (!/^https?:\/\//i.test(normalized)) {
    normalized = 'https://' + normalized;
  }

  try {
    const parsed = new URL(normalized);
    const protocol = parsed.protocol;
    const hostname = parsed.hostname.toLowerCase();
    const pathname = parsed.pathname;
    const search = parsed.search;

    const parts = hostname.split('.');
    const tld = parts.length > 1 ? '.' + parts[parts.length - 1] : '';
    const mainDomain = parts.length >= 2 ? parts.slice(-2).join('.') : hostname;
    const subdomain = parts.length > 2 ? parts.slice(0, -2).join('.') : '(none)';

    const isShortener = [
      'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly',
      'rb.gy', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc'
    ].some(short => hostname.endsWith(short));

    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
    const hasUnusualTld = ['.xyz', '.top', '.club', '.online', '.work', '.click', '.loan', '.stream', '.buzz'].some(t => hostname.endsWith(t));
    const hyphenCount = (hostname.match(/-/g) || []).length;
    const hasMultipleHyphens = hyphenCount >= 2;

    const observations = [];

    if (protocol === 'http:') {
      observations.push({
        status: 'warning',
        label: 'Insecure Connection',
        detail: 'Uses unencrypted HTTP. Data sent to this address can be intercepted.'
      });
    } else {
      observations.push({
        status: 'safe',
        label: 'HTTPS Protocol',
        detail: 'The connection is encrypted with HTTPS. (Note: HTTPS only protects encryption in transit; it does not verify whether a website owner is trustworthy.)'
      });
    }

    if (isShortener) {
      observations.push({
        status: 'warning',
        label: 'Shortened URL Detected',
        detail: 'This link uses a shortening redirect service. The real destination is hidden until clicked.'
      });
    }

    if (isIp) {
      observations.push({
        status: 'warning',
        label: 'Numeric IP Address',
        detail: 'Links pointing to raw numeric IP addresses rather than registered domain names are uncommon for legitimate consumer services.'
      });
    }

    if (hasUnusualTld) {
      observations.push({
        status: 'warning',
        label: `Domain Extension (${tld})`,
        detail: `The top-level domain ${tld} is frequently favored in mass spam campaigns due to low registration fees.`
      });
    }

    if (parts.length >= 4) {
      observations.push({
        status: 'warning',
        label: 'Deep Subdomain Structure',
        detail: 'Multiple subdomains can be deliberately crafted to look like a trusted site (e.g. brand.com.evil-site.org).'
      });
    }

    if (hasMultipleHyphens) {
      observations.push({
        status: 'warning',
        label: 'Multiple Hyphens in Hostname',
        detail: 'Hyphenated strings (e.g. account-security-verify-login) are often used to imitate genuine brands.'
      });
    }

    return {
      rawInput: clean,
      protocol,
      hostname,
      mainDomain,
      subdomain,
      tld,
      pathname: pathname || '/',
      search: search || '(none)',
      isShortener,
      isIp,
      observations,
      conclusion: observations.some(o => o.status === 'warning')
        ? 'This link exhibits patterns that deserve closer inspection before opening.'
        : 'No obvious red flags detected in the link structure. Always ensure you recognize the domain before entering credentials.'
    };
  } catch (err) {
    return {
      error: 'Invalid URL format. Please ensure the link is structured like: example.com or https://example.com'
    };
  }
}

/**
 * Sender Check Logic
 */
export function inspectSenderInfo(inputSender, inputEmail = null) {
  let displayName = typeof inputSender === 'string' ? inputSender.trim() : '';
  let email = typeof inputEmail === 'string' && inputEmail.trim() ? inputEmail.trim().toLowerCase() : null;

  // If email was not passed as second param, attempt extraction from inputSender
  if (!email && displayName) {
    const emailRegex = /<([^\s<>@]+@[^\s<>@]+)>|([^\s<>@]+@[^\s<>@]+)/;
    const match = displayName.match(emailRegex);
    if (match) {
      email = (match[1] || match[2]).toLowerCase();
      displayName = displayName.replace(match[0], '').replace(/[<>]/g, '').trim();
    }
  }

  if (!displayName && !email) {
    return { error: 'Please enter a display name or email address.' };
  }

  if (!displayName) displayName = '(None provided)';

  const clean = email ? `${displayName !== '(None provided)' ? displayName + ' ' : ''}<${email}>` : displayName;
  const observations = [];

  if (!email) {
    observations.push({
      status: 'neutral',
      label: 'Sender Display Text Only',
      detail: 'No valid email address was identified. Sender IDs or phone numbers can be spoofed by bulk messaging operators.'
    });

    return {
      rawInput: clean,
      displayName,
      email: '(Not detected)',
      domain: '(Not detected)',
      observations,
      conclusion: 'Without a full email address or cryptographic signature, sender display text can easily be spoofed.'
    };
  }

  const [localPart, domain] = email.split('@');
  const freeEmailProviders = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'proton.me', 'icloud.com'];
  const isFreeProvider = freeEmailProviders.includes(domain);

  // Check for brand name mentioned in display name or local part vs free domain
  const brandKeywords = ['bank', 'paypal', 'apple', 'amazon', 'netflix', 'support', 'security', 'official', 'service', 'ups', 'fedex', 'irs'];
  const hasBrandInDisplay = brandKeywords.some(kw => displayName.toLowerCase().includes(kw) || localPart.includes(kw));

  if (isFreeProvider && hasBrandInDisplay) {
    observations.push({
      status: 'warning',
      label: 'Brand Claim from Free Webmail',
      detail: `The sender name mentions "${displayName}", but the email address is hosted on a free provider (@${domain}). Official organizations send notices from their own verified domains.`
    });
  }

  if (['.xyz', '.top', '.work', '.click'].some(ext => domain.endsWith(ext))) {
    observations.push({
      status: 'warning',
      label: 'High-Risk Sender Domain Extension',
      detail: `The email domain ends with ${domain.substring(domain.lastIndexOf('.'))}, which is rarely used for primary corporate communication.`
    });
  }

  observations.push({
    status: 'neutral',
    label: 'Domain Identification',
    detail: `Sender domain is registered as: ${domain}. Check if this matches the official web portal of the organization.`
  });

  return {
    rawInput: clean,
    displayName,
    email,
    domain,
    observations,
    conclusion: observations.some(o => o.status === 'warning')
      ? 'The sender address shows inconsistencies between the claimed identity and the sending domain.'
      : 'Review the domain carefully. Remember that email display names can be configured arbitrarily by any sender.'
  };
}
