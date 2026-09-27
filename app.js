/**
 * ScamSense Main Application Controller
 */

import {
  analyzeMessage,
  detectSensitiveCredentials,
  redactSensitiveData,
  CATEGORY_DETAILS,
  RULE_CATEGORIES
} from './analyzer.js';

import {
  getHistory,
  saveToHistory,
  deleteHistoryItem,
  clearAllHistory,
  getSavedAnalyses,
  isAnalysisSaved,
  saveToSaved,
  removeFromSaved,
  getStats,
  getThemePreference,
  setThemePreference,
  clearAllLocalData
} from './history.js';

import { downloadAnalysisPDF } from './pdfGenerator.js';

import {
  LEARN_TOPICS,
  inspectSingleUrl,
  inspectSenderInfo
} from './learn.js';

// Global application state
const AppState = {
  currentView: 'home',
  currentAnalysis: null,
  pendingModalConfirm: null
};

// Preset sample messages
const SAMPLES = {
  reward: "Congratulations! You have won ₹50,000 in the Annual Grand Festival Lottery. Claim your prize immediately by clicking this link: http://win-claim-portal.rewards-update.online/claim?id=99281. Valid today only.",
  threat: "Dear customer, your primary bank account will be closed today due to incomplete KYC verification. Verify your details immediately using the link below: http://secure-bank-login.update-notice.xyz/auth. Failure to act will result in legal action.",
  delivery: "Your delivery parcel #IN-90812 could not be completed due to missing address info. Pay ₹25 to reschedule your delivery via http://quick-express-parcel.track-fee.info/pay within 24 hours.",
  appointment: "Hi Sarah, your appointment with Dr. Mehta is confirmed for tomorrow at 10:00 AM at City Care Clinic. Please arrive 10 minutes early. Contact our clinic front desk at 011-2345-6789 if you need to reschedule.",
  jobOffer: "Congratulations user! You are selected for online data entry work earning ₹45,000/week. Deposit ₹1,500 security verification fee today only. Keep this secret until onboarding is complete."
};

/**
 * Initialize ScamSense application on DOM ready
 */
document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initRouting();
  initHomeDashboard();
  initAnalyzeWorkspace();
  initLearnCenter();
  initHistoryView();
  initSavedView();
  initTools();
  initAboutView();
  initModals();
});

/* ================================================= */
/* THEME MANAGEMENT                                  */
/* ================================================= */
function initTheme() {
  const saved = getThemePreference();
  document.documentElement.setAttribute('data-theme', saved);
  updateThemeIcons(saved);

  const toggleBtn = document.getElementById('themeToggleBtn');
  if (toggleBtn) {
    toggleBtn.addEventListener('click', () => {
      const current = document.documentElement.getAttribute('data-theme') || 'light';
      const next = current === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      setThemePreference(next);
      updateThemeIcons(next);
      showToast(`Switched to ${next} theme`);
    });
  }
}

function updateThemeIcons(theme) {
  const iconSun = document.getElementById('themeIconSun');
  const iconMoon = document.getElementById('themeIconMoon');
  if (iconSun && iconMoon) {
    if (theme === 'dark') {
      iconSun.style.display = 'block';
      iconMoon.style.display = 'none';
    } else {
      iconSun.style.display = 'none';
      iconMoon.style.display = 'block';
    }
  }
}

/* ================================================= */
/* NAVIGATION & ROUTING                              */
/* ================================================= */
function initRouting() {
  // Listen for hash changes
  window.addEventListener('hashchange', () => {
    const hash = window.location.hash.replace('#', '') || 'home';
    switchView(hash);
  });

  // Handle all internal navigation links with data-view
  document.querySelectorAll('[data-view]').forEach(elem => {
    elem.addEventListener('click', (e) => {
      e.preventDefault();
      const target = elem.getAttribute('data-view');
      window.location.hash = target;
      closeMobileDrawer();
    });
  });

  // Mobile menu toggle
  const mobileToggle = document.getElementById('mobileMenuToggle');
  const mobileDrawer = document.getElementById('mobileNavDrawer');
  if (mobileToggle && mobileDrawer) {
    mobileToggle.addEventListener('click', () => {
      mobileDrawer.classList.toggle('open');
    });
  }

  // Initial route
  const initialHash = window.location.hash.replace('#', '') || 'home';
  switchView(initialHash);
}

function closeMobileDrawer() {
  const mobileDrawer = document.getElementById('mobileNavDrawer');
  if (mobileDrawer) {
    mobileDrawer.classList.remove('open');
  }
}

function switchView(viewName) {
  // Normalize allowed views
  const validViews = ['home', 'analyze', 'results', 'history', 'saved', 'learn', 'about'];
  const activeView = validViews.includes(viewName) ? viewName : 'home';
  AppState.currentView = activeView;

  // Update navigation active states
  document.querySelectorAll('.nav-link, .mobile-nav-link').forEach(link => {
    const linkTarget = link.getAttribute('data-view');
    if (linkTarget === activeView || (activeView === 'results' && linkTarget === 'analyze')) {
      link.classList.add('active');
    } else {
      link.classList.remove('active');
    }
  });

  // Switch visible section
  document.querySelectorAll('.view-section').forEach(sec => {
    sec.classList.remove('active-view');
  });

  const targetSection = document.getElementById(`view-${activeView}`);
  if (targetSection) {
    targetSection.classList.add('active-view');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  // Refresh view contents if needed
  if (activeView === 'home') {
    refreshHomeStats();
  } else if (activeView === 'history') {
    renderHistoryList();
  } else if (activeView === 'saved') {
    renderSavedList();
  }
}

/* ================================================= */
/* HOME VIEW & DASHBOARD                             */
/* ================================================= */
function initHomeDashboard() {
  refreshHomeStats();
}

function refreshHomeStats() {
  const stats = getStats();
  const elChecked = document.getElementById('statMessagesChecked');
  const elWarnings = document.getElementById('statWarningSigns');
  const elSaved = document.getElementById('statSavedAnalyses');

  if (elChecked) elChecked.textContent = stats.messagesChecked;
  if (elWarnings) elWarnings.textContent = stats.warningSignsFound;
  if (elSaved) elSaved.textContent = stats.savedAnalyses;
}

/* ================================================= */
/* ANALYZE WORKSPACE                                 */
/* ================================================= */
function initAnalyzeWorkspace() {
  const textarea = document.getElementById('messageInput');
  const charCounter = document.getElementById('charCount');
  const wordCounter = document.getElementById('wordCount');
  const warningBanner = document.getElementById('sensitiveWarningBanner');
  const redactBtn = document.getElementById('redactSensitiveBtn');
  const clearBtn = document.getElementById('clearInputBtn');
  const analyzeBtn = document.getElementById('analyzeBtn');

  if (!textarea) return;

  function updateCountersAndChecks() {
    const text = textarea.value;
    const chars = text.length;
    const words = text.trim() ? text.trim().split(/\s+/).length : 0;

    if (charCounter) charCounter.textContent = `${chars} chars`;
    if (wordCounter) wordCounter.textContent = `${words} words`;

    // Check for sensitive credential patterns
    const sensitive = detectSensitiveCredentials(text);
    if (sensitive.hasSensitiveData) {
      if (warningBanner) {
        warningBanner.classList.add('visible');
        const detailText = document.getElementById('sensitiveWarningDetail');
        if (detailText) {
          detailText.textContent = `Warning: We detected ${sensitive.findings.join(', ')}. Please remove sensitive numbers before analyzing.`;
        }
      }
    } else {
      if (warningBanner) warningBanner.classList.remove('visible');
    }
  }

  textarea.addEventListener('input', updateCountersAndChecks);

  // Redact button
  if (redactBtn) {
    redactBtn.addEventListener('click', () => {
      textarea.value = redactSensitiveData(textarea.value);
      updateCountersAndChecks();
      showToast('Sensitive numbers masked');
    });
  }

  // Clear button
  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      if (!textarea.value.trim()) return;
      textarea.value = '';
      updateCountersAndChecks();
      textarea.focus();
      showToast('Workspace cleared');
    });
  }

  // Example message buttons
  document.querySelectorAll('.example-chip-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const type = btn.getAttribute('data-example-type');
      if (SAMPLES[type]) {
        textarea.value = SAMPLES[type];
        updateCountersAndChecks();
        showToast(`Loaded ${btn.textContent.trim()} example`);
      }
    });
  });

  // Main Analyze Button
  if (analyzeBtn) {
    analyzeBtn.addEventListener('click', () => {
      const messageText = textarea.value.trim();
      if (!messageText) {
        showToast('Please paste a message before analyzing.');
        textarea.focus();
        return;
      }

      if (messageText.length < 10) {
        showToast('Please enter a longer message snippet for meaningful analysis.');
        textarea.focus();
        return;
      }

      runAnalysisWithAnimation(messageText);
    });
  }

  // Keyboard shortcut: Ctrl/Cmd + Enter to analyze
  textarea.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      analyzeBtn.click();
    }
  });
}

/**
 * Executes multi-step scanning animation sequence then reveals results
 */
function runAnalysisWithAnimation(text) {
  const overlay = document.getElementById('scanningOverlay');
  const stepLabel = document.getElementById('scanningStepLabel');
  const progressFill = document.getElementById('scanningProgressFill');

  if (!overlay) {
    completeAnalysis(text);
    return;
  }

  overlay.classList.add('active');

  const steps = [
    { label: 'SCANNING MESSAGE STRUCTURE...', pct: 20 },
    { label: 'CHECKING URGENCY & THREAT PATTERNS...', pct: 40 },
    { label: 'INSPECTING EMBEDDED URLS & DOMAINS...', pct: 60 },
    { label: 'CHECKING PAYMENT & CREDENTIAL REQUESTS...', pct: 80 },
    { label: 'BUILDING EDUCATIONAL REPORT...', pct: 100 }
  ];

  let currentStep = 0;
  const stepInterval = setInterval(() => {
    if (currentStep < steps.length) {
      if (stepLabel) stepLabel.textContent = steps[currentStep].label;
      if (progressFill) progressFill.style.width = `${steps[currentStep].pct}%`;
      currentStep++;
    } else {
      clearInterval(stepInterval);
      setTimeout(() => {
        overlay.classList.remove('active');
        completeAnalysis(text);
      }, 250);
    }
  }, 220);
}

function completeAnalysis(text) {
  const result = analyzeMessage(text);
  AppState.currentAnalysis = result;

  // Automatically save to local history
  saveToHistory(result);

  // Render Result View
  renderResultsView(result);

  // Switch to Results
  window.location.hash = 'results';
  showToast('Analysis complete');
}

/* ================================================= */
/* RESULTS VIEW RENDERING                            */
/* ================================================= */
function renderResultsView(result) {
  if (!result) return;

  const headerBanner = document.getElementById('resultHeaderBanner');
  const gaugeMeter = document.getElementById('gaugeMeter');
  const gaugeLevelLabel = document.getElementById('gaugeLevelLabel');
  const resultTitle = document.getElementById('resultLevelTitle');
  const resultExplanation = document.getElementById('resultLevelExplanation');

  if (headerBanner) {
    headerBanner.className = `results-header-banner ${result.levelClass}`;
  }

  if (gaugeLevelLabel) gaugeLevelLabel.textContent = result.level;
  if (resultTitle) resultTitle.textContent = result.levelTitle;

  // Explain why level was assigned
  if (resultExplanation) {
    if (result.warningSignCount === 0) {
      resultExplanation.textContent = 'ScamSense did not find obvious warning patterns in this text. Note: this does not guarantee the message is genuine. Always verify unexpected requests through trusted channels.';
    } else {
      resultExplanation.textContent = `${result.warningSignCount} warning ${result.warningSignCount === 1 ? 'sign was' : 'signs were'} detected across ${result.categoriesCount} ${result.categoriesCount === 1 ? 'category' : 'categories'}. These patterns deserve caution and independent verification.`;
    }
  }

  // Animate Gauge Stroke: circumference is 2 * pi * 50 ≈ 314.16
  if (gaugeMeter) {
    const circumference = 314.16;
    gaugeMeter.style.strokeDasharray = `${circumference} ${circumference}`;
    let offset = circumference;
    if (result.level === 'HIGH') offset = circumference * 0.15;
    else if (result.level === 'MODERATE') offset = circumference * 0.55;
    else offset = circumference * 0.90;
    setTimeout(() => {
      gaugeMeter.style.strokeDashoffset = offset;
    }, 50);
  }

  // Numerical Breakdown Cards
  const elSigns = document.getElementById('breakdownSigns');
  const elLinks = document.getElementById('breakdownLinks');
  const elPayments = document.getElementById('breakdownPayments');
  const elPressure = document.getElementById('breakdownPressure');

  if (elSigns) elSigns.textContent = result.warningSignCount;
  if (elLinks) elLinks.textContent = result.stats.links;
  if (elPayments) elPayments.textContent = result.stats.paymentRequests;
  if (elPressure) elPressure.textContent = result.stats.urgencyPhrases + result.stats.pressurePhrases;

  // Annotated Original Message
  const annotatedContainer = document.getElementById('annotatedMessageBody');
  if (annotatedContainer) {
    annotatedContainer.innerHTML = result.highlightedHtml;
  }

  // Warning Sign Cards
  const findingsList = document.getElementById('findingsCardsList');
  const noFindingsBox = document.getElementById('noFindingsBanner');

  if (findingsList) {
    if (result.findings.length === 0) {
      findingsList.style.display = 'none';
      if (noFindingsBox) noFindingsBox.style.display = 'block';
    } else {
      findingsList.style.display = 'block';
      if (noFindingsBox) noFindingsBox.style.display = 'none';

      findingsList.innerHTML = result.findings.map(f => {
        const cat = CATEGORY_DETAILS[f.category] || {};
        return `
          <div class="finding-card">
            <div class="finding-header">
              <div class="finding-title-group">
                <span>${cat.icon || '⚠'}</span>
                <span>${escapeHtml(f.title)}</span>
              </div>
              <span class="finding-badge">${escapeHtml(cat.badge || 'Warning')}</span>
            </div>
            ${f.matchedText ? `<div class="finding-excerpt">"${escapeHtml(f.matchedText)}"</div>` : ''}
            <div class="finding-details-grid">
              <div>
                <div class="detail-label">Why it matters</div>
                <div class="detail-body">${escapeHtml(f.whyItMatters)}</div>
              </div>
              <div>
                <div class="detail-label">What to do</div>
                <div class="detail-body">${escapeHtml(f.whatToDo)}</div>
              </div>
            </div>
          </div>
        `;
      }).join('');
    }
  }

  // "What Should I Do?" Action Checklist
  const actionListContainer = document.getElementById('actionStepsList');
  if (actionListContainer) {
    actionListContainer.innerHTML = result.actionList.map((step, idx) => `
      <div class="action-step-item">
        <div class="action-step-number">${idx + 1}</div>
        <div class="action-step-content">
          <h4>${escapeHtml(step.title)}</h4>
          <p>${escapeHtml(step.detail)}</p>
        </div>
      </div>
    `).join('');
  }

  // Wire Result Action Buttons
  wireResultActions(result);
}

function wireResultActions(result) {
  const saveBtn = document.getElementById('saveAnalysisBtn');
  const copyBtn = document.getElementById('copyReportBtn');
  const downloadPdfBtn = document.getElementById('downloadPdfBtn');
  const reanalyzeBtn = document.getElementById('reanalyzeBtn');
  const newScanBtn = document.getElementById('newScanBtn');

  // Update save button state based on whether result is saved
  function updateSaveBtnState() {
    if (!saveBtn) return;
    const saved = isAnalysisSaved(result.id);
    if (saved) {
      saveBtn.textContent = 'Saved ✓';
      saveBtn.className = 'btn btn-secondary btn-sm btn-save-toggle saved';
    } else {
      saveBtn.textContent = 'Save Analysis';
      saveBtn.className = 'btn btn-primary btn-sm btn-save-toggle';
    }
  }

  updateSaveBtnState();

  if (saveBtn) {
    saveBtn.onclick = () => {
      const alreadySaved = isAnalysisSaved(result.id);
      if (alreadySaved) {
        removeFromSaved(result.id);
        showToast('Removed from saved');
      } else {
        saveToSaved(result);
        showToast('Analysis saved');
      }
      updateSaveBtnState();
      refreshHomeStats();
    };
  }

  if (downloadPdfBtn) {
    downloadPdfBtn.onclick = () => {
      downloadAnalysisPDF(result);
      showToast('PDF downloaded');
    };
  }

  if (copyBtn) {
    copyBtn.onclick = () => {
      const summaryText = `ScamSense Safety Review
Level: ${result.level} (${result.levelTitle})
Warning signs detected: ${result.warningSignCount}
Categories flagged: ${result.categoriesDetected.map(c => CATEGORY_DETAILS[c]?.name || c).join(', ') || 'None'}

Key Recommendations:
${result.actionList.map((s, i) => `${i + 1}. ${s.title}: ${s.detail}`).join('\n')}

Note: ScamSense is an educational pattern reviewer, not a guarantee of safety or fraud. Always verify independently.`;

      navigator.clipboard.writeText(summaryText).then(() => {
        showToast('Report copied to clipboard');
      }).catch(() => {
        showToast('Failed to copy report');
      });
    };
  }

  if (reanalyzeBtn) {
    reanalyzeBtn.onclick = () => {
      if (result.type === 'link_inspection') {
        const linkInput = document.getElementById('linkInspectorInput');
        if (linkInput) linkInput.value = result.originalText;
        window.location.hash = 'analyze';
        setTimeout(() => {
          document.getElementById('analyzeLinkCard')?.scrollIntoView({ behavior: 'smooth' });
        }, 120);
      } else if (result.type === 'sender_check') {
        const nameInput = document.getElementById('senderDisplayNameInput');
        const emailInput = document.getElementById('senderEmailInput');
        if (result.senderDetails) {
          if (nameInput) nameInput.value = result.senderDetails.displayName !== '(None provided)' ? result.senderDetails.displayName : '';
          if (emailInput) emailInput.value = result.senderDetails.email !== '(Not detected)' ? result.senderDetails.email : '';
        }
        window.location.hash = 'analyze';
        setTimeout(() => {
          document.getElementById('analyzeSenderCard')?.scrollIntoView({ behavior: 'smooth' });
        }, 120);
      } else {
        const textarea = document.getElementById('messageInput');
        if (textarea) {
          textarea.value = result.originalText;
          textarea.dispatchEvent(new Event('input'));
        }
        window.location.hash = 'analyze';
      }
    };
  }

  if (newScanBtn) {
    newScanBtn.onclick = () => {
      const textarea = document.getElementById('messageInput');
      if (textarea) {
        textarea.value = '';
        textarea.dispatchEvent(new Event('input'));
      }
      window.location.hash = 'analyze';
    };
  }
}

/* ================================================= */
/* HISTORY VIEW                                      */
/* ================================================= */
function initHistoryView() {
  const searchInput = document.getElementById('historySearchInput');
  const clearAllBtn = document.getElementById('clearHistoryBtn');

  if (searchInput) {
    searchInput.addEventListener('input', () => {
      renderHistoryList(searchInput.value.trim());
    });
  }

  if (clearAllBtn) {
    clearAllBtn.addEventListener('click', () => {
      const history = getHistory();
      if (history.length === 0) {
        showToast('History is already empty');
        return;
      }

      openConfirmModal({
        title: 'Clear Analysis History?',
        message: 'Are you sure you want to clear your analysis history? Your saved analyses in Saved will remain safe.',
        confirmText: 'Clear History',
        confirmClass: 'btn-danger',
        onConfirm: () => {
          clearAllHistory();
          renderHistoryList();
          refreshHomeStats();
          showToast('History cleared');
        }
      });
    });
  }
}

function renderHistoryList(filterTerm = '') {
  const container = document.getElementById('historyGrid');
  const emptyState = document.getElementById('emptyHistoryState');
  if (!container) return;

  const history = getHistory();
  const lowerFilter = filterTerm.toLowerCase();

  const filtered = history.filter(item => {
    if (!filterTerm) return true;
    return (item.originalText || '').toLowerCase().includes(lowerFilter) ||
           (item.level || '').toLowerCase().includes(lowerFilter);
  });

  if (filtered.length === 0) {
    container.style.display = 'none';
    if (emptyState) emptyState.style.display = 'flex';
    return;
  }

  container.style.display = 'grid';
  if (emptyState) emptyState.style.display = 'none';

  container.innerHTML = filtered.map(item => {
    const dateFormatted = item.timestamp ? new Date(item.timestamp).toLocaleString(undefined, {
      dateStyle: 'medium',
      timeStyle: 'short'
    }) : 'Recent';

    const levelBadgeClass = item.level ? item.level.toLowerCase() : 'low';
    const isSaved = isAnalysisSaved(item.id);
    const typeBadge = item.type === 'link_inspection'
      ? '<span class="tool-type-badge">🔗 Link</span>'
      : (item.type === 'sender_check' ? '<span class="tool-type-badge">👤 Sender</span>' : '<span class="tool-type-badge">✉ Message</span>');

    return `
      <div class="compact-card" data-history-id="${item.id}">
        <div class="compact-card-main">
          <div class="compact-card-header">
            <span class="compact-card-date">${typeBadge}<span>${escapeHtml(dateFormatted)}</span></span>
            <span class="history-level-badge ${levelBadgeClass}">${escapeHtml(item.level)}</span>
          </div>
          <p class="compact-card-body">${escapeHtml(item.originalText)}</p>
        </div>
        <div class="compact-card-footer">
          <span class="compact-card-count">${item.warningSignCount} warning ${item.warningSignCount === 1 ? 'sign' : 'signs'}</span>
          <div class="compact-card-actions">
            <button class="btn btn-secondary btn-sm history-view-btn" data-id="${item.id}">View Analysis</button>
            <button class="btn btn-secondary btn-sm history-save-btn btn-save-toggle ${isSaved ? 'saved' : ''}" data-id="${item.id}">
              ${isSaved ? 'Saved ✓' : 'Save'}
            </button>
            <button class="btn btn-subtle btn-sm history-del-btn" data-id="${item.id}" title="Delete from history">✕</button>
          </div>
        </div>
      </div>
    `;
  }).join('');

  // Attach event handlers
  container.querySelectorAll('.history-view-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const id = btn.getAttribute('data-id');
      const item = history.find(h => h.id === id);
      if (item) {
        AppState.currentAnalysis = item;
        renderResultsView(item);
        window.location.hash = 'results';
      }
    });
  });

  container.querySelectorAll('.history-save-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const id = btn.getAttribute('data-id');
      const item = history.find(h => h.id === id);
      if (!item) return;

      const alreadySaved = isAnalysisSaved(id);
      if (alreadySaved) {
        removeFromSaved(id);
        btn.textContent = 'Save';
        btn.classList.remove('saved');
        showToast('Removed from saved');
      } else {
        saveToSaved(item);
        btn.textContent = 'Saved ✓';
        btn.classList.add('saved');
        showToast('Analysis saved');
      }
      refreshHomeStats();
    });
  });

  container.querySelectorAll('.history-del-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const id = btn.getAttribute('data-id');
      openConfirmModal({
        title: 'Delete this record?',
        message: 'Do you want to remove this analysis from your history?',
        confirmText: 'Delete',
        confirmClass: 'btn-danger',
        onConfirm: () => {
          deleteHistoryItem(id);
          renderHistoryList(filterTerm);
          refreshHomeStats();
          showToast('Record deleted');
        }
      });
    });
  });
}

/* ================================================= */
/* SAVED VIEW                                        */
/* ================================================= */
function initSavedView() {
  const searchInput = document.getElementById('savedSearchInput');
  if (searchInput) {
    searchInput.addEventListener('input', () => {
      renderSavedList(searchInput.value.trim());
    });
  }
}

function renderSavedList(filterTerm = '') {
  const container = document.getElementById('savedGrid');
  const emptyState = document.getElementById('emptySavedState');
  const countLabel = document.getElementById('savedCountLabel');
  if (!container) return;

  const savedList = getSavedAnalyses();
  if (countLabel) {
    countLabel.textContent = `${savedList.length} ${savedList.length === 1 ? 'saved item' : 'saved items'}`;
  }

  const lowerFilter = filterTerm.toLowerCase();
  const filtered = savedList.filter(item => {
    if (!filterTerm) return true;
    return (item.originalText || '').toLowerCase().includes(lowerFilter) ||
           (item.level || '').toLowerCase().includes(lowerFilter);
  });

  if (filtered.length === 0) {
    container.style.display = 'none';
    if (emptyState) emptyState.style.display = 'flex';
    return;
  }

  container.style.display = 'grid';
  if (emptyState) emptyState.style.display = 'none';

  container.innerHTML = filtered.map(item => {
    const dateFormatted = item.savedAt ? new Date(item.savedAt).toLocaleString(undefined, {
      dateStyle: 'medium',
      timeStyle: 'short'
    }) : (item.timestamp ? new Date(item.timestamp).toLocaleString(undefined, {
      dateStyle: 'medium',
      timeStyle: 'short'
    }) : 'Recent');

    const levelBadgeClass = item.level ? item.level.toLowerCase() : 'low';
    const typeBadge = item.type === 'link_inspection'
      ? '<span class="tool-type-badge">🔗 Link</span>'
      : (item.type === 'sender_check' ? '<span class="tool-type-badge">👤 Sender</span>' : '<span class="tool-type-badge">✉ Message</span>');

    return `
      <div class="compact-card" data-saved-id="${item.id}">
        <div class="compact-card-main">
          <div class="compact-card-header">
            <span class="compact-card-date">${typeBadge}<span>Saved ${escapeHtml(dateFormatted)}</span></span>
            <span class="history-level-badge ${levelBadgeClass}">${escapeHtml(item.level)}</span>
          </div>
          <p class="compact-card-body">${escapeHtml(item.originalText)}</p>
        </div>
        <div class="compact-card-footer">
          <span class="compact-card-count">${item.warningSignCount} warning ${item.warningSignCount === 1 ? 'sign' : 'signs'}</span>
          <div class="compact-card-actions">
            <button class="btn btn-secondary btn-sm saved-view-btn" data-id="${item.id}">View</button>
            <button class="btn btn-secondary btn-sm saved-pdf-btn" data-id="${item.id}">Download PDF</button>
            <button class="btn btn-subtle btn-sm saved-unsave-btn" data-id="${item.id}" title="Remove from saved">Unsave</button>
          </div>
        </div>
      </div>
    `;
  }).join('');

  // Event handlers
  container.querySelectorAll('.saved-view-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const id = btn.getAttribute('data-id');
      const item = savedList.find(s => s.id === id);
      if (item) {
        AppState.currentAnalysis = item;
        renderResultsView(item);
        window.location.hash = 'results';
      }
    });
  });

  container.querySelectorAll('.saved-pdf-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const id = btn.getAttribute('data-id');
      const item = savedList.find(s => s.id === id);
      if (item) {
        downloadAnalysisPDF(item);
        showToast('PDF downloaded');
      }
    });
  });

  container.querySelectorAll('.saved-unsave-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const id = btn.getAttribute('data-id');
      removeFromSaved(id);
      renderSavedList(filterTerm);
      refreshHomeStats();
      showToast('Removed from saved');
    });
  });
}

/* ================================================= */
/* LEARN VIEW                                        */
/* ================================================= */
function initLearnCenter() {
  renderTopicsAccordion();
}

function renderTopicsAccordion() {
  const container = document.getElementById('topicsAccordion');
  if (!container) return;

  container.innerHTML = LEARN_TOPICS.map((topic, idx) => `
    <div class="topic-card ${idx === 0 ? 'open' : ''}" data-topic-id="${topic.id}">
      <div class="topic-header">
        <div class="topic-title-group">
          <span class="topic-icon">${topic.icon}</span>
          <div>
            <h3>${escapeHtml(topic.title)}</h3>
            <p>${escapeHtml(topic.subtitle)}</p>
          </div>
        </div>
        <span class="topic-toggle-indicator">+</span>
      </div>
      <div class="topic-body">
        ${topic.content}
      </div>
    </div>
  `).join('');

  container.querySelectorAll('.topic-header').forEach(header => {
    header.addEventListener('click', () => {
      const card = header.closest('.topic-card');
      card.classList.toggle('open');
    });
  });
}

/* ================================================= */
/* TOOLS: LINK INSPECTOR & SENDER CHECK              */
/* ================================================= */
function createLinkAnalysisRecord(report) {
  const warningObservations = (report.observations || []).filter(o => o.status === 'warning');
  const count = warningObservations.length;

  let level = 'LOW';
  let levelTitle = 'NO OBVIOUS WARNING SIGNS FOUND';
  let levelClass = 'status-low';

  if (count >= 2 || report.isShortener || report.isIp) {
    level = 'HIGH';
    levelTitle = 'WARNING SIGNS FOUND';
    levelClass = 'status-high';
  } else if (count === 1) {
    level = 'MODERATE';
    levelTitle = 'POSSIBLE CONCERN FOUND';
    levelClass = 'status-moderate';
  }

  const findings = (report.observations || []).map(obs => ({
    category: RULE_CATEGORIES.SUSPICIOUS_LINK,
    matchedText: report.rawInput,
    title: obs.label,
    whyItMatters: obs.detail,
    whatToDo: obs.status === 'warning'
      ? 'Avoid opening this link directly. Always open a fresh browser tab and manually enter the recognized official domain.'
      : 'Even when encrypted with HTTPS, make sure you recognize the host domain before entering any login information.'
  }));

  const actionList = [
    {
      priority: count > 0 ? 'critical' : 'info',
      title: 'Verify the true destination host',
      detail: `The actual domain is "${report.mainDomain}". Confirm whether this is the genuine registered domain of the company.`
    },
    {
      priority: count > 0 ? 'high' : 'medium',
      title: 'Do not click links received in unprompted messages',
      detail: 'If you received this URL via SMS, WhatsApp, or an unexpected email, navigate to the service through official bookmarks or apps instead.'
    },
    {
      priority: 'info',
      title: 'Never submit credentials or OTPs on unverified domains',
      detail: 'Legitimate institutions never request your password, PIN, or OTP through strange domain addresses.'
    }
  ];

  return {
    id: 'link_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7),
    type: 'link_inspection',
    timestamp: new Date().toISOString(),
    originalText: report.rawInput,
    charCount: report.rawInput.length,
    wordCount: 1,
    level,
    levelTitle,
    levelClass,
    warningSignCount: count,
    categoriesCount: count > 0 ? 1 : 0,
    totalCategoriesChecked: Object.keys(RULE_CATEGORIES).length,
    findings: findings.length > 0 ? findings : [{
      category: RULE_CATEGORIES.SUSPICIOUS_LINK,
      matchedText: report.rawInput,
      title: 'Link Structure Checked',
      whyItMatters: 'No obvious red flags detected in the technical structure of this link.',
      whatToDo: 'Always verify the domain independently before typing passwords or payment details.'
    }],
    categoriesDetected: count > 0 ? [RULE_CATEGORIES.SUSPICIOUS_LINK] : [],
    linkReports: [{
      rawUrl: report.rawInput,
      protocol: report.protocol,
      hostname: report.hostname,
      domain: report.mainDomain,
      subdomain: report.subdomain,
      isShortener: report.isShortener,
      isIp: report.isIp,
      flags: warningObservations.map(o => ({ type: o.label, detail: o.detail }))
    }],
    actionList,
    highlightedHtml: `<div class="tool-highlight-box"><span style="color:var(--text-muted);">${escapeHtml(report.protocol)}//</span><mark class="highlight-token highlight-suspicious_link">${escapeHtml(report.hostname)}</mark><span style="color:var(--text-muted);">${escapeHtml(report.pathname)}${escapeHtml(report.search !== '(none)' ? report.search : '')}</span></div>`,
    stats: {
      links: 1,
      urgencyPhrases: 0,
      paymentRequests: 0,
      credentialRequests: 0,
      threatPhrases: 0,
      pressurePhrases: 0
    },
    linkDetails: report
  };
}

function createSenderAnalysisRecord(report) {
  const warningObservations = (report.observations || []).filter(o => o.status === 'warning');
  const count = warningObservations.length;

  let level = 'LOW';
  let levelTitle = 'NO OBVIOUS WARNING SIGNS FOUND';
  let levelClass = 'status-low';

  if (count >= 2) {
    level = 'HIGH';
    levelTitle = 'WARNING SIGNS FOUND';
    levelClass = 'status-high';
  } else if (count === 1) {
    level = 'MODERATE';
    levelTitle = 'POSSIBLE CONCERN FOUND';
    levelClass = 'status-moderate';
  }

  const findings = (report.observations || []).map(obs => ({
    category: RULE_CATEGORIES.IMPERSONATION,
    matchedText: report.email !== '(Not detected)' ? report.email : report.displayName,
    title: obs.label,
    whyItMatters: obs.detail,
    whatToDo: obs.status === 'warning'
      ? 'Do not reply to this message. Contact the organization directly through their official public directory.'
      : 'Be aware that display names can be configured arbitrarily by any sender.'
  }));

  const actionList = [
    {
      priority: count > 0 ? 'critical' : 'info',
      title: 'Compare sending domain with verified web address',
      detail: report.domain !== '(Not detected)'
        ? `The message originates from "${report.domain}". Verify if this domain matches the company's real website.`
        : 'Display names can be spoofed easily. Look for cryptographic signing or verified sender badges.'
    },
    {
      priority: 'high',
      title: 'Never send sensitive details or money to unverified senders',
      detail: 'Official institutions will never request confidential information or OTPs through email replies.'
    },
    {
      priority: 'medium',
      title: 'Verify directly via known official helpline',
      detail: 'Call the official customer support number printed on your card or bill to check if the notice was real.'
    }
  ];

  const fullSenderText = (report.displayName && report.displayName !== '(None provided)' && report.email && report.email !== '(Not detected)')
    ? `${report.displayName} <${report.email}>`
    : (report.email !== '(Not detected)' ? report.email : report.displayName);

  return {
    id: 'sender_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7),
    type: 'sender_check',
    timestamp: new Date().toISOString(),
    originalText: fullSenderText,
    charCount: fullSenderText.length,
    wordCount: fullSenderText.split(/\s+/).length,
    level,
    levelTitle,
    levelClass,
    warningSignCount: count,
    categoriesCount: count > 0 ? 1 : 0,
    totalCategoriesChecked: Object.keys(RULE_CATEGORIES).length,
    findings: findings.length > 0 ? findings : [{
      category: RULE_CATEGORIES.IMPERSONATION,
      matchedText: fullSenderText,
      title: 'Sender Identity Evaluated',
      whyItMatters: 'No obvious red flags detected in sender address structure.',
      whatToDo: 'Always verify unexpected notices independently through trusted channels.'
    }],
    categoriesDetected: count > 0 ? [RULE_CATEGORIES.IMPERSONATION] : [],
    linkReports: [],
    actionList,
    highlightedHtml: `<div class="tool-highlight-box"><strong>${escapeHtml(report.displayName)}</strong> &lt;<mark class="highlight-token highlight-impersonation">${escapeHtml(report.email)}</mark>&gt;</div>`,
    stats: {
      links: 0,
      urgencyPhrases: 0,
      paymentRequests: 0,
      credentialRequests: 0,
      threatPhrases: 0,
      pressurePhrases: 0
    },
    senderDetails: report
  };
}

function initTools() {
  // 1. LINK INSPECTOR (on Analyze page)
  const linkInput = document.getElementById('linkInspectorInput');
  const inspectBtn = document.getElementById('inspectLinkBtn');

  if (inspectBtn && linkInput) {
    inspectBtn.addEventListener('click', () => {
      const url = linkInput.value.trim();
      if (!url) {
        showToast('Please enter a web address to inspect');
        linkInput.focus();
        return;
      }

      const report = inspectSingleUrl(url);
      if (report.error) {
        showToast(report.error);
        return;
      }

      // Convert to full Analysis record
      const linkAnalysis = createLinkAnalysisRecord(report);

      // Automatically save to local history (works like message analysis)
      saveToHistory(linkAnalysis);
      AppState.currentAnalysis = linkAnalysis;

      // Render the result panel
      renderLinkInspectorResults(report, linkAnalysis);

      // Refresh home stats
      refreshHomeStats();

      showToast('Link inspection complete & recorded to History');
    });

    // Preset link buttons
    document.querySelectorAll('.preset-link-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        linkInput.value = btn.getAttribute('data-url');
        inspectBtn.click();
      });
    });
  }

  // 2. SENDER CHECK (on Analyze page)
  const senderDisplayNameInput = document.getElementById('senderDisplayNameInput');
  const senderEmailInput = document.getElementById('senderEmailInput');
  const checkSenderBtn = document.getElementById('checkSenderBtn');

  if (checkSenderBtn) {
    checkSenderBtn.addEventListener('click', () => {
      const displayName = senderDisplayNameInput ? senderDisplayNameInput.value.trim() : '';
      const email = senderEmailInput ? senderEmailInput.value.trim() : '';

      if (!displayName && !email) {
        showToast('Please enter a display name or email address');
        if (senderDisplayNameInput) senderDisplayNameInput.focus();
        return;
      }

      const report = inspectSenderInfo(displayName, email);
      if (report.error) {
        showToast(report.error);
        return;
      }

      // Convert to full Analysis record
      const senderAnalysis = createSenderAnalysisRecord(report);

      // Automatically save to local history (works like message analysis)
      saveToHistory(senderAnalysis);
      AppState.currentAnalysis = senderAnalysis;

      // Render the result panel
      renderSenderCheckResults(report, senderAnalysis);

      // Refresh home stats
      refreshHomeStats();

      showToast('Sender check complete & recorded to History');
    });

    // Preset sender buttons
    document.querySelectorAll('.preset-sender-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        if (senderDisplayNameInput) senderDisplayNameInput.value = btn.getAttribute('data-name') || '';
        if (senderEmailInput) senderEmailInput.value = btn.getAttribute('data-email') || '';
        checkSenderBtn.click();
      });
    });
  }
}

function renderLinkInspectorResults(report, linkAnalysis) {
  const panel = document.getElementById('linkResultsPanel');
  if (!panel) return;

  panel.classList.add('visible');

  const elProto = document.getElementById('linkMetricProtocol');
  const elHost = document.getElementById('linkMetricHostname');
  const elDomain = document.getElementById('linkMetricDomain');
  const elSub = document.getElementById('linkMetricSubdomain');
  const elPath = document.getElementById('linkMetricPath');
  const elShort = document.getElementById('linkMetricShortener');
  const obsList = document.getElementById('linkObservationsList');
  const conclusion = document.getElementById('linkConclusionText');

  if (elProto) elProto.textContent = report.protocol;
  if (elHost) elHost.textContent = report.hostname;
  if (elDomain) elDomain.textContent = report.mainDomain;
  if (elSub) elSub.textContent = report.subdomain;
  if (elPath) elPath.textContent = report.pathname;
  if (elShort) elShort.textContent = report.isShortener ? 'Yes (Shortened)' : 'No';

  if (obsList) {
    obsList.innerHTML = report.observations.map(obs => `
      <div class="tool-observation-item ${obs.status}">
        <strong>${escapeHtml(obs.label)}:</strong>
        <span>${escapeHtml(obs.detail)}</span>
      </div>
    `).join('');
  }

  if (conclusion) {
    conclusion.textContent = report.conclusion;
  }

  // Wire action buttons
  const viewFullBtn = document.getElementById('linkViewFullBtn');
  const saveBtn = document.getElementById('linkSaveBtn');
  const copyBtn = document.getElementById('linkCopyBtn');

  if (viewFullBtn) {
    viewFullBtn.onclick = () => {
      AppState.currentAnalysis = linkAnalysis;
      renderResultsView(linkAnalysis);
      window.location.hash = 'results';
    };
  }

  function updateLinkSaveBtnState() {
    if (!saveBtn) return;
    const isSaved = isAnalysisSaved(linkAnalysis.id);
    if (isSaved) {
      saveBtn.textContent = 'Saved ✓';
      saveBtn.className = 'btn btn-secondary btn-sm btn-save-toggle saved';
    } else {
      saveBtn.textContent = 'Save';
      saveBtn.className = 'btn btn-secondary btn-sm btn-save-toggle';
    }
  }

  updateLinkSaveBtnState();

  if (saveBtn) {
    saveBtn.onclick = () => {
      const isSaved = isAnalysisSaved(linkAnalysis.id);
      if (isSaved) {
        removeFromSaved(linkAnalysis.id);
        showToast('Removed from saved');
      } else {
        saveToSaved(linkAnalysis);
        showToast('Analysis saved to collection');
      }
      updateLinkSaveBtnState();
      refreshHomeStats();
    };
  }

  if (copyBtn) {
    copyBtn.onclick = () => {
      const text = `ScamSense Link Inspection:
URL: ${report.rawInput}
Host: ${report.hostname} (Domain: ${report.mainDomain})
Risk Level: ${linkAnalysis.level}
${report.observations.map(o => `• [${o.status.toUpperCase()}] ${o.label}: ${o.detail}`).join('\n')}
Educational Note: ${report.conclusion}`;

      navigator.clipboard.writeText(text).then(() => {
        showToast('Link inspection copied to clipboard');
      }).catch(() => {
        showToast('Failed to copy');
      });
    };
  }
}

function renderSenderCheckResults(report, senderAnalysis) {
  const panel = document.getElementById('senderResultsPanel');
  if (!panel) return;

  panel.classList.add('visible');

  const elName = document.getElementById('senderMetricName');
  const elEmail = document.getElementById('senderMetricEmail');
  const elDomain = document.getElementById('senderMetricDomain');
  const obsList = document.getElementById('senderObservationsList');
  const conclusion = document.getElementById('senderConclusionText');

  if (elName) elName.textContent = report.displayName;
  if (elEmail) elEmail.textContent = report.email;
  if (elDomain) elDomain.textContent = report.domain;

  if (obsList) {
    obsList.innerHTML = report.observations.map(obs => `
      <div class="tool-observation-item ${obs.status}">
        <strong>${escapeHtml(obs.label)}:</strong>
        <span>${escapeHtml(obs.detail)}</span>
      </div>
    `).join('');
  }

  if (conclusion) {
    conclusion.textContent = report.conclusion;
  }

  // Wire action buttons
  const viewFullBtn = document.getElementById('senderViewFullBtn');
  const saveBtn = document.getElementById('senderSaveBtn');
  const copyBtn = document.getElementById('senderCopyBtn');

  if (viewFullBtn) {
    viewFullBtn.onclick = () => {
      AppState.currentAnalysis = senderAnalysis;
      renderResultsView(senderAnalysis);
      window.location.hash = 'results';
    };
  }

  function updateSenderSaveBtnState() {
    if (!saveBtn) return;
    const isSaved = isAnalysisSaved(senderAnalysis.id);
    if (isSaved) {
      saveBtn.textContent = 'Saved ✓';
      saveBtn.className = 'btn btn-secondary btn-sm btn-save-toggle saved';
    } else {
      saveBtn.textContent = 'Save';
      saveBtn.className = 'btn btn-secondary btn-sm btn-save-toggle';
    }
  }

  updateSenderSaveBtnState();

  if (saveBtn) {
    saveBtn.onclick = () => {
      const isSaved = isAnalysisSaved(senderAnalysis.id);
      if (isSaved) {
        removeFromSaved(senderAnalysis.id);
        showToast('Removed from saved');
      } else {
        saveToSaved(senderAnalysis);
        showToast('Analysis saved to collection');
      }
      updateSenderSaveBtnState();
      refreshHomeStats();
    };
  }

  if (copyBtn) {
    copyBtn.onclick = () => {
      const text = `ScamSense Sender Verification:
Display Name: ${report.displayName}
Detected Email: ${report.email}
Domain: ${report.domain}
Risk Level: ${senderAnalysis.level}
${report.observations.map(o => `• [${o.status.toUpperCase()}] ${o.label}: ${o.detail}`).join('\n')}
Educational Note: ${report.conclusion}`;

      navigator.clipboard.writeText(text).then(() => {
        showToast('Sender check copied to clipboard');
      }).catch(() => {
        showToast('Failed to copy');
      });
    };
  }
}

/* ================================================= */
/* ABOUT VIEW                                        */
/* ================================================= */
function initAboutView() {
  const clearDataBtn = document.getElementById('clearAllDataBtn');
  if (clearDataBtn) {
    clearDataBtn.addEventListener('click', () => {
      openConfirmModal({
        title: 'Clear All Local Data?',
        message: 'This will reset your analysis history, saved analyses, and application settings. Everything stored in this browser for ScamSense will be erased.',
        confirmText: 'Clear Everything',
        confirmClass: 'btn-danger',
        onConfirm: () => {
          clearAllLocalData();
          renderHistoryList();
          refreshHomeStats();
          showToast('All local data cleared');
        }
      });
    });
  }
}

/* ================================================= */
/* MODALS & TOAST NOTIFICATIONS                      */
/* ================================================= */
function initModals() {
  const overlay = document.getElementById('confirmModalOverlay');
  const closeBtn = document.getElementById('confirmModalClose');
  const cancelBtn = document.getElementById('confirmModalCancel');
  const actionBtn = document.getElementById('confirmModalAction');

  function closeModal() {
    if (overlay) overlay.classList.remove('open');
    AppState.pendingModalConfirm = null;
  }

  if (closeBtn) closeBtn.addEventListener('click', closeModal);
  if (cancelBtn) cancelBtn.addEventListener('click', closeModal);

  if (actionBtn) {
    actionBtn.addEventListener('click', () => {
      if (typeof AppState.pendingModalConfirm === 'function') {
        AppState.pendingModalConfirm();
      }
      closeModal();
    });
  }

  // Close on backdrop click
  if (overlay) {
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) closeModal();
    });
  }

  // Close on Esc key
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      closeModal();
    }
  });
}

function openConfirmModal({ title, message, confirmText = 'Confirm', confirmClass = 'btn-primary', onConfirm }) {
  const overlay = document.getElementById('confirmModalOverlay');
  const titleEl = document.getElementById('confirmModalTitle');
  const bodyEl = document.getElementById('confirmModalBody');
  const actionBtn = document.getElementById('confirmModalAction');

  if (titleEl) titleEl.textContent = title;
  if (bodyEl) bodyEl.textContent = message;
  if (actionBtn) {
    actionBtn.textContent = confirmText;
    actionBtn.className = `btn ${confirmClass}`;
  }

  AppState.pendingModalConfirm = onConfirm;
  if (overlay) overlay.classList.add('open');
}

export function showToast(message, duration = 3200) {
  const container = document.getElementById('toastContainer');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.innerHTML = `<span>⚡</span><span>${escapeHtml(message)}</span>`;

  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    toast.style.transition = 'all 0.25s ease';
    setTimeout(() => {
      if (toast.parentNode) toast.parentNode.removeChild(toast);
    }, 250);
  }, duration);
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
