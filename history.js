/**
 * ScamSense Storage & History Manager
 * Manages browser localStorage for analysis history, checklist progress,
 * learning quiz records, and dashboard metrics.
 */

const STORAGE_KEYS = {
  HISTORY: 'scamsense_history_v1',
  SAVED: 'scamsense_saved_v1',
  THEME: 'scamsense_theme_v1',
  STATS: 'scamsense_stats_v1'
};

/**
 * Get all analysis history entries (newest first)
 */
export function getHistory() {
  try {
    const raw = localStorage.getItem(STORAGE_KEYS.HISTORY);
    return raw ? JSON.parse(raw) : [];
  } catch (err) {
    console.error('Error reading ScamSense history from localStorage:', err);
    return [];
  }
}

/**
 * Automatically record completed analysis into history
 */
export function saveToHistory(analysisResult) {
  if (!analysisResult) return null;

  try {
    const history = getHistory();
    // Prepend new analysis, capping at 50 records
    const updated = [analysisResult, ...history.filter(h => h.id !== analysisResult.id)].slice(0, 50);
    localStorage.setItem(STORAGE_KEYS.HISTORY, JSON.stringify(updated));

    // Update global aggregate stats
    incrementStats(analysisResult.warningSignCount);

    return true;
  } catch (err) {
    console.error('Error saving to history:', err);
    return false;
  }
}

/**
 * Delete a specific history entry by ID (does NOT touch Saved)
 */
export function deleteHistoryItem(id) {
  try {
    const history = getHistory();
    const filtered = history.filter(item => item.id !== id);
    localStorage.setItem(STORAGE_KEYS.HISTORY, JSON.stringify(filtered));
    return true;
  } catch (err) {
    console.error('Error deleting history item:', err);
    return false;
  }
}

/**
 * Clear all history (does NOT delete Saved analyses)
 */
export function clearAllHistory() {
  try {
    localStorage.removeItem(STORAGE_KEYS.HISTORY);
    return true;
  } catch (err) {
    console.error('Error clearing history:', err);
    return false;
  }
}

/**
 * SAVED ANALYSES (Explicitly saved by user only)
 */
export function getSavedAnalyses() {
  try {
    const raw = localStorage.getItem(STORAGE_KEYS.SAVED);
    return raw ? JSON.parse(raw) : [];
  } catch (err) {
    console.error('Error reading saved analyses from localStorage:', err);
    return [];
  }
}

export function isAnalysisSaved(id) {
  if (!id) return false;
  const saved = getSavedAnalyses();
  return saved.some(item => item.id === id);
}

export function saveToSaved(analysisResult) {
  if (!analysisResult) return false;
  try {
    const saved = getSavedAnalyses();
    if (saved.some(s => s.id === analysisResult.id)) {
      return true; // Already saved
    }
    const record = {
      ...analysisResult,
      savedAt: new Date().toISOString()
    };
    const updated = [record, ...saved].slice(0, 50);
    localStorage.setItem(STORAGE_KEYS.SAVED, JSON.stringify(updated));
    return true;
  } catch (err) {
    console.error('Error saving analysis:', err);
    return false;
  }
}

export function removeFromSaved(id) {
  try {
    const saved = getSavedAnalyses();
    const filtered = saved.filter(item => item.id !== id);
    localStorage.setItem(STORAGE_KEYS.SAVED, JSON.stringify(filtered));
    return true;
  } catch (err) {
    console.error('Error removing from saved:', err);
    return false;
  }
}

export function clearAllSaved() {
  try {
    localStorage.removeItem(STORAGE_KEYS.SAVED);
    return true;
  } catch (err) {
    console.error('Error clearing saved analyses:', err);
    return false;
  }
}

/**
 * Dashboard & Usage Stats
 */
export function getStats() {
  try {
    const raw = localStorage.getItem(STORAGE_KEYS.STATS);
    const parsed = raw ? JSON.parse(raw) : { messagesChecked: 0, warningSignsFound: 0 };
    const history = getHistory();
    const saved = getSavedAnalyses();

    return {
      messagesChecked: Math.max(parsed.messagesChecked || 0, history.length),
      warningSignsFound: parsed.warningSignsFound || history.reduce((sum, h) => sum + (h.warningSignCount || 0), 0),
      savedAnalyses: saved.length
    };
  } catch {
    return { messagesChecked: 0, warningSignsFound: 0, savedAnalyses: 0 };
  }
}

function incrementStats(warningSignsCount = 0) {
  try {
    const stats = getStats();
    stats.messagesChecked += 1;
    stats.warningSignsFound += (warningSignsCount || 0);
    localStorage.setItem(STORAGE_KEYS.STATS, JSON.stringify({
      messagesChecked: stats.messagesChecked,
      warningSignsFound: stats.warningSignsFound
    }));
  } catch (err) {
    console.error('Error incrementing stats:', err);
  }
}

/**
 * Theme Preference
 */
export function getThemePreference() {
  try {
    return localStorage.getItem(STORAGE_KEYS.THEME) || 'light';
  } catch {
    return 'light';
  }
}

export function setThemePreference(theme) {
  try {
    localStorage.setItem(STORAGE_KEYS.THEME, theme);
  } catch (err) {
    console.error('Error setting theme:', err);
  }
}

/**
 * Reset all local storage data for ScamSense
 */
export function clearAllLocalData() {
  try {
    localStorage.removeItem(STORAGE_KEYS.HISTORY);
    localStorage.removeItem(STORAGE_KEYS.SAVED);
    localStorage.removeItem(STORAGE_KEYS.STATS);
    // Keep theme as convenience or reset
    return true;
  } catch (err) {
    console.error('Error resetting local data:', err);
    return false;
  }
}
