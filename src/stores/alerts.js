import { writable, derived } from 'svelte/store';
import { invoke } from '@tauri-apps/api/tauri';

export const alerts = writable([]);
export const alertCount = writable(0);
export const maxAlerts = writable(50000);
export const alertsLoading = writable(false);

let pollInterval = null;

export async function loadAlerts() {
  alertsLoading.set(true);
  try {
    const allAlerts = await invoke('get_alerts');
    alerts.set(allAlerts || []);
    alertCount.set(allAlerts ? allAlerts.length : 0);
  } catch (e) {
    console.error('Load alerts error:', e);
  } finally {
    alertsLoading.set(false);
  }
}

export async function fetchNewAlerts() {
  try {
    const newAlerts = await invoke('get_new_alerts');
    if (newAlerts && newAlerts.length > 0) {
      alerts.update(existing => {
        const combined = newAlerts.concat(existing);
        return combined.length > maxAlerts
          ? combined.slice(0, maxAlerts)
          : combined;
      });
      alertCount.update(c => c + newAlerts.length);
      return newAlerts;
    }
    return [];
  } catch (e) {
    console.error('Fetch new alerts error:', e);
    return [];
  }
}

export function startAlertPolling() {
  if (pollInterval) clearInterval(pollInterval);
  pollInterval = setInterval(fetchNewAlerts, 500);
}

export function stopAlertPolling() {
  if (pollInterval) {
    clearInterval(pollInterval);
    pollInterval = null;
  }
}

export async function clearAlerts() {
  try {
    await invoke('clear_alerts');
    alerts.set([]);
    alertCount.set(0);
    return true;
  } catch (e) {
    console.error('Clear alerts error:', e);
    return false;
  }
}

export const priorityColors = {
  high: {
    bg: 'rgba(239, 83, 80, 0.2)',
    border: '#ef5350',
    text: '#ef5350',
    label: '高'
  },
  medium: {
    bg: 'rgba(255, 152, 0, 0.2)',
    border: '#ff9800',
    text: '#ff9800',
    label: '中'
  },
  low: {
    bg: 'rgba(255, 235, 59, 0.2)',
    border: '#ffeb3b',
    text: '#ffeb3b',
    label: '低'
  }
};

export function getPriorityColor(priority) {
  return priorityColors[priority] || priorityColors.low;
}

export function formatAlertTime(secs, micros) {
  const date = new Date(secs * 1000 + Math.floor(micros / 1000));
  const h = String(date.getHours()).padStart(2, '0');
  const m = String(date.getMinutes()).padStart(2, '0');
  const s = String(date.getSeconds()).padStart(2, '0');
  const ms = String(Math.floor(micros / 1000)).padStart(3, '0');
  return `${h}:${m}:${s}.${ms}`;
}

export const filteredAlerts = writable([]);
export const alertFilters = writable({
  priority: 'all',
  ruleName: '',
  timeRange: null,
});

export function applyAlertFilters() {
  alerts.update(currentAlerts => {
    const filters = get(alertFilters);
    let result = currentAlerts;

    if (filters.priority !== 'all') {
      result = result.filter(a => a.priority === filters.priority);
    }

    if (filters.ruleName && filters.ruleName.trim()) {
      const search = filters.ruleName.toLowerCase();
      result = result.filter(a => a.rule_name.toLowerCase().includes(search));
    }

    if (filters.timeRange) {
      const now = Date.now() / 1000;
      result = result.filter(a => now - a.timestamp_secs <= filters.timeRange);
    }

    filteredAlerts.set(result);
    return currentAlerts;
  });
}

import { get } from 'svelte/store';
