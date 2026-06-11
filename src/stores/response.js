import { writable } from 'svelte/store';
import { invoke } from '@tauri-apps/api/tauri';

export const responseLogs = writable([]);
export const banEntries = writable([]);
export const responseConfig = writable({
  default_cooldown_secs: 60,
  script_whitelist_dirs: [],
  webhook_default_timeout_secs: 10,
  ban_list_path: 'ban_list.json',
});

export async function loadResponseLogs() {
  try {
    const logs = await invoke('get_response_logs');
    responseLogs.set(logs || []);
  } catch (e) {
    console.error('Load response logs error:', e);
  }
}

export async function loadResponseLogsFiltered(ruleName, timeFrom, timeTo) {
  try {
    const logs = await invoke('get_response_logs_filtered', {
      ruleName: ruleName || '',
      timeFrom: timeFrom || null,
      timeTo: timeTo || null,
    });
    responseLogs.set(logs || []);
  } catch (e) {
    console.error('Load filtered response logs error:', e);
  }
}

export async function clearResponseLogs() {
  try {
    await invoke('clear_response_logs');
    responseLogs.set([]);
  } catch (e) {
    console.error('Clear response logs error:', e);
  }
}

export async function loadBanEntries() {
  try {
    const entries = await invoke('get_ban_entries');
    banEntries.set(entries || []);
  } catch (e) {
    console.error('Load ban entries error:', e);
  }
}

export async function unbanIp(ip) {
  try {
    await invoke('unban_ip', { ip });
    await loadBanEntries();
    return true;
  } catch (e) {
    console.error('Unban IP error:', e);
    throw e;
  }
}

export async function cleanupExpiredBans() {
  try {
    const count = await invoke('cleanup_expired_bans');
    await loadBanEntries();
    return count;
  } catch (e) {
    console.error('Cleanup expired bans error:', e);
    throw e;
  }
}

export async function clearAllBans() {
  try {
    await invoke('clear_all_bans');
    banEntries.set([]);
  } catch (e) {
    console.error('Clear all bans error:', e);
  }
}

export async function loadResponseConfig() {
  try {
    const config = await invoke('get_response_config');
    responseConfig.set(config);
  } catch (e) {
    console.error('Load response config error:', e);
  }
}

export async function saveResponseConfig(config) {
  try {
    await invoke('save_response_config', { config });
    responseConfig.set(config);
    return true;
  } catch (e) {
    console.error('Save response config error:', e);
    throw e;
  }
}

export function getResultLabel(result) {
  switch (result) {
    case 'success': return '成功';
    case 'failed': return '失败';
    case 'timeout': return '超时';
    case 'cooldown_skipped': return '冷却跳过';
    case 'condition_skipped': return '条件跳过';
    default: return result;
  }
}

export function getResultColor(result) {
  switch (result) {
    case 'success': return '#4caf50';
    case 'failed': return '#ef5350';
    case 'timeout': return '#ff9800';
    case 'cooldown_skipped': return '#888';
    case 'condition_skipped': return '#9e9e9e';
    default: return '#888';
  }
}

export function getActionTypeLabel(type) {
  switch (type) {
    case 'webhook': return 'Webhook';
    case 'ip_ban': return 'IP封禁';
    case 'script_exec': return '脚本执行';
    case 'chain': return '响应链';
    default: return type;
  }
}

export function getActionTypeIcon(type) {
  switch (type) {
    case 'webhook': return '🔗';
    case 'ip_ban': return '🚫';
    case 'script_exec': return '📜';
    case 'chain': return '⚡';
    default: return '📋';
  }
}

export function formatResponseTime(timestamp_secs) {
  const date = new Date(timestamp_secs * 1000);
  const h = String(date.getHours()).padStart(2, '0');
  const m = String(date.getMinutes()).padStart(2, '0');
  const s = String(date.getSeconds()).padStart(2, '0');
  return `${h}:${m}:${s}`;
}

export function formatBanTime(timestamp_secs) {
  const date = new Date(timestamp_secs * 1000);
  const y = date.getFullYear();
  const mo = String(date.getMonth() + 1).padStart(2, '0');
  const d = String(date.getDate()).padStart(2, '0');
  const h = String(date.getHours()).padStart(2, '0');
  const m = String(date.getMinutes()).padStart(2, '0');
  const s = String(date.getSeconds()).padStart(2, '0');
  return `${y}-${mo}-${d} ${h}:${m}:${s}`;
}

export function isBanExpired(entry) {
  if (entry.expire_minutes === 0) return false;
  const now = Math.floor(Date.now() / 1000);
  return now > entry.ban_time + entry.expire_minutes * 60;
}

export function getConditionModeLabel(mode) {
  switch (mode) {
    case 'always': return '始终执行';
    case 'on_success': return '成功时执行';
    case 'on_failure': return '失败时执行';
    default: return '始终执行';
  }
}

export function getConditionModeColor(mode) {
  switch (mode) {
    case 'on_success': return '#4caf50';
    case 'on_failure': return '#ef5350';
    default: return '#888';
  }
}

export async function getBanRelatedAlerts(ip) {
  try {
    const alerts = await invoke('get_ban_related_alerts', { ip });
    return alerts || [];
  } catch (e) {
    console.error('Get ban related alerts error:', e);
    return [];
  }
}

export async function exportBanCsv() {
  try {
    const csv = await invoke('export_ban_csv');
    return csv;
  } catch (e) {
    console.error('Export ban CSV error:', e);
    throw e;
  }
}

export async function importBanCsv(content) {
  try {
    const result = await invoke('import_ban_csv', { content });
    await loadBanEntries();
    return result;
  } catch (e) {
    console.error('Import ban CSV error:', e);
    throw e;
  }
}
