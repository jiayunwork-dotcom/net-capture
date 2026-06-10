import { writable } from 'svelte/store';
import { invoke } from '@tauri-apps/api/tauri';

export const stats = writable({
  protocol_counts: [],
  protocol_bytes: [],
  pps_timeline: [],
  bps_timeline: [],
  top_src_ips: [],
  top_dst_ips: [],
  top_ports: [],
  tcp_states: [],
});

let pollInterval = null;

export async function loadStats() {
  try {
    const result = await invoke('get_stats');
    stats.set(result);
  } catch (e) {
    console.error('Load stats error:', e);
  }
}

export function startStatsPolling() {
  if (pollInterval) clearInterval(pollInterval);
  pollInterval = setInterval(loadStats, 1000);
  loadStats();
}

export function stopStatsPolling() {
  if (pollInterval) {
    clearInterval(pollInterval);
    pollInterval = null;
  }
}
