import { writable } from 'svelte/store';
import { invoke } from '@tauri-apps/api/tauri';

export const sessions = writable([]);
export const tcpStreamData = writable(null);
export const showStreamPanel = writable(false);

export async function loadSessions() {
  try {
    const result = await invoke('get_sessions');
    sessions.set(result);
  } catch (e) {
    console.error('Load sessions error:', e);
  }
}

export async function traceTcpStream(sessionId) {
  try {
    const data = await invoke('trace_tcp_stream', { sessionId });
    tcpStreamData.set(data);
    showStreamPanel.set(true);
  } catch (e) {
    console.error('Trace stream error:', e);
  }
}

export function closeStreamPanel() {
  showStreamPanel.set(false);
  tcpStreamData.set(null);
}
