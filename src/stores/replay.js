import { writable } from 'svelte/store';
import { invoke } from '@tauri-apps/api/tauri';
import { save } from '@tauri-apps/api/dialog';

export const replayResults = writable(null);
export const replayBatchSummary = writable(null);
export const replayProgress = writable(null);
export const isReplaying = writable(false);
export const showReplayResult = writable(false);

export async function replaySessions(sessionIds) {
  if (!sessionIds || sessionIds.length === 0) return;
  isReplaying.set(true);
  replayProgress.set({
    currentSession: 0,
    totalSessions: sessionIds.length,
    currentPacket: 0,
    totalPackets: 0,
  });
  try {
    const result = await invoke('replay_sessions', { sessionIds });
    replayBatchSummary.set(result);
    replayResults.set(result.per_session_results);
    showReplayResult.set(true);
    return result;
  } catch (e) {
    console.error('Replay sessions error:', e);
    throw e;
  } finally {
    isReplaying.set(false);
    replayProgress.set(null);
  }
}

export async function exportReplayResult(result, path) {
  try {
    if (!path) {
      path = await save({
        filters: [{ name: 'JSON', extensions: ['json'] }],
        defaultPath: 'replay_result.json',
      });
    }
    if (path) {
      await invoke('export_replay_result_json', { result, path });
      return true;
    }
    return false;
  } catch (e) {
    console.error('Export replay result error:', e);
    return false;
  }
}

export async function exportBatchSummary(summary) {
  try {
    const path = await save({
      filters: [{ name: 'JSON', extensions: ['json'] }],
      defaultPath: 'replay_batch_summary.json',
    });
    if (path) {
      await invoke('export_batch_summary_json', { summary, path });
      return true;
    }
    return false;
  } catch (e) {
    console.error('Export batch summary error:', e);
    return false;
  }
}

export function closeReplayResult() {
  showReplayResult.set(false);
}
