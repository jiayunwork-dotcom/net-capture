import { writable } from 'svelte/store';
import { invoke } from '@tauri-apps/api/tauri';
import { save } from '@tauri-apps/api/dialog';
import { listen } from '@tauri-apps/api/event';

export const replayResults = writable(null);
export const replayBatchSummary = writable(null);
export const replayProgress = writable(null);
export const isReplaying = writable(false);
export const showReplayResult = writable(false);
export const replaySpeed = writable('1x');

export const SPEED_OPTIONS = [
  { value: '0.5x', label: '0.5x' },
  { value: '1x', label: '1x' },
  { value: '2x', label: '2x' },
  { value: '5x', label: '5x' },
  { value: 'max', label: '最大速度' },
];

let unlistenReplayProgress = null;

async function ensureReplayProgressListener() {
  if (unlistenReplayProgress) return;
  unlistenReplayProgress = await listen('replay_progress', (event) => {
    replayProgress.set(event.payload);
  });
}

export async function replaySessions(sessionIds, speedLabel) {
  if (!sessionIds || sessionIds.length === 0) return;
  isReplaying.set(true);
  replayProgress.set({
    session_index: 0,
    total_sessions: sessionIds.length,
    current_packet: 0,
    total_packets: 0,
    session_id: '',
    session_label: '',
  });

  try {
    await ensureReplayProgressListener();
    const result = await invoke('replay_sessions', { sessionIds, speedLabel: speedLabel || '1x' });
    replayBatchSummary.set(result);
    replayResults.set(result.per_session_results);
    showReplayResult.set(true);
    return result;
  } catch (e) {
    console.error('Replay sessions error:', e);
    throw e;
  } finally {
    isReplaying.set(false);
    setTimeout(() => {
      replayProgress.set(null);
    }, 500);
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
