import { writable } from 'svelte/store';
import { invoke } from '@tauri-apps/api/tauri';
import { save } from '@tauri-apps/api/dialog';
import { listen } from '@tauri-apps/api/event';

export const attackPatterns = writable([]);
export const patternSimResult = writable(null);
export const effectivenessReport = writable(null);
export const showEffectivenessReport = writable(false);
export const showPatternSimResult = writable(false);
export const isGeneratingTraffic = writable(false);
export const isRunningReport = writable(false);
export const simulationProgress = writable(null);
export const reportProgress = writable(null);
export const simSpeed = writable('1x');
export const heatmapData = writable(null);
export const isGeneratingHeatmap = writable(false);
export const heatmapProgress = writable(null);

let unlistenSimProgress = null;
let unlistenReportProgress = null;
let unlistenHeatmapProgress = null;

async function ensureSimProgressListener() {
  if (unlistenSimProgress) return;
  unlistenSimProgress = await listen('simulation_progress', (event) => {
    simulationProgress.set(event.payload);
  });
}

async function ensureReportProgressListener() {
  if (unlistenReportProgress) return;
  unlistenReportProgress = await listen('effectiveness_report_progress', (event) => {
    reportProgress.set(event.payload);
  });
}

async function ensureHeatmapProgressListener() {
  if (unlistenHeatmapProgress) return;
  unlistenHeatmapProgress = await listen('heatmap_progress', (event) => {
    heatmapProgress.set(event.payload);
  });
}

export async function loadAttackPatterns(category) {
  try {
    const result = await invoke('get_attack_patterns', { category: category || null });
    attackPatterns.set(result);
    return result;
  } catch (e) {
    console.error('Load attack patterns error:', e);
    return [];
  }
}

export async function addAttackPattern(pattern) {
  try {
    await invoke('add_attack_pattern', { pattern });
    await loadAttackPatterns();
    return true;
  } catch (e) {
    console.error('Add attack pattern error:', e);
    return false;
  }
}

export async function updateAttackPattern(pattern) {
  try {
    await invoke('update_attack_pattern', { pattern });
    await loadAttackPatterns();
    return true;
  } catch (e) {
    console.error('Update attack pattern error:', e);
    return false;
  }
}

export async function deleteAttackPattern(patternId) {
  try {
    await invoke('delete_attack_pattern', { patternId });
    await loadAttackPatterns();
    return true;
  } catch (e) {
    console.error('Delete attack pattern error:', e);
    return false;
  }
}

export async function runPatternAgainstEngine(patternId, targetIp, speedLabel) {
  isGeneratingTraffic.set(true);
  simulationProgress.set({
    session_index: 0,
    total_sessions: 1,
    current_packet: 0,
    total_packets: 0,
    session_id: patternId,
    session_label: '',
  });
  try {
    await ensureSimProgressListener();
    const result = await invoke('run_pattern_against_engine', {
      patternId,
      targetIp: targetIp || null,
      speedLabel: speedLabel || '1x',
    });
    patternSimResult.set(result);
    showPatternSimResult.set(true);
    return result;
  } catch (e) {
    console.error('Run pattern against engine error:', e);
    throw e;
  } finally {
    isGeneratingTraffic.set(false);
    setTimeout(() => {
      simulationProgress.set(null);
    }, 500);
  }
}

export async function generateEffectivenessReport(patternIds, targetIp) {
  isRunningReport.set(true);
  reportProgress.set({
    current_pattern: 0,
    total_patterns: patternIds.length,
    pattern_id: '',
    pattern_name: '',
  });
  try {
    await ensureReportProgressListener();
    const report = await invoke('generate_rule_effectiveness_report', {
      patternIds,
      targetIp: targetIp || null,
    });
    effectivenessReport.set(report);
    showEffectivenessReport.set(true);
    return report;
  } catch (e) {
    console.error('Generate effectiveness report error:', e);
    throw e;
  } finally {
    isRunningReport.set(false);
    setTimeout(() => {
      reportProgress.set(null);
    }, 500);
  }
}

export async function exportEffectivenessReport(report) {
  try {
    const path = await save({
      filters: [{ name: 'JSON', extensions: ['json'] }],
      defaultPath: 'rule_effectiveness_report.json',
    });
    if (path) {
      await invoke('export_effectiveness_report_json', { report, path });
      return true;
    }
    return false;
  } catch (e) {
    console.error('Export effectiveness report error:', e);
    return false;
  }
}

export function closePatternSimResult() {
  showPatternSimResult.set(false);
  patternSimResult.set(null);
}

export function closeEffectivenessReport() {
  showEffectivenessReport.set(false);
  effectivenessReport.set(null);
}

export async function generateHeatmap() {
  isGeneratingHeatmap.set(true);
  heatmapProgress.set(null);
  heatmapData.set(null);
  try {
    await ensureHeatmapProgressListener();
    const result = await invoke('generate_heatmap', {});
    heatmapData.set(result);
    return result;
  } catch (e) {
    console.error('Generate heatmap error:', e);
    throw e;
  } finally {
    isGeneratingHeatmap.set(false);
    setTimeout(() => {
      heatmapProgress.set(null);
    }, 500);
  }
}

export const ATTACK_CATEGORIES = [
  { value: 'port_scan', label: '端口扫描' },
  { value: 'syn_flood', label: 'SYN洪泛' },
  { value: 'dns_amplification', label: 'DNS放大' },
  { value: 'brute_force', label: '暴力破解' },
  { value: 'arp_spoof', label: 'ARP欺骗' },
  { value: 'http_flood', label: 'HTTP洪泛' },
  { value: 'udp_flood', label: 'UDP洪泛' },
  { value: 'icmp_flood', label: 'ICMP洪泛' },
  { value: 'slow_loris', label: 'SlowLoris' },
  { value: 'custom', label: '自定义' },
];
