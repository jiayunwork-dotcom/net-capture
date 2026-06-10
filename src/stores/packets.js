import { writable } from 'svelte/store';
import { invoke } from '@tauri-apps/api/tauri';

export const packets = writable([]);
export const filteredPackets = writable([]);
export const selectedPacketNo = writable(null);
export const packetDetail = writable(null);
export const hexDump = writable([]);
export const autoScroll = writable(true);

const MAX_DISPLAY_PACKETS = 500000;

let pollInterval = null;
let lastCount = 0;

export async function fetchNewPackets() {
  try {
    const status = await invoke('get_capture_status');
    if (status.packet_count > lastCount) {
      const allFiltered = await invoke('apply_display_filter', { filterExpr: '' });
      packets.set(allFiltered.slice(-MAX_DISPLAY_PACKETS));
      filteredPackets.set(allFiltered.slice(-MAX_DISPLAY_PACKETS));
      lastCount = status.packet_count;
    }
  } catch (e) {
    console.error('Fetch packets error:', e);
  }
}

export function startPacketPolling() {
  if (pollInterval) clearInterval(pollInterval);
  lastCount = 0;
  pollInterval = setInterval(fetchNewPackets, 200);
}

export function stopPacketPolling() {
  if (pollInterval) {
    clearInterval(pollInterval);
    pollInterval = null;
  }
}

export async function loadPacketDetail(no, rawData) {
  try {
    const detail = await invoke('get_packet_detail', { no, rawData: rawData || null });
    packetDetail.set(detail);
    selectedPacketNo.set(no);

    if (detail.raw_data && detail.raw_data.length > 0) {
      const hex = await invoke('get_hex_dump', { rawData: detail.raw_data });
      hexDump.set(hex);
    } else {
      hexDump.set([]);
    }
  } catch (e) {
    console.error('Load detail error:', e);
  }
}

export async function applyDisplayFilter(filterExpr) {
  try {
    const filtered = await invoke('apply_display_filter', { filterExpr });
    filteredPackets.set(filtered.slice(-MAX_DISPLAY_PACKETS));
    return true;
  } catch (e) {
    console.error('Filter error:', e);
    return false;
  }
}
