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

export async function fetchNewPackets() {
  try {
    const newPackets = await invoke('drain_new_packets');
    if (newPackets.length > 0) {
      packets.update(existing => {
        const combined = existing.concat(newPackets);
        return combined.length > MAX_DISPLAY_PACKETS
          ? combined.slice(-MAX_DISPLAY_PACKETS)
          : combined;
      });
      filteredPackets.update(filtered => {
        const combined = filtered.concat(newPackets);
        return combined.length > MAX_DISPLAY_PACKETS
          ? combined.slice(-MAX_DISPLAY_PACKETS)
          : combined;
      });
    }
  } catch (e) {
    console.error('Fetch packets error:', e);
  }
}

export function startPacketPolling() {
  if (pollInterval) clearInterval(pollInterval);
  packets.set([]);
  filteredPackets.set([]);
  pollInterval = setInterval(fetchNewPackets, 200);
}

export function stopPacketPolling() {
  if (pollInterval) {
    clearInterval(pollInterval);
    pollInterval = null;
  }
}

export async function loadPacketDetail(no) {
  try {
    const detail = await invoke('get_packet_detail', { no });
    packetDetail.set(detail);
    selectedPacketNo.set(no);

    const hex = await invoke('get_hex_dump', { no });
    hexDump.set(hex);
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
