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

export function applyMarkFilter(markFilterType, commentFilterText, marksMap) {
  return new Promise((resolve) => {
    filteredPackets.update(current => {
      if (markFilterType === 'all' && !commentFilterText.trim()) {
        return current;
      }

      const result = current.filter(pkt => {
        const mark = marksMap[pkt.no];
        const hasMark = !!mark;

        let markMatch = true;
        switch (markFilterType) {
          case 'marked':
            markMatch = hasMark;
            break;
          case 'unmarked':
            markMatch = !hasMark;
            break;
          case 'starred':
            markMatch = hasMark && mark.level === 'starred';
            break;
          case 'warning':
            markMatch = hasMark && mark.level === 'warning';
            break;
          case 'important':
            markMatch = hasMark && mark.level === 'important';
            break;
          default:
            markMatch = true;
        }

        let commentMatch = true;
        if (commentFilterText.trim()) {
          const searchLower = commentFilterText.toLowerCase();
          commentMatch = hasMark && mark.comment && mark.comment.toLowerCase().includes(searchLower);
        }

        return markMatch && commentMatch;
      });

      return result;
    });
    resolve(true);
  });
}
