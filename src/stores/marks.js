import { writable, get } from 'svelte/store';
import { invoke } from '@tauri-apps/api/tauri';

export const marks = writable({});
export const markCount = writable(0);

export async function loadAllMarks() {
  try {
    const allMarks = await invoke('get_all_marks');
    const markMap = {};
    allMarks.forEach(m => {
      markMap[m.packet_no] = m;
    });
    marks.set(markMap);
    markCount.set(allMarks.length);
  } catch (e) {
    console.error('Load marks error:', e);
  }
}

export async function setPacketMark(packetNo, level, comment) {
  try {
    await invoke('set_packet_mark', { packetNo, level, comment });
    await loadAllMarks();
    return true;
  } catch (e) {
    console.error('Set mark error:', e);
    return false;
  }
}

export async function removePacketMark(packetNo) {
  try {
    await invoke('remove_packet_mark', { packetNo });
    await loadAllMarks();
    return true;
  } catch (e) {
    console.error('Remove mark error:', e);
    return false;
  }
}

export function getMarkColor(level) {
  switch (level) {
    case 'starred': return '#ffca28';
    case 'warning': return '#ef5350';
    case 'important': return '#42a5f5';
    default: return '#888';
  }
}

export function getMarkLabel(level) {
  switch (level) {
    case 'starred': return '星标';
    case 'warning': return '警告';
    case 'important': return '重要';
    default: return '';
  }
}
