import { writable, get } from 'svelte/store';
import { invoke } from '@tauri-apps/api/tauri';

export const interfaces = writable([]);
export const selectedInterface = writable('');
export const captureMode = writable('normal');
export const bpfFilter = writable('');
export const bpfError = writable('');
export const isCapturing = writable(false);
export const captureStatus = writable({ is_capturing: false, packet_count: 0, dropped_count: 0 });

export async function loadInterfaces() {
  try {
    const result = await invoke('list_interfaces');
    interfaces.set(result);
  } catch (e) {
    console.error('Failed to load interfaces:', e);
  }
}

export async function startCapture() {
  try {
    bpfError.set('');
    const iface = get(selectedInterface);
    if (!iface) {
      bpfError.set('请选择网络接口');
      return;
    }

    const filter = get(bpfFilter) || null;
    const promisc = get(captureMode) === 'promiscuous';

    await invoke('start_capture', {
      interfaceName: iface,
      promiscuous: promisc,
      bpfFilter: filter,
    });
    isCapturing.set(true);
  } catch (e) {
    bpfError.set(String(e));
    isCapturing.set(false);
  }
}

export async function stopCapture() {
  try {
    await invoke('stop_capture');
    isCapturing.set(false);
  } catch (e) {
    console.error('Failed to stop capture:', e);
  }
}

export async function validateBpf(filter) {
  if (!filter || filter.trim() === '') {
    bpfError.set('');
    return true;
  }
  try {
    await invoke('validate_bpf', { filter });
    bpfError.set('');
    return true;
  } catch (e) {
    bpfError.set('表达式无效: ' + String(e));
    return false;
  }
}

let statusInterval = null;

export function startStatusPolling() {
  if (statusInterval) clearInterval(statusInterval);
  statusInterval = setInterval(async () => {
    try {
      const status = await invoke('get_capture_status');
      captureStatus.set(status);
      isCapturing.set(status.is_capturing);
    } catch (e) {
      console.error('Status poll error:', e);
    }
  }, 500);
}

export function stopStatusPolling() {
  if (statusInterval) {
    clearInterval(statusInterval);
    statusInterval = null;
  }
}
