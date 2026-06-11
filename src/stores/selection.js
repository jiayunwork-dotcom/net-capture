import { writable } from 'svelte/store';

export const selectedPackets = writable([]);

export function clearSelection() {
  selectedPackets.set([]);
}

export function toggleSelection(pktNo) {
  selectedPackets.update(selected => {
    if (selected.includes(pktNo)) {
      return selected.filter(n => n !== pktNo);
    } else {
      return [...selected, pktNo];
    }
  });
}
