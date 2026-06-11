import { writable } from 'svelte/store';

export const displayFilter = writable('');
export const filterStatus = writable('');
export const markFilter = writable('all');
export const commentFilter = writable('');
