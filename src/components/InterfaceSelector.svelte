<script>
  import { onMount } from 'svelte';
  import {
    interfaces, selectedInterface, captureMode, bpfFilter, bpfError,
    isCapturing, loadInterfaces, startCapture, stopCapture, validateBpf,
    startStatusPolling, stopStatusPolling
  } from '../stores/capture.js';
  import { startPacketPolling, stopPacketPolling } from '../stores/packets.js';
  import { startStatsPolling, stopStatsPolling } from '../stores/stats.js';

  let localIface = '';
  let localMode = 'normal';
  let localBpf = '';

  onMount(() => {
    loadInterfaces();
  });

  $: {
    if (localIface) $selectedInterface = localIface;
  }
  $: $captureMode = localMode;
  $: $bpfFilter = localBpf;

  async function handleStart() {
    await startCapture();
    if ($isCapturing) {
      startPacketPolling();
      startStatusPolling();
      startStatsPolling();
    }
  }

  async function handleStop() {
    await stopCapture();
    stopPacketPolling();
    stopStatusPolling();
    stopStatsPolling();
  }

  async function onBpfChange(e) {
    localBpf = e.target.value;
    if (localBpf.trim()) {
      await validateBpf(localBpf);
    } else {
      $bpfError = '';
    }
  }
</script>

<div class="interface-selector">
  <div class="control-row">
    <label>网络接口</label>
    <select bind:value={localIface} disabled={$isCapturing}>
      <option value="">-- 选择接口 --</option>
      {#each $interfaces as iface}
        <option value={iface.name}>
          {iface.friendly_name} ({#each iface.ips as ip, i}{#if i > 0}, {/if}{ip}{/each})
          {#if iface.is_loopback}[回环]{/if}
          {#if !iface.is_up}[未启用]{/if}
        </option>
      {/each}
    </select>
  </div>

  <div class="control-row">
    <label>捕获模式</label>
    <select bind:value={localMode} disabled={$isCapturing}>
      <option value="normal">普通模式</option>
      <option value="promiscuous">混杂模式</option>
    </select>
  </div>

  <div class="control-row bpf-row">
    <label>BPF过滤</label>
    <input
      type="text"
      placeholder="例: tcp port 80, host 192.168.1.1"
      value={localBpf}
      on:input={onBpfChange}
      disabled={$isCapturing}
    />
    {#if $bpfError}
      <span class="bpf-error">{$bpfError}</span>
    {/if}
  </div>

  <div class="control-row buttons">
    {#if !$isCapturing}
      <button class="btn-start" on:click={handleStart} disabled={!localIface || $bpfError}>
        ▶ 开始捕获
      </button>
    {:else}
      <button class="btn-stop" on:click={handleStop}>
        ■ 停止捕获
      </button>
    {/if}
  </div>
</div>

<style>
  .interface-selector {
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 8px 16px;
    background: #2d2d2d;
    border-bottom: 1px solid #444;
    flex-wrap: wrap;
  }
  .control-row {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .control-row label {
    color: #ccc;
    font-size: 13px;
    white-space: nowrap;
  }
  select, input[type="text"] {
    background: #1e1e1e;
    color: #e0e0e0;
    border: 1px solid #555;
    border-radius: 4px;
    padding: 4px 8px;
    font-size: 13px;
    min-width: 180px;
  }
  select:focus, input:focus {
    outline: none;
    border-color: #4fc3f7;
  }
  input[type="text"] {
    min-width: 240px;
  }
  .bpf-row {
    position: relative;
  }
  .bpf-error {
    color: #ef5350;
    font-size: 11px;
    position: absolute;
    bottom: -16px;
    left: 60px;
  }
  .btn-start {
    background: #2e7d32;
    color: white;
    border: none;
    border-radius: 4px;
    padding: 6px 16px;
    cursor: pointer;
    font-size: 13px;
    font-weight: 500;
  }
  .btn-start:hover {
    background: #388e3c;
  }
  .btn-start:disabled {
    background: #555;
    cursor: not-allowed;
  }
  .btn-stop {
    background: #c62828;
    color: white;
    border: none;
    border-radius: 4px;
    padding: 6px 16px;
    cursor: pointer;
    font-size: 13px;
    font-weight: 500;
  }
  .btn-stop:hover {
    background: #d32f2f;
  }
  .buttons {
    margin-left: auto;
  }
</style>
