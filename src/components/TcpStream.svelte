<script>
  import { tcpStreamData, closeStreamPanel, showStreamPanel } from '../stores/sessions.js';

  let clientTab = true;

  $: data = $tcpStreamData;
  $: currentSegments = clientTab ? (data?.client_data || []) : (data?.server_data || []);

  function formatSegment(seg) {
    if (seg.missing) {
      return `[数据缺失: seq ${seg.seq_start}-${seg.seq_end}]`;
    }
    if (seg.is_retransmission) {
      return `[重传] ${new TextDecoder().decode(seg.data.slice(0, 500))}`;
    }
    return new TextDecoder().decode(seg.data.slice(0, 500));
  }

  function formatHex(data) {
    return Array.from(data.slice(0, 64))
      .map(b => b.toString(16).padStart(2, '0'))
      .join(' ');
  }

  function close() {
    closeStreamPanel();
  }
</script>

{#if $showStreamPanel && data}
  <div class="tcp-stream-panel">
    <div class="stream-header">
      <h3>TCP流追踪</h3>
      <span class="stream-id">{data.session_id}</span>
      {#if data.has_gap}
        <span class="gap-warning">⚠ {data.gap_info || '数据缺失'}</span>
      {/if}
      <button class="btn-close" on:click={close}>✕</button>
    </div>

    <div class="tab-bar">
      <button class="tab" class:active={clientTab} on:click={() => clientTab = true}>
        客户端 → 服务端
      </button>
      <button class="tab" class:active={!clientTab} on:click={() => clientTab = false}>
        服务端 → 客户端
      </button>
    </div>

    <div class="stream-content" class:client={clientTab} class:server={!clientTab}>
      {#each currentSegments as seg, i}
        <div class="segment" class:missing={seg.missing} class:retrans={seg.is_retransmission}>
          <div class="seg-header">
            <span class="seg-seq">Seq: {seg.seq_start}-{seg.seq_end}</span>
            <span class="seg-len">Len: {seg.data.length}</span>
            {#if seg.is_retransmission}
              <span class="seg-flag retrans-flag">重传</span>
            {/if}
            {#if seg.missing}
              <span class="seg-flag missing-flag">缺失</span>
            {/if}
          </div>
          <pre class="seg-data">{formatSegment(seg)}</pre>
        </div>
      {/each}
      {#if currentSegments.length === 0}
        <div class="no-data">暂无数据</div>
      {/if}
    </div>
  </div>
{/if}

<style>
  .tcp-stream-panel {
    position: fixed;
    right: 0;
    top: 0;
    bottom: 0;
    width: 600px;
    background: #1e1e1e;
    border-left: 2px solid #444;
    display: flex;
    flex-direction: column;
    z-index: 100;
  }
  .stream-header {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 16px;
    background: #2d2d2d;
    border-bottom: 1px solid #444;
  }
  .stream-header h3 {
    color: #ccc;
    font-size: 14px;
    margin: 0;
  }
  .stream-id {
    color: #888;
    font-size: 12px;
    font-family: monospace;
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .gap-warning {
    color: #ffa726;
    font-size: 12px;
  }
  .btn-close {
    background: transparent;
    color: #888;
    border: none;
    cursor: pointer;
    font-size: 18px;
    padding: 2px 8px;
  }
  .btn-close:hover {
    color: #ef5350;
  }
  .tab-bar {
    display: flex;
    background: #252525;
    border-bottom: 1px solid #444;
  }
  .tab {
    flex: 1;
    padding: 8px;
    background: transparent;
    color: #888;
    border: none;
    cursor: pointer;
    font-size: 13px;
  }
  .tab.active {
    color: #4fc3f7;
    border-bottom: 2px solid #4fc3f7;
  }
  .tab:hover {
    background: #2a2a2a;
  }
  .stream-content {
    flex: 1;
    overflow-y: auto;
    padding: 8px;
  }
  .stream-content.client .segment:not(.missing) {
    border-left: 3px solid #ef5350;
  }
  .stream-content.server .segment:not(.missing) {
    border-left: 3px solid #42a5f5;
  }
  .segment {
    margin-bottom: 6px;
    padding: 6px 10px;
    background: #2d2d2d;
    border-radius: 4px;
  }
  .segment.missing {
    background: #3e2723;
    border-left: 3px solid #ff9800;
  }
  .segment.retrans {
    border-left-color: #ab47bc !important;
  }
  .seg-header {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 4px;
    font-size: 11px;
  }
  .seg-seq, .seg-len {
    color: #888;
    font-family: monospace;
  }
  .seg-flag {
    font-size: 10px;
    padding: 1px 4px;
    border-radius: 2px;
  }
  .retrans-flag {
    background: #4a148c;
    color: #ce93d8;
  }
  .missing-flag {
    background: #e65100;
    color: #ffcc80;
  }
  .seg-data {
    font-family: 'Menlo', monospace;
    font-size: 12px;
    color: #e0e0e0;
    white-space: pre-wrap;
    word-break: break-all;
    margin: 0;
    max-height: 200px;
    overflow-y: auto;
  }
  .no-data {
    color: #666;
    text-align: center;
    padding: 40px;
  }
</style>
