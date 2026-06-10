<script>
  import { onMount } from 'svelte';
  import { sessions, loadSessions } from '../stores/sessions.js';
  import { isCapturing } from '../stores/capture.js';

  let sessionPollInterval = null;

  onMount(() => {
    loadSessions();
  });

  $: if ($isCapturing) {
    startSessionPolling();
  } else {
    stopSessionPolling();
  }

  function startSessionPolling() {
    if (sessionPollInterval) return;
    sessionPollInterval = setInterval(loadSessions, 2000);
  }

  function stopSessionPolling() {
    if (sessionPollInterval) {
      clearInterval(sessionPollInterval);
      sessionPollInterval = null;
    }
  }

  function formatDuration(ms) {
    if (ms < 1000) return ms + 'ms';
    if (ms < 60000) return (ms / 1000).toFixed(1) + 's';
    return (ms / 60000).toFixed(1) + 'm';
  }

  function formatBytes(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  }

  function stateClass(state) {
    if (state === 'Active') return 'state-active';
    if (state === 'Closed') return 'state-closed';
    return 'state-expired';
  }
</script>

<div class="session-list">
  <div class="session-header">
    <h3>会话列表</h3>
    <button class="btn-refresh" on:click={loadSessions}>刷新</button>
  </div>
  <div class="table-wrapper">
    <table>
      <thead>
        <tr>
          <th>源地址</th>
          <th>目的地址</th>
          <th>协议</th>
          <th>包数</th>
          <th>字节</th>
          <th>持续</th>
          <th>状态</th>
        </tr>
      </thead>
      <tbody>
        {#each $sessions as session}
          <tr>
            <td>{session.src_addr}:{session.src_port}</td>
            <td>{session.dst_addr}:{session.dst_port}</td>
            <td>{session.protocol}</td>
            <td>{session.packet_count}</td>
            <td>{formatBytes(session.byte_count)}</td>
            <td>{formatDuration(session.duration_ms)}</td>
            <td><span class="state-badge {stateClass(session.state)}">{session.state}</span></td>
          </tr>
        {/each}
      </tbody>
    </table>
    {#if $sessions.length === 0}
      <div class="no-sessions">暂无会话数据</div>
    {/if}
  </div>
</div>

<style>
  .session-list {
    height: 100%;
    display: flex;
    flex-direction: column;
    background: #1e1e1e;
  }
  .session-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 8px 12px;
    background: #2d2d2d;
    border-bottom: 1px solid #444;
  }
  .session-header h3 {
    color: #ccc;
    font-size: 14px;
    margin: 0;
    font-weight: 500;
  }
  .btn-refresh {
    background: #444;
    color: #ccc;
    border: none;
    border-radius: 4px;
    padding: 4px 10px;
    cursor: pointer;
    font-size: 12px;
  }
  .btn-refresh:hover {
    background: #555;
  }
  .table-wrapper {
    flex: 1;
    overflow-y: auto;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }
  thead {
    position: sticky;
    top: 0;
    background: #333;
    z-index: 5;
  }
  th {
    color: #aaa;
    text-align: left;
    padding: 6px 8px;
    font-weight: 500;
    border-bottom: 1px solid #444;
  }
  td {
    color: #ccc;
    padding: 4px 8px;
    border-bottom: 1px solid #333;
    font-family: 'Menlo', monospace;
  }
  tr:hover td {
    background: #2a2a2a;
  }
  .state-badge {
    display: inline-block;
    padding: 1px 6px;
    border-radius: 3px;
    font-size: 11px;
  }
  .state-active { background: #1b5e20; color: #a5d6a7; }
  .state-closed { background: #4a148c; color: #ce93d8; }
  .state-expired { background: #3e2723; color: #bcaaa4; }
  .no-sessions {
    color: #666;
    text-align: center;
    padding: 40px;
    font-size: 14px;
  }
</style>
