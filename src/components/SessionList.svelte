<script>
  import { onMount } from 'svelte';
  import { sessions, loadSessions } from '../stores/sessions.js';
  import { isCapturing } from '../stores/capture.js';
  import { replaySessions, replaySpeed, SPEED_OPTIONS } from '../stores/replay.js';
  import { traceTcpStream } from '../stores/sessions.js';

  let sessionPollInterval = null;
  let selectedSessionIds = new Set();
  let contextMenu = { visible: false, x: 0, y: 0, sessionId: null };

  onMount(() => {
    loadSessions();
    document.addEventListener('click', closeContextMenu);
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

  function toggleSelect(sessionId, event) {
    if (event.ctrlKey || event.metaKey || event.shiftKey) {
      if (selectedSessionIds.has(sessionId)) {
        selectedSessionIds.delete(sessionId);
      } else {
        selectedSessionIds.add(sessionId);
      }
    } else {
      selectedSessionIds.clear();
      selectedSessionIds.add(sessionId);
    }
    selectedSessionIds = new Set(selectedSessionIds);
  }

  function selectAll() {
    selectedSessionIds = new Set($sessions.map(s => s.id));
  }

  function clearSelection() {
    selectedSessionIds = new Set();
  }

  function showContextMenu(event, sessionId) {
    event.preventDefault();
    event.stopPropagation();
    if (!selectedSessionIds.has(sessionId)) {
      selectedSessionIds.clear();
      selectedSessionIds.add(sessionId);
      selectedSessionIds = new Set(selectedSessionIds);
    }
    contextMenu = {
      visible: true,
      x: event.clientX,
      y: event.clientY,
      sessionId,
    };
  }

  function closeContextMenu() {
    contextMenu = { visible: false, x: 0, y: 0, sessionId: null };
  }

  async function handleReplaySelected() {
    closeContextMenu();
    const ids = Array.from(selectedSessionIds);
    if (ids.length === 0) return;
    try {
      await replaySessions(ids, $replaySpeed);
    } catch (e) {
      alert('回放失败: ' + e);
    }
  }

  function handleViewStream(sessionId) {
    closeContextMenu();
    traceTcpStream(sessionId);
  }

  $: selectedCount = selectedSessionIds.size;
</script>

<div class="session-list">
  <div class="session-header">
    <h3>会话列表 {selectedCount > 0 ? `(已选 ${selectedCount})` : ''}</h3>
    <div class="header-actions">
      {#if selectedCount > 0}
        <button class="btn-action" on:click={clearSelection}>取消选择</button>
      {/if}
      <button class="btn-select-all" on:click={selectAll}>全选</button>
      <button class="btn-refresh" on:click={loadSessions}>刷新</button>
    </div>
  </div>
  <div class="table-wrapper">
    <table>
      <thead>
        <tr>
          <th style="width: 30px;"></th>
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
        {#each $sessions as session (session.id)}
          <tr
            class:selected={selectedSessionIds.has(session.id)}
            on:click={(e) => toggleSelect(session.id, e)}
            on:contextmenu={(e) => showContextMenu(e, session.id)}
          >
            <td>
              <input
                type="checkbox"
                checked={selectedSessionIds.has(session.id)}
                on:click|stopPropagation
                on:change={(e) => {
                  if (e.target.checked) selectedSessionIds.add(session.id);
                  else selectedSessionIds.delete(session.id);
                  selectedSessionIds = new Set(selectedSessionIds);
                }}
              />
            </td>
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

  {#if contextMenu.visible}
    <div
      class="context-menu"
      style="left: {contextMenu.x}px; top: {contextMenu.y}px;"
      onclick="event.stopPropagation()"
    >
      <div class="menu-item speed-item">
        <span>回放速度:</span>
        <select bind:value={$replaySpeed} class="speed-select">
          {#each SPEED_OPTIONS as opt}
            <option value={opt.value}>{opt.label}</option>
          {/each}
        </select>
      </div>
      <div class="menu-item" on:click={handleReplaySelected}>
        ▶️ 回放到规则引擎 {selectedCount > 1 ? `(${selectedCount}个会话)` : ''}
      </div>
      {#if selectedCount === 1}
        <div class="menu-item" on:click={() => handleViewStream(contextMenu.sessionId)}>
          📊 查看TCP流
        </div>
      {/if}
    </div>
  {/if}
</div>

<style>
  .session-list {
    height: 100%;
    display: flex;
    flex-direction: column;
    background: #1e1e1e;
    position: relative;
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
  .header-actions {
    display: flex;
    gap: 6px;
  }
  .btn-refresh, .btn-select-all, .btn-action {
    background: #444;
    color: #ccc;
    border: none;
    border-radius: 4px;
    padding: 4px 10px;
    cursor: pointer;
    font-size: 12px;
  }
  .btn-refresh:hover, .btn-select-all:hover, .btn-action:hover {
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
  tr.selected td {
    background: #1e3a5f;
  }
  tr.selected:hover td {
    background: #254876;
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
  input[type="checkbox"] {
    cursor: pointer;
  }
  .context-menu {
    position: fixed;
    background: #2d2d2d;
    border: 1px solid #555;
    border-radius: 6px;
    min-width: 200px;
    z-index: 1000;
    box-shadow: 0 6px 20px rgba(0,0,0,0.4);
    overflow: hidden;
  }
  .menu-item {
    padding: 8px 14px;
    cursor: pointer;
    color: #ccc;
    font-size: 13px;
  }
  .menu-item:hover {
    background: #3a3a3a;
    color: #fff;
  }
  .speed-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    color: #aaa;
    font-size: 12px;
  }
  .speed-select {
    background: #1e1e1e;
    color: #ddd;
    border: 1px solid #555;
    border-radius: 3px;
    padding: 2px 6px;
    font-size: 11px;
  }
</style>
