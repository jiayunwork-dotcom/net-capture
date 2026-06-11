<script>
  import { onMount } from 'svelte';
  import {
    responseLogs, loadResponseLogs, loadResponseLogsFiltered, clearResponseLogs,
    getResultLabel, getResultColor, getActionTypeLabel, getActionTypeIcon,
    formatResponseTime,
  } from '../stores/response.js';

  let ruleNameFilter = '';
  let timeFrom = null;
  let timeTo = null;
  let autoRefresh = true;
  let refreshInterval = null;

  const timeRangePresets = [
    { label: '全部', from: null, to: null },
    { label: '最近5分钟', from: () => Math.floor(Date.now()/1000) - 300, to: null },
    { label: '最近1小时', from: () => Math.floor(Date.now()/1000) - 3600, to: null },
    { label: '最近24小时', from: () => Math.floor(Date.now()/1000) - 86400, to: null },
  ];

  let selectedTimePreset = 0;

  function applyFilter() {
    const preset = timeRangePresets[selectedTimePreset];
    const from = preset.from ? preset.from() : null;
    const to = preset.to ? preset.to() : null;
    loadResponseLogsFiltered(ruleNameFilter, from, to);
  }

  function handleClearLogs() {
    if (confirm('确定清空所有响应日志吗？')) {
      clearResponseLogs();
    }
  }

  function refresh() {
    applyFilter();
  }

  onMount(() => {
    loadResponseLogs();
    if (autoRefresh) {
      refreshInterval = setInterval(refresh, 2000);
    }
    return () => {
      if (refreshInterval) clearInterval(refreshInterval);
    };
  });
</script>

<div class="response-log-panel">
  <div class="toolbar">
    <div class="filter-group">
      <input
        type="text"
        bind:value={ruleNameFilter}
        placeholder="搜索规则名称..."
        class="search-input"
        on:keydown={(e) => e.key === 'Enter' && applyFilter()}
      />
      <select bind:value={selectedTimePreset} on:change={applyFilter}>
        {#each timeRangePresets as preset, i}
          <option value={i}>{preset.label}</option>
        {/each}
      </select>
      <button class="btn-small" on:click={applyFilter}>筛选</button>
    </div>
    <div class="toolbar-right">
      <span class="log-count">共 {$responseLogs.length} 条</span>
      <button class="btn-small" on:click={refresh}>刷新</button>
      <button class="btn-small danger" on:click={handleClearLogs}>清空</button>
    </div>
  </div>

  <div class="logs-list">
    {#if $responseLogs.length === 0}
      <div class="empty-state">
        <div class="empty-icon">📋</div>
        <div class="empty-text">暂无响应日志</div>
        <div class="empty-hint">配置自动响应动作后，执行记录将在此处显示</div>
      </div>
    {:else}
      <table class="logs-table">
        <thead>
          <tr>
            <th>时间</th>
            <th>规则</th>
            <th>动作</th>
            <th>结果</th>
            <th>耗时</th>
            <th>详情</th>
          </tr>
        </thead>
        <tbody>
          {#each $responseLogs as log (log.id)}
            <tr class="result-{log.result} action-{log.action_type}">
              <td class="time">{formatResponseTime(log.trigger_time)}</td>
              <td class="rule-name">{log.rule_name}</td>
              <td class="action-type">
                <span class="action-badge">{getActionTypeIcon(log.action_type)} {getActionTypeLabel(log.action_type)}</span>
              </td>
              <td class="result">
                <span class="result-badge" style="color: {getResultColor(log.result)}">
                  {getResultLabel(log.result)}
                </span>
              </td>
              <td class="duration">{log.duration_ms}ms</td>
              <td class="detail" title={log.detail || ''}>
                {log.detail || '-'}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </div>
</div>

<style>
  .response-log-panel {
    display: flex;
    flex-direction: column;
    height: 100%;
    background: #1e1e1e;
    color: #e0e0e0;
    font-size: 12px;
  }

  .toolbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 10px 16px;
    background: #252525;
    border-bottom: 1px solid #3a3a3a;
    gap: 12px;
  }

  .filter-group {
    display: flex;
    gap: 8px;
    align-items: center;
  }

  .search-input {
    padding: 6px 10px;
    background: #1e1e1e;
    color: #e0e0e0;
    border: 1px solid #444;
    border-radius: 4px;
    font-size: 12px;
    width: 180px;
  }

  .search-input:focus {
    outline: none;
    border-color: #4fc3f7;
  }

  .filter-group select {
    padding: 6px 10px;
    background: #1e1e1e;
    color: #e0e0e0;
    border: 1px solid #444;
    border-radius: 4px;
    font-size: 12px;
  }

  .toolbar-right {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .log-count {
    color: #888;
    font-size: 11px;
  }

  .btn-small {
    padding: 5px 10px;
    background: #3a3a3a;
    color: #ccc;
    border: 1px solid #555;
    border-radius: 3px;
    cursor: pointer;
    font-size: 11px;
  }

  .btn-small:hover {
    background: #4a4a4a;
  }

  .btn-small.danger {
    color: #ef5350;
    border-color: #ef5350;
  }

  .btn-small.danger:hover {
    background: rgba(239, 83, 80, 0.15);
  }

  .logs-list {
    flex: 1;
    overflow-y: auto;
  }

  .empty-state {
    text-align: center;
    padding: 60px 20px;
    color: #666;
  }

  .empty-icon {
    font-size: 48px;
    margin-bottom: 12px;
    opacity: 0.5;
  }

  .empty-text {
    font-size: 14px;
    margin-bottom: 6px;
    color: #888;
  }

  .empty-hint {
    font-size: 12px;
  }

  .logs-table {
    width: 100%;
    border-collapse: collapse;
  }

  .logs-table thead {
    position: sticky;
    top: 0;
    z-index: 1;
  }

  .logs-table th {
    background: #252525;
    padding: 8px 12px;
    text-align: left;
    font-size: 11px;
    color: #888;
    font-weight: 600;
    border-bottom: 1px solid #3a3a3a;
    text-transform: uppercase;
  }

  .logs-table td {
    padding: 8px 12px;
    border-bottom: 1px solid #2d2d2d;
    font-size: 12px;
  }

  .logs-table tr:hover {
    background: #252525;
  }

  .logs-table tr.result-failed {
    background: rgba(239, 83, 80, 0.05);
  }

  .logs-table tr.result-timeout {
    background: rgba(255, 152, 0, 0.05);
  }

  .logs-table tr.result-condition_skipped {
    background: rgba(158, 158, 158, 0.05);
    opacity: 0.7;
  }

  .logs-table tr.action-chain {
    background: rgba(79, 195, 247, 0.08);
    border-bottom: 1px solid rgba(79, 195, 247, 0.25);
  }

  .logs-table tr.action-chain td {
    font-weight: 600;
  }

  .logs-table tr.action-chain .action-badge {
    background: rgba(79, 195, 247, 0.2);
    color: #4fc3f7;
  }

  .logs-table tr.action-chain .duration {
    color: #ba68c8;
    font-weight: 700;
    font-size: 13px;
  }

  .time {
    font-family: monospace;
    color: #888;
    font-size: 11px;
  }

  .rule-name {
    font-weight: 500;
    color: #e0e0e0;
  }

  .action-badge {
    padding: 2px 8px;
    background: #2d2d2d;
    border-radius: 3px;
    font-size: 11px;
  }

  .result-badge {
    font-weight: 600;
    font-size: 11px;
  }

  .duration {
    font-family: monospace;
    color: #888;
    font-size: 11px;
  }

  .detail {
    max-width: 300px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: #aaa;
    font-size: 11px;
  }
</style>
