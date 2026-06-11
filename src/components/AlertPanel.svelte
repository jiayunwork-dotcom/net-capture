<script>
  import { onMount, onDestroy } from 'svelte';
  import { invoke } from '@tauri-apps/api/tauri';
  import {
    alerts, alertCount, maxAlerts,
    loadAlerts, fetchNewAlerts, clearAlerts,
    startAlertPolling, stopAlertPolling,
    getPriorityColor, formatAlertTime,
    alertFilters, filteredAlerts,
  } from '../stores/alerts.js';
  import { selectedPacketNo, loadPacketDetail } from '../stores/packets.js';

  export let onSelectPacket = null;

  let priorityFilter = 'all';
  let ruleNameFilter = '';
  let timeRangeFilter = null;

  const timeRangeOptions = [
    { value: null, label: '全部' },
    { value: 300, label: '最近5分钟' },
    { value: 3600, label: '最近1小时' },
    { value: 86400, label: '最近24小时' },
  ];

  const priorityOptions = [
    { value: 'all', label: '全部优先级' },
    { value: 'high', label: '高优先级' },
    { value: 'medium', label: '中优先级' },
    { value: 'low', label: '低优先级' },
  ];

  function handleAlertClick(alert) {
    if (onSelectPacket) {
      onSelectPacket(alert.packet_no);
    } else {
      loadPacketDetail(alert.packet_no);
    }
  }

  function handleClearAlerts() {
    if (confirm('确定清空所有告警记录吗？')) {
      clearAlerts();
    }
  }

  function applyFilters() {
    alertFilters.set({
      priority: priorityFilter,
      ruleName: ruleNameFilter,
      timeRange: timeRangeFilter,
    });
  }

  $: {
    priorityFilter;
    ruleNameFilter;
    timeRangeFilter;
    applyFilters();
  }

  $: displayAlerts = computeFilteredAlerts($alerts, priorityFilter, ruleNameFilter, timeRangeFilter);

  function computeFilteredAlerts(allAlerts, priority, ruleName, timeRange) {
    let result = allAlerts;

    if (priority !== 'all') {
      result = result.filter(a => a.priority === priority);
    }

    if (ruleName && ruleName.trim()) {
      const search = ruleName.toLowerCase();
      result = result.filter(a => a.rule_name.toLowerCase().includes(search));
    }

    if (timeRange) {
      const now = Date.now() / 1000;
      result = result.filter(a => now - a.timestamp_secs <= timeRange);
    }

    return result;
  }

  onMount(() => {
    loadAlerts();
    startAlertPolling();
  });

  onDestroy(() => {
    stopAlertPolling();
  });
</script>

<div class="alerts-panel">
  <div class="alerts-toolbar">
    <div class="filter-group">
      <select bind:value={priorityFilter}>
        {#each priorityOptions as opt}
          <option value={opt.value}>{opt.label}</option>
        {/each}
      </select>

      <input
        type="text"
        bind:value={ruleNameFilter}
        placeholder="搜索规则名称..."
        class="search-input"
      />

      <select bind:value={timeRangeFilter}>
        {#each timeRangeOptions as opt}
          <option value={opt.value}>{opt.label}</option>
        {/each}
      </select>
    </div>

    <div class="toolbar-right">
      <span class="alert-count">
        共 {$alerts.length} 条告警
        <span class="filtered">{displayAlerts.length !== $alerts.length ? ` (显示 ${displayAlerts.length})` : ''}</span>
      </span>
      <button class="clear-btn" on:click={handleClearAlerts} title="清空告警">
        🗑️ 清空
      </button>
    </div>
  </div>

  <div class="alerts-list">
    {#if displayAlerts.length === 0}
      <div class="empty-state">
        <div class="empty-icon">🔔</div>
        <div class="empty-text">暂无告警记录</div>
        <div class="empty-hint">启用检测规则后，匹配的包将在此处显示</div>
      </div>
    {:else}
      {#each displayAlerts as alert (alert.id)}
        {@const priorityColor = getPriorityColor(alert.priority)}
        <div
          class="alert-item priority-{alert.priority} {alert.banned_hit ? 'banned-hit' : ''}"
          style="border-left-color: {priorityColor.border};"
          on:click={() => handleAlertClick(alert)}
        >
          <div class="alert-header">
            <span class="alert-time">{formatAlertTime(alert.timestamp_secs, alert.timestamp_micros)}</span>
            <div class="alert-header-badges">
              {#if alert.banned_hit}
                <span class="banned-badge">已封禁IP</span>
              {/if}
              <span
                class="priority-badge"
                style="background: {priorityColor.bg}; color: {priorityColor.text};"
              >
                {priorityColor.label}优先级
              </span>
            </div>
          </div>
          <div class="alert-title">
            <span class="rule-name">{alert.rule_name}</span>
            <span class="packet-no">#{alert.packet_no}</span>
          </div>
          <div class="alert-summary">{alert.match_summary}</div>
          <div class="alert-detail">
            <span class="proto-tag">{alert.protocol}</span>
            <span class="addr">{alert.src_addr} → {alert.dst_addr}</span>
          </div>
        </div>
      {/each}
    {/if}
  </div>
</div>

<style>
  .alerts-panel {
    display: flex;
    flex-direction: column;
    height: 100%;
    background: #1e1e1e;
    color: #e0e0e0;
    font-size: 12px;
  }

  .alerts-toolbar {
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
    gap: 10px;
    align-items: center;
  }

  .filter-group select,
  .search-input {
    padding: 6px 10px;
    background: #1e1e1e;
    color: #e0e0e0;
    border: 1px solid #444;
    border-radius: 4px;
    font-size: 12px;
  }

  .search-input {
    width: 200px;
  }

  .filter-group select:focus,
  .search-input:focus {
    outline: none;
    border-color: #4fc3f7;
  }

  .toolbar-right {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .alert-count {
    color: #888;
    font-size: 11px;
  }

  .alert-count .filtered {
    color: #4fc3f7;
  }

  .clear-btn {
    padding: 6px 12px;
    background: #3a3a3a;
    color: #ccc;
    border: 1px solid #555;
    border-radius: 4px;
    cursor: pointer;
    font-size: 11px;
  }

  .clear-btn:hover {
    background: #4a4a4a;
  }

  .alerts-list {
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

  .alert-item {
    padding: 12px 16px;
    border-bottom: 1px solid #2d2d2d;
    border-left: 3px solid transparent;
    cursor: pointer;
    transition: background 0.2s;
  }

  .alert-item:hover {
    background: #252525;
  }

  .alert-item.priority-high {
    background: rgba(239, 83, 80, 0.05);
  }

  .alert-item.priority-high:hover {
    background: rgba(239, 83, 80, 0.1);
  }

  .alert-item.priority-medium {
    background: rgba(255, 152, 0, 0.05);
  }

  .alert-item.priority-medium:hover {
    background: rgba(255, 152, 0, 0.1);
  }

  .alert-item.priority-low {
    background: rgba(255, 235, 59, 0.03);
  }

  .alert-item.priority-low:hover {
    background: rgba(255, 235, 59, 0.08);
  }

  .alert-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 6px;
  }

  .alert-header-badges {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .banned-badge {
    padding: 2px 6px;
    border-radius: 3px;
    font-size: 9px;
    font-weight: 600;
    background: rgba(239, 83, 80, 0.2);
    color: #ef5350;
    border: 1px solid rgba(239, 83, 80, 0.3);
  }

  .banned-hit .rule-name,
  .banned-hit .alert-summary,
  .banned-hit .alert-detail {
    text-decoration: line-through;
    opacity: 0.6;
  }

  .alert-time {
    font-family: monospace;
    font-size: 11px;
    color: #888;
  }

  .priority-badge {
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 10px;
    font-weight: 600;
  }

  .alert-title {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 6px;
  }

  .rule-name {
    font-size: 13px;
    font-weight: 600;
    color: #e0e0e0;
  }

  .packet-no {
    font-size: 11px;
    color: #666;
    font-family: monospace;
  }

  .alert-summary {
    font-size: 12px;
    color: #aaa;
    margin-bottom: 8px;
  }

  .alert-detail {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 11px;
  }

  .proto-tag {
    padding: 2px 6px;
    background: #3a3a3a;
    border-radius: 3px;
    color: #ccc;
    font-size: 10px;
    font-weight: 500;
  }

  .addr {
    color: #888;
    font-family: monospace;
  }
</style>
