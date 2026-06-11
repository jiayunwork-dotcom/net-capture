<script>
  import { onMount } from 'svelte';
  import {
    banEntries, loadBanEntries, unbanIp, cleanupExpiredBans, clearAllBans,
    formatBanTime, isBanExpired,
  } from '../stores/response.js';

  function handleUnban(ip) {
    if (!confirm(`确定解封 IP "${ip}" 吗？`)) return;
    unbanIp(ip);
  }

  function handleCleanup() {
    cleanupExpiredBans().then(count => {
      if (count > 0) {
        alert(`已清理 ${count} 条过期封禁`);
      } else {
        alert('没有过期的封禁条目');
      }
    });
  }

  function handleClearAll() {
    if (!confirm('确定清空所有封禁条目吗？此操作不可撤销！')) return;
    clearAllBans();
  }

  onMount(() => {
    loadBanEntries();
  });
</script>

<div class="ban-list-panel">
  <div class="toolbar">
    <div class="toolbar-left">
      <span class="entry-count">共 {$banEntries.length} 条封禁</span>
    </div>
    <div class="toolbar-right">
      <button class="btn-small" on:click={loadBanEntries}>刷新</button>
      <button class="btn-small" on:click={handleCleanup}>清理过期</button>
      <button class="btn-small danger" on:click={handleClearAll}>清空全部</button>
    </div>
  </div>

  <div class="ban-list">
    {#if $banEntries.length === 0}
      <div class="empty-state">
        <div class="empty-icon">🛡️</div>
        <div class="empty-text">封禁列表为空</div>
        <div class="empty-hint">通过IP封禁响应动作或手动添加封禁IP</div>
      </div>
    {:else}
      <table class="ban-table">
        <thead>
          <tr>
            <th>IP地址</th>
            <th>封禁时间</th>
            <th>关联规则</th>
            <th>过期</th>
            <th>状态</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          {#each $banEntries as entry (entry.ip)}
            {@const expired = isBanExpired(entry)}
            <tr class:expired-row={expired}>
              <td class="ip-addr">{entry.ip}</td>
              <td class="ban-time">{formatBanTime(entry.ban_time)}</td>
              <td class="rule-name">{entry.rule_name}</td>
              <td class="expire">
                {entry.expire_minutes === 0 ? '永久' : `${entry.expire_minutes}分钟`}
              </td>
              <td class="status">
                {#if expired}
                  <span class="status-badge expired">已过期</span>
                {:else}
                  <span class="status-badge active">封禁中</span>
                {/if}
              </td>
              <td class="actions">
                <button class="btn-unban" on:click={() => handleUnban(entry.ip)}>解封</button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </div>
</div>

<style>
  .ban-list-panel {
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

  .toolbar-left, .toolbar-right {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .entry-count {
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

  .ban-list {
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

  .ban-table {
    width: 100%;
    border-collapse: collapse;
  }

  .ban-table thead {
    position: sticky;
    top: 0;
    z-index: 1;
  }

  .ban-table th {
    background: #252525;
    padding: 8px 12px;
    text-align: left;
    font-size: 11px;
    color: #888;
    font-weight: 600;
    border-bottom: 1px solid #3a3a3a;
    text-transform: uppercase;
  }

  .ban-table td {
    padding: 8px 12px;
    border-bottom: 1px solid #2d2d2d;
    font-size: 12px;
  }

  .ban-table tr:hover {
    background: #252525;
  }

  .expired-row {
    opacity: 0.5;
  }

  .ip-addr {
    font-family: monospace;
    color: #e0e0e0;
    font-weight: 500;
  }

  .ban-time {
    font-family: monospace;
    color: #888;
    font-size: 11px;
  }

  .rule-name {
    color: #4fc3f7;
  }

  .expire {
    color: #aaa;
  }

  .status-badge {
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 10px;
    font-weight: 600;
  }

  .status-badge.active {
    background: rgba(239, 83, 80, 0.15);
    color: #ef5350;
  }

  .status-badge.expired {
    background: rgba(136, 136, 136, 0.15);
    color: #888;
  }

  .btn-unban {
    padding: 3px 8px;
    background: #3a3a3a;
    color: #4fc3f7;
    border: 1px solid #4fc3f7;
    border-radius: 3px;
    cursor: pointer;
    font-size: 10px;
  }

  .btn-unban:hover {
    background: rgba(79, 195, 247, 0.15);
  }
</style>
