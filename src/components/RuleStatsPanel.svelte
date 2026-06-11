<script>
  import { rules, ruleStats, ruleGroups } from '../stores/rules.js';

  let sortBy = 'total_triggers';
  let sortDir = 'desc';

  function formatTime(ts) {
    if (!ts) return '-';
    const d = new Date(ts * 1000);
    return d.toLocaleString('zh-CN');
  }

  function getRuleName(ruleId) {
    const rule = $rules.find(r => r.id === ruleId);
    return rule ? rule.name : ruleId;
  }

  function getRuleGroup(ruleId) {
    const rule = $rules.find(r => r.id === ruleId);
    if (!rule || !rule.group) return '未分组';
    const group = $ruleGroups.find(g => g.id === rule.group);
    return group ? group.name : '未分组';
  }

  function calcFrequency(stat) {
    if (!stat.first_trigger_time || !stat.last_trigger_time) return 0;
    const duration = stat.last_trigger_time - stat.first_trigger_time;
    if (duration === 0) return stat.total_triggers;
    return (stat.total_triggers / duration * 60).toFixed(2);
  }

  $: sortedStats = [...$ruleStats].sort((a, b) => {
    let va, vb;
    switch (sortBy) {
      case 'total_triggers':
        va = a.total_triggers;
        vb = b.total_triggers;
        break;
      case 'last_trigger_time':
        va = a.last_trigger_time || 0;
        vb = b.last_trigger_time || 0;
        break;
      case 'frequency':
        va = parseFloat(calcFrequency(a));
        vb = parseFloat(calcFrequency(b));
        break;
      default:
        va = a.total_triggers;
        vb = b.total_triggers;
    }
    return sortDir === 'desc' ? vb - va : va - vb;
  });

  function toggleSort(field) {
    if (sortBy === field) {
      sortDir = sortDir === 'desc' ? 'asc' : 'desc';
    } else {
      sortBy = field;
      sortDir = 'desc';
    }
  }

  function getSortIcon(field) {
    if (sortBy !== field) return '↕';
    return sortDir === 'desc' ? '↓' : '↑';
  }
</script>

<div class="stats-panel">
  <div class="stats-table">
    <div class="table-header">
      <div class="col-name">规则名称</div>
      <div class="col-group">分组</div>
      <div class="col sortable" on:click={() => toggleSort('total_triggers')}>
        总触发 {getSortIcon('total_triggers')}
      </div>
      <div class="col">24h触发</div>
      <div class="col sortable" on:click={() => toggleSort('last_trigger_time')}>
        最近触发 {getSortIcon('last_trigger_time')}
      </div>
      <div class="col sortable" on:click={() => toggleSort('frequency')}>
        次/分钟 {getSortIcon('frequency')}
      </div>
    </div>

    {#each sortedStats as stat}
      <div class="table-row">
        <div class="col-name">{getRuleName(stat.rule_id)}</div>
        <div class="col-group">{getRuleGroup(stat.rule_id)}</div>
        <div class="col total">{stat.total_triggers}</div>
        <div class="col">{stat.last_24h_triggers}</div>
        <div class="col time">{formatTime(stat.last_trigger_time)}</div>
        <div class="col freq">{calcFrequency(stat)}</div>
      </div>
    {/each}

    {#if sortedStats.length === 0}
      <div class="empty-state">
        <div class="empty-text">暂无触发统计数据</div>
        <div class="empty-hint">规则触发告警后将在此显示统计信息</div>
      </div>
    {/if}
  </div>
</div>

<style>
  .stats-panel {
    display: flex;
    flex-direction: column;
    height: 100%;
  }

  .stats-table {
    border: 1px solid #3a3a3a;
    border-radius: 6px;
    overflow: hidden;
  }

  .table-header {
    display: flex;
    align-items: center;
    padding: 10px 12px;
    background: #2d2d2d;
    font-size: 11px;
    color: #888;
    text-transform: uppercase;
    font-weight: 500;
    border-bottom: 1px solid #3a3a3a;
  }

  .table-row {
    display: flex;
    align-items: center;
    padding: 10px 12px;
    border-bottom: 1px solid #2d2d2d;
    font-size: 12px;
    color: #ccc;
    transition: background 0.15s;
  }

  .table-row:hover {
    background: #2a2a2a;
  }

  .col {
    width: 90px;
    text-align: center;
  }

  .col.sortable {
    cursor: pointer;
    user-select: none;
  }

  .col.sortable:hover {
    color: #4fc3f7;
  }

  .col-name {
    flex: 2;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .col-group {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: #888;
  }

  .col.total {
    color: #4fc3f7;
    font-weight: 500;
  }

  .col.time {
    color: #aaa;
    font-size: 11px;
  }

  .col.freq {
    color: #ff9800;
    font-weight: 500;
  }

  .empty-state {
    text-align: center;
    padding: 40px 20px;
    color: #666;
  }

  .empty-text {
    font-size: 14px;
    margin-bottom: 6px;
    color: #888;
  }

  .empty-hint {
    font-size: 12px;
  }
</style>
