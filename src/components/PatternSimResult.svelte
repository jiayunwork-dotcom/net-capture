<script>
  import {
    patternSimResult,
    showPatternSimResult,
    closePatternSimResult,
  } from '../stores/attack_patterns.js';
  import { exportReplayResult } from '../stores/replay.js';

  function formatTimestamp(secs, micros) {
    if (!secs) return '-';
    try {
      const d = new Date(secs * 1000 + micros / 1000);
      return d.toLocaleTimeString() + '.' + String(micros).padStart(6, '0').slice(0, 3);
    } catch {
      return '-';
    }
  }

  async function handleExport() {
    if ($patternSimResult) {
      const ok = await exportReplayResult($patternSimResult);
      if (ok) alert('导出成功');
    }
  }
</script>

{#if $showPatternSimResult && $patternSimResult}
  <div class="sim-overlay" on:click={closePatternSimResult}>
    <div class="sim-dialog" on:click|stopPropagation>
      <div class="dialog-header">
        <h3>🎯 模拟流量检测结果</h3>
        <div class="header-actions">
          <button class="btn-export" on:click={handleExport}>📤 导出JSON</button>
          <button class="btn-close" on:click={closePatternSimResult}>✕</button>
        </div>
      </div>

      <div class="sim-body">
        <div class="sim-info">
          <div class="info-row">
            <span class="label">特征:</span>
            <span class="value highlight">{$patternSimResult.session_label}</span>
          </div>
          <div class="info-row">
            <span class="label">数据包数:</span>
            <span class="value">{$patternSimResult.processed_packets} / {$patternSimResult.total_packets}</span>
          </div>
          <div class="info-row">
            <span class="label">触发规则数:</span>
            <span class="value {$patternSimResult.matched_rules.length > 0 ? 'hit' : 'miss'}">
              {$patternSimResult.matched_rules.length}
            </span>
          </div>
          <div class="info-row">
            <span class="label">响应动作数:</span>
            <span class="value">{$patternSimResult.response_logs.length}</span>
          </div>
        </div>

        <div class="section">
          <h4>🚨 触发规则</h4>
          {#if $patternSimResult.matched_rules.length === 0}
            <div class="empty-state miss">
              ⚠️ 未触发任何规则 - 该攻击特征未被检测到
            </div>
          {:else}
            <table class="result-table">
              <thead>
                <tr>
                  <th>规则名称</th>
                  <th>触发次数</th>
                  <th>首次触发包</th>
                  <th>首次触发时间</th>
                </tr>
              </thead>
              <tbody>
                {#each $patternSimResult.matched_rules as rule}
                  <tr>
                    <td class="rule-name">{rule.rule_name}</td>
                    <td class="count">{rule.trigger_count}</td>
                    <td class="mono">#{rule.first_packet_no}</td>
                    <td>{formatTimestamp(rule.first_timestamp_secs, rule.first_timestamp_micros)}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          {/if}
        </div>

        <div class="section">
          <h4>⚡ 响应动作</h4>
          {#if $patternSimResult.response_logs.length === 0}
            <div class="empty-state">无响应动作执行</div>
          {:else}
            <table class="result-table">
              <thead>
                <tr>
                  <th>规则</th>
                  <th>动作类型</th>
                  <th>结果</th>
                  <th>详情</th>
                </tr>
              </thead>
              <tbody>
                {#each $patternSimResult.response_logs as log}
                  <tr>
                    <td class="rule-name">{log.rule_name}</td>
                    <td><span class="action-tag">{log.action_type}</span></td>
                    <td><span class="result-tag">{log.result}</span></td>
                    <td class="detail">{log.detail || '-'}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          {/if}
        </div>
      </div>
    </div>
  </div>
{/if}

<style>
  .sim-overlay {
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(0,0,0,0.7);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 3000;
  }
  .sim-dialog {
    background: #2d2d2d;
    border: 1px solid #555;
    border-radius: 8px;
    width: 800px;
    max-width: 95vw;
    max-height: 85vh;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    box-shadow: 0 8px 32px rgba(0,0,0,0.6);
  }
  .dialog-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 12px 18px;
    background: #1e1e1e;
    border-bottom: 1px solid #444;
  }
  .dialog-header h3 {
    margin: 0;
    color: #eee;
    font-size: 15px;
  }
  .header-actions { display: flex; gap: 8px; }
  .btn-close, .btn-export {
    background: transparent;
    border: none;
    color: #888;
    cursor: pointer;
    padding: 4px 10px;
    border-radius: 4px;
  }
  .btn-close { font-size: 16px; }
  .btn-close:hover { background: #444; color: #eee; }
  .btn-export {
    background: #1565c0;
    color: #fff;
    font-size: 12px;
  }
  .btn-export:hover { background: #1976d2; }
  .sim-body {
    flex: 1;
    overflow-y: auto;
    padding: 16px 20px;
  }
  .sim-info {
    display: flex;
    flex-wrap: wrap;
    gap: 16px;
    background: #1e1e1e;
    padding: 12px 16px;
    border-radius: 6px;
    margin-bottom: 16px;
  }
  .info-row {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .info-row .label { color: #888; font-size: 12px; }
  .info-row .value { color: #ddd; font-size: 13px; font-weight: 500; }
  .info-row .value.highlight { color: #4fc3f7; }
  .info-row .value.hit { color: #ef5350; font-size: 16px; }
  .info-row .value.miss { color: #66bb6a; }
  .section { margin-bottom: 18px; }
  .section h4 {
    margin: 0 0 8px 0;
    color: #bbb;
    font-size: 13px;
  }
  .result-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }
  .result-table th {
    text-align: left;
    padding: 8px 10px;
    background: #333;
    color: #aaa;
    font-weight: 500;
    border-bottom: 1px solid #444;
  }
  .result-table td {
    padding: 7px 10px;
    border-bottom: 1px solid #333;
    color: #ccc;
  }
  .rule-name { color: #fff; font-weight: 500; }
  .count { color: #ffb74d; font-weight: 600; }
  .mono { font-family: monospace; }
  .empty-state {
    padding: 20px;
    text-align: center;
    color: #888;
    background: #1e1e1e;
    border-radius: 4px;
    font-size: 13px;
  }
  .empty-state.miss {
    background: #3e1e1e;
    color: #ef9a9a;
  }
  .action-tag {
    display: inline-block;
    padding: 2px 8px;
    background: #4a148c;
    color: #ce93d8;
    border-radius: 3px;
    font-size: 11px;
    text-transform: uppercase;
  }
  .result-tag {
    display: inline-block;
    padding: 2px 8px;
    background: #1b5e20;
    color: #a5d6a7;
    border-radius: 3px;
    font-size: 11px;
  }
  .detail {
    color: #888;
    font-size: 11px;
    max-width: 300px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
</style>
