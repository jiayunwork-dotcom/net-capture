<script>
  import {
    showReplayResult,
    replayResults,
    replayBatchSummary,
    closeReplayResult,
    exportReplayResult,
    exportBatchSummary,
  } from '../stores/replay.js';

  let selectedSessionIndex = 0;

  $: currentResult = $replayResults && $replayResults[selectedSessionIndex]
    ? $replayResults[selectedSessionIndex]
    : null;

  function formatTimestamp(secs, micros) {
    if (!secs) return '-';
    try {
      const d = new Date(secs * 1000 + micros / 1000);
      return d.toLocaleTimeString() + '.' + String(micros).padStart(6, '0').slice(0, 3);
    } catch {
      return '-';
    }
  }

  function formatDuration(start, end) {
    const ms = (end - start) * 1000;
    if (ms < 1000) return ms + 'ms';
    if (ms < 60000) return (ms / 1000).toFixed(2) + 's';
    return (ms / 60000).toFixed(2) + 'm';
  }

  async function handleExportSession() {
    if (currentResult) {
      const ok = await exportReplayResult(currentResult);
      if (ok) alert('导出成功');
    }
  }

  async function handleExportBatch() {
    if ($replayBatchSummary) {
      const ok = await exportBatchSummary($replayBatchSummary);
      if (ok) alert('导出成功');
    }
  }
</script>

{#if $showReplayResult && $replayBatchSummary}
  <div class="replay-overlay" on:click={closeReplayResult}>
    <div class="replay-dialog" on:click|stopPropagation>
      <div class="dialog-header">
        <h3>🎬 流量回放结果</h3>
        <button class="btn-close" on:click={closeReplayResult}>✕</button>
      </div>

      <div class="summary-section">
        <h4>📊 汇总统计</h4>
        <div class="summary-grid">
          <div class="summary-item">
            <span class="label">会话总数</span>
            <span class="value">{$replayBatchSummary.session_count}</span>
          </div>
          <div class="summary-item">
            <span class="label">总数据包数</span>
            <span class="value">{$replayBatchSummary.total_packets}</span>
          </div>
          <div class="summary-item highlight">
            <span class="label">触发规则数</span>
            <span class="value">{$replayBatchSummary.total_matched_rules}</span>
          </div>
          <div class="summary-item highlight">
            <span class="label">响应动作数</span>
            <span class="value">{$replayBatchSummary.total_response_actions}</span>
          </div>
          <div class="summary-item success">
            <span class="label">命中会话</span>
            <span class="value">{$replayBatchSummary.sessions_with_hits.length}</span>
          </div>
          <div class="summary-item warn">
            <span class="label">未命中会话</span>
            <span class="value">{$replayBatchSummary.sessions_without_hits.length}</span>
          </div>
        </div>
        <button class="btn-export" on:click={handleExportBatch}>📤 导出汇总JSON</button>
      </div>

      {#if $replayResults && $replayResults.length > 0}
        <div class="session-tabs">
          {#each $replayResults as result, idx}
            <button
              class="session-tab"
              class:active={idx === selectedSessionIndex}
              class:has-hit={result.matched_rules.length > 0}
              on:click={() => selectedSessionIndex = idx}
              title={result.session_label}
            >
              {result.matched_rules.length > 0 ? '🔴' : '⚪'}
              会话{idx + 1}
              <span class="tab-count">({result.matched_rules.length})</span>
            </button>
          {/each}
        </div>

        {#if currentResult}
          <div class="session-detail">
            <div class="session-info">
              <div class="info-row">
                <span class="label">会话标签:</span>
                <span class="value mono">{currentResult.session_label}</span>
              </div>
              <div class="info-row">
                <span class="label">数据包数:</span>
                <span class="value">{currentResult.processed_packets} / {currentResult.total_packets}</span>
              </div>
              <div class="info-row">
                <span class="label">耗时:</span>
                <span class="value">{formatDuration(currentResult.started_at, currentResult.finished_at)}</span>
              </div>
              <button class="btn-export-small" on:click={handleExportSession}>📤 导出JSON</button>
            </div>

            <div class="rules-section">
              <h5>🚨 触发规则 ({currentResult.matched_rules.length})</h5>
              {#if currentResult.matched_rules.length === 0}
                <div class="empty-state">未触发任何规则</div>
              {:else}
                <table class="rules-table">
                  <thead>
                    <tr>
                      <th>规则名称</th>
                      <th>触发次数</th>
                      <th>首次触发包编号</th>
                      <th>首次触发时间</th>
                    </tr>
                  </thead>
                  <tbody>
                    {#each currentResult.matched_rules as rule}
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

            <div class="response-section">
              <h5>⚡ 响应动作 ({currentResult.response_logs.length})</h5>
              {#if currentResult.response_logs.length === 0}
                <div class="empty-state">无响应动作执行</div>
              {:else}
                <table class="response-table">
                  <thead>
                    <tr>
                      <th>规则</th>
                      <th>动作类型</th>
                      <th>结果</th>
                      <th>详情</th>
                    </tr>
                  </thead>
                  <tbody>
                    {#each currentResult.response_logs as log}
                      <tr>
                        <td class="rule-name">{log.rule_name}</td>
                        <td><span class="action-badge">{log.action_type}</span></td>
                        <td><span class="result-badge">{log.result}</span></td>
                        <td class="detail">{log.detail || '-'}</td>
                      </tr>
                    {/each}
                  </tbody>
                </table>
              {/if}
            </div>
          </div>
        {/if}
      {/if}
    </div>
  </div>
{/if}

<style>
  .replay-overlay {
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(0,0,0,0.7);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 3000;
  }
  .replay-dialog {
    background: #2d2d2d;
    border: 1px solid #555;
    border-radius: 8px;
    width: 900px;
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
  .btn-close {
    background: transparent;
    border: none;
    color: #888;
    font-size: 18px;
    cursor: pointer;
    padding: 4px 8px;
    border-radius: 4px;
  }
  .btn-close:hover {
    background: #444;
    color: #eee;
  }
  .summary-section {
    padding: 14px 18px;
    border-bottom: 1px solid #444;
    background: #252525;
  }
  .summary-section h4 {
    margin: 0 0 10px 0;
    color: #ccc;
    font-size: 13px;
  }
  .summary-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 10px;
    margin-bottom: 12px;
  }
  .summary-item {
    background: #1e1e1e;
    padding: 10px 12px;
    border-radius: 6px;
    border: 1px solid #3a3a3a;
  }
  .summary-item.highlight { border-color: #ff9800; }
  .summary-item.success { border-color: #4caf50; }
  .summary-item.warn { border-color: #f44336; }
  .summary-item .label {
    display: block;
    color: #888;
    font-size: 11px;
    margin-bottom: 4px;
  }
  .summary-item .value {
    display: block;
    color: #fff;
    font-size: 18px;
    font-weight: 600;
  }
  .summary-item.highlight .value { color: #ffb74d; }
  .summary-item.success .value { color: #81c784; }
  .summary-item.warn .value { color: #e57373; }
  .btn-export, .btn-export-small {
    background: #1565c0;
    color: #fff;
    border: none;
    border-radius: 4px;
    padding: 6px 14px;
    cursor: pointer;
    font-size: 12px;
  }
  .btn-export:hover { background: #1976d2; }
  .btn-export-small {
    padding: 4px 10px;
    font-size: 11px;
  }
  .session-tabs {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    padding: 10px 18px;
    background: #333;
    border-bottom: 1px solid #444;
  }
  .session-tab {
    background: #2a2a2a;
    color: #aaa;
    border: 1px solid #444;
    border-radius: 4px;
    padding: 6px 10px;
    cursor: pointer;
    font-size: 12px;
  }
  .session-tab:hover { background: #353535; color: #ccc; }
  .session-tab.active {
    background: #1565c0;
    color: #fff;
    border-color: #1976d2;
  }
  .session-tab.has-hit:not(.active) {
    border-color: #ef5350;
  }
  .tab-count {
    opacity: 0.7;
    font-size: 11px;
  }
  .session-detail {
    padding: 14px 18px;
    overflow-y: auto;
    flex: 1;
  }
  .session-info {
    display: flex;
    flex-wrap: wrap;
    gap: 16px;
    align-items: center;
    background: #1e1e1e;
    padding: 10px 14px;
    border-radius: 6px;
    margin-bottom: 14px;
  }
  .info-row {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .info-row .label {
    color: #888;
    font-size: 12px;
  }
  .info-row .value {
    color: #ddd;
    font-size: 13px;
  }
  .mono { font-family: 'Menlo', monospace; }
  .rules-section, .response-section {
    margin-bottom: 16px;
  }
  .rules-section h5, .response-section h5 {
    margin: 0 0 8px 0;
    color: #bbb;
    font-size: 13px;
  }
  .rules-table, .response-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }
  .rules-table th, .response-table th {
    text-align: left;
    padding: 8px 10px;
    background: #333;
    color: #aaa;
    font-weight: 500;
    border-bottom: 1px solid #444;
  }
  .rules-table td, .response-table td {
    padding: 7px 10px;
    border-bottom: 1px solid #333;
    color: #ccc;
  }
  .rule-name {
    color: #fff;
    font-weight: 500;
  }
  .count {
    color: #ffb74d;
    font-weight: 600;
  }
  .empty-state {
    padding: 20px;
    text-align: center;
    color: #666;
    background: #1e1e1e;
    border-radius: 4px;
    font-size: 13px;
  }
  .action-badge {
    display: inline-block;
    padding: 2px 8px;
    background: #4a148c;
    color: #ce93d8;
    border-radius: 3px;
    font-size: 11px;
    text-transform: uppercase;
  }
  .result-badge {
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
