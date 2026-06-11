<script>
  import {
    effectivenessReport,
    showEffectivenessReport,
    closeEffectivenessReport,
    exportEffectivenessReport,
  } from '../stores/attack_patterns.js';

  function formatRate(rate) {
    return (rate * 100).toFixed(1) + '%';
  }

  function formatTime(ts) {
    if (!ts) return '-';
    try {
      return new Date(ts * 1000).toLocaleString();
    } catch {
      return '-';
    }
  }

  async function handleExport() {
    if ($effectivenessReport) {
      const ok = await exportEffectivenessReport($effectivenessReport);
      if (ok) alert('导出成功');
    }
  }
</script>

{#if $showEffectivenessReport && $effectivenessReport}
  <div class="report-overlay" on:click={closeEffectivenessReport}>
    <div class="report-dialog" on:click|stopPropagation>
      <div class="dialog-header">
        <h3>📊 规则有效性报告</h3>
        <div class="header-actions">
          <button class="btn-export" on:click={handleExport}>📤 导出JSON</button>
          <button class="btn-close" on:click={closeEffectivenessReport}>✕</button>
        </div>
      </div>

      <div class="report-summary">
        <div class="summary-item">
          <span class="label">生成时间</span>
          <span class="value">{formatTime($effectivenessReport.generated_at)}</span>
        </div>
        <div class="summary-item">
          <span class="label">攻击特征数</span>
          <span class="value">{$effectivenessReport.total_patterns}</span>
        </div>
        <div class="summary-item success">
          <span class="label">已检测到</span>
          <span class="value">{$effectivenessReport.detected_count}</span>
        </div>
        <div class="summary-item danger">
          <span class="label">未检测到</span>
          <span class="value">{$effectivenessReport.undetected_count}</span>
        </div>
        <div class="summary-item highlight {$effectivenessReport.detection_rate < 0.8 ? 'warn' : ''}">
          <span class="label">检测率</span>
          <span class="value">{formatRate($effectivenessReport.detection_rate)}</span>
        </div>
      </div>

      <div class="report-table-wrapper">
        <table class="report-table">
          <thead>
            <tr>
              <th style="width: 100px;">状态</th>
              <th>攻击特征名称</th>
              <th style="width: 100px;">分类</th>
              <th>命中规则</th>
              <th style="width: 80px;">响应触发</th>
              <th style="width: 80px;">数据包</th>
            </tr>
          </thead>
          <tbody>
            {#each $effectivenessReport.items as item}
              <tr class:missed={!item.is_detected}>
                <td>
                  {#if item.is_detected}
                    <span class="status-badge hit">✅ 命中</span>
                  {:else}
                    <span class="status-badge miss">❌ 未命中</span>
                  {/if}
                </td>
                <td class="pattern-name">{item.pattern_name}</td>
                <td>{item.pattern_category}</td>
                <td>
                  {#if item.matched_rule_names.length === 0}
                    <span class="no-rules">无</span>
                  {:else}
                    <div class="rule-tags">
                      {#each item.matched_rule_names as rn}
                        <span class="rule-tag">{rn}</span>
                      {/each}
                    </div>
                  {/if}
                </td>
                <td>
                  {#if item.response_triggered}
                    <span class="yes">✅</span>
                    <div class="resp-tags">
                      {#each item.response_actions as ra}
                        <span class="resp-tag">{ra}</span>
                      {/each}
                    </div>
                  {:else}
                    <span class="no">❌</span>
                  {/if}
                </td>
                <td class="mono">{item.total_packets}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>

      {#if $effectivenessReport.undetected_count > 0}
        <div class="warning-banner">
          ⚠️ 有 <b>{$effectivenessReport.undetected_count}</b> 个攻击特征未被检测到，建议补充相关检测规则。
        </div>
      {/if}
    </div>
  </div>
{/if}

<style>
  .report-overlay {
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(0,0,0,0.7);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 3000;
  }
  .report-dialog {
    background: #2d2d2d;
    border: 1px solid #555;
    border-radius: 8px;
    width: 1000px;
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
  .header-actions {
    display: flex;
    gap: 8px;
  }
  .btn-close, .btn-export {
    background: transparent;
    border: none;
    color: #888;
    font-size: 16px;
    cursor: pointer;
    padding: 4px 10px;
    border-radius: 4px;
  }
  .btn-close:hover { background: #444; color: #eee; }
  .btn-export {
    background: #1565c0;
    color: #fff;
    font-size: 12px;
  }
  .btn-export:hover { background: #1976d2; }
  .report-summary {
    display: flex;
    gap: 12px;
    padding: 14px 18px;
    background: #252525;
    border-bottom: 1px solid #444;
    flex-wrap: wrap;
  }
  .summary-item {
    background: #1e1e1e;
    padding: 10px 14px;
    border-radius: 6px;
    border: 1px solid #3a3a3a;
    min-width: 120px;
  }
  .summary-item.success { border-color: #4caf50; }
  .summary-item.danger { border-color: #f44336; }
  .summary-item.highlight { border-color: #ff9800; }
  .summary-item.highlight.warn { border-color: #f44336; }
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
  .summary-item.success .value { color: #81c784; }
  .summary-item.danger .value { color: #e57373; }
  .summary-item.highlight .value { color: #ffb74d; }
  .summary-item.highlight.warn .value { color: #e57373; }
  .report-table-wrapper {
    flex: 1;
    overflow-y: auto;
    padding: 14px 18px;
  }
  .report-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }
  .report-table th {
    text-align: left;
    padding: 10px 12px;
    background: #333;
    color: #aaa;
    font-weight: 500;
    border-bottom: 1px solid #444;
    position: sticky;
    top: 0;
    z-index: 2;
  }
  .report-table td {
    padding: 10px 12px;
    border-bottom: 1px solid #333;
    color: #ccc;
    vertical-align: top;
  }
  .report-table tr.missed {
    background: rgba(244, 67, 54, 0.08);
  }
  .report-table tr.missed td {
    border-bottom-color: rgba(244, 67, 54, 0.2);
  }
  .pattern-name {
    color: #fff;
    font-weight: 500;
  }
  .mono { font-family: monospace; text-align: center; }
  .status-badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 600;
  }
  .status-badge.hit { background: #1b5e20; color: #a5d6a7; }
  .status-badge.miss { background: #b71c1c; color: #ef9a9a; }
  .rule-tags, .resp-tags {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    margin-top: 2px;
  }
  .rule-tag {
    background: #1565c0;
    color: #90caf9;
    padding: 1px 6px;
    border-radius: 3px;
    font-size: 11px;
  }
  .resp-tag {
    background: #4a148c;
    color: #ce93d8;
    padding: 1px 6px;
    border-radius: 3px;
    font-size: 10px;
    text-transform: uppercase;
  }
  .no-rules { color: #888; font-style: italic; }
  .yes { color: #4caf50; }
  .no { color: #f44336; }
  .warning-banner {
    background: #4a2c00;
    color: #ffcc80;
    padding: 12px 18px;
    border-top: 1px solid #5d3a00;
    font-size: 13px;
  }
  .warning-banner b { color: #ffab40; }
</style>
