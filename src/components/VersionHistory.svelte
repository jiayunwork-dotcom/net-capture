<script>
  import { createEventDispatcher } from 'svelte';
  import { getRuleVersions, rollbackRuleVersion, getNodeLabel } from '../stores/rules.js';
  import ConditionDiff from './ConditionDiff.svelte';

  export let ruleId = '';
  export let currentCondition = null;

  const dispatch = createEventDispatcher();

  let versions = [];
  let loading = true;
  let selectedVersions = [];
  let showDiff = false;
  let diffVersionA = null;
  let diffVersionB = null;
  let previewVersion = null;

  async function loadVersions() {
    loading = true;
    try {
      versions = await getRuleVersions(ruleId);
      if (versions) {
        versions = [...versions].reverse();
      }
    } catch (e) {
      console.error('Load versions error:', e);
    } finally {
      loading = false;
    }
  }

  loadVersions();

  function formatTime(timestamp) {
    if (!timestamp) return '-';
    const d = new Date(timestamp * 1000);
    return d.toLocaleString('zh-CN');
  }

  function toggleVersionSelect(version) {
    const idx = selectedVersions.findIndex(v => v.version === version.version);
    if (idx >= 0) {
      selectedVersions = selectedVersions.filter(v => v.version !== version.version);
    } else if (selectedVersions.length < 2) {
      selectedVersions = [...selectedVersions, version];
    } else {
      selectedVersions = [selectedVersions[1], version];
    }
  }

  function isSelected(version) {
    return selectedVersions.some(v => v.version === version.version);
  }

  function startDiff() {
    if (selectedVersions.length === 2) {
      diffVersionA = selectedVersions[0];
      diffVersionB = selectedVersions[1];
      showDiff = true;
    }
  }

  function preview(version) {
    previewVersion = version;
  }

  async function rollback(version) {
    if (!confirm(`确定回滚到版本 v${version.version} 吗？此操作将创建一个新版本，内容与回滚目标相同。`)) return;
    try {
      await rollbackRuleVersion(ruleId, version.version);
      dispatch('rollback');
      loadVersions();
    } catch (e) {
      alert('回滚失败: ' + e);
    }
  }

  function close() {
    dispatch('close');
  }
</script>

<div class="version-history-modal" on:click|self={close}>
  <div class="version-dialog">
    <div class="dialog-header">
      <h3>历史版本</h3>
      <button class="close-btn" on:click={close}>✕</button>
    </div>

    <div class="dialog-body">
      {#if loading}
        <div class="loading">加载中...</div>
      {:else if !versions || versions.length === 0}
        <div class="empty">暂无历史版本</div>
      {:else}
        <div class="version-toolbar">
          <span class="hint">选择两个版本进行差异对比</span>
          <button
            class="btn-primary"
            disabled={selectedVersions.length !== 2}
            on:click={startDiff}
          >
            差异对比
          </button>
        </div>

        <div class="version-list">
          <div class="version-header-row">
            <div class="col-select">选择</div>
            <div class="col-version">版本号</div>
            <div class="col-time">修改时间</div>
            <div class="col-summary">条件摘要</div>
            <div class="col-actions">操作</div>
          </div>
          {#each versions as v}
            <div class="version-row" class:selected={isSelected(v)}>
              <div class="col-select">
                <input
                  type="checkbox"
                  checked={isSelected(v)}
                  on:change={() => toggleVersionSelect(v)}
                />
              </div>
              <div class="col-version">v{v.version}</div>
              <div class="col-time">{formatTime(v.saved_at)}</div>
              <div class="col-summary" title={v.summary}>{v.summary}</div>
              <div class="col-actions">
                <button class="btn-small" on:click={() => preview(v)}>预览</button>
                <button class="btn-small rollback" on:click={() => rollback(v)}>回滚</button>
              </div>
            </div>
          {/each}
        </div>

        {#if previewVersion}
          <div class="preview-panel">
            <div class="preview-header">
              <span>版本 v{previewVersion.version} 预览</span>
              <button class="btn-small" on:click={() => previewVersion = null}>关闭</button>
            </div>
            <div class="preview-expression">
              <code>{previewVersion.expression || '(无表达式)'}</code>
            </div>
          </div>
        {/if}

        {#if showDiff && diffVersionA && diffVersionB}
          <div class="diff-panel">
            <div class="diff-header">
              <span>版本 v{diffVersionA.version} vs v{diffVersionB.version} 差异对比</span>
              <button class="btn-small" on:click={() => showDiff = false}>关闭</button>
            </div>
            <ConditionDiff
              nodeA={diffVersionA.condition}
              nodeB={diffVersionB.condition}
            />
          </div>
        {/if}
      {/if}
    </div>
  </div>
</div>

<style>
  .version-history-modal {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.7);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 2000;
  }

  .version-dialog {
    width: 800px;
    max-height: 85vh;
    background: #1e1e1e;
    border-radius: 8px;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  .dialog-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 14px 20px;
    background: #252525;
    border-bottom: 1px solid #3a3a3a;
  }

  .dialog-header h3 {
    margin: 0;
    font-size: 15px;
    color: #4fc3f7;
  }

  .close-btn {
    background: transparent;
    border: none;
    color: #888;
    cursor: pointer;
    font-size: 18px;
    padding: 4px 8px;
  }

  .close-btn:hover {
    color: #fff;
  }

  .dialog-body {
    flex: 1;
    overflow-y: auto;
    padding: 16px;
  }

  .loading, .empty {
    text-align: center;
    padding: 40px;
    color: #888;
  }

  .version-toolbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 12px;
  }

  .hint {
    font-size: 12px;
    color: #888;
  }

  .btn-primary {
    padding: 6px 14px;
    background: #1565c0;
    color: #fff;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 12px;
  }

  .btn-primary:hover:not(:disabled) {
    background: #1976d2;
  }

  .btn-primary:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }

  .version-list {
    border: 1px solid #3a3a3a;
    border-radius: 6px;
    overflow: hidden;
  }

  .version-header-row {
    display: flex;
    align-items: center;
    padding: 10px 12px;
    background: #2d2d2d;
    font-size: 11px;
    color: #888;
    text-transform: uppercase;
    font-weight: 500;
  }

  .version-row {
    display: flex;
    align-items: center;
    padding: 10px 12px;
    border-top: 1px solid #333;
    font-size: 12px;
    color: #ccc;
    transition: background 0.15s;
  }

  .version-row:hover {
    background: #2a2a2a;
  }

  .version-row.selected {
    background: rgba(79, 195, 247, 0.08);
    border-left: 3px solid #4fc3f7;
  }

  .col-select {
    width: 50px;
    text-align: center;
  }

  .col-version {
    width: 70px;
    font-weight: 500;
  }

  .col-time {
    width: 160px;
    color: #aaa;
    font-size: 11px;
  }

  .col-summary {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .col-actions {
    width: 120px;
    display: flex;
    gap: 6px;
    justify-content: flex-end;
  }

  .btn-small {
    padding: 3px 10px;
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

  .btn-small.rollback {
    color: #ff9800;
    border-color: #ff9800;
  }

  .btn-small.rollback:hover {
    background: rgba(255, 152, 0, 0.15);
  }

  .preview-panel {
    margin-top: 16px;
    border: 1px solid #444;
    border-radius: 6px;
    overflow: hidden;
  }

  .preview-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 8px 12px;
    background: #2d2d2d;
    font-size: 12px;
    color: #4fc3f7;
  }

  .preview-expression {
    padding: 12px;
    background: #1a1a1a;
  }

  .preview-expression code {
    font-family: monospace;
    font-size: 12px;
    color: #e0e0e0;
    white-space: pre-wrap;
    word-break: break-all;
  }

  .diff-panel {
    margin-top: 16px;
    border: 1px solid #444;
    border-radius: 6px;
    overflow: hidden;
  }

  .diff-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 8px 12px;
    background: #2d2d2d;
    font-size: 12px;
    color: #4fc3f7;
  }
</style>
