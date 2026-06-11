<script>
  import { diffConditionTrees, getNodeLabel } from '../stores/rules.js';

  export let nodeA = null;
  export let nodeB = null;

  $: diffResult = diffConditionTrees(nodeA, nodeB);

  function getStatusClass(status) {
    switch (status) {
      case 'added': return 'diff-added';
      case 'removed': return 'diff-removed';
      case 'modified': return 'diff-modified';
      default: return 'diff-unchanged';
    }
  }

  function getStatusIcon(status) {
    switch (status) {
      case 'added': return '+';
      case 'removed': return '-';
      case 'modified': return '~';
      default: return ' ';
    }
  }

  function getStatusLabel(status) {
    switch (status) {
      case 'added': return '新增';
      case 'removed': return '删除';
      case 'modified': return '修改';
      default: return '';
    }
  }
</script>

<div class="condition-diff">
  <div class="diff-container">
    <div class="diff-side">
      <div class="side-label">版本 A</div>
      <div class="tree-view">
        {#if diffResult}
          <svelte:self diffNode={diffResult} side="a" depth={0} />
        {:else}
          <div class="no-data">无数据</div>
        {/if}
      </div>
    </div>
    <div class="diff-divider" />
    <div class="diff-side">
      <div class="side-label">版本 B</div>
      <div class="tree-view">
        {#if diffResult}
          <svelte:self diffNode={diffResult} side="b" depth={0} />
        {:else}
          <div class="no-data">无数据</div>
        {/if}
      </div>
    </div>
  </div>

  <div class="diff-legend">
    <span class="legend-item added">+ 新增</span>
    <span class="legend-item removed">- 删除</span>
    <span class="legend-item modified">~ 修改</span>
    <span class="legend-item unchanged">  未变</span>
  </div>
</div>

{#if diffResult}
  <div class="diff-tree">
    {#each flattenDiff(diffResult) as item}
      <div class="diff-row {getStatusClass(item.status)}" style="padding-left: {item.depth * 20 + 12}px;">
        <span class="diff-icon">{getStatusIcon(item.status)}</span>
        <span class="diff-label">{item.label}</span>
        {#if item.status === 'modified' && item.labelA !== item.labelB}
          <span class="diff-detail">{item.labelA} → {item.labelB}</span>
        {/if}
        {#if item.status !== 'unchanged'}
          <span class="diff-badge {getStatusClass(item.status)}">{getStatusLabel(item.status)}</span>
        {/if}
      </div>
    {/each}
  </div>
{/if}

<script context="module">
  function flattenDiff(diffNode, depth = 0) {
    if (!diffNode) return [];
    const result = [];
    const node = diffNode.node || diffNode.nodeB;
    const nodeA = diffNode.nodeA;
    const nodeB = diffNode.nodeB;

    let label = '';
    let labelA = '';
    let labelB = '';

    if (diffNode.status === 'added' && node) {
      label = getNodeLabel(node);
    } else if (diffNode.status === 'removed' && node) {
      label = getNodeLabel(node);
    } else if (diffNode.status === 'modified') {
      labelA = nodeA ? getNodeLabel(nodeA) : '';
      labelB = nodeB ? getNodeLabel(nodeB) : '';
      label = labelB || labelA;
    } else if (node) {
      label = getNodeLabel(node);
    }

    result.push({ status: diffNode.status, label, labelA, labelB, depth });

    if (diffNode.children) {
      for (const child of diffNode.children) {
        result.push(...flattenDiff(child, depth + 1));
      }
    }

    return result;
  }
</script>

<style>
  .condition-diff {
    display: flex;
    flex-direction: column;
  }

  .diff-container {
    display: flex;
    min-height: 200px;
  }

  .diff-side {
    flex: 1;
    overflow: auto;
  }

  .side-label {
    padding: 6px 12px;
    background: #2d2d2d;
    font-size: 11px;
    color: #888;
    text-transform: uppercase;
    font-weight: 500;
    border-bottom: 1px solid #3a3a3a;
  }

  .diff-divider {
    width: 1px;
    background: #3a3a3a;
  }

  .tree-view {
    padding: 8px;
    font-size: 12px;
  }

  .no-data {
    text-align: center;
    color: #666;
    padding: 20px;
  }

  .diff-legend {
    display: flex;
    gap: 16px;
    padding: 8px 12px;
    background: #252525;
    border-top: 1px solid #3a3a3a;
    font-size: 11px;
  }

  .legend-item {
    display: flex;
    align-items: center;
    gap: 4px;
  }

  .legend-item.added {
    color: #4caf50;
  }

  .legend-item.removed {
    color: #ef5350;
  }

  .legend-item.modified {
    color: #ff9800;
  }

  .legend-item.unchanged {
    color: #888;
  }

  .diff-tree {
    margin-top: 12px;
    border: 1px solid #3a3a3a;
    border-radius: 6px;
    overflow: hidden;
  }

  .diff-row {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 12px;
    font-size: 12px;
    border-bottom: 1px solid #2d2d2d;
    color: #ccc;
  }

  .diff-row:hover {
    background: #2a2a2a;
  }

  .diff-row.diff-added {
    background: rgba(76, 175, 80, 0.08);
    border-left: 3px solid #4caf50;
  }

  .diff-row.diff-removed {
    background: rgba(239, 83, 80, 0.08);
    border-left: 3px solid #ef5350;
  }

  .diff-row.diff-modified {
    background: rgba(255, 152, 0, 0.08);
    border-left: 3px solid #ff9800;
  }

  .diff-icon {
    width: 16px;
    text-align: center;
    font-weight: bold;
    font-family: monospace;
  }

  .diff-added .diff-icon {
    color: #4caf50;
  }

  .diff-removed .diff-icon {
    color: #ef5350;
  }

  .diff-modified .diff-icon {
    color: #ff9800;
  }

  .diff-label {
    flex: 1;
  }

  .diff-detail {
    color: #888;
    font-size: 11px;
    font-style: italic;
  }

  .diff-badge {
    padding: 1px 6px;
    border-radius: 3px;
    font-size: 10px;
    font-weight: 500;
  }

  .diff-badge.diff-added {
    background: rgba(76, 175, 80, 0.2);
    color: #4caf50;
  }

  .diff-badge.diff-removed {
    background: rgba(239, 83, 80, 0.2);
    color: #ef5350;
  }

  .diff-badge.diff-modified {
    background: rgba(255, 152, 0, 0.2);
    color: #ff9800;
  }
</style>
