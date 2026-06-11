<script>
  import { createEventDispatcher } from 'svelte';

  export let rule;

  const dispatch = createEventDispatcher();

  function getPriorityClass(priority) {
    switch (priority) {
      case 'high': return 'priority-high';
      case 'medium': return 'priority-medium';
      case 'low': return 'priority-low';
      default: return '';
    }
  }

  function getPriorityLabel(priority) {
    switch (priority) {
      case 'high': return '高';
      case 'medium': return '中';
      case 'low': return '低';
      default: return '';
    }
  }
</script>

<div class="rule-item {rule.enabled ? '' : 'disabled'}">
  <div class="rule-main" on:click={() => dispatch('edit')}>
    <div class="rule-info">
      <span class={`priority-badge ${getPriorityClass(rule.priority)}`}>
        {getPriorityLabel(rule.priority)}
      </span>
      <span class="rule-name">{rule.name}</span>
    </div>
    <div class="rule-desc">{rule.description || rule.expression || '无描述'}</div>
  </div>
  <div class="rule-actions">
    <label class="toggle-switch">
      <input
        type="checkbox"
        checked={rule.enabled}
        on:change={(e) => dispatch('toggle', e.target.checked)}
        on:click|stopPropagation
      />
      <span class="toggle-slider"></span>
    </label>
    <button class="action-btn edit" on:click|stopPropagation={() => dispatch('edit')} title="编辑">
      ✏️
    </button>
    <button class="action-btn delete" on:click|stopPropagation={() => dispatch('delete')} title="删除">
      🗑️
    </button>
  </div>
</div>

<style>
  .rule-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 14px;
    background: #252525;
    border-bottom: 1px solid #333;
    cursor: pointer;
    transition: background 0.2s;
  }

  .rule-item:hover {
    background: #2d2d2d;
  }

  .rule-item.disabled {
    opacity: 0.5;
  }

  .rule-main {
    flex: 1;
    min-width: 0;
  }

  .rule-info {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 4px;
  }

  .priority-badge {
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
  }

  .priority-high {
    background: rgba(239, 83, 80, 0.2);
    color: #ef5350;
  }

  .priority-medium {
    background: rgba(255, 152, 0, 0.2);
    color: #ff9800;
  }

  .priority-low {
    background: rgba(255, 235, 59, 0.2);
    color: #ffeb3b;
  }

  .rule-name {
    font-size: 13px;
    font-weight: 500;
    color: #e0e0e0;
  }

  .rule-desc {
    font-size: 11px;
    color: #888;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 400px;
  }

  .rule-actions {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .toggle-switch {
    position: relative;
    display: inline-block;
    width: 36px;
    height: 20px;
    cursor: pointer;
  }

  .toggle-switch input {
    opacity: 0;
    width: 0;
    height: 0;
  }

  .toggle-slider {
    position: absolute;
    inset: 0;
    background: #555;
    border-radius: 10px;
    transition: 0.2s;
  }

  .toggle-slider::before {
    content: '';
    position: absolute;
    width: 14px;
    height: 14px;
    left: 3px;
    bottom: 3px;
    background: white;
    border-radius: 50%;
    transition: 0.2s;
  }

  input:checked + .toggle-slider {
    background: #4caf50;
  }

  input:checked + .toggle-slider::before {
    transform: translateX(16px);
  }

  .action-btn {
    width: 28px;
    height: 28px;
    display: flex;
    align-items: center;
    justify-content: center;
    background: transparent;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 14px;
    opacity: 0.6;
    transition: all 0.2s;
  }

  .action-btn:hover {
    opacity: 1;
    background: #3a3a3a;
  }

  .action-btn.delete:hover {
    background: rgba(239, 83, 80, 0.2);
  }
</style>
