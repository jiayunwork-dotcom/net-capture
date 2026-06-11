<script>
  import { createEventDispatcher } from 'svelte';

  export let node;
  export let selectedId = null;
  export let isRoot = false;

  const dispatch = createEventDispatcher();

  function handleSelect(event) {
    event.stopPropagation();
    dispatch('select', { id: node.id });
  }

  function handleRemove(event) {
    event.stopPropagation();
    dispatch('remove', { id: node.id });
  }

  function handleToggle(event) {
    event.stopPropagation();
    dispatch('toggle', { id: node.id });
  }

  function handleDragStart(event) {
    event.stopPropagation();
    dispatch('dragstart', { id: node.id });
  }

  function handleDrop(event) {
    event.preventDefault();
    event.stopPropagation();
    dispatch('drop', { id: node.id, position: 'inside' });
  }

  function handleContextMenu(event) {
    event.preventDefault();
    event.stopPropagation();
    dispatch('contextmenu', { id: node.id });
  }

  function isLogic(type) {
    return ['and', 'or', 'not'].includes(type);
  }

  function getNodeIcon(type) {
    switch (type) {
      case 'and': return '🔗';
      case 'or': return '🔀';
      case 'not': return '🚫';
      case 'protocol_match': return '📡';
      case 'ip_match': return '🌐';
      case 'port_range': return '🚪';
      case 'packet_length': return '📏';
      case 'tcp_flags': return '🚩';
      case 'payload_keyword': return '🔍';
      case 'rate_limit': return '⚡';
      case 'dns_blacklist': return '🚫';
      default: return '📋';
    }
  }

  function getNodeLabel(node) {
    switch (node.type) {
      case 'and': return 'AND (与)';
      case 'or': return 'OR (或)';
      case 'not': return 'NOT (非)';
      case 'protocol_match': return `协议: ${node.protocol}`;
      case 'ip_match': {
        const field = node.field === 'src' ? '源' : node.field === 'dst' ? '目的' : '';
        return `${field}IP: ${node.cidr}`;
      }
      case 'port_range': {
        const field = node.field === 'src' ? '源' : node.field === 'dst' ? '目的' : '';
        return `${field}端口: ${node.min}-${node.max}`;
      }
      case 'packet_length': {
        const op = node.operator === 'greater_than' ? '>' : node.operator === 'less_than' ? '<' : '==';
        return `包长 ${op} ${node.value}`;
      }
      case 'tcp_flags': return `TCP标志: ${node.flags.join(', ')}`;
      case 'payload_keyword': return `载荷: ${node.pattern}`;
      case 'rate_limit': return `速率: ${node.threshold}包/${node.window_secs}s`;
      case 'dns_blacklist': return `DNS黑名单: ${node.domains.length}个`;
      default: return node.type;
    }
  }
</script>

<div
  class={`tree-node ${isLogic(node.type) ? 'logic' : 'condition'} ${selectedId === node.id ? 'selected' : ''} ${isRoot ? 'root' : ''}`}
  on:click={handleSelect}
  on:contextmenu={handleContextMenu}
  draggable={!isRoot}
  on:dragstart={handleDragStart}
  on:dragover|preventDefault
  on:drop={handleDrop}
>
  <div class="node-header">
    <span class="node-icon">{getNodeIcon(node.type)}</span>
    <span class="node-label">{getNodeLabel(node)}</span>
    {#if isLogic(node.type)}
      <button class="toggle-btn" on:click={handleToggle} title="切换逻辑类型">
        ⟳
      </button>
    {/if}
    {#if !isRoot}
      <button class="remove-btn" on:click={handleRemove} title="删除">
        ✕
      </button>
    {/if}
  </div>

  {#if node.type === 'not' && node.child}
    <div class="node-children single">
      <svelte:self
        node={node.child}
        selectedId={selectedId}
        on:select
        on:remove
        on:toggle
        on:dragstart
        on:dragover
        on:drop
        on:contextmenu
      />
    </div>
  {/if}

  {#if node.children && node.children.length > 0}
    <div class="node-children">
      {#each node.children as child (child.id)}
        <svelte:self
          node={child}
          selectedId={selectedId}
          on:select
          on:remove
          on:toggle
          on:dragstart
          on:dragover
          on:drop
          on:contextmenu
        />
      {/each}
    </div>
  {/if}
</div>

<style>
  .tree-node {
    margin: 4px 0;
    border: 1px solid #3a3a3a;
    border-radius: 6px;
    background: #252525;
    cursor: pointer;
    transition: all 0.2s;
    min-width: 120px;
  }

  .tree-node:hover {
    border-color: #555;
    background: #2d2d2d;
  }

  .tree-node.selected {
    border-color: #4fc3f7;
    box-shadow: 0 0 0 2px rgba(79, 195, 247, 0.3);
  }

  .tree-node.logic {
    background: #2a2a3a;
    border-color: #4a4a6a;
  }

  .tree-node.logic:hover {
    background: #3a3a5a;
  }

  .tree-node.logic.selected {
    border-color: #7c4dff;
    box-shadow: 0 0 0 2px rgba(124, 77, 255, 0.3);
  }

  .tree-node.root {
    border-style: dashed;
  }

  .node-header {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 12px;
    font-size: 12px;
  }

  .node-icon {
    font-size: 14px;
  }

  .node-label {
    flex: 1;
    color: #ccc;
    font-weight: 500;
  }

  .toggle-btn,
  .remove-btn {
    background: transparent;
    border: none;
    color: #888;
    cursor: pointer;
    font-size: 11px;
    padding: 2px 6px;
    border-radius: 3px;
    opacity: 0;
    transition: opacity 0.2s;
  }

  .tree-node:hover .toggle-btn,
  .tree-node:hover .remove-btn {
    opacity: 1;
  }

  .toggle-btn:hover {
    background: rgba(79, 195, 247, 0.2);
    color: #4fc3f7;
  }

  .remove-btn:hover {
    background: rgba(239, 83, 80, 0.2);
    color: #ef5350;
  }

  .node-children {
    padding: 0 12px 12px 24px;
    border-left: 2px solid #3a3a3a;
    margin-left: 16px;
  }

  .node-children.single {
    padding: 0 12px 12px 24px;
  }

  .logic .node-children {
    border-left-color: #4a4a6a;
  }
</style>
