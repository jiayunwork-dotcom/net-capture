<script>
  import { onMount, createEventDispatcher } from 'svelte';
  import { parseExpression, nodeToExpression, validateRegex, validateCidr } from '../stores/rules.js';
  import TreeNode from './TreeNode.svelte';
  import NodeProperties from './NodeProperties.svelte';

  export let condition = null;
  export let expression = '';
  export let error = null;

  const dispatch = createEventDispatcher();

  let selectedNodeId = null;
  let draggedNode = null;
  let textExpression = '';
  let textError = null;
  let treeData = null;

  const conditionTypes = [
    { type: 'protocol_match', label: '协议匹配', icon: '📡', category: '基础' },
    { type: 'ip_match', label: 'IP地址匹配', icon: '🌐', category: '网络' },
    { type: 'port_range', label: '端口范围', icon: '🚪', category: '网络' },
    { type: 'packet_length', label: '包长度', icon: '📏', category: '基础' },
    { type: 'tcp_flags', label: 'TCP标志位', icon: '🚩', category: 'TCP' },
    { type: 'payload_keyword', label: '载荷关键字', icon: '🔍', category: '内容' },
    { type: 'rate_limit', label: '速率检测', icon: '⚡', category: '统计' },
    { type: 'dns_blacklist', label: 'DNS黑名单', icon: '🚫', category: 'DNS' },
  ];

  const logicTypes = [
    { type: 'and', label: 'AND (与)', icon: '🔗' },
    { type: 'or', label: 'OR (或)', icon: '🔀' },
    { type: 'not', label: 'NOT (非)', icon: '🚫' },
  ];

  function generateId() {
    return 'node_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
  }

  function initTree() {
    if (condition) {
      treeData = JSON.parse(JSON.stringify(condition));
      assignIds(treeData);
      updateTextExpression();
    } else {
      treeData = {
        id: generateId(),
        type: 'and',
        children: []
      };
      textExpression = '';
    }
  }

  function assignIds(node) {
    if (!node.id) node.id = generateId();
    if (node.children) {
      node.children.forEach(child => assignIds(child));
    }
    if (node.child) {
      assignIds(node.child);
    }
  }

  function nodeFromTemplate(type) {
    const id = generateId();
    switch (type) {
      case 'and':
        return { id, type: 'and', children: [] };
      case 'or':
        return { id, type: 'or', children: [] };
      case 'not':
        return { id, type: 'not', child: null };
      case 'protocol_match':
        return { id, type: 'protocol_match', protocol: 'tcp' };
      case 'ip_match':
        return { id, type: 'ip_match', field: 'src', cidr: '192.168.1.0/24' };
      case 'port_range':
        return { id, type: 'port_range', field: 'dst', min: 1, max: 1024 };
      case 'packet_length':
        return { id, type: 'packet_length', operator: 'greater_than', value: 1000 };
      case 'tcp_flags':
        return { id, type: 'tcp_flags', flags: ['SYN'], mode: 'all' };
      case 'payload_keyword':
        return { id, type: 'payload_keyword', pattern: '.*' };
      case 'rate_limit':
        return { id, type: 'rate_limit', window_secs: 10, threshold: 100, src_ip: true };
      case 'dns_blacklist':
        return { id, type: 'dns_blacklist', domains: ['example.com'] };
      default:
        return { id, type: 'protocol_match', protocol: 'tcp' };
    }
  }

  function addCondition(type) {
    const newNode = nodeFromTemplate(type);
    if (treeData.type === 'not') {
      treeData.child = newNode;
    } else if (treeData.children) {
      treeData.children.push(newNode);
    }
    selectedNodeId = newNode.id;
    treeData = treeData;
    updateTextExpression();
  }

  function addLogic(type) {
    const newNode = nodeFromTemplate(type);
    const oldRoot = JSON.parse(JSON.stringify(treeData));
    if (type === 'not') {
      newNode.child = oldRoot;
    } else {
      newNode.children = [oldRoot];
    }
    treeData = newNode;
    selectedNodeId = newNode.id;
    updateTextExpression();
  }

  function removeNode(nodeId) {
    if (treeData.id === nodeId) {
      treeData = { id: generateId(), type: 'and', children: [] };
      selectedNodeId = null;
      updateTextExpression();
      return;
    }

    function removeFromParent(parent, targetId) {
      if (parent.children) {
        const idx = parent.children.findIndex(c => c.id === targetId);
        if (idx !== -1) {
          parent.children.splice(idx, 1);
          return true;
        }
        for (const child of parent.children) {
          if (removeFromParent(child, targetId)) return true;
        }
      }
      if (parent.child) {
        if (parent.child.id === targetId) {
          parent.child = null;
          return true;
        }
        return removeFromParent(parent.child, targetId);
      }
      return false;
    }

    removeFromParent(treeData, nodeId);
    if (selectedNodeId === nodeId) selectedNodeId = null;
    treeData = treeData;
    updateTextExpression();
  }

  function toggleNodeType(nodeId) {
    function findNode(node, id) {
      if (node.id === id) return node;
      if (node.children) {
        for (const child of node.children) {
          const found = findNode(child, id);
          if (found) return found;
        }
      }
      if (node.child) {
        return findNode(node.child, id);
      }
      return null;
    }

    const node = findNode(treeData, nodeId);
    if (!node) return;

    const typeOrder = ['and', 'or', 'not'];
    const currentIdx = typeOrder.indexOf(node.type);
    const nextType = typeOrder[(currentIdx + 1) % typeOrder.length];

    if (node.type === 'not') {
      const child = node.child;
      node.type = nextType;
      node.children = child ? [child] : [];
      delete node.child;
    } else if (nextType === 'not') {
      const firstChild = node.children && node.children.length > 0 ? node.children[0] : null;
      node.type = nextType;
      node.child = firstChild;
      delete node.children;
    } else {
      node.type = nextType;
    }

    treeData = treeData;
    updateTextExpression();
  }

  function onDragStartCondition(event, type) {
    draggedNode = { type: 'new', conditionType: type };
    event.dataTransfer.effectAllowed = 'copy';
  }

  function onDragStartNode(event, nodeId) {
    draggedNode = { type: 'move', nodeId };
    event.dataTransfer.effectAllowed = 'move';
  }

  function onDragOver(event) {
    event.preventDefault();
    event.dataTransfer.dropEffect = draggedNode?.type === 'new' ? 'copy' : 'move';
  }

  function onDrop(event, targetNodeId, position) {
    event.preventDefault();
    if (!draggedNode) return;

    function findNode(node, id) {
      if (node.id === id) return node;
      if (node.children) {
        for (const child of node.children) {
          const found = findNode(child, id);
          if (found) return found;
        }
      }
      if (node.child) {
        return findNode(node.child, id);
      }
      return null;
    }

    const targetNode = findNode(treeData, targetNodeId);
    if (!targetNode) return;

    if (draggedNode.type === 'new') {
      const newNode = nodeFromTemplate(draggedNode.conditionType);
      if (targetNode.type === 'not') {
        targetNode.child = newNode;
      } else if (targetNode.children) {
        targetNode.children.push(newNode);
      }
      selectedNodeId = newNode.id;
    } else if (draggedNode.type === 'move' && draggedNode.nodeId !== targetNodeId) {
      let movedNode = null;
      function removeNode(node, id) {
        if (node.children) {
          const idx = node.children.findIndex(c => c.id === id);
          if (idx !== -1) {
            movedNode = node.children.splice(idx, 1)[0];
            return true;
          }
          for (const child of node.children) {
            if (removeNode(child, id)) return true;
          }
        }
        if (node.child && node.child.id === id) {
          movedNode = node.child;
          node.child = null;
          return true;
        }
        if (node.child) {
          return removeNode(node.child, id);
        }
        return false;
      }

      if (treeData.id === draggedNode.nodeId) {
        movedNode = JSON.parse(JSON.stringify(treeData));
      } else {
        removeNode(treeData, draggedNode.nodeId);
      }

      if (movedNode && !isDescendant(movedNode, targetNodeId)) {
        if (targetNode.type === 'not') {
          targetNode.child = movedNode;
        } else if (targetNode.children) {
          targetNode.children.push(movedNode);
        }
      }
    }

    draggedNode = null;
    treeData = treeData;
    updateTextExpression();
  }

  function isDescendant(node, targetId) {
    if (node.id === targetId) return true;
    if (node.children) {
      return node.children.some(child => isDescendant(child, targetId));
    }
    if (node.child) {
      return isDescendant(node.child, targetId);
    }
    return false;
  }

  function selectNode(nodeId) {
    selectedNodeId = nodeId;
  }

  function updateNodeParam(nodeId, param, value) {
    function findAndUpdate(node, id) {
      if (node.id === id) {
        node[param] = value;
        return true;
      }
      if (node.children) {
        for (const child of node.children) {
          if (findAndUpdate(child, id)) return true;
        }
      }
      if (node.child) {
        return findAndUpdate(node.child, id);
      }
      return false;
    }

    findAndUpdate(treeData, nodeId);
    treeData = treeData;
    updateTextExpression();
  }

  async function updateTextExpression() {
    try {
      const expr = await nodeToExpression(treeToConditionNode(treeData));
      textExpression = expr;
      textError = null;
      dispatch('change', { condition: treeToConditionNode(treeData), expression: expr });
    } catch (e) {
      textError = String(e);
    }
  }

  function treeToConditionNode(node) {
    const copy = JSON.parse(JSON.stringify(node));
    delete copy.id;
    return copy;
  }

  async function parseTextExpression() {
    try {
      const result = await parseExpression(textExpression);
      if (result.success) {
        treeData = result.node;
        assignIds(treeData);
        textError = null;
        error = null;
        dispatch('change', { condition: result.node, expression: textExpression });
      } else {
        textError = result.error;
      }
    } catch (e) {
      textError = String(e);
    }
  }

  $: if (condition && !treeData) {
    initTree();
  }

  onMount(() => {
    initTree();
  });

  function getNodeLabel(node) {
    switch (node.type) {
      case 'and': return 'AND';
      case 'or': return 'OR';
      case 'not': return 'NOT';
      case 'protocol_match': return `协议: ${node.protocol}`;
      case 'ip_match': return `${node.field === 'src' ? '源' : node.field === 'dst' ? '目的' : ''}IP: ${node.cidr}`;
      case 'port_range': return `${node.field === 'src' ? '源' : node.field === 'dst' ? '目的' : ''}端口: ${node.min}-${node.max}`;
      case 'packet_length': return `包长 ${node.operator === 'greater_than' ? '>' : node.operator === 'less_than' ? '<' : '=='} ${node.value}`;
      case 'tcp_flags': return `TCP标志: ${node.flags.join(', ')}`;
      case 'payload_keyword': return `载荷: ${node.pattern}`;
      case 'rate_limit': return `速率: ${node.threshold}包/${node.window_secs}s`;
      case 'dns_blacklist': return `DNS黑名单: ${node.domains.length}个`;
      default: return node.type;
    }
  }

  function getNodeIcon(node) {
    switch (node.type) {
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

  function isLogicNode(node) {
    return ['and', 'or', 'not'].includes(node.type);
  }

  let showContextMenu = false;
  let contextMenuNode = null;
  let contextMenuX = 0;
  let contextMenuY = 0;

  function onNodeContextMenu(event, nodeId) {
    event.preventDefault();
    contextMenuNode = nodeId;
    contextMenuX = event.clientX;
    contextMenuY = event.clientY;
    showContextMenu = true;
  }

  function closeContextMenu() {
    showContextMenu = false;
    contextMenuNode = null;
  }

  $: if (showContextMenu) {
    setTimeout(() => {
      document.addEventListener('click', closeContextMenu, { once: true });
    }, 0);
  }

  function findSelectedNode(node, id) {
    if (!node) return null;
    if (node.id === id) return node;
    if (node.children) {
      for (const child of node.children) {
        const found = findSelectedNode(child, id);
        if (found) return found;
      }
    }
    if (node.child) {
      return findSelectedNode(node.child, id);
    }
    return null;
  }
</script>

<div class="rule-editor">
  <div class="editor-layout">
    <div class="condition-palette">
      <div class="palette-title">条件类型</div>
      <div class="palette-section">
        <div class="section-label">逻辑运算</div>
        {#each logicTypes as item}
          <div
            class="palette-item logic"
            draggable="true"
            on:dragstart={(e) => onDragStartCondition(e, item.type)}
            on:click={() => addLogic(item.type)}
            title="拖拽到编辑区或点击添加"
          >
            <span class="item-icon">{item.icon}</span>
            <span class="item-label">{item.label}</span>
          </div>
        {/each}
      </div>
      <div class="palette-section">
        <div class="section-label">条件原子</div>
        {#each conditionTypes as item}
          <div
            class="palette-item"
            draggable="true"
            on:dragstart={(e) => onDragStartCondition(e, item.type)}
            on:click={() => addCondition(item.type)}
            title="拖拽到编辑区或点击添加"
          >
            <span class="item-icon">{item.icon}</span>
            <span class="item-label">{item.label}</span>
          </div>
        {/each}
      </div>
    </div>

    <div class="editor-main">
      <div class="tree-editor" on:dragover={onDragOver} on:drop={(e) => onDrop(e, treeData.id, 'inside')}>
        {#if treeData}
          <TreeNode
            node={treeData}
            selectedId={selectedNodeId}
            isRoot={true}
            on:select={(e) => selectNode(e.detail.id)}
            on:remove={(e) => removeNode(e.detail.id)}
            on:toggle={(e) => toggleNodeType(e.detail.id)}
            on:dragstart={(e) => onDragStartNode(e, e.detail.id)}
            on:dragover={onDragOver}
            on:drop={(e) => onDrop(e, e.detail.id, e.detail.position)}
            on:contextmenu={(e) => onNodeContextMenu(e, e.detail.id)}
          />
        {/if}
      </div>

      <div class="property-panel">
        <div class="panel-title">属性</div>
        {#if selectedNodeId}
          <NodeProperties
            node={findSelectedNode(treeData, selectedNodeId)}
            on:update={(e) => updateNodeParam(selectedNodeId, e.detail.param, e.detail.value)}
          />
        {:else}
          <div class="no-selection">请选择一个节点编辑属性</div>
        {/if}
      </div>
    </div>
  </div>

  <div class="expression-section">
    <div class="section-header">
      <span class="section-title">文本表达式</span>
      <button class="btn-small" on:click={parseTextExpression}>应用</button>
    </div>
    <textarea
      class={`expression-input ${textError ? 'error' : ''}`}
      bind:value={textExpression}
      placeholder='例如: protocol == "tcp" AND src_ip == "192.168.1.0/24"'
      rows={3}
    />
    {#if textError}
      <div class="expression-error">{textError}</div>
    {/if}
  </div>

  {#if showContextMenu}
    <div class="context-menu" style="left: {contextMenuX}px; top: {contextMenuY}px;">
      <div class="menu-item" on:click={() => { toggleNodeType(contextMenuNode); closeContextMenu(); }}>
        切换逻辑类型
      </div>
      <div class="menu-item delete" on:click={() => { removeNode(contextMenuNode); closeContextMenu(); }}>
        删除节点
      </div>
    </div>
  {/if}
</div>

<style>
  .rule-editor {
    display: flex;
    flex-direction: column;
    height: 100%;
    background: #1e1e1e;
    color: #e0e0e0;
    font-size: 12px;
  }

  .editor-layout {
    display: flex;
    flex: 1;
    min-height: 0;
    overflow: hidden;
  }

  .condition-palette {
    width: 180px;
    background: #252525;
    border-right: 1px solid #3a3a3a;
    padding: 12px;
    overflow-y: auto;
  }

  .palette-title {
    font-size: 13px;
    font-weight: 600;
    color: #4fc3f7;
    margin-bottom: 12px;
  }

  .palette-section {
    margin-bottom: 16px;
  }

  .section-label {
    font-size: 11px;
    color: #888;
    text-transform: uppercase;
    margin-bottom: 8px;
  }

  .palette-item {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 10px;
    background: #2d2d2d;
    border: 1px solid #3a3a3a;
    border-radius: 4px;
    margin-bottom: 6px;
    cursor: grab;
    transition: all 0.2s;
  }

  .palette-item:hover {
    background: #3a3a3a;
    border-color: #4fc3f7;
  }

  .palette-item:active {
    cursor: grabbing;
  }

  .palette-item.logic {
    background: #2a2a3a;
    border-color: #4a4a6a;
  }

  .palette-item.logic:hover {
    background: #3a3a5a;
  }

  .item-icon {
    font-size: 14px;
  }

  .item-label {
    font-size: 12px;
    color: #ccc;
  }

  .editor-main {
    flex: 1;
    display: flex;
    min-width: 0;
  }

  .tree-editor {
    flex: 1;
    padding: 20px;
    overflow: auto;
    background: #1a1a1a;
  }

  .property-panel {
    width: 260px;
    background: #252525;
    border-left: 1px solid #3a3a3a;
    padding: 12px;
    overflow-y: auto;
  }

  .panel-title {
    font-size: 13px;
    font-weight: 600;
    color: #4fc3f7;
    margin-bottom: 12px;
  }

  .no-selection {
    color: #666;
    text-align: center;
    padding: 20px 0;
    font-size: 12px;
  }

  .expression-section {
    border-top: 1px solid #3a3a3a;
    padding: 12px;
    background: #252525;
  }

  .section-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 8px;
  }

  .section-title {
    font-size: 12px;
    color: #888;
    text-transform: uppercase;
  }

  .btn-small {
    padding: 4px 12px;
    background: #1565c0;
    color: #fff;
    border: none;
    border-radius: 3px;
    cursor: pointer;
    font-size: 11px;
  }

  .btn-small:hover {
    background: #1976d2;
  }

  .expression-input {
    width: 100%;
    box-sizing: border-box;
    padding: 8px 10px;
    background: #1e1e1e;
    color: #e0e0e0;
    border: 1px solid #444;
    border-radius: 4px;
    font-family: monospace;
    font-size: 12px;
    resize: vertical;
  }

  .expression-input.error {
    border-color: #ef5350;
  }

  .expression-input:focus {
    outline: none;
    border-color: #4fc3f7;
  }

  .expression-error {
    color: #ef5350;
    font-size: 11px;
    margin-top: 6px;
  }

  .context-menu {
    position: fixed;
    background: #2d2d2d;
    border: 1px solid #555;
    border-radius: 6px;
    padding: 4px 0;
    z-index: 1000;
    min-width: 140px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.4);
  }

  .menu-item {
    padding: 8px 14px;
    cursor: pointer;
    font-size: 12px;
    color: #ccc;
  }

  .menu-item:hover {
    background: #3a3a3a;
  }

  .menu-item.delete {
    color: #ef5350;
  }

  .menu-item.delete:hover {
    background: rgba(239, 83, 80, 0.1);
  }
</style>
