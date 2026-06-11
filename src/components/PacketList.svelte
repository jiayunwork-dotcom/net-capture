<script>
  import { onMount, onDestroy } from 'svelte';
  import { filteredPackets, selectedPacketNo, autoScroll, loadPacketDetail } from '../stores/packets.js';
  import { marks, setPacketMark, removePacketMark, getMarkColor, loadAllMarks } from '../stores/marks.js';
  import { selectedPackets } from '../stores/selection.js';

  const PROTOCOL_COLORS = {
    HTTP: '#c8e6c9',
    DNS: '#bbdefb',
    TCP: '#e0e0e0',
    UDP: '#e1bee7',
    TLS: '#ffe0b2',
    ICMP: '#f8bbd0',
    ARP: '#fff9c4',
  };

  const DEFAULT_COLUMNS = [
    { id: 'no', label: '序号', width: 70, default: true, sortable: true, align: 'right' },
    { id: 'time', label: '时间戳', width: 150, default: true, sortable: true, align: 'left' },
    { id: 'src', label: '源地址', width: 220, default: true, sortable: true, align: 'left' },
    { id: 'dst', label: '目的地址', width: 220, default: true, sortable: true, align: 'left' },
    { id: 'proto', label: '协议', width: 60, default: true, sortable: true, align: 'center' },
    { id: 'len', label: '长度', width: 70, default: true, sortable: true, align: 'right' },
    { id: 'summary', label: '摘要', width: null, default: true, sortable: false, align: 'left' },
  ];

  const EXTRA_COLUMNS = [
    { id: 'ttl', label: 'TTL', width: 50, default: false, sortable: true, align: 'right' },
    { id: 'window', label: '窗口大小', width: 80, default: false, sortable: true, align: 'right' },
    { id: 'flags', label: 'TCP标志', width: 100, default: false, sortable: false, align: 'left' },
    { id: 'ip_id', label: 'IP标识符', width: 90, default: false, sortable: true, align: 'right' },
    { id: 'frag_offset', label: '分片偏移', width: 80, default: false, sortable: true, align: 'right' },
  ];

  const ROW_HEIGHT = 24;
  let containerEl;
  let scrollTop = 0;
  let containerHeight = 600;

  let visibleColumns = [...DEFAULT_COLUMNS];
  let sortColumn = null;
  let sortDirection = 'asc';

  let contextMenuVisible = false;
  let contextMenuX = 0;
  let contextMenuY = 0;
  let contextMenuPacket = null;

  let columnMenuVisible = false;
  let columnMenuX = 0;
  let columnMenuY = 0;

  let showMarkDialog = false;
  let markDialogLevel = 'starred';
  let markDialogComment = '';

  let resizingCol = null;
  let resizeStartX = 0;
  let resizeStartWidth = 0;

  let columnWidths = {};

  function loadColumnConfig() {
    try {
      const saved = localStorage.getItem('packetList_columns');
      if (saved) {
        const config = JSON.parse(saved);
        columnWidths = config.widths || {};
        const visibleIds = config.visible || DEFAULT_COLUMNS.map(c => c.id);
        const allCols = [...DEFAULT_COLUMNS, ...EXTRA_COLUMNS];
        visibleColumns = visibleIds
          .map(id => allCols.find(c => c.id === id))
          .filter(Boolean)
          .map(c => ({
            ...c,
            width: columnWidths[c.id] || c.width
          }));
      }
    } catch (e) {
      console.error('Load column config error:', e);
    }
  }

  function saveColumnConfig() {
    try {
      const config = {
        visible: visibleColumns.map(c => c.id),
        widths: visibleColumns.reduce((acc, c) => {
          if (c.width) acc[c.id] = c.width;
          return acc;
        }, {})
      };
      localStorage.setItem('packetList_columns', JSON.stringify(config));
    } catch (e) {
      console.error('Save column config error:', e);
    }
  }

  function toggleColumn(colId) {
    const allCols = [...DEFAULT_COLUMNS, ...EXTRA_COLUMNS];
    const col = allCols.find(c => c.id === colId);
    if (!col) return;

    const isVisible = visibleColumns.some(c => c.id === colId);
    if (isVisible) {
      if (DEFAULT_COLUMNS.some(c => c.id === colId && c.default)) return;
      visibleColumns = visibleColumns.filter(c => c.id !== colId);
    } else {
      const newCol = { ...col, width: columnWidths[colId] || col.width };
      const defaultIds = DEFAULT_COLUMNS.map(c => c.id);
      const insertIndex = visibleColumns.findIndex(c => !defaultIds.includes(c.id));
      if (insertIndex === -1) {
        visibleColumns = [...visibleColumns, newCol];
      } else {
        visibleColumns = [
          ...visibleColumns.slice(0, insertIndex),
          newCol,
          ...visibleColumns.slice(insertIndex)
        ];
      }
    }
    saveColumnConfig();
    columnMenuVisible = false;
  }

  function isColumnVisible(colId) {
    return visibleColumns.some(c => c.id === colId);
  }

  function startResize(e, col) {
    e.stopPropagation();
    e.preventDefault();
    resizingCol = col;
    resizeStartX = e.clientX;
    resizeStartWidth = col.width || 100;
    document.addEventListener('mousemove', onResizeMove);
    document.addEventListener('mouseup', stopResize);
  }

  function onResizeMove(e) {
    if (!resizingCol) return;
    const diff = e.clientX - resizeStartX;
    const newWidth = Math.max(30, resizeStartWidth + diff);
    visibleColumns = visibleColumns.map(c =>
      c.id === resizingCol.id ? { ...c, width: newWidth } : c
    );
    columnWidths[resizingCol.id] = newWidth;
  }

  function stopResize() {
    if (resizingCol) {
      saveColumnConfig();
    }
    resizingCol = null;
    document.removeEventListener('mousemove', onResizeMove);
    document.removeEventListener('mouseup', stopResize);
  }

  function handleHeaderClick(col) {
    if (!col.sortable) return;
    if (sortColumn === col.id) {
      sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
    } else {
      sortColumn = col.id;
      sortDirection = 'asc';
    }
    autoScroll.set(false);
  }

  function getSortIcon(col) {
    if (sortColumn !== col.id) return '';
    return sortDirection === 'asc' ? ' ↑' : ' ↓';
  }

  $: sortedPackets = (() => {
    if (!sortColumn || sortColumn === 'no' && sortDirection === 'asc') {
      return $filteredPackets;
    }
    const arr = [...$filteredPackets];
    const dir = sortDirection === 'asc' ? 1 : -1;

    arr.sort((a, b) => {
      let va, vb;
      switch (sortColumn) {
        case 'no':
          va = a.no; vb = b.no; break;
        case 'time':
          va = a.timestamp_secs * 1000000 + a.timestamp_micros;
          vb = b.timestamp_secs * 1000000 + b.timestamp_micros;
          break;
        case 'src':
          va = a.src_addr; vb = b.src_addr; break;
        case 'dst':
          va = a.dst_addr; vb = b.dst_addr; break;
        case 'proto':
          va = a.protocol; vb = b.protocol; break;
        case 'len':
          va = a.length; vb = b.length; break;
        default:
          va = a.no; vb = b.no;
      }
      if (va < vb) return -dir;
      if (va > vb) return dir;
      return 0;
    });
    return arr;
  })();

  $: visibleStart = Math.floor(scrollTop / ROW_HEIGHT);
  $: visibleCount = Math.ceil(containerHeight / ROW_HEIGHT) + 5;
  $: visibleEnd = Math.min(visibleStart + visibleCount, sortedPackets.length);
  $: totalHeight = sortedPackets.length * ROW_HEIGHT;
  $: offsetY = visibleStart * ROW_HEIGHT;
  $: visiblePackets = sortedPackets.slice(visibleStart, visibleEnd);

  function onScroll(e) {
    scrollTop = e.target.scrollTop;
  }

  function selectPacket(pkt, e) {
    if (e && e.ctrlKey) {
      selectedPackets.update(selected => {
        if (selected.includes(pkt.no)) {
          return selected.filter(n => n !== pkt.no);
        } else {
          return [...selected, pkt.no];
        }
      });
    } else {
      selectedPackets.set([pkt.no]);
      loadPacketDetail(pkt.no);
    }
  }

  function isSelected(pktNo) {
    return $selectedPackets.includes(pktNo);
  }

  function formatAddr(pkt) {
    const src = pkt.src_port ? `${pkt.src_addr}:${pkt.src_port}` : pkt.src_addr;
    const dst = pkt.dst_port ? `${pkt.dst_addr}:${pkt.dst_port}` : pkt.dst_addr;
    return { src, dst };
  }

  function getProtoColor(proto) {
    return PROTOCOL_COLORS[proto] || '#ffffff';
  }

  function getProtoTextColor(proto) {
    const dark = ['TCP'];
    return dark.includes(proto) ? '#333' : '#1a1a1a';
  }

  function getCellValue(pkt, colId) {
    const addr = formatAddr(pkt);
    switch (colId) {
      case 'no': return pkt.no;
      case 'time': return pkt.timestamp_str;
      case 'src': return addr.src;
      case 'dst': return addr.dst;
      case 'proto': return pkt.protocol;
      case 'len': return pkt.length;
      case 'summary': return pkt.summary;
      case 'ttl': return pkt.ttl ?? '';
      case 'window': return pkt.window_size ?? '';
      case 'flags': return pkt.tcp_flags ?? '';
      case 'ip_id': return pkt.ip_id != null ? `0x${pkt.ip_id.toString(16).padStart(4, '0')}` : '';
      case 'frag_offset': return pkt.fragment_offset ?? '';
      default: return '';
    }
  }

  function getMark(pktNo) {
    return $marks[pktNo];
  }

  function showContextMenu(e, pkt) {
    e.preventDefault();
    e.stopPropagation();
    contextMenuPacket = pkt;
    contextMenuX = e.clientX;
    contextMenuY = e.clientY;
    contextMenuVisible = true;
  }

  function hideContextMenu() {
    contextMenuVisible = false;
    contextMenuPacket = null;
  }

  function showColumnMenu(e) {
    e.preventDefault();
    e.stopPropagation();
    columnMenuX = e.clientX;
    columnMenuY = e.clientY;
    columnMenuVisible = true;
  }

  function hideColumnMenu() {
    columnMenuVisible = false;
  }

  function openMarkDialog(level) {
    markDialogLevel = level;
    markDialogComment = '';
    if (contextMenuPacket) {
      const existing = $marks[contextMenuPacket.no];
      if (existing) {
        markDialogComment = existing.comment || '';
      }
    }
    showMarkDialog = true;
    hideContextMenu();
  }

  async function confirmMark() {
    if (contextMenuPacket) {
      const success = await setPacketMark(
        contextMenuPacket.no,
        markDialogLevel,
        markDialogComment
      );
      if (!success) {
        alert('标记数量已达上限（10000个），请清理旧标记');
      }
    }
    showMarkDialog = false;
  }

  async function handleRemoveMark() {
    if (contextMenuPacket) {
      await removePacketMark(contextMenuPacket.no);
    }
    hideContextMenu();
  }

  export function scrollToBottom() {
    if (containerEl && $autoScroll) {
      containerEl.scrollTop = containerEl.scrollHeight;
    }
  }

  $: if (sortedPackets.length > 0 && $autoScroll && sortColumn === null) {
    requestAnimationFrame(scrollToBottom);
  }

  function handleResize() {
    if (containerEl) {
      containerHeight = containerEl.clientHeight - 30;
    }
  }

  onMount(() => {
    loadColumnConfig();
    loadAllMarks();
    window.addEventListener('resize', handleResize);
    setTimeout(handleResize, 100);

    document.addEventListener('click', (e) => {
      if (contextMenuVisible) hideContextMenu();
      if (columnMenuVisible) hideColumnMenu();
    });
  });

  onDestroy(() => {
    window.removeEventListener('resize', handleResize);
  });
</script>

<div class="packet-list" bind:this={containerEl} on:scroll={onScroll} on:contextmenu={showColumnMenu}>
  <div class="header" on:contextmenu={showColumnMenu}>
    {#each visibleColumns as col (col.id)}
      <span
        class="col-header col-{col.id}"
        style="width: {col.width ? col.width + 'px' : 'auto'}; text-align: {col.align};"
        class:sortable={col.sortable}
        on:click={() => handleHeaderClick(col)}
      >
        {col.label}{col.sortable ? getSortIcon(col) : ''}
        {#if col.width}
          <span class="resize-handle" on:mousedown={(e) => startResize(e, col)}></span>
        {/if}
      </span>
    {/each}
  </div>

  <div class="virtual-container" style="height: {totalHeight}px;">
    <div class="virtual-content" style="transform: translateY({offsetY}px);">
      {#each visiblePackets as pkt (pkt.no)}
        {@const addr = formatAddr(pkt)}
        {@const mark = getMark(pkt.no)}
        <div
          class="packet-row {isSelected(pkt.no) ? 'selected' : ''}"
          style="height: {ROW_HEIGHT}px; background-color: {getProtoColor(pkt.protocol)};"
          on:click={(e) => selectPacket(pkt, e)}
          on:contextmenu={(e) => showContextMenu(e, pkt)}
        >
          {#if mark}
            <span class="mark-dot" style="background: {getMarkColor(mark.level)}" title="{mark.level}: {mark.comment}"></span>
          {/if}
          {#each visibleColumns as col (col.id)}
            <span
              class="cell col-{col.id}"
              style="width: {col.width ? col.width + 'px' : 'auto'}; text-align: {col.align};"
            >
              {#if col.id === 'no' && mark}
                <span class="mark-indicator" style="color: {getMarkColor(mark.level)}">●</span>
              {/if}
              {getCellValue(pkt, col.id)}
            </span>
          {/each}
        </div>
      {/each}
    </div>
  </div>
</div>

{#if contextMenuVisible}
  <div class="context-menu" style="left: {contextMenuX}px; top: {contextMenuY}px;" onclick="event.stopPropagation()">
    <div class="menu-item" on:click={() => openMarkDialog('starred')}>
      <span class="menu-icon" style="color: #ffca28;">●</span>
      <span>标记为星标</span>
    </div>
    <div class="menu-item" on:click={() => openMarkDialog('warning')}>
      <span class="menu-icon" style="color: #ef5350;">●</span>
      <span>标记为警告</span>
    </div>
    <div class="menu-item" on:click={() => openMarkDialog('important')}>
      <span class="menu-icon" style="color: #42a5f5;">●</span>
      <span>标记为重要</span>
    </div>
    <div class="menu-separator"></div>
    <div class="menu-item" on:click={handleRemoveMark}>
      <span class="menu-icon">✕</span>
      <span>移除标记</span>
    </div>
  </div>
{/if}

{#if columnMenuVisible}
  <div class="context-menu" style="left: {columnMenuX}px; top: {columnMenuY}px;" onclick="event.stopPropagation()">
    <div class="menu-title">显示列</div>
    {#each [...DEFAULT_COLUMNS, ...EXTRA_COLUMNS] as col (col.id)}
      <div class="menu-item {col.default ? 'default' : ''}" on:click={() => toggleColumn(col.id)}>
        <span class="menu-check">{isColumnVisible(col.id) ? '✓' : ''}</span>
        <span>{col.label}</span>
      </div>
    {/each}
  </div>
{/if}

{#if showMarkDialog}
  <div class="dialog-overlay" on:click={() => showMarkDialog = false}>
    <div class="dialog" on:click|stopPropagation>
      <h3>添加标记</h3>
      <div class="form-group">
        <label>标记级别</label>
        <div class="level-selector">
          {#each ['starred', 'warning', 'important'] as level}
            <button
              class="level-btn {markDialogLevel === level ? 'active' : ''}"
              on:click={() => markDialogLevel = level}
            >
              <span class="level-dot" style="background: {getMarkColor(level)}"></span>
              {level === 'starred' ? '星标' : level === 'warning' ? '警告' : '重要'}
            </button>
          {/each}
        </div>
      </div>
      <div class="form-group">
        <label>注释（最多200字）</label>
        <textarea
          bind:value={markDialogComment}
          maxlength="200"
          rows="4"
          placeholder="输入注释内容..."
        ></textarea>
        <span class="char-count">{markDialogComment.length}/200</span>
      </div>
      <div class="dialog-actions">
        <button class="btn-cancel" on:click={() => showMarkDialog = false}>取消</button>
        <button class="btn-confirm" on:click={confirmMark}>确定</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .packet-list {
    flex: 1;
    overflow-y: auto;
    background: #1e1e1e;
    font-family: 'Menlo', 'Consolas', 'Monaco', monospace;
    font-size: 12px;
    position: relative;
  }
  .header {
    display: flex;
    align-items: center;
    background: #333;
    color: #ccc;
    padding: 4px 0;
    border-bottom: 2px solid #444;
    position: sticky;
    top: 0;
    z-index: 10;
    font-weight: 600;
    cursor: default;
    user-select: none;
  }
  .col-header {
    position: relative;
    padding: 0 8px;
    flex-shrink: 0;
  }
  .col-header.sortable {
    cursor: pointer;
  }
  .col-header.sortable:hover {
    background: #444;
  }
  .resize-handle {
    position: absolute;
    right: 0;
    top: 0;
    bottom: 0;
    width: 6px;
    cursor: col-resize;
    z-index: 2;
  }
  .resize-handle:hover {
    background: #4fc3f7;
  }
  .virtual-container {
    position: relative;
  }
  .virtual-content {
    position: absolute;
    left: 0;
    right: 0;
  }
  .packet-row {
    display: flex;
    align-items: center;
    cursor: pointer;
    border-bottom: 1px solid rgba(0,0,0,0.1);
    padding: 0 4px;
    transition: opacity 0.1s;
    position: relative;
  }
  .packet-row:hover {
    opacity: 0.85;
  }
  .packet-row.selected {
    outline: 2px solid #1565c0;
    outline-offset: -2px;
  }
  .mark-dot {
    position: absolute;
    left: 4px;
    top: 50%;
    transform: translateY(-50%);
    width: 8px;
    height: 8px;
    border-radius: 50%;
    z-index: 1;
  }
  .mark-indicator {
    margin-right: 4px;
    font-size: 10px;
  }
  .cell {
    padding: 0 8px;
    flex-shrink: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .cell.col-summary {
    flex: 1;
  }
  .context-menu {
    position: fixed;
    background: #2d2d2d;
    border: 1px solid #555;
    border-radius: 4px;
    padding: 4px 0;
    min-width: 160px;
    z-index: 1000;
    box-shadow: 0 4px 12px rgba(0,0,0,0.4);
  }
  .menu-item {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 12px;
    cursor: pointer;
    color: #ccc;
    font-size: 12px;
  }
  .menu-item:hover {
    background: #3a3a3a;
  }
  .menu-icon {
    width: 16px;
    text-align: center;
    font-size: 10px;
  }
  .menu-check {
    width: 16px;
    text-align: center;
    font-size: 12px;
    color: #4fc3f7;
  }
  .menu-separator {
    height: 1px;
    background: #444;
    margin: 4px 0;
  }
  .menu-title {
    padding: 6px 12px;
    font-size: 11px;
    color: #888;
    font-weight: 600;
    border-bottom: 1px solid #444;
    margin-bottom: 4px;
  }
  .dialog-overlay {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0,0,0,0.6);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 2000;
  }
  .dialog {
    background: #2d2d2d;
    border: 1px solid #555;
    border-radius: 8px;
    padding: 20px;
    min-width: 360px;
    box-shadow: 0 8px 24px rgba(0,0,0,0.5);
  }
  .dialog h3 {
    color: #eee;
    margin: 0 0 16px 0;
    font-size: 15px;
  }
  .form-group {
    margin-bottom: 16px;
  }
  .form-group label {
    display: block;
    color: #aaa;
    font-size: 12px;
    margin-bottom: 6px;
  }
  .level-selector {
    display: flex;
    gap: 8px;
  }
  .level-btn {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    padding: 8px;
    background: #3a3a3a;
    border: 1px solid #555;
    border-radius: 4px;
    color: #ccc;
    cursor: pointer;
    font-size: 12px;
  }
  .level-btn:hover {
    background: #444;
  }
  .level-btn.active {
    border-color: #4fc3f7;
    background: rgba(79, 195, 247, 0.1);
  }
  .level-dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
  }
  textarea {
    width: 100%;
    box-sizing: border-box;
    background: #1e1e1e;
    color: #e0e0e0;
    border: 1px solid #555;
    border-radius: 4px;
    padding: 8px;
    font-family: 'Menlo', 'Consolas', monospace;
    font-size: 12px;
    resize: vertical;
  }
  textarea:focus {
    outline: none;
    border-color: #4fc3f7;
  }
  .char-count {
    display: block;
    text-align: right;
    color: #666;
    font-size: 11px;
    margin-top: 4px;
  }
  .dialog-actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    margin-top: 16px;
  }
  .btn-cancel {
    padding: 6px 16px;
    background: #3a3a3a;
    border: 1px solid #555;
    border-radius: 4px;
    color: #ccc;
    cursor: pointer;
    font-size: 12px;
  }
  .btn-cancel:hover {
    background: #444;
  }
  .btn-confirm {
    padding: 6px 16px;
    background: #1565c0;
    border: 1px solid #1976d2;
    border-radius: 4px;
    color: #fff;
    cursor: pointer;
    font-size: 12px;
  }
  .btn-confirm:hover {
    background: #1976d2;
  }
</style>
