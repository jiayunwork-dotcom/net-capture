<script>
  import { displayFilter, filterStatus, markFilter, commentFilter } from '../stores/filters.js';
  import { applyDisplayFilter, filteredPackets, packets, applyMarkFilter } from '../stores/packets.js';
  import { marks } from '../stores/marks.js';

  let localFilter = '';
  let localMarkFilter = 'all';
  let localCommentFilter = '';
  let debounceTimer = null;
  let filtering = false;

  $: $displayFilter = localFilter;
  $: $markFilter = localMarkFilter;
  $: $commentFilter = localCommentFilter;

  async function onFilterInput(e) {
    localFilter = e.target.value;
    if (debounceTimer) clearTimeout(debounceTimer);

    if (!localFilter.trim() && localMarkFilter === 'all' && !localCommentFilter.trim()) {
      $filteredPackets = $packets;
      $filterStatus = '';
      return;
    }

    filtering = true;
    $filterStatus = '过滤中...';

    debounceTimer = setTimeout(async () => {
      const start = performance.now();
      const success = await applyDisplayFilter(localFilter);
      if (success) {
        await applyMarkFilter(localMarkFilter, localCommentFilter, $marks);
        const elapsed = performance.now() - start;
        $filterStatus = `已过滤 (${$filteredPackets.length}/${$packets.length}) ${elapsed.toFixed(0)}ms`;
      } else {
        $filterStatus = '过滤表达式错误';
      }
      filtering = false;
    }, 300);
  }

  async function onMarkFilterChange(e) {
    localMarkFilter = e.target.value;
    if (debounceTimer) clearTimeout(debounceTimer);
    
    filtering = true;
    $filterStatus = '过滤中...';

    const start = performance.now();
    
    if (localFilter.trim()) {
      const success = await applyDisplayFilter(localFilter);
      if (!success) {
        $filterStatus = '过滤表达式错误';
        filtering = false;
        return;
      }
    } else {
      $filteredPackets = $packets.slice();
    }
    
    await applyMarkFilter(localMarkFilter, localCommentFilter, $marks);
    const elapsed = performance.now() - start;
    $filterStatus = `已过滤 (${$filteredPackets.length}/${$packets.length}) ${elapsed.toFixed(0)}ms`;
    filtering = false;
  }

  async function onCommentFilterInput(e) {
    localCommentFilter = e.target.value;
    if (debounceTimer) clearTimeout(debounceTimer);

    if (!localFilter.trim() && localMarkFilter === 'all' && !localCommentFilter.trim()) {
      $filteredPackets = $packets;
      $filterStatus = '';
      return;
    }

    filtering = true;
    $filterStatus = '过滤中...';

    debounceTimer = setTimeout(async () => {
      const start = performance.now();
      
      if (localFilter.trim()) {
        const success = await applyDisplayFilter(localFilter);
        if (!success) {
          $filterStatus = '过滤表达式错误';
          filtering = false;
          return;
        }
      } else {
        $filteredPackets = $packets.slice();
      }
      
      await applyMarkFilter(localMarkFilter, localCommentFilter, $marks);
      const elapsed = performance.now() - start;
      $filterStatus = `已过滤 (${$filteredPackets.length}/${$packets.length}) ${elapsed.toFixed(0)}ms`;
      filtering = false;
    }, 300);
  }

  function clearFilter() {
    localFilter = '';
    localMarkFilter = 'all';
    localCommentFilter = '';
    $filteredPackets = $packets;
    $filterStatus = '';
  }
</script>

<div class="display-filter">
  <label>显示过滤:</label>
  <input
    type="text"
    placeholder="例: http, ip.src==192.168.1.1, tcp.port==443"
    value={localFilter}
    on:input={onFilterInput}
    class="filter-input"
  />
  
  <select class="mark-filter" value={localMarkFilter} on:change={onMarkFilterChange} title="按标记状态过滤">
    <option value="all">全部状态</option>
    <option value="marked">已标记</option>
    <option value="unmarked">未标记</option>
    <option value="starred">⭐ 星标</option>
    <option value="warning">⚠️ 警告</option>
    <option value="important">🔵 重要</option>
  </select>

  <input
    type="text"
    class="comment-filter"
    placeholder="注释搜索..."
    value={localCommentFilter}
    on:input={onCommentFilterInput}
    title="按注释内容搜索"
  />
  
  {#if localFilter || localMarkFilter !== 'all' || localCommentFilter}
    <button class="btn-clear" on:click={clearFilter}>✕</button>
  {/if}
  <span class="filter-status" class:filtering>
    {$filterStatus}
  </span>
</div>

<style>
  .display-filter {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 16px;
    background: #252525;
    border-bottom: 1px solid #444;
  }
  label {
    color: #aaa;
    font-size: 13px;
    white-space: nowrap;
  }
  .filter-input {
    flex: 1;
    background: #1e1e1e;
    color: #e0e0e0;
    border: 1px solid #555;
    border-radius: 4px;
    padding: 5px 10px;
    font-size: 13px;
    font-family: 'Menlo', 'Consolas', 'Monaco', monospace;
  }
  .mark-filter {
    background: #1e1e1e;
    color: #e0e0e0;
    border: 1px solid #555;
    border-radius: 4px;
    padding: 4px 8px;
    font-size: 12px;
    cursor: pointer;
    min-width: 100px;
  }
  .mark-filter:focus {
    outline: none;
    border-color: #4fc3f7;
  }
  .comment-filter {
    background: #1e1e1e;
    color: #e0e0e0;
    border: 1px solid #555;
    border-radius: 4px;
    padding: 5px 10px;
    font-size: 12px;
    width: 150px;
  }
  .comment-filter:focus {
    outline: none;
    border-color: #4fc3f7;
  }
  input:focus {
    outline: none;
    border-color: #4fc3f7;
  }
  .btn-clear {
    background: transparent;
    color: #888;
    border: none;
    cursor: pointer;
    font-size: 14px;
    padding: 2px 6px;
  }
  .btn-clear:hover {
    color: #ef5350;
  }
  .filter-status {
    color: #888;
    font-size: 12px;
    white-space: nowrap;
  }
  .filter-status.filtering {
    color: #ffa726;
  }
</style>
