<script>
  import { displayFilter, filterStatus } from '../stores/filters.js';
  import { applyDisplayFilter, filteredPackets, packets } from '../stores/packets.js';

  let localFilter = '';
  let debounceTimer = null;
  let filtering = false;

  $: $displayFilter = localFilter;

  async function onFilterInput(e) {
    localFilter = e.target.value;
    if (debounceTimer) clearTimeout(debounceTimer);

    if (!localFilter.trim()) {
      $filteredPackets = $packets;
      $filterStatus = '';
      return;
    }

    filtering = true;
    $filterStatus = '过滤中...';

    debounceTimer = setTimeout(async () => {
      const start = performance.now();
      const success = await applyDisplayFilter(localFilter);
      const elapsed = performance.now() - start;

      if (success) {
        $filterStatus = `已过滤 (${$filteredPackets.length}/${$packets.length}) ${elapsed.toFixed(0)}ms`;
      } else {
        $filterStatus = '过滤表达式错误';
      }
      filtering = false;
    }, 300);
  }

  function clearFilter() {
    localFilter = '';
    $filteredPackets = $packets;
    $filterStatus = '';
  }
</script>

<div class="display-filter">
  <label>显示过滤:</label>
  <input
    type="text"
    placeholder="例: http, ip.src==192.168.1.1, tcp.port==443, dns and not port 53"
    value={localFilter}
    on:input={onFilterInput}
  />
  {#if localFilter}
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
  input[type="text"] {
    flex: 1;
    background: #1e1e1e;
    color: #e0e0e0;
    border: 1px solid #555;
    border-radius: 4px;
    padding: 5px 10px;
    font-size: 13px;
    font-family: 'Menlo', 'Consolas', 'Monaco', monospace;
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
