<script>
  import { onMount } from 'svelte';
  import {
    attackPatterns,
    loadAttackPatterns,
    addAttackPattern,
    updateAttackPattern,
    deleteAttackPattern,
    runPatternAgainstEngine,
    generateEffectivenessReport,
    generateHeatmap,
    ATTACK_CATEGORIES,
    isGeneratingTraffic,
    isRunningReport,
    simSpeed,
    heatmapData,
    isGeneratingHeatmap,
    heatmapProgress,
  } from '../stores/attack_patterns.js';
  import { SPEED_OPTIONS, setReplaySpeed } from '../stores/replay.js';
  import { loadPacketDetail, selectedPacketNo } from '../stores/packets.js';

  let categoryFilter = 'all';
  let showAddDialog = false;
  let showEditDialog = false;
  let selectedPatternIds = new Set();
  let targetIp = '127.0.0.1';
  let editingPattern = null;
  let heatmapTooltip = null;
  let heatmapCellDetail = null;

  let newPattern = {
    name: '',
    category: 'custom',
    description: '',
    params: defaultParams(),
  };

  function defaultParams() {
    return {
      targetIp: null,
      targetPortMin: 1,
      targetPortMax: 1024,
      sourcePortMin: 1024,
      sourcePortMax: 65535,
      packetCount: 100,
      packetsPerSecond: 10,
      protocol: 'TCP',
      payloadPattern: null,
      randomSourceIp: true,
      tcpFlags: null,
      dnsDomain: null,
      httpMethod: null,
      httpPath: null,
    };
  }

  onMount(() => {
    loadAttackPatterns();
  });

  $: filteredPatterns = categoryFilter === 'all'
    ? $attackPatterns
    : $attackPatterns.filter(p => snakeCategory(p.category) === categoryFilter);

  function snakeCategory(cat) {
    const map = {
      '端口扫描': 'port_scan',
      'SYN洪泛': 'syn_flood',
      'DNS放大': 'dns_amplification',
      '暴力破解': 'brute_force',
      'ARP欺骗': 'arp_spoof',
      'HTTP洪泛': 'http_flood',
      'UDP洪泛': 'udp_flood',
      'ICMP洪泛': 'icmp_flood',
      'SlowLoris': 'slow_loris',
      '自定义': 'custom',
    };
    if (typeof cat === 'string') {
      return map[cat] || cat.toLowerCase().replace(/\s+/g, '_');
    }
    const key = Object.keys(map).find(k => map[k] === cat || cat === cat);
    return map[cat] || 'custom';
  }

  function toggleSelect(patternId, event) {
    if (event && (event.ctrlKey || event.metaKey || event.shiftKey)) {
      if (selectedPatternIds.has(patternId)) {
        selectedPatternIds.delete(patternId);
      } else {
        selectedPatternIds.add(patternId);
      }
    } else {
      selectedPatternIds.clear();
      selectedPatternIds.add(patternId);
    }
    selectedPatternIds = new Set(selectedPatternIds);
  }

  function selectAllPatterns() {
    selectedPatternIds = new Set(filteredPatterns.map(p => p.id));
  }

  function clearPatternSelection() {
    selectedPatternIds = new Set();
  }

  function openAddDialog() {
    newPattern = {
      name: '',
      category: 'custom',
      description: '',
      params: defaultParams(),
    };
    showAddDialog = true;
  }

  function closeAddDialog() {
    showAddDialog = false;
  }

  function openEditDialog(pattern) {
    editingPattern = JSON.parse(JSON.stringify(pattern));
    if (editingPattern.params.tcpFlags && !Array.isArray(editingPattern.params.tcpFlags)) {
      editingPattern.params.tcpFlags = editingPattern.params.tcpFlags;
    }
    showEditDialog = true;
  }

  function closeEditDialog() {
    showEditDialog = false;
    editingPattern = null;
  }

  async function handleAdd() {
    if (!newPattern.name.trim()) {
      alert('请输入特征名称');
      return;
    }
    const pattern = {
      id: 'custom_' + Date.now(),
      name: newPattern.name.trim(),
      category: mapCategoryValue(newPattern.category),
      description: newPattern.description,
      params: mapParams(newPattern.params),
      is_builtin: false,
    };
    const ok = await addAttackPattern(pattern);
    if (ok) {
      closeAddDialog();
    } else {
      alert('添加失败');
    }
  }

  async function handleUpdate() {
    if (!editingPattern.name.trim()) {
      alert('请输入特征名称');
      return;
    }
    const pattern = {
      ...editingPattern,
      category: mapCategoryValue(typeof editingPattern.category === 'string'
        ? editingPattern.category
        : snakeCategory(editingPattern.category)),
      params: mapParams(editingPattern.params),
    };
    const ok = await updateAttackPattern(pattern);
    if (ok) {
      closeEditDialog();
    } else {
      alert('更新失败');
    }
  }

  async function handleDelete(pattern) {
    if (pattern.is_builtin) {
      alert('内置特征不可删除');
      return;
    }
    if (!confirm(`确定删除特征 "${pattern.name}" 吗？`)) return;
    await deleteAttackPattern(pattern.id);
  }

  function mapCategoryValue(v) {
    if (typeof v === 'object' && v !== null) return v;
    const map = {
      'port_scan': { type: 'port_scan' },
      'syn_flood': { type: 'syn_flood' },
      'dns_amplification': { type: 'dns_amplification' },
      'brute_force': { type: 'brute_force' },
      'arp_spoof': { type: 'arp_spoof' },
      'http_flood': { type: 'http_flood' },
      'udp_flood': { type: 'udp_flood' },
      'icmp_flood': { type: 'icmp_flood' },
      'slow_loris': { type: 'slow_loris' },
      'custom': { type: 'custom' },
    };
    return map[v] || { type: 'custom' };
  }

  function mapParams(p) {
    let tcpFlags = p.tcpFlags;
    if (typeof tcpFlags === 'string' && tcpFlags.trim()) {
      tcpFlags = tcpFlags.split(',').map(s => s.trim().toUpperCase()).filter(Boolean);
    } else if (!Array.isArray(tcpFlags) || tcpFlags.length === 0) {
      tcpFlags = null;
    }
    return {
      target_ip: p.targetIp || null,
      target_port_min: Number(p.targetPortMin) || 1,
      target_port_max: Number(p.targetPortMax) || 1024,
      source_port_min: Number(p.sourcePortMin) || 1024,
      source_port_max: Number(p.sourcePortMax) || 65535,
      packet_count: Number(p.packetCount) || 100,
      packets_per_second: Number(p.packetsPerSecond) || 10,
      protocol: p.protocol || 'TCP',
      payload_pattern: p.payloadPattern || null,
      random_source_ip: !!p.randomSourceIp,
      tcp_flags: tcpFlags,
      dns_domain: p.dnsDomain || null,
      http_method: p.httpMethod || null,
      http_path: p.httpPath || null,
    };
  }

  function categoryLabel(cat) {
    if (typeof cat === 'string') {
      const found = ATTACK_CATEGORIES.find(c => c.value === cat || c.label === cat);
      return found ? found.label : cat;
    }
    const map = {
      port_scan: '端口扫描',
      syn_flood: 'SYN洪泛',
      dns_amplification: 'DNS放大',
      brute_force: '暴力破解',
      arp_spoof: 'ARP欺骗',
      http_flood: 'HTTP洪泛',
      udp_flood: 'UDP洪泛',
      icmp_flood: 'ICMP洪泛',
      slow_loris: 'SlowLoris',
      custom: '自定义',
    };
    if (cat && cat.type) return map[cat.type] || '自定义';
    if (cat && typeof cat === 'object') {
      const key = Object.keys(cat)[0];
      return map[key] || map[cat[key]] || '自定义';
    }
    return map[String(cat)] || '自定义';
  }

  function categoryColorClass(cat) {
    const key = typeof cat === 'string' ? cat : (cat && cat.type ? cat.type : 'custom');
    const colorMap = {
      port_scan: 'cat-portscan',
      syn_flood: 'cat-synflood',
      dns_amplification: 'cat-dns',
      brute_force: 'cat-brute',
      arp_spoof: 'cat-arp',
      http_flood: 'cat-http',
      udp_flood: 'cat-udp',
      icmp_flood: 'cat-icmp',
      slow_loris: 'cat-slow',
      custom: 'cat-custom',
    };
    return colorMap[key] || 'cat-custom';
  }

  async function handleRunPattern(pattern) {
    try {
      await runPatternAgainstEngine(pattern.id, targetIp, $simSpeed);
    } catch (e) {
      alert('执行失败: ' + e);
    }
  }

  function handleSimSpeedChange(e) {
    const val = e.target.value;
    simSpeed.set(val);
    setReplaySpeed(val);
  }

  async function handleRunReport() {
    if (selectedPatternIds.size === 0) {
      alert('请先选择至少一个攻击特征');
      return;
    }
    try {
      await generateEffectivenessReport(Array.from(selectedPatternIds), targetIp);
    } catch (e) {
      alert('生成报告失败: ' + e);
    }
  }

  async function handleGenerateHeatmap() {
    try {
      await generateHeatmap();
    } catch (e) {
      alert('生成热力图失败: ' + e);
    }
  }

  function getHeatmapCellColor(count) {
    if (count === 0) return 'h0';
    if (count <= 5) return 'h1';
    if (count <= 20) return 'h2';
    return 'h3';
  }

  function handleHeatmapMouseEnter(event, cell) {
    const rect = event.target.getBoundingClientRect();
    heatmapTooltip = {
      x: rect.left,
      y: rect.top - 4,
      patternName: cell.pattern_name,
      ruleName: cell.rule_name,
      count: cell.trigger_count,
      packetNos: cell.triggered_packet_nos,
    };
  }

  function handleHeatmapMouseLeave() {
    heatmapTooltip = null;
  }

  function handleHeatmapCellClick(cell) {
    if (cell.trigger_count === 0) return;
    heatmapCellDetail = cell;
  }

  function closeHeatmapCellDetail() {
    heatmapCellDetail = null;
  }

  function handlePacketClick(packetNo) {
    closeHeatmapCellDetail();
    loadPacketDetail(packetNo);
  }

  $: heatmapMatrix = (() => {
    if (!$heatmapData) return null;
    const { pattern_ids, rule_ids, cells } = $heatmapData;
    const matrix = {};
    for (const cell of cells) {
      const key = cell.pattern_id + '|' + cell.rule_id;
      matrix[key] = cell;
    }
    return { patternIds: pattern_ids, ruleIds: rule_ids, lookup: matrix };
  })();

  $: selectedCount = selectedPatternIds.size;

  function getCategoryString(cat) {
    if (typeof cat === 'string') return cat;
    if (cat && cat.type) return cat.type;
    return 'custom';
  }
</script>

<div class="attack-pattern-panel">
  <div class="panel-header">
    <h3>⚔️ 攻击特征库</h3>
    <div class="header-actions">
      <label class="target-ip-label">
        目标IP:
        <input type="text" bind:value={targetIp} placeholder="127.0.0.1" />
      </label>
      <label class="speed-label">
        速度:
        <select value={$simSpeed} on:change={handleSimSpeedChange} class="speed-select">
          {#each SPEED_OPTIONS as opt}
            <option value={opt.value}>{opt.label}</option>
          {/each}
        </select>
      </label>
      <button class="btn-report" disabled={selectedCount === 0 || $isRunningReport} on:click={handleRunReport}>
        {$isRunningReport ? '⏳ 生成中...' : '📊 规则有效性报告'}
        {selectedCount > 0 && !$isRunningReport && `(${selectedCount})`}
      </button>
      <button class="btn-add" on:click={openAddDialog}>➕ 新增特征</button>
    </div>
  </div>

  <div class="filter-bar">
    <span class="filter-label">分类筛选:</span>
    <select bind:value={categoryFilter}>
      <option value="all">全部</option>
      {#each ATTACK_CATEGORIES as cat}
        <option value={cat.value}>{cat.label}</option>
      {/each}
    </select>
    <div class="spacer"></div>
    {#if selectedCount > 0}
      <button class="btn-small" on:click={clearPatternSelection}>取消选择({selectedCount})</button>
    {/if}
    <button class="btn-small" on:click={selectAllPatterns}>全选当前</button>
    <button class="btn-small" on:click={() => loadAttackPatterns(categoryFilter === 'all' ? null : categoryFilter)}>🔄 刷新</button>
  </div>

  <div class="patterns-list">
    {#if filteredPatterns.length === 0}
      <div class="empty">暂无攻击特征</div>
    {:else}
      {#each filteredPatterns as pattern (pattern.id)}
        <div
          class="pattern-card {selectedPatternIds.has(pattern.id) ? 'selected' : ''}"
          on:click={(e) => toggleSelect(pattern.id, e)}
        >
          <div class="card-header">
            <div class="card-title">
              <input
                type="checkbox"
                checked={selectedPatternIds.has(pattern.id)}
                on:click|stopPropagation
                on:change={(e) => {
                  if (e.target.checked) selectedPatternIds.add(pattern.id);
                  else selectedPatternIds.delete(pattern.id);
                  selectedPatternIds = new Set(selectedPatternIds);
                }}
              />
              <span class="pattern-name">{pattern.name}</span>
              {#if pattern.is_builtin}
                <span class="badge-builtin">内置</span>
              {:else}
                <span class="badge-custom">自定义</span>
              {/if}
            </div>
            <span class="category-tag {categoryColorClass(pattern.category)}">{categoryLabel(pattern.category)}</span>
          </div>
          <div class="card-description">{pattern.description || '无描述'}</div>
          <div class="card-params">
            <span class="param">协议: <b>{pattern.params.protocol}</b></span>
            <span class="param">端口: <b>{pattern.params.target_port_min}-{pattern.params.target_port_max}</b></span>
            <span class="param">包数: <b>{pattern.params.packet_count}</b></span>
            <span class="param">速率: <b>{pattern.params.packets_per_second}/s</b></span>
          </div>
          <div class="card-actions">
            <button
              class="btn-run"
              disabled={$isGeneratingTraffic}
              on:click|stopPropagation={() => handleRunPattern(pattern)}
            >
              {$isGeneratingTraffic ? '⏳ 生成中...' : '▶️ 生成模拟流量并检测'}
            </button>
            {#if !pattern.is_builtin}
              <button class="btn-edit" on:click|stopPropagation={() => openEditDialog(pattern)}>✏️ 编辑</button>
              <button class="btn-delete" on:click|stopPropagation={() => handleDelete(pattern)}>🗑️ 删除</button>
            {/if}
          </div>
        </div>
      {/each}
    {/if}
  </div>

  <div class="heatmap-section">
    <div class="heatmap-header">
      <h4>🗺️ 规则覆盖热力图</h4>
      <button
        class="btn-heatmap"
        disabled={$isGeneratingHeatmap}
        on:click={handleGenerateHeatmap}
      >
        {$isGeneratingHeatmap ? '⏳ 生成中...' : '🔥 生成热力图'}
      </button>
    </div>
    {#if $heatmapProgress}
      <div class="heatmap-progress">
        正在分析第 {$heatmapProgress.current + 1}/{$heatmapProgress.total} 条特征 ({$heatmapProgress.pattern_name})
      </div>
    {/if}
    {#if heatmapMatrix && heatmapMatrix.patternIds.length > 0 && heatmapMatrix.ruleIds.length > 0}
      <div class="heatmap-wrapper">
        <table class="heatmap-table">
          <thead>
            <tr>
              <th class="corner-cell">特征\规则</th>
              {#each heatmapMatrix.ruleIds as rid, ri}
                <th class="rule-col" title={$heatmapData.rule_names[ri]}>
                  {$heatmapData.rule_names[ri].length > 8 ? $heatmapData.rule_names[ri].slice(0, 8) + '…' : $heatmapData.rule_names[ri]}
                </th>
              {/each}
            </tr>
          </thead>
          <tbody>
            {#each heatmapMatrix.patternIds as pid, pi}
              <tr>
                <td class="pattern-cell" title={$heatmapData.pattern_names[pi]}>
                  {$heatmapData.pattern_names[pi].length > 12 ? $heatmapData.pattern_names[pi].slice(0, 12) + '…' : $heatmapData.pattern_names[pi]}
                </td>
                {#each heatmapMatrix.ruleIds as rid, ri}
                  {@const cell = heatmapMatrix.lookup[pid + '|' + rid]}
                  <td
                    class="heatmap-cell {cell ? getHeatmapCellColor(cell.trigger_count) : 'h0'}"
                    on:mouseenter={(e) => cell && handleHeatmapMouseEnter(e, cell)}
                    on:mouseleave={handleHeatmapMouseLeave}
                    on:click={() => cell && handleHeatmapCellClick(cell)}
                  >
                    {cell ? cell.trigger_count : 0}
                  </td>
                {/each}
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      <div class="heatmap-legend">
        <span class="legend-item"><span class="legend-box h0"></span> 0次</span>
        <span class="legend-item"><span class="legend-box h1"></span> 1-5次</span>
        <span class="legend-item"><span class="legend-box h2"></span> 6-20次</span>
        <span class="legend-item"><span class="legend-box h3"></span> >20次</span>
      </div>
    {:else if !$isGeneratingHeatmap && $heatmapData}
      <div class="heatmap-empty">暂无数据，请先生成热力图</div>
    {/if}
  </div>
</div>

{#if heatmapTooltip}
  <div class="heatmap-tooltip" style="left:{heatmapTooltip.x}px; top:{heatmapTooltip.y}px;">
    <div><b>{heatmapTooltip.patternName}</b> × <b>{heatmapTooltip.ruleName}</b></div>
    <div>触发次数: {heatmapTooltip.count}</div>
    {#if heatmapTooltip.packetNos && heatmapTooltip.packetNos.length > 0}
      <div class="tooltip-packets">包编号: {heatmapTooltip.packetNos.slice(0, 10).map(n => '#' + n).join(', ')}{heatmapTooltip.packetNos.length > 10 ? '...' : ''}</div>
    {/if}
  </div>
{/if}

{#if heatmapCellDetail}
  <div class="cell-detail-overlay" on:click={closeHeatmapCellDetail}>
    <div class="cell-detail-dialog" on:click|stopPropagation>
      <div class="dialog-header">
        <h3>📋 触发包详情</h3>
        <button class="btn-close" on:click={closeHeatmapCellDetail}>✕</button>
      </div>
      <div class="cell-detail-body">
        <div class="cell-detail-info">
          <span><b>特征:</b> {heatmapCellDetail.pattern_name}</span>
          <span><b>规则:</b> {heatmapCellDetail.rule_name}</span>
          <span><b>触发次数:</b> {heatmapCellDetail.trigger_count}</span>
        </div>
        <div class="cell-detail-packets">
          <span class="packet-label">触发包编号:</span>
          {#each heatmapCellDetail.triggered_packet_nos as pktNo}
            <button
              class="packet-btn"
              class:active={$selectedPacketNo === pktNo}
              on:click={() => handlePacketClick(pktNo)}
            >
              #{pktNo}
            </button>
          {/each}
        </div>
      </div>
    </div>
  </div>
{/if}

{#if showAddDialog}
  <div class="dialog-overlay" on:click={closeAddDialog}>
    <div class="dialog" on:click|stopPropagation>
      <h3>➕ 新增攻击特征</h3>
      <div class="form-body">
        <div class="form-group">
          <label>特征名称 *</label>
          <input type="text" bind:value={newPattern.name} placeholder="例如: 自定义端口扫描" />
        </div>
        <div class="form-group">
          <label>分类</label>
          <select bind:value={newPattern.category}>
            {#each ATTACK_CATEGORIES as cat}
              <option value={cat.value}>{cat.label}</option>
            {/each}
          </select>
        </div>
        <div class="form-group">
          <label>描述</label>
          <textarea bind:value={newPattern.description} rows="2" placeholder="描述该攻击特征..."></textarea>
        </div>
        <h4 class="params-title">生成参数</h4>
        <div class="params-grid">
          <div class="form-group">
            <label>协议类型</label>
            <select bind:value={newPattern.params.protocol}>
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
              <option value="ICMP">ICMP</option>
              <option value="HTTP">HTTP</option>
              <option value="DNS">DNS</option>
              <option value="ARP">ARP</option>
              <option value="TLS">TLS</option>
            </select>
          </div>
          <div class="form-group">
            <label>目标端口范围(最小)</label>
            <input type="number" bind:value={newPattern.params.targetPortMin} min="1" max="65535" />
          </div>
          <div class="form-group">
            <label>目标端口范围(最大)</label>
            <input type="number" bind:value={newPattern.params.targetPortMax} min="1" max="65535" />
          </div>
          <div class="form-group">
            <label>源端口范围(最小)</label>
            <input type="number" bind:value={newPattern.params.sourcePortMin} min="1" max="65535" />
          </div>
          <div class="form-group">
            <label>源端口范围(最大)</label>
            <input type="number" bind:value={newPattern.params.sourcePortMax} min="1" max="65535" />
          </div>
          <div class="form-group">
            <label>数据包数量</label>
            <input type="number" bind:value={newPattern.params.packetCount} min="1" />
          </div>
          <div class="form-group">
            <label>每秒包数(速率)</label>
            <input type="number" bind:value={newPattern.params.packetsPerSecond} min="1" />
          </div>
          <div class="form-group checkbox-group">
            <label>
              <input type="checkbox" bind:checked={newPattern.params.randomSourceIp} />
              随机源IP
            </label>
          </div>
          <div class="form-group">
            <label>TCP标志 (逗号分隔, 如 SYN,ACK)</label>
            <input type="text" bind:value={newPattern.params.tcpFlags} placeholder="SYN" />
          </div>
          <div class="form-group">
            <label>HTTP方法</label>
            <input type="text" bind:value={newPattern.params.httpMethod} placeholder="GET / POST / ..." />
          </div>
          <div class="form-group">
            <label>HTTP路径</label>
            <input type="text" bind:value={newPattern.params.httpPath} placeholder="/" />
          </div>
          <div class="form-group">
            <label>DNS查询域名</label>
            <input type="text" bind:value={newPattern.params.dnsDomain} placeholder="example.com" />
          </div>
          <div class="form-group full-width">
            <label>载荷关键字/模式</label>
            <input type="text" bind:value={newPattern.params.payloadPattern} placeholder="可选的载荷内容" />
          </div>
        </div>
      </div>
      <div class="dialog-actions">
        <button class="btn-cancel" on:click={closeAddDialog}>取消</button>
        <button class="btn-confirm" on:click={handleAdd}>添加</button>
      </div>
    </div>
  </div>
{/if}

{#if showEditDialog && editingPattern}
  <div class="dialog-overlay" on:click={closeEditDialog}>
    <div class="dialog" on:click|stopPropagation>
      <h3>✏️ 编辑攻击特征</h3>
      <div class="form-body">
        <div class="form-group">
          <label>特征名称 *</label>
          <input type="text" bind:value={editingPattern.name} />
        </div>
        <div class="form-group">
          <label>分类</label>
          <select bind:value={editingPattern.category}>
            {#each ATTACK_CATEGORIES as cat}
              <option value={cat.value} selected={getCategoryString(editingPattern.category) === cat.value}>{cat.label}</option>
            {/each}
          </select>
        </div>
        <div class="form-group">
          <label>描述</label>
          <textarea bind:value={editingPattern.description} rows="2"></textarea>
        </div>
        <h4 class="params-title">生成参数</h4>
        <div class="params-grid">
          <div class="form-group">
            <label>协议类型</label>
            <select bind:value={editingPattern.params.protocol}>
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
              <option value="ICMP">ICMP</option>
              <option value="HTTP">HTTP</option>
              <option value="DNS">DNS</option>
              <option value="ARP">ARP</option>
              <option value="TLS">TLS</option>
            </select>
          </div>
          <div class="form-group">
            <label>目标端口范围(最小)</label>
            <input type="number" bind:value={editingPattern.params.target_port_min} min="1" max="65535" />
          </div>
          <div class="form-group">
            <label>目标端口范围(最大)</label>
            <input type="number" bind:value={editingPattern.params.target_port_max} min="1" max="65535" />
          </div>
          <div class="form-group">
            <label>源端口范围(最小)</label>
            <input type="number" bind:value={editingPattern.params.source_port_min} min="1" max="65535" />
          </div>
          <div class="form-group">
            <label>源端口范围(最大)</label>
            <input type="number" bind:value={editingPattern.params.source_port_max} min="1" max="65535" />
          </div>
          <div class="form-group">
            <label>数据包数量</label>
            <input type="number" bind:value={editingPattern.params.packet_count} min="1" />
          </div>
          <div class="form-group">
            <label>每秒包数(速率)</label>
            <input type="number" bind:value={editingPattern.params.packets_per_second} min="1" />
          </div>
          <div class="form-group checkbox-group">
            <label>
              <input type="checkbox" bind:checked={editingPattern.params.random_source_ip} />
              随机源IP
            </label>
          </div>
          <div class="form-group">
            <label>TCP标志 (逗号分隔)</label>
            <input type="text" bind:value={editingPattern.params.tcp_flags} />
          </div>
          <div class="form-group">
            <label>HTTP方法</label>
            <input type="text" bind:value={editingPattern.params.http_method} />
          </div>
          <div class="form-group">
            <label>HTTP路径</label>
            <input type="text" bind:value={editingPattern.params.http_path} />
          </div>
          <div class="form-group">
            <label>DNS查询域名</label>
            <input type="text" bind:value={editingPattern.params.dns_domain} />
          </div>
          <div class="form-group full-width">
            <label>载荷关键字/模式</label>
            <input type="text" bind:value={editingPattern.params.payload_pattern} />
          </div>
        </div>
      </div>
      <div class="dialog-actions">
        <button class="btn-cancel" on:click={closeEditDialog}>取消</button>
        <button class="btn-confirm" on:click={handleUpdate}>保存</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .attack-pattern-panel {
    height: 100%;
    display: flex;
    flex-direction: column;
    background: #1e1e1e;
  }
  .panel-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 16px;
    background: #2d2d2d;
    border-bottom: 1px solid #444;
  }
  .panel-header h3 {
    color: #eee;
    font-size: 14px;
    margin: 0;
    font-weight: 500;
  }
  .header-actions {
    display: flex;
    gap: 8px;
    align-items: center;
  }
  .target-ip-label {
    color: #aaa;
    font-size: 12px;
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .target-ip-label input {
    background: #1e1e1e;
    color: #ddd;
    border: 1px solid #555;
    border-radius: 4px;
    padding: 4px 8px;
    font-size: 12px;
    width: 120px;
    font-family: monospace;
  }
  .speed-label {
    color: #aaa;
    font-size: 12px;
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .speed-select {
    background: #1e1e1e;
    color: #ddd;
    border: 1px solid #555;
    border-radius: 4px;
    padding: 4px 8px;
    font-size: 12px;
  }
  .btn-add, .btn-report {
    background: #2e7d32;
    color: #fff;
    border: none;
    border-radius: 4px;
    padding: 6px 12px;
    cursor: pointer;
    font-size: 12px;
  }
  .btn-report {
    background: #1565c0;
  }
  .btn-report:disabled, .btn-add:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .btn-add:hover:not(:disabled) { background: #388e3c; }
  .btn-report:hover:not(:disabled) { background: #1976d2; }
  .filter-bar {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 16px;
    background: #252525;
    border-bottom: 1px solid #3a3a3a;
  }
  .filter-label {
    color: #aaa;
    font-size: 12px;
  }
  .filter-bar select {
    background: #1e1e1e;
    color: #ddd;
    border: 1px solid #555;
    border-radius: 4px;
    padding: 4px 8px;
    font-size: 12px;
  }
  .spacer { flex: 1; }
  .btn-small {
    background: #3a3a3a;
    color: #ccc;
    border: 1px solid #555;
    border-radius: 4px;
    padding: 3px 10px;
    cursor: pointer;
    font-size: 11px;
  }
  .btn-small:hover { background: #4a4a4a; }
  .patterns-list {
    flex: 1;
    overflow-y: auto;
    padding: 12px 16px;
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
    gap: 12px;
    align-content: start;
  }
  .empty {
    grid-column: 1 / -1;
    text-align: center;
    color: #666;
    padding: 40px;
    font-size: 14px;
  }
  .pattern-card {
    background: #2a2a2a;
    border: 1px solid #3a3a3a;
    border-radius: 6px;
    padding: 12px;
    cursor: pointer;
    transition: all 0.15s;
  }
  .pattern-card:hover {
    border-color: #555;
    background: #303030;
  }
  .pattern-card.selected {
    border-color: #1976d2;
    background: #1e3a5f;
  }
  .card-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 6px;
  }
  .card-title {
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
  }
  .pattern-name {
    color: #fff;
    font-weight: 600;
    font-size: 13px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .badge-builtin {
    background: #1b5e20;
    color: #a5d6a7;
    font-size: 10px;
    padding: 1px 6px;
    border-radius: 3px;
    flex-shrink: 0;
  }
  .badge-custom {
    background: #e65100;
    color: #ffcc80;
    font-size: 10px;
    padding: 1px 6px;
    border-radius: 3px;
    flex-shrink: 0;
  }
  .category-tag {
    font-size: 11px;
    padding: 2px 8px;
    border-radius: 3px;
    flex-shrink: 0;
    font-weight: 500;
  }
  .cat-portscan { background: #311b92; color: #b39ddb; }
  .cat-synflood { background: #b71c1c; color: #ef9a9a; }
  .cat-dns { background: #006064; color: #80deea; }
  .cat-brute { background: #4a148c; color: #ce93d8; }
  .cat-arp { background: #bf360c; color: #ffab91; }
  .cat-http { background: #0d47a1; color: #90caf9; }
  .cat-udp { background: #004d40; color: #80cbc4; }
  .cat-icmp { background: #880e4f; color: #f48fb1; }
  .cat-slow { background: #33691e; color: #c5e1a5; }
  .cat-custom { background: #3e2723; color: #d7ccc8; }
  .card-description {
    color: #999;
    font-size: 12px;
    margin-bottom: 8px;
    line-height: 1.4;
    min-height: 16px;
  }
  .card-params {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin-bottom: 10px;
  }
  .param {
    color: #888;
    font-size: 11px;
  }
  .param b {
    color: #bbb;
    font-family: monospace;
  }
  .card-actions {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
  }
  .btn-run, .btn-edit, .btn-delete {
    border: none;
    border-radius: 4px;
    padding: 5px 10px;
    cursor: pointer;
    font-size: 11px;
  }
  .btn-run {
    background: #1565c0;
    color: #fff;
    flex: 1;
  }
  .btn-run:hover:not(:disabled) { background: #1976d2; }
  .btn-run:disabled { opacity: 0.5; cursor: not-allowed; }
  .btn-edit { background: #444; color: #ccc; }
  .btn-edit:hover { background: #555; }
  .btn-delete { background: #5d1b1b; color: #ef9a9a; }
  .btn-delete:hover { background: #7a2525; }

  .heatmap-section {
    border-top: 1px solid #444;
    background: #252525;
    padding: 12px 16px;
    max-height: 300px;
    overflow-y: auto;
  }
  .heatmap-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 8px;
  }
  .heatmap-header h4 {
    color: #ccc;
    font-size: 13px;
    margin: 0;
  }
  .btn-heatmap {
    background: #e65100;
    color: #fff;
    border: none;
    border-radius: 4px;
    padding: 5px 12px;
    cursor: pointer;
    font-size: 12px;
  }
  .btn-heatmap:hover:not(:disabled) { background: #f57c00; }
  .btn-heatmap:disabled { opacity: 0.5; cursor: not-allowed; }
  .heatmap-progress {
    color: #4fc3f7;
    font-size: 12px;
    margin-bottom: 8px;
    animation: pulse 1.5s ease-in-out infinite;
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
  }
  .heatmap-wrapper {
    overflow-x: auto;
    margin-bottom: 8px;
  }
  .heatmap-table {
    border-collapse: collapse;
    font-size: 11px;
  }
  .corner-cell {
    background: #333;
    color: #aaa;
    padding: 4px 6px;
    font-size: 10px;
    position: sticky;
    top: 0;
    left: 0;
    z-index: 3;
  }
  .rule-col {
    background: #333;
    color: #aaa;
    padding: 4px 6px;
    font-size: 10px;
    position: sticky;
    top: 0;
    z-index: 2;
    min-width: 50px;
    max-width: 70px;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .pattern-cell {
    background: #2a2a2a;
    color: #ccc;
    padding: 4px 6px;
    font-size: 10px;
    position: sticky;
    left: 0;
    z-index: 1;
    white-space: nowrap;
    max-width: 100px;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .heatmap-cell {
    padding: 4px 6px;
    text-align: center;
    cursor: pointer;
    border: 1px solid #333;
    min-width: 36px;
    transition: opacity 0.15s;
  }
  .heatmap-cell:hover {
    opacity: 0.8;
    outline: 2px solid #4fc3f7;
  }
  .heatmap-cell.h0 { background: #3a3a3a; color: #666; }
  .heatmap-cell.h1 { background: #2e7d32; color: #c8e6c9; }
  .heatmap-cell.h2 { background: #1b5e20; color: #a5d6a7; }
  .heatmap-cell.h3 { background: #0a3d0a; color: #69f069; font-weight: 600; }
  .heatmap-legend {
    display: flex;
    gap: 14px;
    align-items: center;
    font-size: 11px;
    color: #aaa;
  }
  .legend-item {
    display: flex;
    align-items: center;
    gap: 4px;
  }
  .legend-box {
    display: inline-block;
    width: 14px;
    height: 14px;
    border-radius: 2px;
  }
  .legend-box.h0 { background: #3a3a3a; }
  .legend-box.h1 { background: #2e7d32; }
  .legend-box.h2 { background: #1b5e20; }
  .legend-box.h3 { background: #0a3d0a; }
  .heatmap-empty {
    color: #666;
    text-align: center;
    padding: 20px;
    font-size: 12px;
  }

  .heatmap-tooltip {
    position: fixed;
    background: #1e1e1e;
    border: 1px solid #555;
    border-radius: 6px;
    padding: 8px 12px;
    font-size: 12px;
    color: #ddd;
    z-index: 5000;
    pointer-events: none;
    transform: translate(-50%, -100%);
    box-shadow: 0 4px 12px rgba(0,0,0,0.5);
    max-width: 300px;
  }
  .heatmap-tooltip b { color: #4fc3f7; }
  .tooltip-packets {
    color: #aaa;
    font-size: 11px;
    margin-top: 4px;
  }

  .cell-detail-overlay {
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(0,0,0,0.6);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 4000;
  }
  .cell-detail-dialog {
    background: #2d2d2d;
    border: 1px solid #555;
    border-radius: 8px;
    width: 600px;
    max-width: 90vw;
    max-height: 70vh;
    overflow-y: auto;
    box-shadow: 0 8px 32px rgba(0,0,0,0.6);
  }
  .cell-detail-dialog .dialog-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 12px 18px;
    background: #1e1e1e;
    border-bottom: 1px solid #444;
  }
  .cell-detail-dialog .dialog-header h3 {
    margin: 0;
    color: #eee;
    font-size: 14px;
  }
  .cell-detail-dialog .btn-close {
    background: transparent;
    border: none;
    color: #888;
    font-size: 16px;
    cursor: pointer;
  }
  .cell-detail-dialog .btn-close:hover { color: #eee; }
  .cell-detail-body {
    padding: 16px 18px;
  }
  .cell-detail-info {
    display: flex;
    gap: 16px;
    flex-wrap: wrap;
    margin-bottom: 12px;
    font-size: 13px;
    color: #ccc;
  }
  .cell-detail-info b { color: #4fc3f7; }
  .cell-detail-packets {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    align-items: center;
  }
  .packet-label {
    color: #888;
    font-size: 12px;
    margin-right: 4px;
  }
  .packet-btn {
    background: #1e3a5f;
    color: #90caf9;
    border: 1px solid #2a5080;
    border-radius: 3px;
    padding: 1px 6px;
    cursor: pointer;
    font-size: 11px;
    font-family: monospace;
  }
  .packet-btn:hover {
    background: #2a5080;
    border-color: #4fc3f7;
  }
  .packet-btn.active {
    background: #1565c0;
    border-color: #4fc3f7;
    color: #fff;
  }

  .dialog-overlay {
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(0,0,0,0.7);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 3000;
  }
  .dialog {
    background: #2d2d2d;
    border: 1px solid #555;
    border-radius: 8px;
    padding: 20px 24px;
    width: 640px;
    max-width: 95vw;
    max-height: 90vh;
    overflow-y: auto;
    box-shadow: 0 8px 32px rgba(0,0,0,0.6);
  }
  .dialog h3 {
    color: #eee;
    margin: 0 0 16px 0;
    font-size: 16px;
  }
  .form-body { margin-bottom: 16px; }
  .form-group {
    margin-bottom: 12px;
  }
  .form-group label {
    display: block;
    color: #aaa;
    font-size: 12px;
    margin-bottom: 4px;
  }
  .form-group input[type="text"],
  .form-group input[type="number"],
  .form-group select,
  .form-group textarea {
    width: 100%;
    box-sizing: border-box;
    background: #1e1e1e;
    color: #e0e0e0;
    border: 1px solid #555;
    border-radius: 4px;
    padding: 6px 10px;
    font-size: 13px;
  }
  .form-group input:focus, .form-group select:focus, .form-group textarea:focus {
    outline: none;
    border-color: #4fc3f7;
  }
  .checkbox-group label {
    display: flex;
    align-items: center;
    gap: 6px;
    color: #ccc;
    font-size: 13px;
  }
  .params-title {
    color: #888;
    font-size: 13px;
    margin: 14px 0 8px 0;
    padding-top: 10px;
    border-top: 1px solid #444;
  }
  .params-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
  }
  .params-grid .full-width { grid-column: 1 / -1; }
  .dialog-actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    padding-top: 12px;
    border-top: 1px solid #444;
  }
  .btn-cancel {
    padding: 7px 18px;
    background: #3a3a3a;
    border: 1px solid #555;
    border-radius: 4px;
    color: #ccc;
    cursor: pointer;
    font-size: 13px;
  }
  .btn-cancel:hover { background: #444; }
  .btn-confirm {
    padding: 7px 18px;
    background: #1565c0;
    border: 1px solid #1976d2;
    border-radius: 4px;
    color: #fff;
    cursor: pointer;
    font-size: 13px;
  }
  .btn-confirm:hover { background: #1976d2; }
</style>
