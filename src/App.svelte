<script>
  import { onMount, onDestroy } from 'svelte';
  import { invoke } from '@tauri-apps/api/tauri';
  import { open, save } from '@tauri-apps/api/dialog';
  import { listen } from '@tauri-apps/api/event';
  import InterfaceSelector from './components/InterfaceSelector.svelte';
  import PacketList from './components/PacketList.svelte';
  import PacketDetail from './components/PacketDetail.svelte';
  import DisplayFilter from './components/DisplayFilter.svelte';
  import StatsPanel from './components/StatsPanel.svelte';
  import SessionList from './components/SessionList.svelte';
  import TcpStream from './components/TcpStream.svelte';
  import PacketCompare from './components/PacketCompare.svelte';
  import AlertPanel from './components/AlertPanel.svelte';
  import RuleSettingsPanel from './components/RuleSettingsPanel.svelte';
  import ResponseLogPanel from './components/ResponseLogPanel.svelte';
  import ReplayResultPanel from './components/ReplayResultPanel.svelte';
  import AttackPatternPanel from './components/AttackPatternPanel.svelte';
  import RuleEffectivenessReport from './components/RuleEffectivenessReport.svelte';
  import PatternSimResult from './components/PatternSimResult.svelte';
  import { isReplaying, replayProgress, replaySpeed, SPEED_OPTIONS, setReplaySpeed } from './stores/replay.js';
  import { isGeneratingTraffic, isRunningReport, simulationProgress, reportProgress, isGeneratingHeatmap, heatmapProgress } from './stores/attack_patterns.js';
  import { captureStatus, isCapturing, loadInterfaces } from './stores/capture.js';
  import { packets, filteredPackets, loadPacketDetail, selectedPacketNo, jumpToPacketNo } from './stores/packets.js';
  import { loadSessions } from './stores/sessions.js';
  import { selectedPackets } from './stores/selection.js';
  import { loadAllMarks } from './stores/marks.js';
  import { loadRules } from './stores/rules.js';
  import { alerts, alertCount, loadAlerts, startAlertPolling, stopAlertPolling } from './stores/alerts.js';

  let activeTab = 'packets';
  let detailVisible = true;
  let showCompare = false;
  let showTemplateMenu = false;
  let showRuleSettings = false;

  let templates = [];
  let templateNameInput = '';
  let showSaveTemplateDialog = false;
  let audioCtx = null;
  let unlistenSound = null;

  $: canCompare = $selectedPackets.length === 2;

  $: if ($jumpToPacketNo !== null && activeTab !== 'packets') {
    activeTab = 'packets';
  }

  onMount(async () => {
    loadInterfaces();
    loadTemplates();
    loadRules();
    loadAlerts();
    startAlertPolling();

    audioCtx = new (window.AudioContext || window.webkitAudioContext)();

    unlistenSound = await listen('rule-alert-sound', (event) => {
      playAlertSound(event.payload);
    });
  });

  onDestroy(() => {
    if (unlistenSound) {
      unlistenSound();
    }
    if (audioCtx) {
      audioCtx.close();
    }
  });

  function playAlertSound(payload) {
    if (!audioCtx) return;
    if (audioCtx.state === 'suspended') {
      audioCtx.resume();
    }

    const priority = payload.priority || 'medium';
    const freq = priority === 'high' ? 880 : priority === 'medium' ? 660 : 440;
    const duration = priority === 'high' ? 0.3 : priority === 'medium' ? 0.2 : 0.15;

    const oscillator = audioCtx.createOscillator();
    const gainNode = audioCtx.createGain();

    oscillator.connect(gainNode);
    gainNode.connect(audioCtx.destination);

    oscillator.type = 'sine';
    oscillator.frequency.setValueAtTime(freq, audioCtx.currentTime);

    gainNode.gain.setValueAtTime(0.3, audioCtx.currentTime);
    gainNode.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + duration);

    oscillator.start(audioCtx.currentTime);
    oscillator.stop(audioCtx.currentTime + duration);
  }

  function handleSelectAlertPacket(packetNo) {
    activeTab = 'packets';
    selectedPackets.set([packetNo]);
    loadPacketDetail(packetNo);
  }

  function openRuleSettings() {
    showRuleSettings = true;
  }

  function closeRuleSettings() {
    showRuleSettings = false;
  }

  async function handleExport() {
    const filePath = await save({
      filters: [{ name: 'PCAP', extensions: ['pcap'] }],
      defaultPath: 'capture.pcap',
    });
    if (filePath) {
      try {
        await invoke('export_pcap', { path: filePath, filteredOnly: false, filterExpr: null });
      } catch (e) {
        console.error('Export error:', e);
      }
    }
  }

  async function handleImport() {
    const filePath = await open({
      filters: [
        { name: 'PCAP', extensions: ['pcap'] },
        { name: 'PCAPNG', extensions: ['pcapng'] },
      ],
      multiple: false,
    });
    if (filePath) {
      try {
        await invoke('import_pcap', { path: filePath });
        loadSessions();
        loadAllMarks();
      } catch (e) {
        console.error('Import error:', e);
      }
    }
  }

  async function handleLoadKeylog() {
    const filePath = await open({
      filters: [{ name: 'Key Log', extensions: ['log', 'txt'] }],
      multiple: false,
    });
    if (filePath) {
      try {
        const count = await invoke('load_sslkeylog', { path: filePath });
        console.log('Loaded', count, 'TLS keys');
      } catch (e) {
        console.error('Load keylog error:', e);
      }
    }
  }

  function openCompare() {
    if (canCompare) {
      showCompare = true;
    }
  }

  function closeCompare() {
    showCompare = false;
  }

  async function loadTemplates() {
    try {
      const result = await invoke('load_capture_templates');
      templates = result || [];
    } catch (e) {
      console.error('Load templates error:', e);
    }
  }

  async function applyTemplate(template) {
    const { invoke: invokeT } = await import('@tauri-apps/api/tauri');
    const { selectedInterface, bpfFilter, captureMode, startCapture } = await import('./stores/capture.js');
    selectedInterface.set(template.interface_name);
    bpfFilter.set(template.bpf_filter);
    captureMode.set(template.promiscuous ? 'promiscuous' : 'normal');
    showTemplateMenu = false;
  }

  async function openSaveTemplateDialog() {
    templateNameInput = '';
    showSaveTemplateDialog = true;
    showTemplateMenu = false;
  }

  async function saveTemplate() {
    if (!templateNameInput.trim()) return;

    try {
      const { get } = await import('svelte/store');
      const { selectedInterface, bpfFilter, captureMode } = await import('./stores/capture.js');

      const iface = get(selectedInterface);
      const filter = get(bpfFilter);
      const promisc = get(captureMode) === 'promiscuous';

      await invoke('save_capture_template', {
        name: templateNameInput.trim(),
        interfaceName: iface,
        bpfFilter: filter,
        promiscuous: promisc,
        description: null,
      });

      await loadTemplates();
      showSaveTemplateDialog = false;
    } catch (e) {
      alert(String(e));
    }
  }

  async function deleteTemplate(template) {
    if (!confirm(`确定删除模板 "${template.name}" 吗？`)) return;
    try {
      await invoke('delete_capture_template', { name: template.name });
      await loadTemplates();
    } catch (e) {
      console.error('Delete template error:', e);
    }
  }

  async function exportTemplates() {
    const filePath = await save({
      filters: [{ name: 'JSON', extensions: ['json'] }],
      defaultPath: 'templates.json',
    });
    if (filePath) {
      try {
        await invoke('export_templates', { path: filePath });
      } catch (e) {
        console.error('Export templates error:', e);
      }
    }
    showTemplateMenu = false;
  }

  async function importTemplates() {
    const filePath = await open({
      filters: [{ name: 'JSON', extensions: ['json'] }],
      multiple: false,
    });
    if (filePath) {
      try {
        const count = await invoke('import_templates', { path: filePath });
        await loadTemplates();
        alert(`成功导入 ${count} 个模板`);
      } catch (e) {
        console.error('Import templates error:', e);
      }
    }
    showTemplateMenu = false;
  }

  function toggleTemplateMenu() {
    showTemplateMenu = !showTemplateMenu;
  }
</script>

<div class="app">
  <header class="toolbar">
    <div class="toolbar-left">
      <span class="app-title">🔍 NetCapture</span>
      <InterfaceSelector />
      <div class="template-selector">
        <button class="toolbar-btn template-btn" on:click={toggleTemplateMenu}>
          📋 模板
        </button>
        {#if showTemplateMenu}
          <div class="template-menu" onclick="event.stopPropagation()">
            <div class="menu-section">
              <div class="menu-title">快速加载</div>
              {#if templates.length === 0}
                <div class="menu-empty">暂无模板</div>
              {:else}
                {#each templates as t (t.name)}
                  <div class="template-item" on:click={() => applyTemplate(t)}>
                    <span class="template-name">{t.name}</span>
                    <button class="template-delete" on:click|stopPropagation={() => deleteTemplate(t)}>✕</button>
                  </div>
                {/each}
              {/if}
            </div>
            <div class="menu-separator"></div>
            <div class="menu-section">
              <div class="template-action" on:click={openSaveTemplateDialog}>💾 保存当前配置为模板</div>
              <div class="template-action" on:click={importTemplates}>📥 导入模板</div>
              <div class="template-action" on:click={exportTemplates}>📤 导出模板</div>
            </div>
          </div>
        {/if}
      </div>
    </div>
    <div class="toolbar-right">
      <span class="status-text">
        包数: {$captureStatus.packet_count}
        {#if $captureStatus.dropped_count > 0}
          <span class="dropped">丢弃: {$captureStatus.dropped_count}</span>
        {/if}
        {#if $isReplaying}
          <span class="replay-status">
            🎬 回放检测中
            {#if $replayProgress && $replayProgress.total_packets > 0}
              ({$replayProgress.session_index + 1}/{$replayProgress.total_sessions} 会话, {$replayProgress.current_packet}/{$replayProgress.total_packets} 包)
            {/if}
          </span>
        {/if}
        {#if $isGeneratingTraffic}
          <span class="replay-status">
            ⚔️ 攻击模拟中
            {#if $simulationProgress && $simulationProgress.total_packets > 0}
              ({$simulationProgress.current_packet}/{$simulationProgress.total_packets} 包)
            {/if}
          </span>
        {/if}
        {#if $isReplaying || $isGeneratingTraffic}
          <span class="speed-control">
            ⏩
            <select
              class="speed-select-inline"
              value={$replaySpeed}
              on:change={(e) => setReplaySpeed(e.target.value)}
              title="回放速度"
            >
              {#each SPEED_OPTIONS as opt}
                <option value={opt.value}>{opt.label}</option>
              {/each}
            </select>
          </span>
        {/if}
        {#if $isRunningReport}
          <span class="replay-status">
            📊 有效性报告生成中
            {#if $reportProgress && $reportProgress.total_patterns > 0}
              ({$reportProgress.current_pattern + 1}/{$reportProgress.total_patterns} 特征)
            {/if}
          </span>
        {/if}
        {#if $isGeneratingHeatmap}
          <span class="replay-status">
            🗺️ 热力图生成中
            {#if $heatmapProgress && $heatmapProgress.total > 0}
              ({$heatmapProgress.current + 1}/{$heatmapProgress.total} 特征)
            {/if}
          </span>
        {/if}
      </span>
      <button
        class="toolbar-btn compare-btn"
        class:disabled={!canCompare}
        disabled={!canCompare}
        on:click={openCompare}
        title={canCompare ? '比较选中的两个包' : '请选择恰好两个数据包'}
      >
        ⚖️ 比较
      </button>
      <button class="toolbar-btn" on:click={handleImport} title="导入PCAP">📥 导入</button>
      <button class="toolbar-btn" on:click={handleExport} title="导出PCAP">📤 导出</button>
      <button class="toolbar-btn" on:click={handleLoadKeylog} title="加载SSLKEYLOG">🔐 TLS</button>
      <button class="toolbar-btn settings-btn" on:click={openRuleSettings} title="检测规则设置">
        ⚙️ 规则
      </button>
    </div>
  </header>

  <DisplayFilter />

  <div class="main-content">
    <div class="tab-bar">
      <button class="tab" class:active={activeTab === 'packets'} on:click={() => activeTab = 'packets'}>
        数据包 ({$filteredPackets.length})
      </button>
      <button class="tab" class:active={activeTab === 'sessions'} on:click={() => activeTab = 'sessions'}>
        会话
      </button>
      <button class="tab" class:active={activeTab === 'stats'} on:click={() => activeTab = 'stats'}>
        统计
      </button>
      <button class="tab alert-tab" class:active={activeTab === 'alerts'} on:click={() => activeTab = 'alerts'}>
        告警
        {#if $alertCount > 0}
          <span class="alert-badge">{$alertCount}</span>
        {/if}
      </button>
      <button class="tab" class:active={activeTab === 'response_log'} on:click={() => activeTab = 'response_log'}>
        响应日志
      </button>
      <button class="tab" class:active={activeTab === 'attack_patterns'} on:click={() => activeTab = 'attack_patterns'}>
        ⚔️ 攻击特征库
      </button>
    </div>

    <div class="content-area">
      {#if activeTab === 'packets'}
        <div class="split-view">
          <div class="packet-list-area">
            <PacketList />
          </div>
          {#if detailVisible}
            <div class="packet-detail-area">
              <PacketDetail />
            </div>
          {/if}
        </div>
      {:else if activeTab === 'sessions'}
        <SessionList />
      {:else if activeTab === 'stats'}
        <StatsPanel />
      {:else if activeTab === 'alerts'}
        <AlertPanel onSelectPacket={handleSelectAlertPacket} />
      {:else if activeTab === 'response_log'}
        <ResponseLogPanel />
      {:else if activeTab === 'attack_patterns'}
        <AttackPatternPanel />
      {/if}
    </div>
  </div>

  <TcpStream />
  <PacketCompare visible={showCompare} onClose={closeCompare} />
  <ReplayResultPanel />
  <RuleEffectivenessReport />
  <PatternSimResult />
</div>

{#if showRuleSettings}
  <div class="dialog-overlay" on:click={closeRuleSettings}>
    <div class="rule-settings-dialog" on:click|stopPropagation>
      <RuleSettingsPanel onClose={closeRuleSettings} />
    </div>
  </div>
{/if}

{#if showSaveTemplateDialog}
  <div class="dialog-overlay" on:click={() => showSaveTemplateDialog = false}>
    <div class="dialog" on:click|stopPropagation>
      <h3>保存捕获配置模板</h3>
      <div class="form-group">
        <label>模板名称</label>
        <input type="text" bind:value={templateNameInput} placeholder="输入模板名称..." />
      </div>
      <div class="dialog-actions">
        <button class="btn-cancel" on:click={() => showSaveTemplateDialog = false}>取消</button>
        <button class="btn-confirm" on:click={saveTemplate}>保存</button>
      </div>
    </div>
  </div>
{/if}

<style>
  :global(*) {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
  }
  :global(body) {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #1e1e1e;
    color: #e0e0e0;
    overflow: hidden;
    height: 100vh;
  }
  :global(#app) {
    height: 100vh;
  }

  .app {
    display: flex;
    flex-direction: column;
    height: 100vh;
  }

  .toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 16px;
    background: #252525;
    border-bottom: 1px solid #444;
    min-height: 44px;
  }
  .toolbar-left {
    display: flex;
    align-items: center;
    gap: 16px;
    flex: 1;
  }
  .toolbar-right {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .app-title {
    color: #4fc3f7;
    font-size: 15px;
    font-weight: 600;
    white-space: nowrap;
  }
  .status-text {
    color: #888;
    font-size: 12px;
    margin-right: 8px;
  }
  .dropped {
    color: #ef5350;
    margin-left: 8px;
  }
  .replay-status {
    color: #4fc3f7;
    margin-left: 12px;
    font-weight: 500;
    animation: pulse 1.5s ease-in-out infinite;
  }
  .speed-control {
    color: #4fc3f7;
    margin-left: 12px;
    display: inline-flex;
    align-items: center;
    gap: 4px;
    font-size: 12px;
  }
  .speed-select-inline {
    background: #1e1e1e;
    color: #90caf9;
    border: 1px solid #3a3a3a;
    border-radius: 4px;
    padding: 2px 6px;
    font-size: 11px;
    cursor: pointer;
  }
  .speed-select-inline:hover {
    border-color: #4fc3f7;
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
  }
  .toolbar-btn {
    background: #3a3a3a;
    color: #ccc;
    border: 1px solid #555;
    border-radius: 4px;
    padding: 4px 12px;
    cursor: pointer;
    font-size: 12px;
    white-space: nowrap;
  }
  .toolbar-btn:hover {
    background: #4a4a4a;
  }
  .toolbar-btn:disabled,
  .toolbar-btn.disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .compare-btn {
    min-width: 70px;
  }
  .template-selector {
    position: relative;
  }
  .template-btn {
    position: relative;
  }
  .template-menu {
    position: absolute;
    top: calc(100% + 4px);
    left: 0;
    background: #2d2d2d;
    border: 1px solid #555;
    border-radius: 6px;
    min-width: 220px;
    z-index: 100;
    box-shadow: 0 6px 20px rgba(0,0,0,0.4);
    overflow: hidden;
  }
  .menu-section {
    padding: 4px 0;
  }
  .menu-title {
    padding: 6px 12px;
    font-size: 11px;
    color: #888;
    font-weight: 600;
    text-transform: uppercase;
  }
  .menu-empty {
    padding: 12px;
    color: #666;
    font-size: 12px;
    text-align: center;
  }
  .template-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 6px 12px;
    cursor: pointer;
    color: #ccc;
    font-size: 12px;
  }
  .template-item:hover {
    background: #3a3a3a;
  }
  .template-name {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .template-delete {
    background: transparent;
    border: none;
    color: #888;
    cursor: pointer;
    font-size: 12px;
    padding: 2px 6px;
    border-radius: 3px;
    opacity: 0;
    transition: opacity 0.2s;
  }
  .template-item:hover .template-delete {
    opacity: 1;
  }
  .template-delete:hover {
    color: #ef5350;
    background: rgba(239, 83, 80, 0.1);
  }
  .menu-separator {
    height: 1px;
    background: #444;
  }
  .template-action {
    padding: 8px 12px;
    cursor: pointer;
    color: #ccc;
    font-size: 12px;
  }
  .template-action:hover {
    background: #3a3a3a;
  }

  .main-content {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  .tab-bar {
    display: flex;
    background: #2d2d2d;
    border-bottom: 1px solid #444;
    padding: 0 16px;
  }
  .tab {
    background: transparent;
    color: #888;
    border: none;
    border-bottom: 2px solid transparent;
    padding: 8px 16px;
    cursor: pointer;
    font-size: 13px;
  }
  .tab.active {
    color: #4fc3f7;
    border-bottom-color: #4fc3f7;
  }
  .tab:hover {
    color: #bbb;
  }

  .content-area {
    flex: 1;
    overflow: hidden;
  }

  .split-view {
    display: flex;
    height: 100%;
  }
  .packet-list-area {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-width: 0;
  }
  .packet-detail-area {
    width: 420px;
    min-width: 320px;
    border-left: 2px solid #444;
    display: flex;
    flex-direction: column;
    overflow: hidden;
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
    min-width: 320px;
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
  .form-group input[type="text"] {
    width: 100%;
    box-sizing: border-box;
    background: #1e1e1e;
    color: #e0e0e0;
    border: 1px solid #555;
    border-radius: 4px;
    padding: 6px 10px;
    font-size: 13px;
  }
  .form-group input:focus {
    outline: none;
    border-color: #4fc3f7;
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

  .alert-tab {
    position: relative;
  }

  .alert-badge {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 18px;
    height: 18px;
    padding: 0 5px;
    margin-left: 6px;
    background: #ef5350;
    color: #fff;
    font-size: 10px;
    font-weight: 600;
    border-radius: 9px;
    line-height: 1;
  }

  .tab.active .alert-badge {
    background: #fff;
    color: #ef5350;
  }

  .settings-btn {
    min-width: 60px;
  }

  .rule-settings-dialog {
    width: auto;
    max-width: none;
    padding: 0;
    overflow: hidden;
  }

  .rule-settings-dialog :global(.settings-panel) {
    width: 900px;
    max-height: 80vh;
  }
</style>
