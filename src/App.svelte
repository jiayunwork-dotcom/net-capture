<script>
  import { onMount } from 'svelte';
  import { invoke } from '@tauri-apps/api/tauri';
  import { open, save } from '@tauri-apps/api/dialog';
  import InterfaceSelector from './components/InterfaceSelector.svelte';
  import PacketList from './components/PacketList.svelte';
  import PacketDetail from './components/PacketDetail.svelte';
  import DisplayFilter from './components/DisplayFilter.svelte';
  import StatsPanel from './components/StatsPanel.svelte';
  import SessionList from './components/SessionList.svelte';
  import TcpStream from './components/TcpStream.svelte';
  import { captureStatus, isCapturing, loadInterfaces } from './stores/capture.js';
  import { packets, filteredPackets } from './stores/packets.js';
  import { loadSessions } from './stores/sessions.js';

  let activeTab = 'packets';
  let detailVisible = true;

  onMount(() => {
    loadInterfaces();
  });

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
</script>

<div class="app">
  <header class="toolbar">
    <div class="toolbar-left">
      <span class="app-title">🔍 NetCapture</span>
      <InterfaceSelector />
    </div>
    <div class="toolbar-right">
      <span class="status-text">
        包数: {$captureStatus.packet_count}
        {#if $captureStatus.dropped_count > 0}
          <span class="dropped">丢弃: {$captureStatus.dropped_count}</span>
        {/if}
      </span>
      <button class="toolbar-btn" on:click={handleImport} title="导入PCAP">📥 导入</button>
      <button class="toolbar-btn" on:click={handleExport} title="导出PCAP">📤 导出</button>
      <button class="toolbar-btn" on:click={handleLoadKeylog} title="加载SSLKEYLOG">🔐 TLS</button>
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
      {/if}
    </div>
  </div>

  <TcpStream />
</div>

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
</style>
