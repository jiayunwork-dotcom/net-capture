<script>
  import { filteredPackets, selectedPacketNo, autoScroll, loadPacketDetail } from '../stores/packets.js';

  const PROTOCOL_COLORS = {
    HTTP: '#c8e6c9',
    DNS: '#bbdefb',
    TCP: '#e0e0e0',
    UDP: '#e1bee7',
    TLS: '#ffe0b2',
    ICMP: '#f8bbd0',
    ARP: '#fff9c4',
  };

  const ROW_HEIGHT = 24;
  let containerEl;
  let scrollTop = 0;
  let containerHeight = 600;

  $: visibleStart = Math.floor(scrollTop / ROW_HEIGHT);
  $: visibleCount = Math.ceil(containerHeight / ROW_HEIGHT) + 5;
  $: visibleEnd = Math.min(visibleStart + visibleCount, $filteredPackets.length);
  $: totalHeight = $filteredPackets.length * ROW_HEIGHT;
  $: offsetY = visibleStart * ROW_HEIGHT;

  $: visiblePackets = $filteredPackets.slice(visibleStart, visibleEnd);

  function onScroll(e) {
    scrollTop = e.target.scrollTop;
  }

  function selectPacket(pkt) {
    loadPacketDetail(pkt.no);
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

  export function scrollToBottom() {
    if (containerEl && $autoScroll) {
      containerEl.scrollTop = containerEl.scrollHeight;
    }
  }

  $: if ($filteredPackets.length > 0 && $autoScroll) {
    requestAnimationFrame(scrollToBottom);
  }
</script>

<div class="packet-list" bind:this={containerEl} on:scroll={onScroll}>
  <div class="header">
    <span class="col-no">序号</span>
    <span class="col-time">时间戳</span>
    <span class="col-src">源地址</span>
    <span class="col-dst">目的地址</span>
    <span class="col-proto">协议</span>
    <span class="col-len">长度</span>
    <span class="col-summary">摘要</span>
  </div>

  <div class="virtual-container" style="height: {totalHeight}px;">
    <div class="virtual-content" style="transform: translateY({offsetY}px);">
      {#each visiblePackets as pkt (pkt.no)}
        {@const addr = formatAddr(pkt)}
        <div
          class="packet-row {pkt.no === $selectedPacketNo ? 'selected' : ''}"
          style="height: {ROW_HEIGHT}px; background-color: {getProtoColor(pkt.protocol)};"
          on:click={() => selectPacket(pkt)}
        >
          <span class="col-no">{pkt.no}</span>
          <span class="col-time">{pkt.timestamp_str}</span>
          <span class="col-src" style="color: {getProtoTextColor(pkt.protocol)}">{addr.src}</span>
          <span class="col-dst" style="color: {getProtoTextColor(pkt.protocol)}">{addr.dst}</span>
          <span class="col-proto" style="color: {getProtoTextColor(pkt.protocol)}; font-weight: 600;">{pkt.protocol}</span>
          <span class="col-len" style="color: {getProtoTextColor(pkt.protocol)}">{pkt.length}</span>
          <span class="col-summary" style="color: {getProtoTextColor(pkt.protocol)}">{pkt.summary}</span>
        </div>
      {/each}
    </div>
  </div>
</div>

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
  }
  .packet-row:hover {
    opacity: 0.85;
  }
  .packet-row.selected {
    outline: 2px solid #1565c0;
    outline-offset: -2px;
  }
  .col-no { width: 70px; text-align: right; padding-right: 8px; }
  .col-time { width: 150px; padding-right: 8px; }
  .col-src { width: 220px; padding-right: 8px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .col-dst { width: 220px; padding-right: 8px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .col-proto { width: 50px; text-align: center; padding-right: 8px; }
  .col-len { width: 60px; text-align: right; padding-right: 8px; }
  .col-summary { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
</style>
