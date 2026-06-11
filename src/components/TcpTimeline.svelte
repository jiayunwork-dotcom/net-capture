<script>
  import { onMount, onDestroy } from 'svelte';
  import { invoke } from '@tauri-apps/api/tauri';
  import { sessions } from '../stores/sessions.js';

  export let sessionId = null;

  let timelineData = null;
  let loading = false;
  let error = '';

  let svgWidth = 600;
  let svgHeight = 400;
  let padding = { top: 40, right: 40, bottom: 40, left: 40 };

  let scale = 1;
  let offsetX = 0;
  let isDragging = false;
  let dragStartX = 0;
  let dragStartOffset = 0;

  let hoveredPacket = null;
  let hoverX = 0;
  let hoverY = 0;

  async function loadTimeline() {
    if (!sessionId) {
      timelineData = null;
      return;
    }
    loading = true;
    error = '';
    try {
      const data = await invoke('get_tcp_timeline', { sessionId });
      timelineData = data;
    } catch (e) {
      error = String(e);
      console.error('Load timeline error:', e);
    } finally {
      loading = false;
    }
  }

  $: if (sessionId) {
    loadTimeline();
  }

  $: chartWidth = svgWidth - padding.left - padding.right;
  $: chartHeight = svgHeight - padding.top - padding.bottom;

  $: clientY = padding.top + chartHeight * 0.25;
  $: serverY = padding.top + chartHeight * 0.75;

  $: timeRange = (() => {
    if (!timelineData || !timelineData.entries.length) return { min: 0, max: 1 };
    const entries = timelineData.entries;
    const first = entries[0];
    const last = entries[entries.length - 1];
    const startTime = first.timestamp_secs * 1000 + first.timestamp_micros / 1000;
    const endTime = last.timestamp_secs * 1000 + last.timestamp_micros / 1000;
    return { min: startTime, max: Math.max(startTime + 1, endTime) };
  })();

  $: visibleTimeRange = {
    min: timeRange.min - offsetX / scale,
    max: timeRange.min + (chartWidth - offsetX) / scale,
  };

  function getX(tsSecs, tsMicros) {
    const time = tsSecs * 1000 + tsMicros / 1000;
    return padding.left + ((time - timeRange.min) / (timeRange.max - timeRange.min)) * chartWidth * scale + offsetX;
  }

  function formatTime(tsSecs, tsMicros) {
    const date = new Date(tsSecs * 1000 + tsMicros / 1000);
    const ms = Math.floor(tsMicros / 1000);
    return `${date.getHours().toString().padStart(2, '0')}:${date.getMinutes().toString().padStart(2, '0')}:${date.getSeconds().toString().padStart(2, '0')}.${ms.toString().padStart(3, '0')}`;
  }

  function handleWheel(e) {
    e.preventDefault();
    const delta = e.deltaY > 0 ? 0.9 : 1.1;
    const newScale = Math.max(0.1, Math.min(10, scale * delta));
    const rect = e.currentTarget.getBoundingClientRect();
    const mouseX = e.clientX - rect.left - padding.left;
    const timeAtMouse = timeRange.min + (mouseX - offsetX) / scale / chartWidth * (timeRange.max - timeRange.min);
    const newOffsetX = mouseX - (timeAtMouse - timeRange.min) / (timeRange.max - timeRange.min) * chartWidth * newScale;
    scale = newScale;
    offsetX = newOffsetX;
  }

  function startDrag(e) {
    isDragging = true;
    dragStartX = e.clientX;
    dragStartOffset = offsetX;
  }

  function onDrag(e) {
    if (!isDragging) return;
    const dx = e.clientX - dragStartX;
    offsetX = dragStartOffset + dx;
  }

  function endDrag() {
    isDragging = false;
  }

  function handleMouseMove(e) {
    if (!timelineData) return;
    const rect = e.currentTarget.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;
    hoverX = e.clientX;
    hoverY = e.clientY;

    let nearest = null;
    let minDist = Infinity;

    for (const entry of timelineData.entries) {
      const x = getX(entry.timestamp_secs, entry.timestamp_micros);
      const y = entry.direction ? clientY : serverY;
      const dist = Math.sqrt((x - mouseX) ** 2 + (y - mouseY) ** 2);
      if (dist < minDist && dist < 20) {
        minDist = dist;
        nearest = entry;
      }
    }
    hoveredPacket = nearest;
  }

  function handleMouseLeave() {
    hoveredPacket = null;
  }

  function resetView() {
    scale = 1;
    offsetX = 0;
  }

  $: arrowPaths = (() => {
    if (!timelineData) return [];
    const paths = [];
    for (const entry of timelineData.entries) {
      const x = getX(entry.timestamp_secs, entry.timestamp_micros);
      const fromY = entry.direction ? clientY : serverY;
      const toY = entry.direction ? serverY : clientY;
      const dy = toY - fromY;
      const arrowLen = 8;
      const arrowAngle = Math.PI / 6;

      const endX = x;
      const endY = toY - 4;

      const arrowLeftX = endX - arrowLen * Math.sin(arrowAngle);
      const arrowLeftY = endY + arrowLen * Math.cos(arrowAngle);
      const arrowRightX = endX + arrowLen * Math.sin(arrowAngle);
      const arrowRightY = endY + arrowLen * Math.cos(arrowAngle);

      paths.push({
        entry,
        x,
        fromY,
        toY,
        endX,
        endY,
        arrowLeftX,
        arrowLeftY,
        arrowRightX,
        arrowRightY,
      });
    }
    return paths;
  })();

  function onMount() {
    document.addEventListener('mousemove', onDrag);
    document.addEventListener('mouseup', endDrag);
  }

  function onDestroy() {
    document.removeEventListener('mousemove', onDrag);
    document.removeEventListener('mouseup', endDrag);
  }
</script>

<div class="tcp-timeline">
  <div class="timeline-header">
    <h4>TCP 连接时序图</h4>
    <div class="timeline-controls">
      <button class="ctrl-btn" on:click={resetView} title="重置视图">⟲</button>
      <button class="ctrl-btn" on:click={() => scale = Math.min(10, scale * 1.5)}>+</button>
      <button class="ctrl-btn" on:click={() => scale = Math.max(0.1, scale / 1.5)}>−</button>
    </div>
  </div>

  {#if loading}
    <div class="loading">加载中...</div>
  {:else if error}
    <div class="error">{error}</div>
  {:else if !timelineData || !timelineData.entries.length}
    <div class="no-data">选择一个 TCP 会话查看时序图</div>
  {:else}
    {#if timelineData.is_truncated}
      <div class="truncate-note">
        ⚠️ 会话包数超过 5000，仅显示首尾各 100 个包（共 {timelineData.total_packets} 个）
      </div>
    {/if}

    <div class="chart-container"
      bind:clientWidth={svgWidth}
      bind:clientHeight={svgHeight}
      on:wheel={handleWheel}
      on:mousedown={startDrag}
      on:mousemove={handleMouseMove}
      on:mouseleave={handleMouseLeave}
      class:dragging={isDragging}
    >
      <svg width={svgWidth} height={svgHeight}>
        <line
          x1={padding.left}
          y1={clientY}
          x2={svgWidth - padding.right}
          y2={clientY}
          stroke="#666"
          stroke-width="2"
        />
        <line
          x1={padding.left}
          y1={serverY}
          x2={svgWidth - padding.right}
          y2={serverY}
          stroke="#666"
          stroke-width="2"
        />

        <text x={padding.left - 10} y={clientY - 10} text-anchor="end" fill="#888" font-size="11">
          {timelineData.client_addr}:{timelineData.client_port}
        </text>
        <text x={padding.left - 10} y={serverY + 18} text-anchor="end" fill="#888" font-size="11">
          {timelineData.server_addr}:{timelineData.server_port}
        </text>

        {#each arrowPaths as p (p.entry.packet_no)}
          <g class="arrow {p.entry.is_retransmission ? 'retrans' : ''}">
            <line
              x1={p.x}
              y1={p.fromY + 4}
              x2={p.endX}
              y2={p.endY}
              stroke={p.entry.is_retransmission ? '#ef5350' : '#4fc3f7'}
              stroke-width="1.5"
              stroke-dasharray={p.entry.is_retransmission ? '4,4' : 'none'}
            />
            <polygon
              points={`${p.endX},${p.endY} ${p.arrowLeftX},${p.arrowLeftY} ${p.arrowRightX},${p.arrowRightY}`}
              fill={p.entry.is_retransmission ? '#ef5350' : '#4fc3f7'}
            />
            <text
              x={p.x + 4}
              y={(p.fromY + p.toY) / 2}
              font-size="9"
              fill="#aaa"
              style="dominant-baseline: middle;"
            >
              {p.entry.flags}
            </text>
            {#if p.entry.is_retransmission}
              <text
                x={p.x + 4}
                y={(p.fromY + p.toY) / 2 + 12}
                font-size="9"
                fill="#ef5350"
                style="dominant-baseline: middle;"
              >
                重传
              </text>
            {/if}
          </g>
        {/each}
      </svg>
    </div>

    <div class="timeline-info">
      <span>总包数: {timelineData.total_packets}</span>
      <span>缩放: {(scale * 100).toFixed(0)}%</span>
    </div>
  {/if}

  {#if hoveredPacket}
    <div class="tooltip" style="left: {hoverX + 10}px; top: {hoverY + 10}px;">
      <div class="tooltip-title">包 #{hoveredPacket.packet_no}</div>
      <div class="tooltip-row">
        <span class="tooltip-label">时间:</span>
        <span>{formatTime(hoveredPacket.timestamp_secs, hoveredPacket.timestamp_micros)}</span>
      </div>
      <div class="tooltip-row">
        <span class="tooltip-label">方向:</span>
        <span>{hoveredPacket.direction ? '客户端 → 服务端' : '服务端 → 客户端'}</span>
      </div>
      <div class="tooltip-row">
        <span class="tooltip-label">序列号:</span>
        <span>{hoveredPacket.seq_num}</span>
      </div>
      <div class="tooltip-row">
        <span class="tooltip-label">确认号:</span>
        <span>{hoveredPacket.ack_num}</span>
      </div>
      <div class="tooltip-row">
        <span class="tooltip-label">载荷大小:</span>
        <span>{hoveredPacket.payload_size} bytes</span>
      </div>
      <div class="tooltip-row">
        <span class="tooltip-label">标志位:</span>
        <span>{hoveredPacket.flags}</span>
      </div>
      <div class="tooltip-row">
        <span class="tooltip-label">窗口大小:</span>
        <span>{hoveredPacket.window_size}</span>
      </div>
    </div>
  {/if}
</div>

<style>
  .tcp-timeline {
    background: #2d2d2d;
    border-radius: 6px;
    padding: 12px;
    position: relative;
  }
  .timeline-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 8px;
  }
  .timeline-header h4 {
    color: #ccc;
    font-size: 13px;
    margin: 0;
    font-weight: 500;
  }
  .timeline-controls {
    display: flex;
    gap: 4px;
  }
  .ctrl-btn {
    width: 28px;
    height: 28px;
    display: flex;
    align-items: center;
    justify-content: center;
    background: #3a3a3a;
    border: 1px solid #555;
    border-radius: 4px;
    color: #ccc;
    cursor: pointer;
    font-size: 14px;
  }
  .ctrl-btn:hover {
    background: #444;
  }
  .chart-container {
    width: 100%;
    height: 350px;
    background: #1e1e1e;
    border-radius: 4px;
    cursor: grab;
    overflow: hidden;
  }
  .chart-container.dragging {
    cursor: grabbing;
  }
  .loading, .no-data, .error {
    text-align: center;
    padding: 40px;
    color: #888;
    font-size: 13px;
  }
  .error {
    color: #ef5350;
  }
  .truncate-note {
    background: rgba(255, 202, 40, 0.1);
    border: 1px solid rgba(255, 202, 40, 0.3);
    color: #ffca28;
    padding: 6px 10px;
    border-radius: 4px;
    font-size: 11px;
    margin-bottom: 8px;
  }
  .timeline-info {
    display: flex;
    gap: 16px;
    margin-top: 8px;
    color: #888;
    font-size: 11px;
  }
  .tooltip {
    position: fixed;
    background: #1e1e1e;
    border: 1px solid #555;
    border-radius: 6px;
    padding: 10px 12px;
    font-size: 11px;
    color: #ccc;
    pointer-events: none;
    z-index: 1000;
    box-shadow: 0 4px 12px rgba(0,0,0,0.4);
    font-family: 'Menlo', 'Consolas', monospace;
  }
  .tooltip-title {
    font-weight: 600;
    color: #4fc3f7;
    margin-bottom: 6px;
    font-size: 12px;
  }
  .tooltip-row {
    display: flex;
    gap: 8px;
    line-height: 1.6;
  }
  .tooltip-label {
    color: #888;
    min-width: 60px;
  }
</style>
