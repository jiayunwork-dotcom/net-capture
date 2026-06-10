<script>
  import { stats } from '../stores/stats.js';

  $: protocolData = $stats.protocol_counts || [];
  $: protocolBytes = $stats.protocol_bytes || [];
  $: ppsTimeline = $stats.pps_timeline || [];
  $: bpsTimeline = $stats.bps_timeline || [];
  $: topSrcIps = $stats.top_src_ips || [];
  $: topDstIps = $stats.top_dst_ips || [];
  $: topPorts = $stats.top_ports || [];
  $: tcpStates = $stats.tcp_states || [];

  $: totalPackets = protocolData.reduce((s, d) => s + d[1], 0);

  const COLORS = ['#4fc3f7', '#66bb6a', '#ffa726', '#ef5350', '#ab47bc', '#78909c', '#ffca28', '#26c6da'];

  function formatBytes(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
  }

  function pieChartPath(data, cx, cy, r) {
    if (!data.length) return '';
    const total = data.reduce((s, d) => s + d[1], 0);
    if (total === 0) return '';
    let paths = '';
    let startAngle = -Math.PI / 2;
    data.forEach((d, i) => {
      const angle = (d[1] / total) * 2 * Math.PI;
      const endAngle = startAngle + angle;
      const largeArc = angle > Math.PI ? 1 : 0;
      const x1 = cx + r * Math.cos(startAngle);
      const y1 = cy + r * Math.sin(startAngle);
      const x2 = cx + r * Math.cos(endAngle);
      const y2 = cy + r * Math.sin(endAngle);
      paths += `M ${cx} ${cy} L ${x1} ${y1} A ${r} ${r} 0 ${largeArc} 1 ${x2} ${y2} Z `;
      startAngle = endAngle;
    });
    return paths;
  }

  $: piePaths = pieChartPath(protocolData, 100, 100, 80);
</script>

<div class="stats-panel">
  <div class="stats-grid">
    <div class="stat-card">
      <h4>协议分布 (包数)</h4>
      <div class="chart-area">
        <svg viewBox="0 0 200 200" width="180" height="180">
          {#each protocolData as d, i}
            <path d={pieChartPath([d], 100, 100, 80)} fill={COLORS[i % COLORS.length]} opacity="0.8" />
          {/each}
        </svg>
        <div class="legend">
          {#each protocolData as d, i}
            <div class="legend-item">
              <span class="legend-color" style="background: {COLORS[i % COLORS.length]}"></span>
              <span>{d[0]}: {d[1]}</span>
            </div>
          {/each}
        </div>
      </div>
    </div>

    <div class="stat-card">
      <h4>协议分布 (字节)</h4>
      <div class="bar-chart">
        {#each protocolBytes as d, i}
          {@const maxVal = Math.max(...protocolBytes.map(x => x[1]), 1)}
          <div class="bar-row">
            <span class="bar-label">{d[0]}</span>
            <div class="bar-track">
              <div class="bar-fill" style="width: {(d[1] / maxVal) * 100}%; background: {COLORS[i % COLORS.length]}"></div>
            </div>
            <span class="bar-value">{formatBytes(d[1])}</span>
          </div>
        {/each}
      </div>
    </div>

    <div class="stat-card">
      <h4>流量时序 (每秒包数)</h4>
      <div class="timeline-chart">
        {#if ppsTimeline.length > 1}
          {@const maxPps = Math.max(...ppsTimeline.map(d => d[1]), 1)}
          <svg viewBox="0 0 300 100" width="100%" height="80">
            <polyline
              fill="none"
              stroke="#4fc3f7"
              stroke-width="2"
              points={ppsTimeline.map((d, i) => `${(i / (ppsTimeline.length - 1)) * 300},${100 - (d[1] / maxPps) * 90}`).join(' ')}
            />
          </svg>
        {:else}
          <div class="no-data">暂无数据</div>
        {/if}
      </div>
    </div>

    <div class="stat-card">
      <h4>Top 源IP</h4>
      <div class="top-list">
        {#each topSrcIps as d, i}
          <div class="top-item">
            <span class="top-rank">{i + 1}</span>
            <span class="top-name">{d[0]}</span>
            <span class="top-count">{d[1]}</span>
          </div>
        {/each}
      </div>
    </div>

    <div class="stat-card">
      <h4>Top 目的IP</h4>
      <div class="top-list">
        {#each topDstIps as d, i}
          <div class="top-item">
            <span class="top-rank">{i + 1}</span>
            <span class="top-name">{d[0]}</span>
            <span class="top-count">{d[1]}</span>
          </div>
        {/each}
      </div>
    </div>

    <div class="stat-card">
      <h4>Top 端口</h4>
      <div class="top-list">
        {#each topPorts as d, i}
          <div class="top-item">
            <span class="top-rank">{i + 1}</span>
            <span class="top-name">:{d[0]}</span>
            <span class="top-count">{d[1]}</span>
          </div>
        {/each}
      </div>
    </div>

    <div class="stat-card">
      <h4>TCP连接状态</h4>
      <div class="top-list">
        {#each tcpStates as d, i}
          <div class="top-item">
            <span class="top-name">{d[0]}</span>
            <span class="top-count">{d[1]}</span>
          </div>
        {/each}
      </div>
    </div>
  </div>
</div>

<style>
  .stats-panel {
    height: 100%;
    overflow-y: auto;
    background: #1e1e1e;
    padding: 8px;
  }
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 8px;
  }
  .stat-card {
    background: #2d2d2d;
    border-radius: 6px;
    padding: 12px;
  }
  .stat-card h4 {
    color: #ccc;
    font-size: 13px;
    margin: 0 0 8px 0;
    font-weight: 500;
  }
  .chart-area {
    display: flex;
    align-items: flex-start;
    gap: 12px;
  }
  .legend {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 11px;
    color: #bbb;
  }
  .legend-item {
    display: flex;
    align-items: center;
    gap: 4px;
  }
  .legend-color {
    width: 10px;
    height: 10px;
    border-radius: 2px;
    display: inline-block;
  }
  .bar-chart {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .bar-row {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .bar-label {
    width: 50px;
    font-size: 11px;
    color: #bbb;
    text-align: right;
  }
  .bar-track {
    flex: 1;
    height: 12px;
    background: #444;
    border-radius: 2px;
    overflow: hidden;
  }
  .bar-fill {
    height: 100%;
    border-radius: 2px;
    transition: width 0.3s;
  }
  .bar-value {
    font-size: 10px;
    color: #aaa;
    min-width: 60px;
  }
  .top-list {
    display: flex;
    flex-direction: column;
    gap: 3px;
  }
  .top-item {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 12px;
    color: #ccc;
    padding: 2px 0;
  }
  .top-rank {
    width: 18px;
    height: 18px;
    background: #444;
    border-radius: 3px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 10px;
    color: #aaa;
  }
  .top-name {
    flex: 1;
    font-family: 'Menlo', monospace;
  }
  .top-count {
    color: #888;
    font-size: 11px;
  }
  .no-data {
    color: #666;
    text-align: center;
    padding: 20px;
    font-size: 13px;
  }
</style>
