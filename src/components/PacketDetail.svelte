<script>
  import { packetDetail, hexDump, selectedPacketNo } from '../stores/packets.js';
  import { traceTcpStream } from '../stores/sessions.js';

  let hoveredRange = null;

  $: layers = $packetDetail ? $packetDetail.layers : [];

  function toggleLayer(layer) {
    layer._expanded = !layer._expanded;
    layers = layers;
  }

  function onFieldHover(field) {
    if (field.byte_range && field.byte_range[0] !== field.byte_range[1]) {
      hoveredRange = field.byte_range;
    } else {
      hoveredRange = null;
    }
  }

  function onFieldLeave() {
    hoveredRange = null;
  }

  function handleContextMenu(layer) {
    if (layer.protocol && layer.protocol.includes('TCP')) {
      traceTcpStream(layer);
    }
  }
</script>

<div class="packet-detail">
  {#if $packetDetail}
    <div class="layers">
      {#each layers as layer, i}
        <div class="layer" on:contextmenu|preventDefault={() => handleContextMenu(layer)}>
          <div class="layer-header" on:click={() => toggleLayer(layer)}>
            <span class="expand-icon">{layer._expanded ? '▼' : '▶'}</span>
            <span class="layer-name">{layer.protocol}</span>
            <span class="layer-bytes">[{layer.byte_range[0]}:{layer.byte_range[1]}]</span>
          </div>

          {#if layer._expanded !== false}
            <div class="layer-fields">
              {#each layer.fields as field}
                <div
                  class="field-row"
                  on:mouseenter={() => onFieldHover(field)}
                  on:mouseleave={onFieldLeave}
                >
                  <span class="field-name">{field.name}:</span>
                  <span class="field-value">{field.value}</span>
                </div>
              {/each}
            </div>
          {/if}
        </div>
      {/each}
    </div>

    <div class="hex-section">
      <div class="hex-header">十六进制转储</div>
      <div class="hex-content">
        {#each $hexDump as line}
          <div class="hex-line">
            <span class="hex-offset">{line.offset}</span>
            <span class="hex-bytes">
              {#each line.hex as byte, i}
                <span class="hex-byte" class:highlight={hoveredRange && isInRange(line, i, hoveredRange)}>
                  {byte}
                </span>
              {/each}
            </span>
            <span class="hex-ascii">{line.ascii}</span>
          </div>
        {/each}
      </div>
    </div>
  {:else}
    <div class="no-selection">
      选择一个数据包查看详情
    </div>
  {/if}
</div>

<script context="module">
  function isInRange(line, byteIndex, range) {
    const lineOffset = parseInt(line.offset, 16);
    const bytePos = lineOffset + byteIndex;
    return bytePos >= range[0] && bytePos < range[1];
  }
</script>

<style>
  .packet-detail {
    display: flex;
    flex-direction: column;
    height: 100%;
    background: #1e1e1e;
    overflow: hidden;
  }
  .layers {
    flex: 1;
    overflow-y: auto;
    padding: 4px 0;
    min-height: 120px;
  }
  .layer {
    border-bottom: 1px solid #333;
  }
  .layer-header {
    display: flex;
    align-items: center;
    padding: 4px 8px;
    cursor: pointer;
    color: #4fc3f7;
    font-size: 13px;
    font-weight: 500;
  }
  .layer-header:hover {
    background: #2a2a2a;
  }
  .expand-icon {
    margin-right: 6px;
    font-size: 10px;
    width: 14px;
  }
  .layer-name {
    flex: 1;
  }
  .layer-bytes {
    color: #888;
    font-size: 11px;
  }
  .layer-fields {
    padding: 2px 8px 6px 28px;
  }
  .field-row {
    display: flex;
    padding: 1px 4px;
    font-size: 12px;
    line-height: 1.6;
  }
  .field-row:hover {
    background: #2a3a4a;
  }
  .field-name {
    color: #aaa;
    min-width: 140px;
    margin-right: 8px;
  }
  .field-value {
    color: #e0e0e0;
    word-break: break-all;
  }
  .hex-section {
    border-top: 2px solid #444;
    flex: 1;
    display: flex;
    flex-direction: column;
    min-height: 100px;
  }
  .hex-header {
    padding: 4px 8px;
    background: #333;
    color: #ccc;
    font-size: 12px;
    font-weight: 600;
  }
  .hex-content {
    flex: 1;
    overflow-y: auto;
    padding: 4px 8px;
    font-family: 'Menlo', 'Consolas', 'Monaco', monospace;
    font-size: 11px;
  }
  .hex-line {
    display: flex;
    line-height: 1.8;
  }
  .hex-offset {
    color: #888;
    min-width: 48px;
    margin-right: 12px;
  }
  .hex-bytes {
    min-width: 400px;
    margin-right: 12px;
  }
  .hex-byte {
    display: inline-block;
    width: 22px;
    margin-right: 4px;
    color: #b0b0b0;
    text-align: center;
  }
  .hex-byte.highlight {
    background: #1565c0;
    color: white;
    border-radius: 2px;
  }
  .hex-ascii {
    color: #888;
  }
  .no-selection {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100%;
    color: #888;
    font-size: 14px;
  }
</style>
