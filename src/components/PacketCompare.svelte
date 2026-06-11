<script>
  import { onMount, onDestroy } from 'svelte';
  import { invoke } from '@tauri-apps/api/tauri';
  import { selectedPackets } from '../stores/selection.js';
  import { packets } from '../stores/packets.js';

  export let visible = false;
  export let onClose;

  let leftDetail = null;
  let rightDetail = null;
  let leftHex = null;
  let rightHex = null;
  let leftMeta = null;
  let rightMeta = null;
  let loading = false;

  $: canCompare = $selectedPackets.length === 2;
  $: compareDisabled = $selectedPackets.length !== 2;

  async function loadComparison() {
    if ($selectedPackets.length !== 2) return;

    loading = true;
    try {
      const [no1, no2] = $selectedPackets;

      const [detail1, detail2, hex1, hex2] = await Promise.all([
        invoke('get_packet_detail', { no: no1 }),
        invoke('get_packet_detail', { no: no2 }),
        invoke('get_hex_dump', { no: no1 }),
        invoke('get_hex_dump', { no: no2 }),
      ]);

      leftDetail = detail1;
      rightDetail = detail2;
      leftHex = hex1;
      rightHex = hex2;

      leftMeta = $packets.find(p => p.no === no1) || null;
      rightMeta = $packets.find(p => p.no === no2) || null;
    } catch (e) {
      console.error('Load comparison error:', e);
    } finally {
      loading = false;
    }
  }

  $: if (visible && $selectedPackets.length === 2) {
    loadComparison();
  }

  function compareLayers(leftLayers, rightLayers) {
    if (!leftLayers || !rightLayers) return [];
    const result = [];
    const maxLen = Math.max(leftLayers.length, rightLayers.length);

    for (let i = 0; i < maxLen; i++) {
      const left = leftLayers[i];
      const right = rightLayers[i];
      const layerResult = {
        leftProtocol: left?.protocol || '',
        rightProtocol: right?.protocol || '',
        fields: [],
        hasDiff: false,
      };

      const leftFields = left?.fields || [];
      const rightFields = right?.fields || [];
      const maxFields = Math.max(leftFields.length, rightFields.length);

      for (let j = 0; j < maxFields; j++) {
        const lf = leftFields[j];
        const rf = rightFields[j];
        const isDiff = lf?.name !== rf?.name || lf?.value !== rf?.value;
        if (isDiff) layerResult.hasDiff = true;
        layerResult.fields.push({
          leftName: lf?.name || '',
          leftValue: lf?.value || '',
          rightName: rf?.name || '',
          rightValue: rf?.value || '',
          isDiff,
        });
      }

      if (left?.protocol !== right?.protocol) layerResult.hasDiff = true;
      result.push(layerResult);
    }
    return result;
  }

  $: comparedLayers = compareLayers(leftDetail?.layers, rightDetail?.layers);

  function getHexDiff(leftLines, rightLines) {
    if (!leftLines || !rightLines) return { left: [], right: [], diffMap: new Map() };
    const diffMap = new Map();
    const maxLen = Math.max(leftLines.length, rightLines.length);

    for (let i = 0; i < maxLen; i++) {
      const leftLine = leftLines[i];
      const rightLine = rightLines[i];
      const diffBytes = [];

      if (leftLine && rightLine) {
        const maxBytes = Math.max(leftLine.hex.length, rightLine.hex.length);
        for (let j = 0; j < maxBytes; j++) {
          if (leftLine.hex[j] !== rightLine.hex[j]) {
            diffBytes.push(j);
          }
        }
      } else if (leftLine || rightLine) {
        const line = leftLine || rightLine;
        for (let j = 0; j < (line?.hex?.length || 0); j++) {
          diffBytes.push(j);
        }
      }

      if (diffBytes.length > 0) {
        diffMap.set(i, diffBytes);
      }
    }

    return { left: leftLines, right: rightLines, diffMap };
  }

  $: hexDiff = getHexDiff(leftHex, rightHex);

  function isDiffByte(lineIndex, byteIndex) {
    const diffBytes = hexDiff.diffMap.get(lineIndex);
    return diffBytes?.includes(byteIndex);
  }

  function close() {
    if (onClose) onClose();
  }

  onMount(() => {
    if (visible && canCompare) {
      loadComparison();
    }
  });
</script>

{#if visible}
  <div class="compare-overlay" on:click={close}>
    <div class="compare-panel" on:click|stopPropagation>
      <div class="compare-header">
        <h3>数据包比较</h3>
        <button class="close-btn" on:click={close}>✕</button>
      </div>

      {#if !canCompare}
        <div class="compare-empty">
          <p>请选择两个数据包进行比较（Ctrl+点击多选）</p>
          <p class="hint">当前已选择 {$selectedPackets.length} 个数据包</p>
        </div>
      {:else if loading}
        <div class="compare-loading">加载中...</div>
      {:else}
        <div class="compare-summary">
          <div class="summary-item">
            <span class="summary-label">包 #{leftMeta?.no ?? '?'}</span>
            <span class="summary-time">{leftMeta?.timestamp_str || ''}</span>
            <span class="summary-proto">{leftMeta?.protocol || ''}</span>
            <span class="summary-len">{leftMeta?.length || 0} bytes</span>
          </div>
          <div class="vs">VS</div>
          <div class="summary-item right">
            <span class="summary-label">包 #{rightMeta?.no ?? '?'}</span>
            <span class="summary-time">{rightMeta?.timestamp_str || ''}</span>
            <span class="summary-proto">{rightMeta?.protocol || ''}</span>
            <span class="summary-len">{rightMeta?.length || 0} bytes</span>
          </div>
        </div>

        <div class="compare-content">
          <div class="compare-section">
            <h4>协议分层解析</h4>
            <div class="layers-compare">
              <div class="layers-left">
                {#each comparedLayers as layer, i}
                  <div class="layer-block {layer.hasDiff ? 'has-diff' : ''}">
                    <div class="layer-title">{layer.leftProtocol}</div>
                    {#each layer.fields as field, j}
                      <div class="field-row {field.isDiff ? 'diff' : ''}">
                        <span class="field-name">{field.leftName}</span>
                        <span class="field-value">{field.leftValue}</span>
                      </div>
                    {/each}
                  </div>
                {/each}
              </div>
              <div class="layers-right">
                {#each comparedLayers as layer, i}
                  <div class="layer-block {layer.hasDiff ? 'has-diff' : ''}">
                    <div class="layer-title">{layer.rightProtocol}</div>
                    {#each layer.fields as field, j}
                      <div class="field-row {field.isDiff ? 'diff' : ''}">
                        <span class="field-name">{field.rightName}</span>
                        <span class="field-value">{field.rightValue}</span>
                      </div>
                    {/each}
                  </div>
                {/each}
              </div>
            </div>
          </div>

          <div class="compare-section">
            <h4>十六进制 Dump 对比</h4>
            <div class="hex-compare">
              <div class="hex-panel">
                <div class="hex-scroll">
                  {#each hexDiff.left as line, i}
                    <div class="hex-line">
                      <span class="hex-offset">{line.offset}</span>
                      <span class="hex-bytes">
                        {#each line.hex as byte, j}
                          <span class:diff-byte={isDiffByte(i, j)}>{byte}</span>
                        {/each}
                      </span>
                      <span class="hex-ascii">{line.ascii}</span>
                    </div>
                  {/each}
                </div>
              </div>
              <div class="hex-panel">
                <div class="hex-scroll">
                  {#each hexDiff.right as line, i}
                    <div class="hex-line">
                      <span class="hex-offset">{line.offset}</span>
                      <span class="hex-bytes">
                        {#each line.hex as byte, j}
                          <span class:diff-byte={isDiffByte(i, j)}>{byte}</span>
                        {/each}
                      </span>
                      <span class="hex-ascii">{line.ascii}</span>
                    </div>
                  {/each}
                </div>
              </div>
            </div>
          </div>
        </div>
      {/if}
    </div>
  </div>
{/if}

<style>
  .compare-overlay {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0,0,0,0.7);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 3000;
  }
  .compare-panel {
    background: #2d2d2d;
    border: 1px solid #555;
    border-radius: 8px;
    width: 90vw;
    height: 85vh;
    max-width: 1200px;
    display: flex;
    flex-direction: column;
    box-shadow: 0 12px 40px rgba(0,0,0,0.6);
  }
  .compare-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 20px;
    border-bottom: 1px solid #444;
  }
  .compare-header h3 {
    color: #eee;
    margin: 0;
    font-size: 16px;
  }
  .close-btn {
    background: transparent;
    border: none;
    color: #888;
    font-size: 18px;
    cursor: pointer;
    padding: 4px 8px;
    border-radius: 4px;
  }
  .close-btn:hover {
    color: #eee;
    background: #444;
  }
  .compare-empty {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    color: #888;
  }
  .compare-empty p {
    margin: 4px 0;
  }
  .compare-empty .hint {
    font-size: 12px;
    color: #666;
  }
  .compare-loading {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #888;
  }
  .compare-summary {
    display: flex;
    align-items: center;
    gap: 20px;
    padding: 12px 20px;
    background: #252525;
    border-bottom: 1px solid #444;
  }
  .summary-item {
    flex: 1;
    display: flex;
    gap: 16px;
    font-size: 12px;
  }
  .summary-item.right {
    justify-content: flex-end;
  }
  .summary-label {
    color: #4fc3f7;
    font-weight: 600;
  }
  .summary-time {
    color: #aaa;
    font-family: 'Menlo', monospace;
  }
  .summary-proto {
    color: #81c784;
  }
  .summary-len {
    color: #888;
  }
  .vs {
    color: #ef5350;
    font-weight: 700;
    font-size: 14px;
  }
  .compare-content {
    flex: 1;
    overflow-y: auto;
    padding: 16px 20px;
  }
  .compare-section {
    margin-bottom: 20px;
  }
  .compare-section h4 {
    color: #ccc;
    font-size: 13px;
    margin: 0 0 10px 0;
    font-weight: 500;
  }
  .layers-compare {
    display: flex;
    gap: 12px;
  }
  .layers-left, .layers-right {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .layer-block {
    background: #333;
    border-radius: 4px;
    padding: 8px 12px;
    border-left: 3px solid #555;
  }
  .layer-block.has-diff {
    border-left-color: #ef5350;
    background: rgba(239, 83, 80, 0.08);
  }
  .layer-title {
    color: #4fc3f7;
    font-weight: 600;
    font-size: 12px;
    margin-bottom: 6px;
  }
  .field-row {
    display: flex;
    gap: 8px;
    font-size: 11px;
    padding: 2px 0;
  }
  .field-row.diff {
    background: rgba(239, 83, 80, 0.2);
    margin: 0 -4px;
    padding: 2px 4px;
    border-radius: 2px;
  }
  .field-name {
    color: #aaa;
    min-width: 120px;
  }
  .field-value {
    color: #ddd;
    font-family: 'Menlo', monospace;
    flex: 1;
  }
  .hex-compare {
    display: flex;
    gap: 12px;
  }
  .hex-panel {
    flex: 1;
    background: #1e1e1e;
    border: 1px solid #444;
    border-radius: 4px;
    overflow: hidden;
  }
  .hex-scroll {
    max-height: 300px;
    overflow-y: auto;
    font-family: 'Menlo', 'Consolas', monospace;
    font-size: 11px;
  }
  .hex-line {
    display: flex;
    align-items: center;
    padding: 1px 8px;
    border-bottom: 1px solid rgba(255,255,255,0.05);
  }
  .hex-offset {
    color: #666;
    width: 50px;
    flex-shrink: 0;
  }
  .hex-bytes {
    color: #b0bec5;
    flex: 1;
    letter-spacing: 1px;
  }
  .hex-bytes .diff-byte {
    background: rgba(239, 83, 80, 0.5);
    color: #fff;
    border-radius: 2px;
    padding: 0 2px;
    margin: 0 -1px;
  }
  .hex-ascii {
    color: #90a4ae;
    margin-left: 8px;
    width: 130px;
    flex-shrink: 0;
  }
</style>
