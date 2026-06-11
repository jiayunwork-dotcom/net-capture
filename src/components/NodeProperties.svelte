<script>
  import { createEventDispatcher, onMount } from 'svelte';
  import { validateRegex, validateCidr } from '../stores/rules.js';

  export let node;
  const dispatch = createEventDispatcher();

  let cidrError = '';
  let regexError = '';

  function update(param, value) {
    dispatch('update', { param, value });
  }

  async function checkCidr(cidr) {
    const result = await validateCidr(cidr);
    cidrError = result.valid ? '' : 'CIDR格式无效';
  }

  async function checkRegex(pattern) {
    const result = await validateRegex(pattern);
    regexError = result.valid ? '' : result.error || '正则表达式无效';
  }

  const protocolOptions = ['tcp', 'udp', 'http', 'dns', 'tls', 'icmp', 'arp', 'ip'];
  const ipFieldOptions = [
    { value: 'src', label: '源IP' },
    { value: 'dst', label: '目的IP' },
    { value: 'either', label: '任意' },
  ];
  const portFieldOptions = [
    { value: 'src', label: '源端口' },
    { value: 'dst', label: '目的端口' },
    { value: 'either', label: '任意' },
  ];
  const lengthOperatorOptions = [
    { value: 'greater_than', label: '大于 (>)' },
    { value: 'less_than', label: '小于 (<)' },
    { value: 'equal', label: '等于 (==)' },
  ];
  const flagModeOptions = [
    { value: 'all', label: '全部匹配' },
    { value: 'any', label: '任一匹配' },
    { value: 'exact', label: '精确匹配' },
    { value: 'none', label: '都不匹配' },
  ];
  const tcpFlagOptions = ['SYN', 'ACK', 'FIN', 'RST', 'PSH', 'URG'];

  function toggleFlag(flag) {
    const flags = [...node.flags];
    const idx = flags.indexOf(flag);
    if (idx === -1) {
      flags.push(flag);
    } else {
      flags.splice(idx, 1);
    }
    update('flags', flags);
  }

  function addDomain() {
    const domains = [...node.domains, ''];
    update('domains', domains);
  }

  function updateDomain(index, value) {
    const domains = [...node.domains];
    domains[index] = value;
    update('domains', domains);
  }

  function removeDomain(index) {
    const domains = node.domains.filter((_, i) => i !== index);
    update('domains', domains);
  }

  $: if (node && node.type === 'ip_match') {
    checkCidr(node.cidr);
  }

  $: if (node && node.type === 'payload_keyword') {
    checkRegex(node.pattern);
  }
</script>

{#if node}
  <div class="property-editor">
    {#if node.type === 'protocol_match'}
      <div class="prop-group">
        <label>协议类型</label>
        <select value={node.protocol} on:change={(e) => update('protocol', e.target.value)}>
          {#each protocolOptions as p}
            <option value={p}>{p.toUpperCase()}</option>
          {/each}
        </select>
      </div>
    {:else if node.type === 'ip_match'}
      <div class="prop-group">
        <label>IP方向</label>
        <select value={node.field} on:change={(e) => update('field', e.target.value)}>
          {#each ipFieldOptions as opt}
            <option value={opt.value}>{opt.label}</option>
          {/each}
        </select>
      </div>
      <div class="prop-group">
        <label>CIDR地址</label>
        <input
          type="text"
          value={node.cidr}
          class:error={cidrError}
          on:input={(e) => update('cidr', e.target.value)}
          placeholder="例如: 192.168.1.0/24"
        />
        {#if cidrError}
          <span class="error-text">{cidrError}</span>
        {/if}
      </div>
    {:else if node.type === 'port_range'}
      <div class="prop-group">
        <label>端口方向</label>
        <select value={node.field} on:change={(e) => update('field', e.target.value)}>
          {#each portFieldOptions as opt}
            <option value={opt.value}>{opt.label}</option>
          {/each}
        </select>
      </div>
      <div class="prop-group">
        <label>端口范围</label>
        <div class="range-inputs">
          <input
            type="number"
            min="1"
            max="65535"
            value={node.min}
            on:input={(e) => update('min', parseInt(e.target.value) || 0)}
          />
          <span class="range-sep">-</span>
          <input
            type="number"
            min="1"
            max="65535"
            value={node.max}
            on:input={(e) => update('max', parseInt(e.target.value) || 0)}
          />
        </div>
      </div>
    {:else if node.type === 'packet_length'}
      <div class="prop-group">
        <label>比较操作</label>
        <select value={node.operator} on:change={(e) => update('operator', e.target.value)}>
          {#each lengthOperatorOptions as opt}
            <option value={opt.value}>{opt.label}</option>
          {/each}
        </select>
      </div>
      <div class="prop-group">
        <label>包长度 (字节)</label>
        <input
          type="number"
          min="0"
          value={node.value}
          on:input={(e) => update('value', parseInt(e.target.value) || 0)}
        />
      </div>
    {:else if node.type === 'tcp_flags'}
      <div class="prop-group">
        <label>匹配模式</label>
        <select value={node.mode} on:change={(e) => update('mode', e.target.value)}>
          {#each flagModeOptions as opt}
            <option value={opt.value}>{opt.label}</option>
          {/each}
        </select>
      </div>
      <div class="prop-group">
        <label>TCP标志位</label>
        <div class="flag-checkboxes">
          {#each tcpFlagOptions as flag}
            <label class="flag-checkbox">
              <input
                type="checkbox"
                checked={node.flags.includes(flag)}
                on:change={() => toggleFlag(flag)}
              />
              <span>{flag}</span>
            </label>
          {/each}
        </div>
      </div>
    {:else if node.type === 'payload_keyword'}
      <div class="prop-group">
        <label>正则表达式</label>
        <textarea
          value={node.pattern}
          class:error={regexError}
          on:input={(e) => update('pattern', e.target.value)}
          rows={3}
          placeholder="输入正则表达式..."
        />
        {#if regexError}
          <span class="error-text">{regexError}</span>
        {/if}
      </div>
    {:else if node.type === 'rate_limit'}
      <div class="prop-group">
        <label>检测方向</label>
        <select
          value={node.src_ip ? 'src' : 'dst'}
          on:change={(e) => update('src_ip', e.target.value === 'src')}
        >
          <option value="src">源IP速率</option>
          <option value="dst">目的IP速率</option>
        </select>
      </div>
      <div class="prop-group">
        <label>时间窗口 (秒)</label>
        <input
          type="number"
          min="1"
          max="60"
          value={node.window_secs}
          on:input={(e) => update('window_secs', parseInt(e.target.value) || 1)}
        />
        <span class="hint">最大60秒</span>
      </div>
      <div class="prop-group">
        <label>阈值 (包数)</label>
        <input
          type="number"
          min="1"
          value={node.threshold}
          on:input={(e) => update('threshold', parseInt(e.target.value) || 1)}
        />
      </div>
    {:else if node.type === 'dns_blacklist'}
      <div class="prop-group">
        <label>黑名单域名</label>
        <div class="domain-list">
          {#each node.domains as domain, index}
            <div class="domain-item">
              <input
                type="text"
                value={domain}
                on:input={(e) => updateDomain(index, e.target.value)}
                placeholder="example.com"
              />
              <button class="remove-domain" on:click={() => removeDomain(index)}>✕</button>
            </div>
          {/each}
        </div>
        <button class="add-domain-btn" on:click={addDomain}>+ 添加域名</button>
      </div>
    {/if}
  </div>
{/if}

<style>
  .property-editor {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .prop-group {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  label {
    font-size: 11px;
    color: #888;
    text-transform: uppercase;
    font-weight: 500;
  }

  select, input, textarea {
    width: 100%;
    box-sizing: border-box;
    padding: 6px 10px;
    background: #1e1e1e;
    color: #e0e0e0;
    border: 1px solid #444;
    border-radius: 4px;
    font-size: 12px;
    font-family: inherit;
  }

  select:focus, input:focus, textarea:focus {
    outline: none;
    border-color: #4fc3f7;
  }

  .error {
    border-color: #ef5350 !important;
  }

  .error-text {
    color: #ef5350;
    font-size: 11px;
  }

  .hint {
    color: #666;
    font-size: 10px;
  }

  .range-inputs {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .range-inputs input {
    flex: 1;
  }

  .range-sep {
    color: #666;
    font-size: 12px;
  }

  .flag-checkboxes {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }

  .flag-checkbox {
    display: flex;
    align-items: center;
    gap: 4px;
    cursor: pointer;
    font-size: 12px;
    color: #ccc;
  }

  .flag-checkbox input {
    width: auto;
    cursor: pointer;
  }

  .domain-list {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .domain-item {
    display: flex;
    gap: 6px;
  }

  .domain-item input {
    flex: 1;
  }

  .remove-domain {
    width: 28px;
    height: 28px;
    display: flex;
    align-items: center;
    justify-content: center;
    background: #2d2d2d;
    color: #888;
    border: 1px solid #444;
    border-radius: 4px;
    cursor: pointer;
    font-size: 11px;
  }

  .remove-domain:hover {
    background: rgba(239, 83, 80, 0.2);
    color: #ef5350;
    border-color: #ef5350;
  }

  .add-domain-btn {
    width: 100%;
    padding: 6px;
    background: #2d2d2d;
    color: #4fc3f7;
    border: 1px dashed #444;
    border-radius: 4px;
    cursor: pointer;
    font-size: 11px;
    margin-top: 4px;
  }

  .add-domain-btn:hover {
    background: #3a3a3a;
    border-color: #4fc3f7;
  }
</style>
