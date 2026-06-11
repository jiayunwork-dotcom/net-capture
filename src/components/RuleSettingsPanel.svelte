<script>
  import { onMount } from 'svelte';
  import { invoke } from '@tauri-apps/api/tauri';
  import { open, save } from '@tauri-apps/api/dialog';
  import RuleEditor from './RuleEditor.svelte';
  import RuleItem from './RuleItem.svelte';
  import VersionHistory from './VersionHistory.svelte';
  import ConflictDialog from './ConflictDialog.svelte';
  import RuleStatsPanel from './RuleStatsPanel.svelte';
  import {
    rules, ruleGroups, maxRules, selectedRuleIds,
    loadRules, addRule, updateRule, deleteRule, toggleRule,
    addRuleGroup, updateRuleGroup, deleteRuleGroup,
    generateRuleId, generateGroupId,
    exportRules, importRules,
    enabledRulesCount, rulesByGroup,
    checkRuleConflicts, batchToggleRules, batchDeleteRules, batchMoveRulesToGroup,
  } from '../stores/rules.js';

  export let onClose = () => {};

  let activeTab = 'rules';
  let showEditor = false;
  let editingRule = null;
  let isNewRule = false;
  let ruleForm = {
    name: '',
    priority: 'medium',
    description: '',
    group: null,
    enabled: true,
    condition: null,
    expression: '',
    actions: {
      system_notification: false,
      sound: false,
      auto_mark: false,
      mark_level: 'warning',
      auto_export: false,
      export_path: '',
    }
  };

  let newGroupName = '';
  let showVersionHistory = false;
  let versionHistoryRuleId = '';
  let conflicts = [];
  let showConflictDialog = false;
  let pendingSaveRule = null;
  let pendingIsNew = false;
  let batchMode = false;
  let batchAction = '';
  let showBatchConfirm = false;
  let batchTargetGroup = null;

  $: rulesByGroupValue = $rulesByGroup;
  $: selectedCount = $selectedRuleIds.length;
  $: allSelected = $rules.length > 0 && $selectedRuleIds.length === $rules.length;

  onMount(() => {
    loadRules();
  });

  function openNewRule() {
    isNewRule = true;
    editingRule = null;
    ruleForm = {
      name: '',
      priority: 'medium',
      description: '',
      group: null,
      enabled: true,
      condition: null,
      expression: '',
      actions: {
        system_notification: false,
        sound: false,
        auto_mark: false,
        mark_level: 'warning',
        auto_export: false,
        export_path: '',
      }
    };
    showEditor = true;
  }

  function openEditRule(rule) {
    isNewRule = false;
    editingRule = rule;
    ruleForm = JSON.parse(JSON.stringify(rule));
    showEditor = true;
  }

  function closeEditor() {
    showEditor = false;
    editingRule = null;
  }

  function onConditionChange(event) {
    ruleForm.condition = event.detail.condition;
    ruleForm.expression = event.detail.expression;
  }

  async function handleSaveRule() {
    if (!ruleForm.name.trim()) {
      alert('请输入规则名称');
      return;
    }

    if (!ruleForm.condition) {
      alert('请配置规则条件');
      return;
    }

    const now = Math.floor(Date.now() / 1000);
    const rule = {
      ...ruleForm,
      id: isNewRule ? generateRuleId() : editingRule.id,
      created_at: isNewRule ? now : editingRule.created_at,
      updated_at: now,
      current_version: isNewRule ? 0 : (editingRule.current_version || 0),
      versions: isNewRule ? [] : (editingRule.versions || []),
    };

    try {
      const detectedConflicts = await checkRuleConflicts(rule);
      if (detectedConflicts.length > 0) {
        conflicts = detectedConflicts;
        pendingSaveRule = rule;
        pendingIsNew = isNewRule;
        showConflictDialog = true;
        return;
      }

      await doSaveRule(rule, isNewRule);
    } catch (e) {
      alert('保存失败: ' + e);
    }
  }

  async function doSaveRule(rule, isNew) {
    try {
      if (isNew) {
        await addRule(rule);
      } else {
        await updateRule(rule);
      }
      closeEditor();
    } catch (e) {
      alert('保存失败: ' + e);
    }
  }

  function onConflictContinue() {
    showConflictDialog = false;
    if (pendingSaveRule) {
      doSaveRule(pendingSaveRule, pendingIsNew);
      pendingSaveRule = null;
    }
  }

  function onConflictCancel() {
    showConflictDialog = false;
    pendingSaveRule = null;
  }

  async function handleDeleteRule(rule) {
    if (!confirm(`确定删除规则 "${rule.name}" 吗？`)) return;
    try {
      await deleteRule(rule.id);
    } catch (e) {
      alert('删除失败: ' + e);
    }
  }

  async function handleToggleRule(rule, enabled) {
    try {
      await toggleRule(rule.id, enabled);
    } catch (e) {
      console.error('Toggle error:', e);
    }
  }

  function openVersionHistory(rule) {
    versionHistoryRuleId = rule.id;
    showVersionHistory = true;
  }

  function onVersionHistoryClose() {
    showVersionHistory = false;
  }

  function onVersionRollback() {
    loadRules();
  }

  function toggleSelectRule(ruleId) {
    if ($selectedRuleIds.includes(ruleId)) {
      selectedRuleIds.update(ids => ids.filter(id => id !== ruleId));
    } else {
      selectedRuleIds.update(ids => [...ids, ruleId]);
    }
  }

  function toggleSelectAll() {
    if (allSelected) {
      selectedRuleIds.set([]);
    } else {
      selectedRuleIds.set($rules.map(r => r.id));
    }
  }

  function toggleBatchMode() {
    batchMode = !batchMode;
    if (!batchMode) {
      selectedRuleIds.set([]);
    }
  }

  function requestBatchAction(action) {
    if ($selectedRuleIds.length === 0) return;
    batchAction = action;
    showBatchConfirm = true;
  }

  async function confirmBatchAction() {
    showBatchConfirm = false;
    try {
      switch (batchAction) {
        case 'enable':
          await batchToggleRules($selectedRuleIds, true);
          break;
        case 'disable':
          await batchToggleRules($selectedRuleIds, false);
          break;
        case 'delete':
          await batchDeleteRules($selectedRuleIds);
          break;
        case 'move':
          await batchMoveRulesToGroup($selectedRuleIds, batchTargetGroup);
          break;
        case 'export':
          await handleBatchExport();
          break;
      }
      selectedRuleIds.set([]);
      batchMode = false;
    } catch (e) {
      alert('批量操作失败: ' + e);
    }
  }

  function getBatchConfirmMessage() {
    const count = $selectedRuleIds.length;
    switch (batchAction) {
      case 'enable': return `确定要启用选中的 ${count} 条规则吗？`;
      case 'disable': return `确定要禁用选中的 ${count} 条规则吗？`;
      case 'delete': return `确定要删除选中的 ${count} 条规则吗？此操作不可撤销！`;
      case 'move': return `确定要将选中的 ${count} 条规则移动到指定分组吗？`;
      case 'export': return `确定要导出选中的 ${count} 条规则吗？`;
      default: return '';
    }
  }

  async function handleBatchExport() {
    try {
      const filePath = await save({
        filters: [{ name: 'JSON', extensions: ['json'] }],
        defaultPath: 'detection_rules.json',
      });
      if (filePath) {
        await exportRules(filePath, $selectedRuleIds);
        alert('导出成功');
      }
    } catch (e) {
      alert('导出失败: ' + e);
    }
  }

  async function handleAddGroup() {
    if (!newGroupName.trim()) {
      alert('请输入分组名称');
      return;
    }
    try {
      await addRuleGroup({
        id: generateGroupId(),
        name: newGroupName.trim(),
        order: $ruleGroups.length,
      });
      newGroupName = '';
    } catch (e) {
      alert('添加分组失败: ' + e);
    }
  }

  async function handleDeleteGroup(group) {
    if (!confirm(`确定删除分组 "${group.name}" 吗？组内规则将变为未分组。`)) return;
    try {
      await deleteRuleGroup(group.id);
    } catch (e) {
      alert('删除分组失败: ' + e);
    }
  }

  async function handleExportRules(ruleIds = null) {
    try {
      const filePath = await save({
        filters: [{ name: 'JSON', extensions: ['json'] }],
        defaultPath: 'detection_rules.json',
      });
      if (filePath) {
        await exportRules(filePath, ruleIds);
        alert('导出成功');
      }
    } catch (e) {
      alert('导出失败: ' + e);
    }
  }

  async function handleImportRules() {
    try {
      const filePath = await open({
        filters: [{ name: 'JSON', extensions: ['json'] }],
        multiple: false,
      });
      if (filePath) {
        const count = await importRules(filePath);
        alert(`成功导入 ${count} 条规则`);
      }
    } catch (e) {
      alert('导入失败: ' + e);
    }
  }

  async function selectExportPath() {
    try {
      const path = await save({
        filters: [{ name: 'PCAP', extensions: ['pcap'] }],
        defaultPath: 'alerts.pcap',
      });
      if (path) {
        ruleForm.actions.export_path = path;
      }
    } catch (e) {
      console.error('Select path error:', e);
    }
  }

  function getPriorityClass(priority) {
    switch (priority) {
      case 'high': return 'priority-high';
      case 'medium': return 'priority-medium';
      case 'low': return 'priority-low';
      default: return '';
    }
  }

  function getPriorityLabel(priority) {
    switch (priority) {
      case 'high': return '高';
      case 'medium': return '中';
      case 'low': return '低';
      default: return '';
    }
  }
</script>

<div class="settings-panel">
  <div class="panel-header">
    <h2>检测规则设置</h2>
    <button class="close-btn" on:click={onClose}>✕</button>
  </div>

  <div class="tabs">
    <button class:active={activeTab === 'rules'} on:click={() => activeTab = 'rules'}>
      规则管理
    </button>
    <button class:active={activeTab === 'groups'} on:click={() => activeTab = 'groups'}>
      分组管理
    </button>
    <button class:active={activeTab === 'stats'} on:click={() => activeTab = 'stats'}>
      触发统计
    </button>
  </div>

  {#if activeTab === 'rules'}
    <div class="rules-section">
      <div class="section-toolbar">
        <div class="toolbar-left">
          <button class="btn-primary" on:click={openNewRule}>+ 新建规则</button>
          <button class="btn-secondary" on:click={toggleBatchMode}>
            {batchMode ? '退出多选' : '☑ 多选'}
          </button>
          <span class="rule-count">
            {$rules.length} / {$maxRules} 条
            <span class="enabled">({$enabledRulesCount} 启用)</span>
          </span>
        </div>
        <div class="toolbar-right">
          <button class="btn-secondary" on:click={handleImportRules}>📥 导入</button>
          <button class="btn-secondary" on:click={() => handleExportRules(null)}>📤 全部导出</button>
        </div>
      </div>

      {#if batchMode && selectedCount > 0}
        <div class="batch-toolbar">
          <span class="batch-count">已选 {selectedCount} 条</span>
          <button class="btn-batch" on:click={() => requestBatchAction('enable')}>批量启用</button>
          <button class="btn-batch" on:click={() => requestBatchAction('disable')}>批量禁用</button>
          <button class="btn-batch danger" on:click={() => requestBatchAction('delete')}>批量删除</button>
          <select bind:value={batchTargetGroup} class="group-select">
            <option value={null}>移动到分组...</option>
            <option value="">未分组</option>
            {#each $ruleGroups as g}
              <option value={g.id}>{g.name}</option>
            {/each}
          </select>
          <button class="btn-batch" on:click={() => requestBatchAction('move')}>移动</button>
          <button class="btn-batch" on:click={() => requestBatchAction('export')}>导出选中</button>
        </div>
      {/if}

      <div class="rules-list">
        {#if batchMode}
          <div class="select-all-row">
            <label class="checkbox-label">
              <input type="checkbox" checked={allSelected} on:change={toggleSelectAll} />
              全选
            </label>
          </div>
        {/if}

        {#if $ruleGroups.length > 0}
          {#each $ruleGroups as group}
            {#if rulesByGroupValue[group.id] && rulesByGroupValue[group.id].rules.length > 0}
              <div class="rule-group">
                <div class="group-header">
                  <span class="group-name">📁 {group.name}</span>
                  <span class="group-count">{rulesByGroupValue[group.id].rules.length} 条</span>
                </div>
                {#each rulesByGroupValue[group.id].rules as rule}
                  <div class="rule-item-wrapper">
                    {#if batchMode}
                      <input
                        type="checkbox"
                        checked={$selectedRuleIds.includes(rule.id)}
                        on:change={() => toggleSelectRule(rule.id)}
                        class="rule-checkbox"
                      />
                    {/if}
                    <div class="rule-item-flex">
                      <RuleItem
                        rule={rule}
                        on:edit={() => openEditRule(rule)}
                        on:delete={() => handleDeleteRule(rule)}
                        on:toggle={(e) => handleToggleRule(rule, e.detail)}
                      />
                    </div>
                    {#if !batchMode}
                      <button class="btn-history" on:click={() => openVersionHistory(rule)} title="历史版本">
                        📜
                      </button>
                    {/if}
                  </div>
                {/each}
              </div>
            {/if}
          {/each}
        {/if}

        {#if rulesByGroupValue['_ungrouped'] && rulesByGroupValue['_ungrouped'].rules.length > 0}
          <div class="rule-group">
            <div class="group-header">
              <span class="group-name">📄 未分组</span>
              <span class="group-count">{rulesByGroupValue['_ungrouped'].rules.length} 条</span>
            </div>
            {#each rulesByGroupValue['_ungrouped'].rules as rule}
              <div class="rule-item-wrapper">
                {#if batchMode}
                  <input
                    type="checkbox"
                    checked={$selectedRuleIds.includes(rule.id)}
                    on:change={() => toggleSelectRule(rule.id)}
                    class="rule-checkbox"
                  />
                {/if}
                <div class="rule-item-flex">
                  <RuleItem
                    rule={rule}
                    on:edit={() => openEditRule(rule)}
                    on:delete={() => handleDeleteRule(rule)}
                    on:toggle={(e) => handleToggleRule(rule, e.detail)}
                  />
                </div>
                {#if !batchMode}
                  <button class="btn-history" on:click={() => openVersionHistory(rule)} title="历史版本">
                    📜
                  </button>
                {/if}
              </div>
            {/each}
          </div>
        {/if}

        {#if $rules.length === 0}
          <div class="empty-state">
            <div class="empty-icon">📋</div>
            <div class="empty-text">暂无检测规则</div>
            <div class="empty-hint">点击"新建规则"创建第一条规则</div>
          </div>
        {/if}
      </div>
    </div>
  {:else if activeTab === 'groups'}
    <div class="groups-section">
      <div class="section-toolbar">
        <div class="group-input">
          <input
            type="text"
            bind:value={newGroupName}
            placeholder="输入分组名称..."
            on:keydown={(e) => e.key === 'Enter' && handleAddGroup()}
          />
          <button class="btn-primary" on:click={handleAddGroup}>添加</button>
        </div>
      </div>

      <div class="groups-list">
        {#each $ruleGroups as group}
          <div class="group-item">
            <span class="group-name">📁 {group.name}</span>
            <div class="group-actions">
              <button class="btn-small" on:click={() => handleDeleteGroup(group)}>删除</button>
            </div>
          </div>
        {/each}
        {#if $ruleGroups.length === 0}
          <div class="empty-state">
            <div class="empty-icon">📁</div>
            <div class="empty-text">暂无分组</div>
            <div class="empty-hint">在上方输入框创建分组</div>
          </div>
        {/if}
      </div>
    </div>
  {:else if activeTab === 'stats'}
    <div class="stats-section">
      <RuleStatsPanel />
    </div>
  {/if}
</div>

{#if showEditor}
  <div class="editor-modal" on:click|self={closeEditor}>
    <div class="editor-dialog">
      <div class="dialog-header">
        <h3>{isNewRule ? '新建规则' : '编辑规则'}</h3>
        <button class="close-btn" on:click={closeEditor}>✕</button>
      </div>

      <div class="dialog-body">
        <div class="form-row">
          <div class="form-group">
            <label>规则名称</label>
            <input type="text" bind:value={ruleForm.name} placeholder="输入规则名称..." />
          </div>
          <div class="form-group">
            <label>优先级</label>
            <select bind:value={ruleForm.priority}>
              <option value="high">高</option>
              <option value="medium">中</option>
              <option value="low">低</option>
            </select>
          </div>
        </div>

        <div class="form-row">
          <div class="form-group">
            <label>分组</label>
            <select bind:value={ruleForm.group}>
              <option value={null}>未分组</option>
              {#each $ruleGroups as g}
                <option value={g.id}>{g.name}</option>
              {/each}
            </select>
          </div>
          <div class="form-group">
            <label class="checkbox-label">
              <input type="checkbox" bind:checked={ruleForm.enabled} />
              启用规则
            </label>
          </div>
        </div>

        <div class="form-group">
          <label>描述</label>
          <textarea bind:value={ruleForm.description} rows={2} placeholder="可选描述信息..." />
        </div>

        <div class="form-group">
          <label>触发条件</label>
          <div class="rule-editor-container">
            <RuleEditor
              condition={ruleForm.condition}
              expression={ruleForm.expression}
              on:change={onConditionChange}
            />
          </div>
        </div>

        <div class="form-group">
          <label>告警动作</label>
          <div class="actions-grid">
            <label class="checkbox-label">
              <input type="checkbox" bind:checked={ruleForm.actions.system_notification} />
              🔔 系统通知
            </label>
            <label class="checkbox-label">
              <input type="checkbox" bind:checked={ruleForm.actions.sound} />
              🔊 声音提示
            </label>
            <label class="checkbox-label">
              <input type="checkbox" bind:checked={ruleForm.actions.auto_mark} />
              🏷️ 自动标记
            </label>
            <label class="checkbox-label">
              <input type="checkbox" bind:checked={ruleForm.actions.auto_export} />
              📤 自动导出
            </label>
          </div>

          {#if ruleForm.actions.auto_mark}
            <div class="nested-setting">
              <label>标记级别</label>
              <select bind:value={ruleForm.actions.mark_level}>
                <option value="starred">星标</option>
                <option value="warning">警告</option>
                <option value="important">重要</option>
              </select>
            </div>
          {/if}

          {#if ruleForm.actions.auto_export}
            <div class="nested-setting">
              <label>导出路径</label>
              <div class="path-input">
                <input type="text" bind:value={ruleForm.actions.export_path} placeholder="选择PCAP文件路径..." readonly />
                <button class="btn-small" on:click={selectExportPath}>浏览...</button>
              </div>
            </div>
          {/if}
        </div>
      </div>

      <div class="dialog-footer">
        {#if !isNewRule && editingRule}
          <button class="btn-version" on:click={() => openVersionHistory(editingRule)}>📜 历史版本</button>
        {/if}
        <div class="footer-spacer" />
        <button class="btn-cancel" on:click={closeEditor}>取消</button>
        <button class="btn-confirm" on:click={handleSaveRule}>保存</button>
      </div>
    </div>
  </div>
{/if}

{#if showVersionHistory}
  <VersionHistory
    ruleId={versionHistoryRuleId}
    on:close={onVersionHistoryClose}
    on:rollback={onVersionRollback}
  />
{/if}

{#if showConflictDialog}
  <ConflictDialog
    {conflicts}
    on:continue={onConflictContinue}
    on:cancel={onConflictCancel}
  />
{/if}

{#if showBatchConfirm}
  <div class="confirm-modal" on:click|self={() => showBatchConfirm = false}>
    <div class="confirm-dialog">
      <div class="confirm-body">
        <p>{getBatchConfirmMessage()}</p>
      </div>
      <div class="confirm-footer">
        <button class="btn-cancel" on:click={() => showBatchConfirm = false}>取消</button>
        <button class="btn-confirm" on:click={confirmBatchAction}>确定</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .settings-panel {
    display: flex;
    flex-direction: column;
    width: 900px;
    max-height: 80vh;
    background: #1e1e1e;
    color: #e0e0e0;
    border-radius: 8px;
    overflow: hidden;
    font-size: 12px;
  }

  .panel-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 16px 20px;
    background: #252525;
    border-bottom: 1px solid #3a3a3a;
  }

  .panel-header h2 {
    margin: 0;
    font-size: 16px;
    color: #4fc3f7;
  }

  .close-btn {
    background: transparent;
    border: none;
    color: #888;
    cursor: pointer;
    font-size: 18px;
    padding: 4px 8px;
  }

  .close-btn:hover {
    color: #fff;
  }

  .tabs {
    display: flex;
    background: #252525;
    border-bottom: 1px solid #3a3a3a;
  }

  .tabs button {
    padding: 10px 20px;
    background: transparent;
    color: #888;
    border: none;
    border-bottom: 2px solid transparent;
    cursor: pointer;
    font-size: 13px;
  }

  .tabs button.active {
    color: #4fc3f7;
    border-bottom-color: #4fc3f7;
  }

  .rules-section, .groups-section, .stats-section {
    flex: 1;
    overflow-y: auto;
    padding: 16px;
  }

  .section-toolbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 16px;
  }

  .toolbar-left, .toolbar-right {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .btn-primary {
    padding: 8px 16px;
    background: #1565c0;
    color: #fff;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 12px;
    font-weight: 500;
  }

  .btn-primary:hover {
    background: #1976d2;
  }

  .btn-secondary {
    padding: 6px 12px;
    background: #3a3a3a;
    color: #ccc;
    border: 1px solid #555;
    border-radius: 4px;
    cursor: pointer;
    font-size: 12px;
  }

  .btn-secondary:hover {
    background: #4a4a4a;
  }

  .rule-count {
    color: #888;
    font-size: 12px;
  }

  .rule-count .enabled {
    color: #4caf50;
  }

  .batch-toolbar {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 10px 12px;
    background: #2d2d2d;
    border: 1px solid #3a3a3a;
    border-radius: 6px;
    margin-bottom: 12px;
  }

  .batch-count {
    font-size: 12px;
    color: #4fc3f7;
    font-weight: 500;
    margin-right: 8px;
  }

  .btn-batch {
    padding: 5px 10px;
    background: #3a3a3a;
    color: #ccc;
    border: 1px solid #555;
    border-radius: 3px;
    cursor: pointer;
    font-size: 11px;
  }

  .btn-batch:hover {
    background: #4a4a4a;
  }

  .btn-batch.danger {
    color: #ef5350;
    border-color: #ef5350;
  }

  .btn-batch.danger:hover {
    background: rgba(239, 83, 80, 0.15);
  }

  .group-select {
    padding: 5px 8px;
    background: #1e1e1e;
    color: #ccc;
    border: 1px solid #555;
    border-radius: 3px;
    font-size: 11px;
    max-width: 140px;
  }

  .select-all-row {
    padding: 8px 14px;
    background: #2d2d2d;
    border: 1px solid #3a3a3a;
    border-radius: 6px;
    margin-bottom: 8px;
  }

  .rule-item-wrapper {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .rule-checkbox {
    margin-left: 10px;
    cursor: pointer;
    width: 16px;
    height: 16px;
  }

  .rule-item-flex {
    flex: 1;
    min-width: 0;
  }

  .btn-history {
    background: transparent;
    border: none;
    cursor: pointer;
    font-size: 16px;
    padding: 4px 6px;
    opacity: 0.5;
    transition: opacity 0.2s;
  }

  .btn-history:hover {
    opacity: 1;
  }

  .rules-list {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .rule-group {
    background: #252525;
    border: 1px solid #3a3a3a;
    border-radius: 6px;
    overflow: hidden;
  }

  .group-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 10px 14px;
    background: #2d2d2d;
    border-bottom: 1px solid #3a3a3a;
  }

  .group-name {
    font-size: 12px;
    font-weight: 500;
    color: #ccc;
  }

  .group-count {
    font-size: 11px;
    color: #888;
  }

  .empty-state {
    text-align: center;
    padding: 40px 20px;
    color: #666;
  }

  .empty-icon {
    font-size: 48px;
    margin-bottom: 12px;
  }

  .empty-text {
    font-size: 14px;
    margin-bottom: 6px;
    color: #888;
  }

  .empty-hint {
    font-size: 12px;
  }

  .group-input {
    display: flex;
    gap: 8px;
    flex: 1;
    max-width: 400px;
  }

  .group-input input {
    flex: 1;
    padding: 8px 12px;
    background: #1e1e1e;
    color: #e0e0e0;
    border: 1px solid #444;
    border-radius: 4px;
    font-size: 12px;
  }

  .groups-list {
    display: flex;
    flex-direction: column;
    gap: 8px;
    margin-top: 16px;
  }

  .group-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 10px 14px;
    background: #252525;
    border: 1px solid #3a3a3a;
    border-radius: 6px;
  }

  .group-actions {
    display: flex;
    gap: 8px;
  }

  .btn-small {
    padding: 4px 10px;
    background: #3a3a3a;
    color: #ccc;
    border: 1px solid #555;
    border-radius: 3px;
    cursor: pointer;
    font-size: 11px;
  }

  .btn-small:hover {
    background: #4a4a4a;
  }

  .editor-modal {
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,0.7);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 2000;
  }

  .editor-dialog {
    width: 1000px;
    max-height: 90vh;
    background: #1e1e1e;
    border-radius: 8px;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  .dialog-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 14px 20px;
    background: #252525;
    border-bottom: 1px solid #3a3a3a;
  }

  .dialog-header h3 {
    margin: 0;
    font-size: 15px;
    color: #4fc3f7;
  }

  .dialog-body {
    flex: 1;
    overflow-y: auto;
    padding: 20px;
  }

  .form-row {
    display: flex;
    gap: 16px;
    margin-bottom: 16px;
  }

  .form-group {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .form-group label {
    font-size: 11px;
    color: #888;
    text-transform: uppercase;
    font-weight: 500;
  }

  .form-group input,
  .form-group select,
  .form-group textarea {
    padding: 8px 10px;
    background: #1e1e1e;
    color: #e0e0e0;
    border: 1px solid #444;
    border-radius: 4px;
    font-size: 12px;
    font-family: inherit;
  }

  .form-group input:focus,
  .form-group select:focus,
  .form-group textarea:focus {
    outline: none;
    border-color: #4fc3f7;
  }

  .checkbox-label {
    display: flex;
    align-items: center;
    gap: 6px;
    cursor: pointer;
    font-size: 12px;
    color: #ccc;
    text-transform: none !important;
  }

  .checkbox-label input {
    width: auto;
    cursor: pointer;
  }

  .rule-editor-container {
    height: 400px;
    border: 1px solid #444;
    border-radius: 6px;
    overflow: hidden;
  }

  .actions-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 10px;
    margin-top: 6px;
  }

  .nested-setting {
    margin-top: 10px;
    padding-left: 24px;
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .nested-setting label {
    font-size: 11px;
    color: #888;
    margin-bottom: 0;
  }

  .nested-setting select {
    padding: 6px 8px;
    font-size: 12px;
  }

  .path-input {
    display: flex;
    gap: 6px;
    flex: 1;
  }

  .path-input input {
    flex: 1;
    padding: 6px 10px;
    background: #1e1e1e;
    color: #888;
    border: 1px solid #444;
    border-radius: 4px;
    font-size: 12px;
  }

  .dialog-footer {
    display: flex;
    justify-content: flex-end;
    align-items: center;
    gap: 10px;
    padding: 14px 20px;
    background: #252525;
    border-top: 1px solid #3a3a3a;
  }

  .footer-spacer {
    flex: 1;
  }

  .btn-version {
    padding: 8px 16px;
    background: #3a3a3a;
    color: #4fc3f7;
    border: 1px solid #4fc3f7;
    border-radius: 4px;
    cursor: pointer;
    font-size: 12px;
  }

  .btn-version:hover {
    background: rgba(79, 195, 247, 0.15);
  }

  .btn-cancel {
    padding: 8px 16px;
    background: #3a3a3a;
    color: #ccc;
    border: 1px solid #555;
    border-radius: 4px;
    cursor: pointer;
    font-size: 12px;
  }

  .btn-cancel:hover {
    background: #4a4a4a;
  }

  .btn-confirm {
    padding: 8px 16px;
    background: #1565c0;
    color: #fff;
    border: 1px solid #1976d2;
    border-radius: 4px;
    cursor: pointer;
    font-size: 12px;
  }

  .btn-confirm:hover {
    background: #1976d2;
  }

  .confirm-modal {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.6);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 3000;
  }

  .confirm-dialog {
    width: 420px;
    background: #1e1e1e;
    border-radius: 8px;
    overflow: hidden;
    border: 1px solid #3a3a3a;
  }

  .confirm-body {
    padding: 24px;
    text-align: center;
  }

  .confirm-body p {
    margin: 0;
    font-size: 14px;
    color: #e0e0e0;
  }

  .confirm-footer {
    display: flex;
    justify-content: center;
    gap: 12px;
    padding: 16px;
    background: #252525;
    border-top: 1px solid #3a3a3a;
  }
</style>
