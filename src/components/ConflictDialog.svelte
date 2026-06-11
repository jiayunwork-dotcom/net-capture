<script>
  import { createEventDispatcher } from 'svelte';

  export let conflicts = [];

  const dispatch = createEventDispatcher();

  function ignoreAndContinue() {
    dispatch('continue');
  }

  function cancel() {
    dispatch('cancel');
  }
</script>

<div class="conflict-modal" on:click|self={cancel}>
  <div class="conflict-dialog">
    <div class="dialog-header">
      <h3>⚠️ 检测到规则冲突</h3>
    </div>

    <div class="dialog-body">
      <div class="conflict-count">发现 {conflicts.length} 条冲突规则</div>

      <div class="conflict-list">
        {#each conflicts as c, i}
          <div class="conflict-item">
            <div class="conflict-rules">
              <span class="rule-tag a">{c.rule_a_name}</span>
              <span class="vs">vs</span>
              <span class="rule-tag b">{c.rule_b_name}</span>
            </div>
            <div class="conflict-detail">
              <div class="detail-row">
                <span class="detail-label">条件交集:</span>
                <span class="detail-value">{c.intersection_desc}</span>
              </div>
              <div class="detail-row">
                <span class="detail-label">动作矛盾:</span>
                <span class="detail-value warn">{c.action_conflict}</span>
              </div>
            </div>
          </div>
        {/each}
      </div>
    </div>

    <div class="dialog-footer">
      <button class="btn-cancel" on:click={cancel}>取消保存</button>
      <button class="btn-ignore" on:click={ignoreAndContinue}>忽略冲突, 继续保存</button>
    </div>
  </div>
</div>

<style>
  .conflict-modal {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.7);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 3000;
  }

  .conflict-dialog {
    width: 650px;
    max-height: 80vh;
    background: #1e1e1e;
    border-radius: 8px;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    border: 1px solid #ff9800;
  }

  .dialog-header {
    padding: 14px 20px;
    background: #2d2d1a;
    border-bottom: 1px solid #555;
  }

  .dialog-header h3 {
    margin: 0;
    font-size: 15px;
    color: #ff9800;
  }

  .dialog-body {
    flex: 1;
    overflow-y: auto;
    padding: 16px;
  }

  .conflict-count {
    font-size: 13px;
    color: #ff9800;
    margin-bottom: 16px;
  }

  .conflict-list {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .conflict-item {
    background: #252525;
    border: 1px solid #3a3a3a;
    border-radius: 6px;
    padding: 12px;
  }

  .conflict-rules {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 10px;
  }

  .rule-tag {
    padding: 3px 10px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: 500;
  }

  .rule-tag.a {
    background: rgba(79, 195, 247, 0.15);
    color: #4fc3f7;
  }

  .rule-tag.b {
    background: rgba(171, 71, 188, 0.15);
    color: #ce93d8;
  }

  .vs {
    font-size: 11px;
    color: #888;
    font-weight: 600;
  }

  .conflict-detail {
    display: flex;
    flex-direction: column;
    gap: 6px;
    padding-left: 12px;
  }

  .detail-row {
    display: flex;
    gap: 8px;
    font-size: 12px;
  }

  .detail-label {
    color: #888;
    min-width: 70px;
  }

  .detail-value {
    color: #ccc;
    flex: 1;
  }

  .detail-value.warn {
    color: #ff9800;
  }

  .dialog-footer {
    display: flex;
    justify-content: flex-end;
    gap: 10px;
    padding: 14px 20px;
    background: #252525;
    border-top: 1px solid #3a3a3a;
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

  .btn-ignore {
    padding: 8px 16px;
    background: #e65100;
    color: #fff;
    border: 1px solid #ff6d00;
    border-radius: 4px;
    cursor: pointer;
    font-size: 12px;
  }

  .btn-ignore:hover {
    background: #ff6d00;
  }
</style>
