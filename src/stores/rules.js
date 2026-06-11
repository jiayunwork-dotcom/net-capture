import { writable, derived } from 'svelte/store';
import { invoke } from '@tauri-apps/api/tauri';

export const rules = writable([]);
export const ruleGroups = writable([]);
export const maxRules = writable(200);
export const rulesLoading = writable(false);
export const rulesError = writable(null);
export const ruleStats = writable([]);
export const selectedRuleIds = writable([]);

export async function loadRules() {
  rulesLoading.set(true);
  rulesError.set(null);
  try {
    const [rulesList, groupsList, max, stats] = await Promise.all([
      invoke('get_rules'),
      invoke('get_rule_groups'),
      invoke('get_max_rules'),
      invoke('get_rule_stats'),
    ]);
    rules.set(rulesList || []);
    ruleGroups.set(groupsList || []);
    maxRules.set(max);
    ruleStats.set(stats || []);
  } catch (e) {
    console.error('Load rules error:', e);
    rulesError.set(String(e));
  } finally {
    rulesLoading.set(false);
  }
}

export async function addRule(rule) {
  try {
    await invoke('add_rule', { rule });
    await loadRules();
    return true;
  } catch (e) {
    console.error('Add rule error:', e);
    throw e;
  }
}

export async function updateRule(rule) {
  try {
    await invoke('update_rule', { rule });
    await loadRules();
    return true;
  } catch (e) {
    console.error('Update rule error:', e);
    throw e;
  }
}

export async function deleteRule(ruleId) {
  try {
    await invoke('delete_rule', { ruleId });
    await loadRules();
    return true;
  } catch (e) {
    console.error('Delete rule error:', e);
    throw e;
  }
}

export async function toggleRule(ruleId, enabled) {
  try {
    await invoke('toggle_rule', { ruleId, enabled });
    await loadRules();
    return true;
  } catch (e) {
    console.error('Toggle rule error:', e);
    throw e;
  }
}

export async function addRuleGroup(group) {
  try {
    await invoke('add_rule_group', { group });
    await loadRules();
    return true;
  } catch (e) {
    console.error('Add group error:', e);
    throw e;
  }
}

export async function updateRuleGroup(group) {
  try {
    await invoke('update_rule_group', { group });
    await loadRules();
    return true;
  } catch (e) {
    console.error('Update group error:', e);
    throw e;
  }
}

export async function deleteRuleGroup(groupId) {
  try {
    await invoke('delete_rule_group', { groupId });
    await loadRules();
    return true;
  } catch (e) {
    console.error('Delete group error:', e);
    throw e;
  }
}

export async function parseExpression(expression) {
  try {
    const node = await invoke('parse_rule_expression', { expression });
    return { success: true, node };
  } catch (e) {
    return { success: false, error: e };
  }
}

export async function nodeToExpression(node) {
  try {
    const expr = await invoke('node_to_expression_string', { node });
    return expr;
  } catch (e) {
    console.error('Node to expression error:', e);
    return '';
  }
}

export async function validateRegex(pattern) {
  try {
    await invoke('validate_rule_regex', { pattern });
    return { valid: true };
  } catch (e) {
    return { valid: false, error: String(e) };
  }
}

export async function validateCidr(cidr) {
  try {
    const valid = await invoke('validate_rule_cidr', { cidr });
    return { valid };
  } catch (e) {
    return { valid: false, error: String(e) };
  }
}

export async function exportRules(filePath, ruleIds = null) {
  try {
    await invoke('export_rules_to_file', { path: filePath, ruleIds });
    return true;
  } catch (e) {
    console.error('Export rules error:', e);
    throw e;
  }
}

export async function importRules(filePath) {
  try {
    const count = await invoke('import_rules_from_file', { path: filePath });
    await loadRules();
    return count;
  } catch (e) {
    console.error('Import rules error:', e);
    throw e;
  }
}

export async function getRuleVersions(ruleId) {
  try {
    const versions = await invoke('get_rule_versions', { ruleId });
    return versions || [];
  } catch (e) {
    console.error('Get rule versions error:', e);
    return [];
  }
}

export async function rollbackRuleVersion(ruleId, targetVersion) {
  try {
    await invoke('rollback_rule_version', { ruleId, targetVersion });
    await loadRules();
    return true;
  } catch (e) {
    console.error('Rollback rule version error:', e);
    throw e;
  }
}

export async function checkRuleConflicts(rule) {
  try {
    const conflicts = await invoke('check_rule_conflicts', { rule });
    return conflicts || [];
  } catch (e) {
    console.error('Check rule conflicts error:', e);
    return [];
  }
}

export async function batchToggleRules(ruleIds, enabled) {
  try {
    await invoke('batch_toggle_rules', { ruleIds, enabled });
    await loadRules();
    return true;
  } catch (e) {
    console.error('Batch toggle error:', e);
    throw e;
  }
}

export async function batchDeleteRules(ruleIds) {
  try {
    await invoke('batch_delete_rules', { ruleIds });
    await loadRules();
    return true;
  } catch (e) {
    console.error('Batch delete error:', e);
    throw e;
  }
}

export async function batchMoveRulesToGroup(ruleIds, groupId) {
  try {
    await invoke('batch_move_rules_to_group', { ruleIds, groupId });
    await loadRules();
    return true;
  } catch (e) {
    console.error('Batch move error:', e);
    throw e;
  }
}

export function generateRuleId() {
  return 'rule_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
}

export function generateGroupId() {
  return 'group_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
}

export const enabledRulesCount = derived(rules, $rules =>
  $rules.filter(r => r.enabled).length
);

export const rulesByGroup = derived([rules, ruleGroups], ([$rules, $groups]) => {
  const result = {};
  for (const g of $groups) {
    result[g.id] = { group: g, rules: [] };
  }
  result['_ungrouped'] = { group: null, rules: [] };
  for (const r of $rules) {
    const key = r.group || '_ungrouped';
    if (result[key]) {
      result[key].rules.push(r);
    } else {
      result['_ungrouped'].rules.push(r);
    }
  }
  return result;
});

export function diffConditionTrees(nodeA, nodeB) {
  return diffNodes(normalizeForDiff(nodeA), normalizeForDiff(nodeB));
}

function normalizeForDiff(node) {
  if (!node) return null;
  const copy = JSON.parse(JSON.stringify(node));
  delete copy.id;
  delete copy.compiled;
  return copy;
}

function nodeKey(node) {
  if (!node) return 'null';
  switch (node.type) {
    case 'and': return 'and';
    case 'or': return 'or';
    case 'not': return 'not';
    case 'protocol_match': return `proto:${node.protocol}`;
    case 'ip_match': return `ip:${node.field}:${node.cidr}`;
    case 'port_range': return `port:${node.field}:${node.min}-${node.max}`;
    case 'packet_length': return `len:${node.operator}:${node.value}`;
    case 'tcp_flags': return `tcp:${node.flags?.join(',')}:${node.mode}`;
    case 'payload_keyword': return `payload:${node.pattern}`;
    case 'rate_limit': return `rate:${node.window_secs}:${node.threshold}:${node.src_ip}`;
    case 'dns_blacklist': return `dns:${node.domains?.join(',')}`;
    default: return node.type;
  }
}

function diffNodes(a, b) {
  if (!a && !b) return null;
  if (!a) return { status: 'added', node: b, children: [] };
  if (!b) return { status: 'removed', node: a, children: [] };

  const keyA = nodeKey(a);
  const keyB = nodeKey(b);

  if (a.type !== b.type) {
    return { status: 'modified', nodeA: a, nodeB: b, children: diffChildren(a, b) };
  }

  const paramsChanged = keyA !== keyB;
  const status = paramsChanged ? 'modified' : 'unchanged';

  return {
    status,
    node: b,
    ...(status === 'modified' ? { nodeA: a, nodeB: b } : {}),
    children: diffChildren(a, b),
  };
}

function diffChildren(a, b) {
  const aChildren = getChildren(a);
  const bChildren = getChildren(b);

  if (a.type === 'not' || b.type === 'not') {
    const aChild = a.type === 'not' ? (a.child ? [a.child] : []) : aChildren;
    const bChild = b.type === 'not' ? (b.child ? [b.child] : []) : bChildren;
    const result = [];
    const maxLen = Math.max(aChild.length, bChild.length);
    for (let i = 0; i < maxLen; i++) {
      result.push(diffNodes(aChild[i] || null, bChild[i] || null));
    }
    return result;
  }

  const result = [];
  const bUsed = new Set();
  const aMatched = new Set();

  for (let i = 0; i < aChildren.length; i++) {
    let matched = false;
    for (let j = 0; j < bChildren.length; j++) {
      if (bUsed.has(j)) continue;
      if (nodeKey(aChildren[i]) === nodeKey(bChildren[j])) {
        result.push(diffNodes(aChildren[i], bChildren[j]));
        bUsed.add(j);
        aMatched.add(i);
        matched = true;
        break;
      }
    }
    if (!matched) {
      aMatched.add(i);
      result.push(diffNodes(aChildren[i], null));
    }
  }

  for (let j = 0; j < bChildren.length; j++) {
    if (!bUsed.has(j)) {
      result.push(diffNodes(null, bChildren[j]));
    }
  }

  return result;
}

function getChildren(node) {
  if (!node) return [];
  if (node.children) return node.children;
  if (node.child) return [node.child];
  return [];
}

export function getNodeLabel(node) {
  if (!node) return '';
  switch (node.type) {
    case 'and': return 'AND';
    case 'or': return 'OR';
    case 'not': return 'NOT';
    case 'protocol_match': return `协议: ${node.protocol}`;
    case 'ip_match': return `${node.field === 'src' ? '源' : node.field === 'dst' ? '目的' : ''}IP: ${node.cidr}`;
    case 'port_range': return `${node.field === 'src' ? '源' : node.field === 'dst' ? '目的' : ''}端口: ${node.min}-${node.max}`;
    case 'packet_length': return `包长 ${node.operator === 'greater_than' ? '>' : node.operator === 'less_than' ? '<' : '=='} ${node.value}`;
    case 'tcp_flags': return `TCP标志: ${(node.flags || []).join(', ')}`;
    case 'payload_keyword': return `载荷: ${node.pattern}`;
    case 'rate_limit': return `速率: ${node.threshold}包/${node.window_secs}s`;
    case 'dns_blacklist': return `DNS黑名单: ${(node.domains || []).length}个`;
    default: return node.type;
  }
}
