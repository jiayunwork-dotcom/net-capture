import { writable, derived } from 'svelte/store';
import { invoke } from '@tauri-apps/api/tauri';

export const rules = writable([]);
export const ruleGroups = writable([]);
export const maxRules = writable(200);
export const rulesLoading = writable(false);
export const rulesError = writable(null);

export async function loadRules() {
  rulesLoading.set(true);
  rulesError.set(null);
  try {
    const [rulesList, groupsList, max] = await Promise.all([
      invoke('get_rules'),
      invoke('get_rule_groups'),
      invoke('get_max_rules'),
    ]);
    rules.set(rulesList || []);
    ruleGroups.set(groupsList || []);
    maxRules.set(max);
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
