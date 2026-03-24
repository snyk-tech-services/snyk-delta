/**
 * Snyk Code delta: compare two SARIF outputs to find new, fixed, and unchanged findings.
 * Findings are matched by fingerprint "snyk/asset/finding/v1" (same finding = same fingerprint).
 * Only findings that do NOT share the same "snyk/asset/finding/v1" value appear in the delta.
 */

const SNYK_ASSET_FINDING_V1 = 'snyk/asset/finding/v1';

import * as fs from 'fs';
import * as path from 'path';
import {
  SarifDocument,
  SarifResult,
  SarifCodeFinding,
  SarifRegion,
  SarifRule,
} from './sarifTypes';

/**
 * Build a stable key for a SARIF result for matching between old and new runs.
 * Use fingerprint "snyk/asset/finding/v1" so only findings that do not share this value are shown as delta.
 * Fallback: fingerprint "0", then ruleId+uri+region.
 */
function getFindingKey(result: SarifResult): string {
  const fpV1 = result.fingerprints?.[SNYK_ASSET_FINDING_V1];
  if (fpV1) {
    return fpV1;
  }
  const fp0 = result.fingerprints?.['0'];
  if (fp0) {
    return fp0;
  }
  const loc = result.locations?.[0]?.physicalLocation;
  const uri = loc?.artifactLocation?.uri ?? '';
  const r = loc?.region;
  const region = r
    ? `${r.startLine ?? ''}:${r.endLine ?? ''}:${r.startColumn ?? ''}:${r.endColumn ?? ''}`
    : '';
  return `${result.ruleId}|${uri}|${region}`;
}

/**
 * Extract primary location (uri + region) from a result.
 */
function getLocation(result: SarifResult): { uri: string; region?: SarifRegion } {
  const loc = result.locations?.[0]?.physicalLocation;
  return {
    uri: loc?.artifactLocation?.uri ?? '',
    region: loc?.region,
  };
}

/**
 * Resolve rule shortDescription.text for a result using the run's driver.rules.
 */
function getShortDescriptionText(
  result: SarifResult,
  rules?: SarifRule[],
): string {
  if (!rules?.length) {
    return '';
  }
  let rule: SarifRule | undefined;
  const idx = result.ruleIndex;
  if (typeof idx === 'number' && idx >= 0 && idx < rules.length) {
    rule = rules[idx];
  }
  if (!rule) {
    rule = rules.find((x) => x.id === result.ruleId);
  }
  const t = rule?.shortDescription?.text;
  return typeof t === 'string' && t.trim() !== '' ? t.trim() : '';
}

/**
 * Convert a SARIF result to a SarifCodeFinding with a stable key.
 */
function resultToFinding(
  result: SarifResult,
  rules?: SarifRule[],
): SarifCodeFinding {
  const { uri, region } = getLocation(result);
  const message =
    typeof result.message?.text === 'string'
      ? result.message.text
      : typeof result.message?.markdown === 'string'
        ? result.message.markdown
        : '';
  return {
    result,
    key: getFindingKey(result),
    uri,
    region,
    ruleId: result.ruleId ?? '',
    shortDescription: getShortDescriptionText(result, rules),
    message,
    level: result.level ?? 'warning',
  };
}

function forEachResultInDoc(
  doc: SarifDocument,
  fn: (result: SarifResult, rules: SarifRule[] | undefined) => void,
): void {
  for (const run of doc.runs ?? []) {
    const rules = run.tool?.driver?.rules;
    for (const r of run.results ?? []) {
      fn(r, rules);
    }
  }
}

/**
 * Collect all results from a SARIF document (all runs).
 */
function collectResults(doc: SarifDocument): SarifResult[] {
  const results: SarifResult[] = [];
  forEachResultInDoc(doc, (r) => results.push(r));
  return results;
}

/**
 * Parse SARIF JSON string into a SarifDocument (e.g. from piped stdin).
 */
function parseSarifContent(content: string): SarifDocument {
  const doc = JSON.parse(content) as SarifDocument;
  if (!doc.runs || !Array.isArray(doc.runs)) {
    throw new Error('Invalid SARIF: missing or non-array "runs"');
  }
  return doc;
}

/**
 * Load and parse a SARIF JSON file.
 */
function loadSarifFile(filePath: string): SarifDocument {
  const resolved = path.resolve(filePath);
  const content = fs.readFileSync(resolved, 'utf-8');
  return parseSarifContent(content);
}

export interface SarifCodeDeltaResult {
  /** Findings only in the new SARIF (new issues) */
  new: SarifCodeFinding[];
  /** Findings only in the old SARIF (fixed issues) */
  fixed: SarifCodeFinding[];
  /** Findings in both (unchanged) */
  unchanged: SarifCodeFinding[];
  /** All findings from new SARIF */
  newTotal: number;
  /** All findings from old SARIF */
  oldTotal: number;
}

/**
 * Compute the delta between baseline (old) and current (new) SARIF Code outputs.
 * Matching is done by fingerprint "0" when present, else ruleId+uri+region.
 */
function computeSarifCodeDelta(
  oldSarif: SarifDocument,
  newSarif: SarifDocument,
): SarifCodeDeltaResult {
  const oldFindings: SarifCodeFinding[] = [];
  const newFindings: SarifCodeFinding[] = [];
  forEachResultInDoc(oldSarif, (r, rules) =>
    oldFindings.push(resultToFinding(r, rules)),
  );
  forEachResultInDoc(newSarif, (r, rules) =>
    newFindings.push(resultToFinding(r, rules)),
  );

  const oldKeys = new Set(oldFindings.map((f) => f.key));
  const newKeys = new Set(newFindings.map((f) => f.key));

  const newOnly: SarifCodeFinding[] = newFindings.filter((f) => !oldKeys.has(f.key));
  const fixed: SarifCodeFinding[] = oldFindings.filter((f) => !newKeys.has(f.key));
  const unchanged: SarifCodeFinding[] = newFindings.filter((f) => oldKeys.has(f.key));

  return {
    new: newOnly,
    fixed,
    unchanged,
    newTotal: newFindings.length,
    oldTotal: oldFindings.length,
  };
}

export interface SarifCodeDeltaAgainstApiResult {
  /** Current SARIF findings whose snyk/asset/finding/v1 is NOT in baseline key_asset set (new issues to report). */
  new: SarifCodeFinding[];
  /** Total findings in current SARIF. */
  newTotal: number;
  /** Count of baseline API issues that had key_asset (used for matching). */
  baselineCount: number;
}

/**
 * Get the snyk/asset/finding/v1 fingerprint from a SARIF result (used for API baseline matching).
 */
function getFindingKeyAsset(result: SarifResult): string | undefined {
  return result.fingerprints?.[SNYK_ASSET_FINDING_V1];
}

/**
 * Compare current SARIF against baseline from REST API.
 * Baseline = set of issue attributes.key_asset from API (only records with key_asset).
 * A current finding is "new" (reported) only if its fingerprints["snyk/asset/finding/v1"] is NOT in the baseline set.
 * If the two values match, they are the same issue and are not printed.
 */
function computeSarifCodeDeltaAgainstBaselineKeys(
  currentSarif: SarifDocument,
  baselineKeyAssetSet: Set<string>,
): SarifCodeDeltaAgainstApiResult {
  const newFindings: SarifCodeFinding[] = [];
  forEachResultInDoc(currentSarif, (r, rules) =>
    newFindings.push(resultToFinding(r, rules)),
  );

  const newOnly: SarifCodeFinding[] = newFindings.filter((f) => {
    const keyAsset = getFindingKeyAsset(f.result);
    if (keyAsset == null) return true;
    return !baselineKeyAssetSet.has(keyAsset);
  });

  return {
    new: newOnly,
    newTotal: newFindings.length,
    baselineCount: baselineKeyAssetSet.size,
  };
}

/**
 * Extract key_asset values from REST API issues response (only records that have key_asset).
 */
function getBaselineKeyAssetSet(apiIssues: { data?: Array<{ attributes?: { key_asset?: string } }> }): Set<string> {
  const set = new Set<string>();
  const data = apiIssues.data ?? [];
  for (const record of data) {
    const keyAsset = record.attributes?.key_asset;
    if (keyAsset != null && keyAsset !== '') {
      set.add(keyAsset);
    }
  }
  return set;
}

export {
  loadSarifFile,
  parseSarifContent,
  computeSarifCodeDelta,
  computeSarifCodeDeltaAgainstBaselineKeys,
  getBaselineKeyAssetSet,
  getFindingKey,
  getFindingKeyAsset,
  resultToFinding,
  collectResults,
};
export type { SarifCodeFinding };
