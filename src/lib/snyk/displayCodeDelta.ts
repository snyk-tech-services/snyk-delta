/**
 * Display Snyk Code delta: new, fixed, and unchanged findings from SARIF comparison.
 */

import chalk from 'chalk';
import * as _ from 'lodash';
import {
  SarifCodeFinding,
  SarifCodeDeltaResult,
  SarifCodeDeltaAgainstApiResult,
} from './sarifCodeDelta';
function formatLocation(finding: SarifCodeFinding): string {
  const r = finding.region;
  if (!r) return finding.uri;
  const line = r.startLine ?? r.endLine ?? '?';
  const col = r.startColumn != null ? `:${r.startColumn}` : '';
  return `${finding.uri}:${line}${col}`;
}

function displayFindings(
  findings: SarifCodeFinding[],
  title: string,
  color: (s: string) => string,
): void {
  if (findings.length === 0) return;
  const label = findings.length === 1 ? 'finding' : 'findings';
  console.log(color(`\n${title} (${findings.length} ${label})`));
  console.log('');
  findings.forEach((f, i) => {
    const levelColor =
      f.level === 'error'
        ? chalk.red
        : f.level === 'warning'
          ? chalk.yellow
          : chalk.gray;
    const title = f.shortDescription || f.ruleId;
    console.log(
      `  ${i + 1}. ${levelColor('[' + _.toUpper(f.level) + ']')} ${chalk.bold(title)}`,
    );
    console.log(`     Finding ID: ${f.key}`);
    console.log(`     Path: ${chalk.cyan(formatLocation(f))}`);
    console.log(`     Info: ${f.message}`);
    console.log('');
  });
}

/**
 * Print code delta summary and lists of new, fixed, and optionally unchanged findings.
 */
function displayCodeDelta(
  delta: SarifCodeDeltaResult,
  options: { showUnchanged?: boolean } = {},
): void {
  const { new: newFindings, fixed, unchanged, newTotal, oldTotal } = delta;

  console.log(chalk.bold('Snyk Code Delta'));
  console.log('================');
  console.log(`Baseline (old): ${oldTotal} finding(s)`);
  console.log(`Current (new):  ${newTotal} finding(s)`);
  console.log('');

  displayFindings(
    newFindings,
    'New findings (in current, not in baseline)',
    (s) => chalk.bgYellow.bold.black(s),
  );
  displayFindings(
    fixed,
    'Fixed findings (in baseline, not in current)',
    (s) => chalk.bgGreen.black(s),
  );
  if (options.showUnchanged && unchanged.length > 0) {
    displayFindings(
      unchanged,
      'Unchanged findings (in both)',
      (s) => chalk.bgGray(s),
    );
  }

  if (newFindings.length === 0 && fixed.length === 0) {
    console.log(chalk.green('No delta: same findings in baseline and current.'));
  } else if (newFindings.length > 0) {
    console.log(
      chalk.yellow(
        `\n${newFindings.length} new finding(s) introduced.`,
      ),
    );
  }
}

/**
 * Print code delta when baseline is from REST API (key_asset).
 * Only findings whose snyk/asset/finding/v1 is NOT in baseline key_asset set are shown as new.
 */
function displayCodeDeltaFromApi(delta: SarifCodeDeltaAgainstApiResult): void {
  const { new: newFindings, newTotal, baselineCount } = delta;

  console.log(chalk.bold('Snyk Code Delta (baseline from Snapshot)'));
  console.log('===========================================');
  console.log(`Baseline (Snapshot): ${baselineCount} issue(s)`);
  console.log(`Current (SARIF):     ${newTotal} finding(s)`);
  console.log('');

  displayFindings(
    newFindings,
    'New findings (in current SARIF, not in baseline Snapshot)',
    (s) => chalk.bgYellow.bold.black(s),
  );

  if (newFindings.length === 0) {
    console.log(chalk.green('No new findings: all current findings match baseline.'));
  } else {
    console.log(
      chalk.yellow(
        `\n${newFindings.length} new finding(s) introduced.`,
      ),
    );
  }
}

export { displayCodeDelta, displayCodeDeltaFromApi, formatLocation };
