import { getDebugModule } from '../utils/utils';
import * as _ from 'lodash';
import * as chalk from 'chalk';
import * as terminalLink from 'terminal-link';
import {SnykVuln, IssueWithPaths } from '../../lib/types';
import { isVulnerablePathNew } from '../utils/issuesUtils';

enum severityThresholds {
  'low' = 1,
  'medium' = 2,
  'high' = 3,
  'critical' = 4,
}



const getNewIssues = (
  snykProject: IssueWithPaths[],
  snykTestJsonIssuesResults: IssueWithPaths[],
  inboundSeverityThreshold = 'low',
  mode: string,
): IssueWithPaths[] => {
  const debug = getDebugModule();

  const MonitoredIssues = snykProject;
  debug(`Monitored snapshot had %d issues`, MonitoredIssues.length);
  const severityThreshold = Object.keys(severityThresholds).indexOf(
    inboundSeverityThreshold,
  );

  debug(`Tested project has %d issues`, snykTestJsonIssuesResults.length);

  let newIssues = snykTestJsonIssuesResults;
  MonitoredIssues.forEach((monitoredIssue) => {
    newIssues = _.reject(newIssues, (issue) => {
      let issueFromArray = issue.from;
      if (mode == 'inline') {
        issueFromArray = issueFromArray.slice(1, issueFromArray.length);
      }

      return (
        monitoredIssue.id == issue.id &&
        !isVulnerablePathNew(monitoredIssue.from, issueFromArray)
      );
    });
  });

  debug('Severity threshold ', inboundSeverityThreshold);
  return newIssues.filter(
    (issue) =>
      Object.keys(severityThresholds).indexOf(issue.severity) >=
      severityThreshold,
  );
};

const displayNewVulns = (
  newVulns: Array<IssueWithPaths>,
  mode: string,
): void => {
  if (newVulns.length == 1) {
    console.log(chalk.bgHex('#fc9803')('\nNew issue introduced !'));
    console.log('Security Vulnerability:\n');
  } else if (newVulns.length > 1) {
    console.log(chalk.bgMagentaBright('\nNew issues introduced !'));
    console.log('Security Vulnerabilities:');
  }
  newVulns.forEach((vuln, index) => {
    const typedVuln: SnykVuln = vuln as SnykVuln;
    switch (vuln.severity) {
      case 'high':
        console.log(
          chalk.bold.red(
            `  ${index + 1}/${newVulns.length}: ${vuln.title} [${_.capitalize(
              vuln.severity,
            )} Severity]`,
          ),
        );
        break;
      case 'medium':
        console.log(
          chalk.bold.yellow(
            `  ${index + 1}/${newVulns.length}: ${vuln.title} [${_.capitalize(
              vuln.severity,
            )} Severity]`,
          ),
        );
        break;
      case 'low':
        console.log(
          chalk.bold.blue(
            `  ${index + 1}/${newVulns.length}: ${vuln.title} [${_.capitalize(
              vuln.severity,
            )} Severity]`,
          ),
        );
        break;
      default:
        console.log(
          chalk.bold(
            `  ${index + 1}/${newVulns.length}: ${vuln.title} [${_.capitalize(
              vuln.severity,
            )} Severity]`,
          ),
        );
    }

    let paths = vuln.from as Array<string>;
    if (mode == 'inline') {
      paths.shift();
    }
    console.log(chalk('    Via:', paths.join(' => ')));
    if (vuln.fixedIn) {
      console.log(
        chalk.yellow(
          '    Fixed in:',
          vuln.packageName,
          vuln.fixedIn.join(', '),
        ),
      );
      if (vuln.isUpgradable) {
        const upgradePaths: Array<string | boolean> = vuln.upgradePath || [];
        console.log(
          chalk.green(
            '    Fixable by upgrade: ',
            upgradePaths.filter((vulnPath) => vulnPath != false).join('=>'),
          ),
        );
      }
      if (vuln.isPatchable) {
        const patchLink = terminalLink(
          'patch',
          'https://support.snyk.io/hc/en-us/articles/360003891078-Snyk-patches-to-fix',
        );
        //console.log("    Fixable by ",patchLink,": ", vuln.patches.map(patch => patch.id))
        console.log(
          chalk.green(
            '    Fixable by',
            patchLink,
            ': ',
            typedVuln.patches.map((patch) => patch.id).join(', '),
          ),
        );
      }
    }
    console.log('\n');
  });
};

const displayNewLicenseIssues = (
  newLicenseIssues: Array<IssueWithPaths>,
  mode: string,
): void => {
  if (newLicenseIssues.length == 1) {
    console.log(chalk.bgHex('#fc9803')('\nNew issue introduced !'));
    console.log('License Issue:\n');
  } else if (newLicenseIssues.length > 1) {
    console.log(chalk.bgMagentaBright('\nNew issues introduced !'));
    console.log('License Issues:');
  }
  newLicenseIssues.forEach((issue, index) => {
    switch (issue.severity) {
      case 'high':
        console.log(
          chalk.bold.red(
            `  ${index + 1}/${newLicenseIssues.length}: ${
              issue.title
            } [${_.capitalize(issue.severity)} Severity]`,
          ),
        );
        break;
      case 'medium':
        console.log(
          chalk.bold.yellow(
            `  ${index + 1}/${newLicenseIssues.length}: ${
              issue.title
            } [${_.capitalize(issue.severity)} Severity]`,
          ),
        );
        break;
      case 'low':
        console.log(
          chalk.bold.blue(
            `  ${index + 1}/${newLicenseIssues.length}: ${
              issue.title
            } [${_.capitalize(issue.severity)} Severity]`,
          ),
        );
        break;
      default:
        console.log(
          chalk.bold(
            `  ${index + 1}/${newLicenseIssues.length}: ${
              issue.title
            } [${_.capitalize(issue.severity)} Severity]`,
          ),
        );
    }

    let paths = issue.from as Array<string>;
    if (mode == 'inline') {
      paths.shift();
    }
    console.log(chalk('    Via:', paths.join(' => '), '\n'));
  });
};

const getIssuesDetailsPerPackage = (
  issuesArray: Array<any>,
  packageName: string,
  packageVersion?: string,
): Array<any> => {
  if (!packageVersion) {
    return [];
  }
  return issuesArray.filter(
    (issues) =>
      (issues.name == packageName || issues.package == packageName) &&
      issues.version == packageVersion,
  );
};

export {
  getNewIssues,
  displayNewVulns,
  displayNewLicenseIssues,
  getIssuesDetailsPerPackage,
};
