import * as _ from 'lodash';
import { getDebugModule } from '../utils/utils';
import { IssueWithPaths } from '../../lib/types';
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
      let upgradePathArray = issue.upgradePath
      if (mode == 'inline') {
        issueFromArray = issueFromArray.slice(1, issueFromArray.length);
        upgradePathArray = upgradePathArray? upgradePathArray.slice(1, issueFromArray.length):undefined;
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
  getIssuesDetailsPerPackage,
};
