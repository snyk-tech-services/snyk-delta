import { IssueWithPaths } from '../types';
import { getDebugModule } from '../utils/utils';

const Configstore = require('@snyk/configstore');

function getConfig(): {
  endpoint: string;
  token: string;
} {
  const snykApiEndpoint: string =
    process.env.SNYK_API ||
    new Configstore('snyk').get('endpoint') ||
    'https://snyk.io/api/v1';
  const snykToken =
    process.env.SNYK_TOKEN || new Configstore('snyk').get('api');
  return { endpoint: snykApiEndpoint, token: snykToken };
}

const computeFailCode = (
  vulns: IssueWithPaths[],
  licenseIssues: IssueWithPaths[],
  failOnFlag?: string,
): number => {
  const debug = getDebugModule();

  let exitCodeToReturn = 1;

  const issues = [...vulns, ...licenseIssues];
  switch (failOnFlag) {
    case 'upgradable':
      exitCodeToReturn =
        issues.filter((issue) => issue.isUpgradable).length > 0 ? 1 : 0;
      break;
    case 'patchable':
      exitCodeToReturn =
        issues.filter((issue) => issue.isPatchable).length > 0 ? 1 : 0;
      break;
    case 'all':
      exitCodeToReturn =
        issues.filter((issue) => issue.isUpgradable || issue.isPatchable)
          .length > 0
          ? 1
          : 0;
      break;
    default:
      exitCodeToReturn = 1;
  }
  debug(`FailOn ${failOnFlag} returns ${exitCodeToReturn} code`);
  return exitCodeToReturn;
};

export { getConfig, computeFailCode };
