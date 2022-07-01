#!/usr/bin/env node
import 'source-map-support/register';
import * as snyk from './snyk/snyk';
import handleError from './error';
import * as utils from './utils/utils';
import * as issues from './snyk/issues';
import * as dependencies from './snyk/dependencies';
import * as isUUID from 'is-uuid';
import { BadInputError } from './customErrors/inputError';
import {
  IssuesPostResponseType,
  SnykCliTestOutput,
  SnykDeltaOutput,
} from './types';
import { displayOutput } from './snyk/displayOutput';
import { computeFailCode } from './snyk/snyk_utils';
export { SnykDeltaOutput } from './types';

const banner = `
================================================
================================================
Snyk Tech Prevent Tool
================================================
================================================
`;

function isJestTesting(): boolean {
  return process.env.JEST_WORKER_ID !== undefined;
}
function parseSnykTestInput(
  snykTestData: string,
): { isAllProjectsOutput: boolean; data: any[] } {
  // Verify it's JSON data structure
  const inputData: Array<any> = JSON.parse(
    '[' + snykTestData.replace(/}\n{/g, '},\n{').replace('}\n[', '},\n[') + ']',
  );
  return { isAllProjectsOutput: inputData.length > 2, data: inputData };
}

async function getBaselineProjectID(
  packageManager: string,
  baselineOrgId: string,
  argvProjectId?: string,
  snykTestProjectId?: string,
  snykTestProjectName?: string,
): Promise<string | undefined> {
  let projectId = argvProjectId ?? snykTestProjectId ?? snykTestProjectName;

  if (projectId && !isUUID.anyNonNil(projectId)) {
    projectId = await snyk.getProjectUUID(
      baselineOrgId,
      projectId,
      'cli',
      packageManager,
    );
  }
  if (!projectId) {
    console.warn(
      `Could not find a matching monitored Snyk project. Ensure --org is set correctly for 'snyk test'`,
    );
    console.warn(
      `'snyk-delta' will return exit code 1 if any vulnerabilities are found in the current project`,
    );
  }
  return projectId;
}

function validateFailOn(failOnFlag?: string): void {
  if (
    failOnFlag &&
    !['all', 'upgradable', 'patchable'].includes(failOnFlag.toLowerCase())
  ) {
    console.error(
      '--fail-on must be one of the following values: all, upgradable, patchable',
    );
    process.exit(2);
  }
}

export async function getDelta(
  snykTestOutput?: string,
  debugMode = false,
  setPassIfNoBaselineFlag = false,
  failOnFlagFromModule?: string,
): Promise<SnykDeltaOutput | number> {
  const argv: {
    currentOrg?: string;
    currentProject?: string;
    baselineOrg?: string;
    baselineProject?: string;
    'fail-on'?: string;
    setPassIfNoBaseline?: boolean;
    type?: string;
  } = utils.init(debugMode);
  const debug = utils.getDebugModule();

  const mode = argv.currentProject || argv.currentOrg ? 'standalone' : 'inline';
  let newVulns, newLicenseIssues;
  const passIfNoBaseline = argv.setPassIfNoBaseline ?? setPassIfNoBaselineFlag;
  let noBaseline = false;

  try {
    if (process.env.NODE_ENV == 'prod') {
      console.log(banner);
    }

    debug(mode, 'mode');

    let snykTestJsonDependencies, snykTestJsonResults;

    if (argv.baselineProject && !isUUID.anyNonNil(argv.baselineProject)) {
      throw new BadInputError(
        '--baselineProject project ID must be valid UUID',
      );
    }

    let baselineProjectId: string | undefined;
    let baselineOrgId = argv.baselineOrg;

    const failOnFlag: string | undefined =
      argv['fail-on'] ?? failOnFlagFromModule?.toLowerCase();
    debug('--fail-on: ', failOnFlag);
    validateFailOn(failOnFlag);

    if (mode == 'inline') {
      const snykTestData: string =
        snykTestOutput ?? (await utils.getPipedDataIn());
      debug('Verify input data for JSON structure');
      const { data, isAllProjectsOutput } = parseSnykTestInput(snykTestData);

      if (isAllProjectsOutput) {
        console.error(
          '--all-projects is not supported. See the Github README.md for advice.',
        );
        process.exitCode = 2;
      }

      snykTestJsonDependencies = data.length > 1 ? data[0] : null;
      snykTestJsonResults = data.length > 1 ? data[1] : data[0];
      const {
        packageManager,
        projectId,
        targetFile,
        projectName,
        org,
      } = snykTestJsonResults;

      baselineOrgId = argv.baselineOrg ?? org;
      if (!baselineOrgId) {
        throw new BadInputError(
          `Organization ID must set & be valid UUID. Ensure it is set via either --baselineOrg or as a parameter --org for 'snyk test'`,
        );
      }

      baselineProjectId = await getBaselineProjectID(
        packageManager,
        baselineOrgId,
        argv.baselineProject,
        projectId,
        targetFile ? `${projectName}:${targetFile}` : `${projectName}`,
      );
    } else {
      // Pull data from currentOrg/currentProject for issues and dep graph and drop it into input data.
      if (
        !argv.currentProject ||
        !argv.currentOrg ||
        !argv.baselineOrg ||
        !argv.baselineProject
      ) {
        throw new BadInputError(
          `In 'standalone' mode --currentProject, --currentOrg, --baselineOrg and --baselineProject are required.`,
        );
      }

      debug(
        `Retrieve Snyk Project to compare %s in org %s`,
        argv.currentOrg,
        argv.currentProject,
      );
      snykTestJsonDependencies = await snyk.getProjectDepGraph(
        argv.currentOrg,
        argv.currentProject,
      );
      const projectIssuesFromAPI = await snyk.getProjectIssues(
        argv.currentOrg,
        argv.currentProject,
      );
      snykTestJsonResults = projectIssuesFromAPI.issues;
    }

    //TODO: If baseline project is '' and strictMode is false, display current vulns
    debug(
      `Retrieve Snyk Project %s in org %s`,
      baselineProjectId,
      baselineOrgId,
    );
    const issueTypeFilter: string = argv.type ?? 'all';
    let snykProject: IssuesPostResponseType;
    const typedSnykTestJsonResults = snykTestJsonResults as SnykCliTestOutput;

    // if no baseline, return returned results straight from CLI
    if (!baselineProjectId) {
      newVulns = typedSnykTestJsonResults.vulnerabilities.filter(
        (x) => x.type != 'license',
      );
      newLicenseIssues = typedSnykTestJsonResults.vulnerabilities.filter(
        (x) => x.type == 'license',
      );

      noBaseline = true;
    } else {
      if (!baselineOrgId) {
        throw new BadInputError(`Organization ID must set & be valid UUID`);
      }
      snykProject = await snyk.getProjectIssues(
        baselineOrgId,
        baselineProjectId,
      );

      const baselineVulnerabilitiesIssues = snykProject.issues.vulnerabilities;

      const currentVulnerabilitiesIssues = typedSnykTestJsonResults.vulnerabilities.filter(
        (x) => x.type != 'license',
      );
      newVulns = issues.getNewIssues(
        baselineVulnerabilitiesIssues,
        currentVulnerabilitiesIssues,
        snykTestJsonResults.severityThreshold,
        mode,
      );

      const baselineLicenseIssues = snykProject.issues.licenses;
      const currentLicensesIssues = typedSnykTestJsonResults.vulnerabilities.filter(
        (x) => x.type == 'license',
      );
      newLicenseIssues = issues.getNewIssues(
        baselineLicenseIssues,
        currentLicensesIssues,
        snykTestJsonResults.severityThreshold,
        mode,
      );

      debug(`New Vulns count =%d`, newVulns.length);
      debug(`New Licenses Issues count =%d`, newLicenseIssues.length);

      if (snykTestJsonDependencies) {
        const monitoredProjectDepGraph = await snyk.getProjectDepGraph(
          baselineOrgId,
          baselineProjectId,
        );
        // TODO: Refactor function below
        await dependencies.displayDependenciesChangeDetails(
          snykTestJsonDependencies,
          monitoredProjectDepGraph,
          snykTestJsonResults.packageManager,
          newVulns,
          newLicenseIssues,
        );
      }
    }

    if (
      !module.parent ||
      (isJestTesting() && !expect.getState().currentTestName.includes('module'))
    ) {
      displayOutput(newVulns, newLicenseIssues, issueTypeFilter, mode);
    }

    if (newVulns.length + newLicenseIssues.length > 0) {
      if (noBaseline && passIfNoBaseline) {
        process.exitCode = 0;
      } else {
        process.exitCode = computeFailCode(
          newVulns,
          newLicenseIssues,
          failOnFlag,
        );
      }
    } else {
      process.exitCode = 0;
    }
  } catch (err) {
    handleError(err as Error);
    process.exitCode = 2;
  } finally {
    if (
      !module.parent ||
      (isJestTesting() && !expect.getState().currentTestName.includes('module'))
    ) {
      process.exit(process.exitCode);
    } else {
      return {
        result: process.exitCode,
        newVulns,
        newLicenseIssues,
        passIfNoBaseline,
        noBaseline,
      };
    }
  }
}

if (!module.parent) {
  getDelta();
}
