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
const IS_JEST_TESTING = process.env.JEST_WORKER_ID !== undefined;

const banner = `
================================================
================================================
Snyk Tech Prevent Tool
================================================
================================================
`;

const getDelta = async (
  snykTestOutput: string | undefined = undefined,
  debugMode = false,
  setPassIfNoBaselineFlag = false,
  failOnFlagFromModule: string = '',
): Promise<SnykDeltaOutput | number> => {
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
  const mode = argv.currentProject ?? argv.currentOrg ? 'standalone' : 'inline';
  let newVulns, newLicenseIssues;
  const passIfNoBaseline = argv.setPassIfNoBaseline ?? setPassIfNoBaselineFlag;
  let noBaseline = false;

  try {
    if (process.env.NODE_ENV == 'prod') {
      console.log(banner);
    }

    debug(mode, 'mode');

    let snykTestJsonDependencies, snykTestJsonResults;
    let baselineOrg: string = argv.baselineOrg ?? '';
    let baselineProject: string = argv.baselineProject ?? '';
    const currentOrg: string = argv.currentOrg ?? '';
    const currentProject: string = argv.currentProject ?? '';
    const failOnFlag: string =
      argv['fail-on'] ?? failOnFlagFromModule.toLowerCase();

    if (
      failOnFlag &&
      !['all', 'upgradable', 'patchable'].includes(failOnFlag.toLowerCase())
    ) {
      console.error(
        '--fail-on must be one of the following values: all, upgradable, patchable',
      );
      process.exit(2);
    }
    debug('--fail-on: ', failOnFlag);
    if (mode == 'inline') {
      const rawSnykTestData = snykTestOutput ?? (await utils.getPipedDataIn());
      // Verify it's JSON data structure
      debug('Verify input data for JSON structure');
      const snykTestJsonInput: Array<any> = JSON.parse(
        '[' +
          rawSnykTestData.replace(/}\n{/g, '},\n{').replace('}\n[', '},\n[') +
          ']',
      );

      // TODO: Handle --all-projects setups, bail for now
      if (snykTestJsonInput.length > 2) {
        console.error(
          '--all-projects is not supported. See the Github README.md for advice.',
        );
        process.exitCode = 2;
      }

      snykTestJsonDependencies =
        snykTestJsonInput.length > 1 ? snykTestJsonInput[0] : null;
      snykTestJsonResults =
        snykTestJsonInput.length > 1
          ? snykTestJsonInput[1]
          : snykTestJsonInput[0];
      const {
        packageManager,
        projectId,
        targetFile,
        projectName,
        org,
      } = snykTestJsonResults;
      const projectNameFromJson = targetFile
        ? `${projectName}:${targetFile}`
        : `${projectName}`;

      baselineOrg = baselineOrg ? baselineOrg : org;
      const baselineProjectId = projectId;
      if (baselineProject) {
        baselineProject = baselineProject;
      } else if (baselineProjectId) {
        baselineProject = baselineProjectId;
      } else {
        baselineProject = projectNameFromJson;
      }

      if (argv.baselineProject && !isUUID.anyNonNil(baselineProject)) {
        throw new BadInputError(
          '--baselineProject project ID must be valid UUID',
        );
      }
      if (!isUUID.anyNonNil(baselineProject)) {
        baselineProject = await snyk.getProjectUUID(
          baselineOrg,
          baselineProject,
          'cli',
          packageManager,
        );
        if (baselineProject == '') {
          console.warn(
            `Could not find a matching monitored Snyk project. Ensure --org is set correctly for 'snyk test'. Proceeding without a baseline.`,
          );
          console.warn(
            `'snyk-delta' will return exit code 1 if any vulnerabilities are found in the current project`,
          );
        }
      }
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
        currentOrg,
        currentProject,
      );
      snykTestJsonDependencies = await snyk.getProjectDepGraph(
        currentOrg,
        currentProject,
      );
      const projectIssuesFromAPI = await snyk.getProjectIssues(
        currentOrg,
        currentProject,
      );
      snykTestJsonResults = projectIssuesFromAPI.issues;
    }

    //TODO: If baseline project is '' and strictMode is false, display current vulns
    debug(`Retrieve Snyk Project %s in org %s`, baselineProject, baselineOrg);
    const issueTypeFilter: string = argv.type ? argv.type : 'all';
    let snykProject: IssuesPostResponseType;
    const typedSnykTestJsonResults = snykTestJsonResults as SnykCliTestOutput;

    // if no baseline, return returned results straight from CLI
    if (baselineProject == '') {
      newVulns = typedSnykTestJsonResults.vulnerabilities.filter(
        (x) => x.type != 'license',
      );
      newLicenseIssues = typedSnykTestJsonResults.vulnerabilities.filter(
        (x) => x.type == 'license',
      );

      noBaseline = true;
    } else {
      snykProject = await snyk.getProjectIssues(baselineOrg, baselineProject);

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
          baselineOrg,
          baselineProject,
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
      (IS_JEST_TESTING && !expect.getState().currentTestName.includes('module'))
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
      (IS_JEST_TESTING && !expect.getState().currentTestName.includes('module'))
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
};

if (!module.parent) {
  getDelta();
}

export { getDelta };
