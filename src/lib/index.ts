#!/usr/bin/env node
import 'source-map-support/register';
import * as snyk from './snyk/snyk';
import handleError from './error';
import { getPipedDataIn, init, getDebugModule } from './utils/utils';
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
const Configstore = require('@snyk/configstore');

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
  failOnOverride?: string,
): Promise<SnykDeltaOutput | number> => {
  /* eslint-disable no-unsafe-finally */

  if (process.env.NODE_ENV == 'prod') {
    console.log(banner);
  }
  const argv: {
    currentOrg?: string;
    currentProject?: string;
    baselineOrg?: string;
    baselineProject?: string;
    'fail-on'?: string;
    setPassIfNoBaseline?: boolean;
    type?: string;
    targetReference?: string;
  } = init(debugMode);
  const debug = getDebugModule();
  if (process.env.NODE_ENV == 'test') {
    argv.type = process.env.TYPE ? process.env.TYPE : 'all';
  }
  const mode = argv.currentProject ?? argv.currentOrg ? 'standalone' : 'inline';
  debug(mode, 'mode');
  const passIfNoBaseline = argv.setPassIfNoBaseline ?? setPassIfNoBaselineFlag;
  let baselineProjectPublicID: string | undefined = argv.baselineProject;
  let snykTestJsonDependencies, snykTestJsonResults, newVulns, newLicenseIssues;
  let baselineOrgPublicId: string | undefined = argv.baselineOrg;

  try {
    if (argv.baselineProject && !isUUID.anyNonNil(argv.baselineProject)) {
      throw new BadInputError(
        '--baselineProject project ID must be valid UUID',
      );
    }
    const currentOrg: string = argv.currentOrg ?? '';
    const currentProject: string = argv.currentProject ?? '';
    const failOnFixableSetting: string | undefined =
      argv['fail-on'] ?? failOnOverride?.toLowerCase();

    if (
      failOnFixableSetting &&
      !['all', 'upgradable', 'patchable'].includes(
        failOnFixableSetting.toLowerCase(),
      )
    ) {
      throw new BadInputError(
        `--fail-on must be one of the following values: all, upgradable, patchable. Received value: ${failOnFixableSetting}`,
      );
    }
    if (mode == 'inline') {
      const rawSnykTestData = snykTestOutput ?? (await getPipedDataIn());
      // Verify it's JSON data structure
      debug('Verify input data for JSON structure');
      const snykTestJsonInput: Array<any> = JSON.parse(
        '[' +
          rawSnykTestData.replace(/}\n{/g, '},\n{').replace('}\n[', '},\n[') +
          ']',
      );

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

      if (!baselineOrgPublicId) {
        // swap out org slug for org ID
        baselineOrgPublicId = !isUUID.anyNonNil(org)
          ? await snyk.getOrgUUID(org)
          : org;
      }

      if (!baselineOrgPublicId) {
        throw new BadInputError(
          `In 'inline' mode --baselineOrg or 'snyk test' is required.`,
        );
      }
      if (!baselineProjectPublicID) {
        baselineProjectPublicID =
          projectId ??
          (await snyk.getProjectUUID(
            baselineOrgPublicId,
            projectNameFromJson,
            'cli',
            packageManager,
            argv.targetReference,
          ));
      }

      if (!baselineProjectPublicID) {
        console.warn(
          `Could not find a matching monitored Snyk project. Ensure --org is set correctly for 'snyk test'. Proceeding without a baseline.`,
        );
        console.warn(
          `'snyk-delta' will return exit code 1 if any vulnerabilities are found in the current project`,
        );
      }
    } else {
      // Pull data from currentOrg/currentProject for issues and dep graph and drop it into input data.
      if (
        !argv.currentProject ||
        !argv.currentOrg ||
        !baselineOrgPublicId ||
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

    debug(
      `Retrieving Snyk Project %s in org %s`,
      baselineProjectPublicID,
      baselineOrgPublicId,
    );
    const issueTypeFilter: string = argv.type ? argv.type : 'all';
    let snykProject: IssuesPostResponseType;
    const typedSnykTestJsonResults = snykTestJsonResults as SnykCliTestOutput;

    if (!typedSnykTestJsonResults.vulnerabilities) {
      throw new BadInputError(
        "Expected 'snyk test --json' output to contain .vulnerabilities[] property but none was found. Ensure 'snyk test --json' completed successfully.",
      );
    }
    // if no baseline, return returned results straight from CLI
    if (!baselineProjectPublicID) {
      newVulns = typedSnykTestJsonResults.vulnerabilities.filter(
        (x) => x.type != 'license',
      );
      newLicenseIssues = typedSnykTestJsonResults.vulnerabilities.filter(
        (x) => x.type == 'license',
      );
    } else {
      snykProject = await snyk.getProjectIssues(
        baselineOrgPublicId,
        baselineProjectPublicID,
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
          baselineOrgPublicId,
          baselineProjectPublicID,
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

    const issuesFilter = [];
    if (issueTypeFilter == 'vuln') {
      issuesFilter.push(...newVulns);
    } else if (issueTypeFilter == 'license') {
      issuesFilter.push(...newLicenseIssues);
    } else {
      issuesFilter.push(...newVulns, ...newLicenseIssues);
    }
    if (issuesFilter.length > 0) {
      if (!baselineProjectPublicID && passIfNoBaseline) {
        process.exitCode = 0;
      } else {
        process.exitCode = computeFailCode(
          newVulns,
          newLicenseIssues,
          failOnFixableSetting,
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
        noBaseline: !baselineProjectPublicID,
      };
    }
  }
  /* eslint-enable no-unsafe-finally */
};

if (!module.parent) {
  getDelta();
}

export { getDelta };
