import * as Error from '../customErrors/apiError';
import * as snykClient from 'snyk-api-ts-client';
import { convertIntoIssueWithPath } from '../utils/issuesUtils';
import { requestsManager } from 'snyk-request-manager';
import { IssuesPostResponseType } from '../types';

const getProject = async (
  orgID: string,
  projectID: string,
): Promise<snykClient.OrgTypes.ProjectGetResponseType> => {
  const requestManager = new requestsManager({ userAgentPrefix: 'snyk-delta' });
  const url = `/org/${orgID}/project/${projectID}`;
  try {
    const projectData = await requestManager.request({
      verb: 'GET',
      url: url,
    });

    if (!projectData.data) {
      throw new Error.NotFoundError(
        `No project data found for ${projectID} from org ${orgID}.`,
      );
    }
    return projectData.data;
  } catch (err) {
    throw new Error.GenericError(
      `Error getting project ${projectID} from org ${orgID}: ${err}.`,
    );
  }
};
async function getOrgUUID(orgSlug: string): Promise<string> {
  const requestManager = new requestsManager({ userAgentPrefix: 'snyk-delta' });
  let orgUUID = '';

  let url = '/orgs';
  const urlQueryParams: Array<string> = [
    'version=2024-10-15',
    'limit=10',
    `slug=${orgSlug}`,
  ];

  if (urlQueryParams.length > 0) {
    url += `?${urlQueryParams.join('&')}`;
  }
  try {
    const orgMetadata = await requestManager.request({
      verb: 'GET',
      url: url,
      useRESTApi: true,
    });
    if (orgMetadata.data.data.length > 1) {
      throw new Error.GenericError(
        `Found more than one orgUUID for org slug ${orgSlug}. Unable to continue result comparison.`,
      );
    } else {
      orgUUID = orgMetadata.data.data[0]?.id || '';
    }
  } catch (err) {
    throw new Error.GenericError(`Error getting org UUID: ${err}`);
  }
  return orgUUID;
}
async function getProjectUUID(
  orgID: string,
  nonUUIDProjectID: string,
  projectType = 'cli',
  packageManager: string,
  targetReference?: string,
): Promise<string> {
  const allProjects = await new snykClient.Org({
    orgId: orgID,
  }).projects.getV3();
  const allProjectsArray = allProjects?.projects as Array<any>;
  const selectedProjectArray: Array<{
    name: string;
    origin: string;
    type: string;
    id: string;
  }> = allProjectsArray.filter(
    (project) =>
      project.name == nonUUIDProjectID &&
      project.origin == projectType &&
      project.type == packageManager &&
      (targetReference ? project.targetReference == targetReference : true),
  );
  if (selectedProjectArray.length == 0) {
    return '';
  } else if (selectedProjectArray.length > 1) {
    throw new Error.NotFoundError(
      `Searched through all projects in organization ${orgID} and could not match to an individual monitored CLI ${packageManager} project with a name of '${nonUUIDProjectID}'.`,
    );
  }
  return selectedProjectArray[0].id;
}
const getProjectIssues = async (
  orgID: string,
  projectID: string,
): Promise<IssuesPostResponseType> => {
  // No filter on patched or non patch issue, getting both
  const filters: snykClient.OrgTypes.Project.AggregatedissuesPostBodyType = {
    includeDescription: false,
    includeIntroducedThrough: false,
    filters: {
      severities: ['high', 'medium', 'low', 'critical'],
      exploitMaturity: [
        'mature',
        'proof-of-concept',
        'no-known-exploit',
        'no-data',
      ],
      types: ['vuln', 'license'],
      ignored: false,
      patched: false,
      priority: {
        score: {
          min: undefined,
          max: undefined,
        },
      },
    },
  };
  const projectAggregatedIssues = await new snykClient.Org({ orgId: orgID })
    .project({ projectId: projectID })
    .aggregatedissues.getAggregatedIssuesWithVulnPaths(filters);

  return await convertIntoIssueWithPath(
    projectAggregatedIssues,
    orgID,
    projectID,
  );
};

const getProjectDepGraph = async (
  orgID: string,
  projectID: string,
): Promise<snykClient.OrgTypes.Project.DepgraphGetResponseType> => {
  const projectDepGraph = await new snykClient.Org({ orgId: orgID })
    .project({ projectId: projectID })
    .depgraph.get();
  return projectDepGraph;
};

interface ProjectIssuePathsLegacy {
  UpgradePathLegacy: string[][];
  IssueFromLegacy: string[][];
}

const getUpgradePath = async (
  orgID: string,
  projectID: string,
  issueId: string,
): Promise<ProjectIssuePathsLegacy> => {
  let projectIssuePaths = await new snykClient.Org({ orgId: orgID })
    .project({ projectId: projectID })
    .issue({ issueId: issueId })
    .paths.get(undefined, 100, 1);

  const projectIssuePathsArray = [];

  projectIssuePathsArray.push(projectIssuePaths);

  if (projectIssuePaths.links && projectIssuePaths.links['next']) {
    let nextPageExist = true;
    let nextPage = 2;
    while (nextPageExist) {
      projectIssuePaths = await new snykClient.Org({ orgId: orgID })
        .project({ projectId: projectID })
        .issue({ issueId: issueId })
        .paths.get(undefined, 100, nextPage);
      nextPage++;
      projectIssuePathsArray.push(projectIssuePaths);
      if (projectIssuePaths.links && !projectIssuePaths.links['next']) {
        nextPageExist = false;
      }
    }
  }

  const projectIssuePathsLegacy: ProjectIssuePathsLegacy = {
    UpgradePathLegacy: [],
    IssueFromLegacy: [],
  };
  let depPathIndex = 0;
  let libNameArray: string[] = [];
  let fixVersionArray: string[] = [];

  projectIssuePathsArray.forEach((projectIssuePaths) => {
    if (projectIssuePaths.paths) {
      projectIssuePaths.paths.map((depPath) => {
        depPath.map((lib) => {
          const libName = lib.name + '@' + lib.version;
          libNameArray.push(libName);
          const fixVersionName = lib.name + '@' + lib.fixVersion;
          if (lib.fixVersion) {
            fixVersionArray.push(fixVersionName);
          }
        });
        projectIssuePathsLegacy.IssueFromLegacy[depPathIndex] = libNameArray;
        if (fixVersionArray.length > 0) {
          projectIssuePathsLegacy.UpgradePathLegacy[
            depPathIndex
          ] = fixVersionArray;
        }
        depPathIndex += 1;
        libNameArray = [];
        fixVersionArray = [];
      });
    }
  });

  return projectIssuePathsLegacy;
};

export {
  getProject,
  getProjectIssues,
  getProjectDepGraph,
  getOrgUUID,
  getProjectUUID,
  getUpgradePath,
};
