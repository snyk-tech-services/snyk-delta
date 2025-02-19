import * as Error from '../customErrors/apiError';
import { convertIntoIssueWithPath } from '../utils/issuesUtils';
import { requestsManager } from 'snyk-request-manager';
import { IssuesPostResponseType } from '../types';
import {
  ProjectGetResponseType,
  ProjectsData,
  ProjectsPostResponseType,
} from './projectTypes';
import { getAggregatedIssuesWithVulnPaths } from './aggregatedIssues';
import { DepgraphGetResponseType } from './depgraphTypes';
import { PathsGetResponseType } from './issuesTypes';



const getProject = async (
  orgID: string,
  projectID: string,
): Promise<ProjectGetResponseType> => {
  const url = `/org/${orgID}/project/${projectID}`;
  try {
    const requestManager = new requestsManager({ userAgentPrefix: 'snyk-delta' });
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
    const requestManager = new requestsManager({ userAgentPrefix: 'snyk-delta' });
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
async function getProjects(orgID: string): Promise<ProjectsPostResponseType> {
  const response: ProjectsPostResponseType = {};
  let url = '';
  const urlQueryParams: Array<string> = ['version=2023-05-29', 'limit=10'];
  url = `/orgs/${orgID}/projects`;

  if (urlQueryParams.length > 0) {
    url += `?${urlQueryParams.join('&')}`;
  }

  try {
    const resultSet: ProjectsData[][] = [];
    let isThereNextPage = false;
    do {
      const requestManager = new requestsManager({ userAgentPrefix: 'snyk-delta' });
      const result = await requestManager.request({
        verb: 'get',
        url: url,
        useRESTApi: true,
      });
      isThereNextPage = result.data.links.next ? true : false;
      if (isThereNextPage) {
        url = result.data.links.next;
      }
      resultSet.push(result.data.data);
    } while (isThereNextPage);

    const v1TypedResult: ProjectsPostResponseType = {};
    v1TypedResult.projects = [];

    if (resultSet.length > 0) {
      v1TypedResult.org = {
        id: resultSet[0][0].relationships?.organization.data.id,
      };
    }
    for (let page = 0; page < resultSet.length; page++) {
      for (let i = 0; i < resultSet[page].length; i++) {
        v1TypedResult.projects?.push({
          id: resultSet[page][i].id,
          name: resultSet[page][i].attributes.name,
          type: resultSet[page][i].attributes.type,
          origin: resultSet[page][i].attributes.origin,
          created: resultSet[page][i].attributes.created.toString(),
          testFrequency:
            resultSet[page][i].attributes.settings.recurring_tests.frequency ||
            undefined,
          importingUser: {
            id: resultSet[page][i].relationships?.importer?.data.id,
          },
          targetReference: resultSet[page][i].attributes.target_reference,
          isMonitored:
            resultSet[page][i].attributes.status == 'active' ? true : false,
        });
      }
    }

    return v1TypedResult;
  } catch (err) {
    throw new Error.NotFoundError(
      `Error getting projects from org ${orgID}: ${err}.`,
    );
  }
}

async function getProjectUUID(
  orgID: string,
  nonUUIDProjectID: string,
  projectType = 'cli',
  packageManager: string,
  targetReference?: string,
): Promise<string> {
  try {
    const allProjects = await getProjects(orgID);
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
  } catch (err) {
    throw new Error.NotFoundError(
      `Error getting projects from org ${orgID}: ${err}.`,
    );
  }
}
const getProjectIssues = async (
  orgID: string,
  projectID: string,
): Promise<IssuesPostResponseType> => {
  const requestManager = new requestsManager({ userAgentPrefix: 'snyk-delta' });
  const projectAggregatedIssues = await getAggregatedIssuesWithVulnPaths(
    requestManager,
    orgID,
    projectID,
  );

  return await convertIntoIssueWithPath(
    projectAggregatedIssues,
    orgID,
    projectID,
  );
};

const getProjectDepGraph = async (
  orgID: string,
  projectID: string,
): Promise<DepgraphGetResponseType> => {
  const requestManager = new requestsManager({ userAgentPrefix: 'snyk-delta' });
  const depGraphUrl = `/org/${orgID}/project/${projectID}/dep-graph`;
  const projectDepGraph = await requestManager.request({
    verb: 'GET',
    url: depGraphUrl,
  });
  if (!projectDepGraph.data || !projectDepGraph.data.depGraph) {
    throw new Error.NotFoundError(
      `No depgraph data found for ${projectID} from org ${orgID}.`,
    );
  }
  return projectDepGraph.data;
};

interface ProjectIssuePathsLegacy {
  UpgradePathLegacy: string[][];
  IssueFromLegacy: string[][];
}

const getIssuePaths = async (
  orgID: string,
  projectID: string,
  issueID: string,
  selectors: {snapshotID?:string,perPage?: number,page?: number}
):Promise<PathsGetResponseType> => {
  let url = '';
  const urlQueryParams = [];
  url = `/org/${orgID}/project/${
    projectID
  }/issue/${issueID}/paths`;
  if (selectors.snapshotID) {
    urlQueryParams.push('snapshotId=' + selectors.snapshotID);
  }
  if (selectors.perPage) {
    urlQueryParams.push('perPage=' + selectors.perPage);
  }
  if (selectors.page) {
    urlQueryParams.push('page=' + selectors.page);
  }
  if (urlQueryParams.length > 0) {
    url += `?${urlQueryParams.join('&')}`;
  }
  try {
    const requestManager = new requestsManager({ userAgentPrefix: 'snyk-delta' });
    const result = await requestManager.request({
      verb: 'get',
      url: url,
    });
    if (!result.data) {
      throw new Error.NotFoundError(`Issue path not found for issue ${issueID} of project ${projectID} in org ${orgID}`)
    }
    return result.data as PathsGetResponseType
  } catch (err) {
    throw new Error.GenericError(`Error getting Issue path for issue ${issueID} of project ${projectID} in org ${orgID}:${err}`);
  }
};

const getUpgradePath = async (
  orgID: string,
  projectID: string,
  issueId: string,
): Promise<ProjectIssuePathsLegacy> => {

  let projectIssuePaths = await getIssuePaths(orgID,projectID,issueId,{perPage:100, page:1})
  
  const projectIssuePathsArray = [];

  projectIssuePathsArray.push(projectIssuePaths);

  if (projectIssuePaths.links && projectIssuePaths.links['next']) {
    let nextPageExist = true;
    let nextPage = 2;
    while (nextPageExist) {
      projectIssuePaths = await getIssuePaths(orgID,projectID,issueId,{perPage:100, page:nextPage})
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
