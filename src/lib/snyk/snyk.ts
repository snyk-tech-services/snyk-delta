import * as Error from '../customErrors/apiError';
import * as snykClient from 'snyk-api-ts-client';

const getProject = async (orgID: string, projectID: string) => {
  const project = await new snykClient.Org({ orgId: orgID })
    .project({ projectId: projectID })
    .get();
  return project;
};

const getProjectUUID = async (
  orgID: string,
  nonUUIDProjectID: string,
  projectType = 'cli',
) => {
  const allProjects = await new snykClient.Org({ orgId: orgID }).projects.post(
    {},
  );
  const allProjectsArray = allProjects.projects as Array<any>;
  const selectedProjectArray: Array<any> = allProjectsArray.filter(
    (project) =>
      project.name == nonUUIDProjectID && project.origin == projectType,
  );
  if (selectedProjectArray.length == 0) {
    return ''
  } else if (selectedProjectArray.length > 1) {
    throw new Error.NotFoundError(
      'Snyk API - Could not find a monitored project matching accurately. \
                                        Make sure to specify the right org when snyk test using --org. Branch support coming soon.',
    );
  }
  return selectedProjectArray[0].id;
};
const getProjectIssues = async (orgID: string, projectID: string) => {
  // No filter on patched or non patch issue, getting both
  const filters: snykClient.OrgTypes.Project.IssuesPostBodyType = {
    filters: {
      severities: ['high', 'medium', 'low'],
      exploitMaturity: [
        'mature',
        'proof-of-concept',
        'no-known-exploit',
        'no-data',
      ],
      types: ['vuln', 'license'],
      ignored: false,
    },
  };
  const projectIssues = await new snykClient.Org({ orgId: orgID })
    .project({ projectId: projectID })
    .issues.post(filters);
  return projectIssues;
};

const getProjectDepGraph = async (orgID: string, projectID: string) => {
  const projectDepGraph = await new snykClient.Org({ orgId: orgID })
    .project({ projectId: projectID })
    .depgraph.get();
  return projectDepGraph;
};

export { getProject, getProjectIssues, getProjectDepGraph, getProjectUUID };
