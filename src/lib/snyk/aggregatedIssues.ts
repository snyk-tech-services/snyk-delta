import * as Error from '../customErrors/apiError';
import { createFromJSON, DepGraph, DepGraphData } from '@snyk/dep-graph';
import { AggregatedissuesPostResponseType } from './issuesTypes';
import { requestsManager } from 'snyk-request-manager';

interface IssuesWithVulnsPaths {
  issues: {
    pkgVersionsWithPaths: { [key: string]: Array<Array<string>> }[];
  }[];
}

export type AggregatedIssuesWithVulnPaths = IssuesWithVulnsPaths &
  AggregatedissuesPostResponseType;

const getVulnPathsForPkgVersionFromGraph = (
  pkgName: string,
  version: string,
  depGraph: DepGraph,
): Array<Array<string>> => {
  const pkg = {
    name: pkgName,
    version: version,
  };

  // Handle binaries vulns that aren't always in the depgraph (like base image stuff). Adding them as top level path.
  if (
    !depGraph
      .getPkgs()
      .map((depPkgInfo) => `${depPkgInfo.name}@${depPkgInfo.version}`)
      .includes(`${pkgName}@${version}`)
  ) {
    return [[`${pkgName}@${version}`]];
  } else {
    const pkgVulnPaths = depGraph.pkgPathsToRoot(pkg) as Array<
      Array<{ name: string; version?: string }>
    >;
    return pkgVulnPaths.map((vulnPath) =>
      vulnPath
        .map((vulnPathPkg) => `${vulnPathPkg.name}@${vulnPathPkg.version}`)
        .reverse()
        .slice(1),
    );
  }
};

export const getAggregatedIssuesWithVulnPaths = async (
  requestManager: requestsManager,
  orgID: string,
  projectID: string,
): Promise<AggregatedIssuesWithVulnPaths> => {
  const url = `/org/${orgID}/project/${projectID}/aggregated-issues`;
  // No filter on patched or non patch issue, getting both
  const filters = {
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
  try {
    const projectAggregatedIssues = await requestManager.request({
      verb: 'POST',
      url: url,
      body: JSON.stringify(filters),
    });
    if (!projectAggregatedIssues.data) {
      throw new Error.NotFoundError(
        `No aggregated issues data found for ${projectID} from org ${orgID}.`,
      );
    }

    const projectAggregatedIssuesData = projectAggregatedIssues.data as AggregatedissuesPostResponseType;

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

    const depGraph = createFromJSON(
      projectDepGraph.data.depGraph as DepGraphData,
    );

    const returnData: AggregatedIssuesWithVulnPaths = {
      issues: [],
    };

    projectAggregatedIssuesData?.issues?.map((issue) => {
      const returnVulnPathsData = issue.pkgVersions.map((version) => {
        const pkg = {
          name: issue.pkgName,
          version: version as string,
        };
        return {
          [`${pkg.version}`]: getVulnPathsForPkgVersionFromGraph(
            pkg.name,
            pkg.version,
            depGraph,
          ),
        };
      });

      const newIssue = {
        pkgVersionsWithPaths: returnVulnPathsData,
        ...issue,
      };

      returnData.issues.push(newIssue);
    });

    return returnData;
  } catch (err) {
    throw new Error.GenericError(
      `Error getting project ${projectID} from org ${orgID}: ${err}.`,
    );
  }
};
