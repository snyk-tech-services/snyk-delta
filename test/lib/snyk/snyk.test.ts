import * as fs from 'fs';
import * as nock from 'nock';
import * as _ from 'lodash';
import * as path from 'path';
import {
  getProject,
  getProjectIssues,
  getProjectDepGraph,
  getProjectUUID,
} from '../../../src/lib/snyk/snyk';
import * as Error from '../../../src/lib/customErrors/apiError';

const fixturesFolderPath = path.resolve(__dirname, '../..') + '/fixtures/';
beforeEach(() => {
  nock('https://snyk.io')
    .persist()
    .post(/^(?!.*xyz).*$/)
    .reply(200, (uri) => {
      switch (uri) {
        case '/api/v1/org/689ce7f9-7943-4a71-b704-2ba575f01089/projects':
          return fs.readFileSync(
            fixturesFolderPath + 'apiResponses/allProjects.json',
          );
        case '/api/v1/org/123/project/123/aggregated-issues':
          return fs.readFileSync(
            fixturesFolderPath +
              'apiResponses/test-goof-aggregated-two-vuln-one-license.json',
          );
        default:
      }
    })
    .get(/^(?!.*xyz).*$/)
    .reply(200, (uri) => {
      switch (uri) {
        case '/api/v1/org/123/project/123':
          return 'project';
          break;
        case '/api/v1/org/123/project/123/dep-graph':
          return fs.readFileSync(
            fixturesFolderPath + 'apiResponses/depGraphGoof.json',
          );
          break;
        case '/api/v1/org/123/project/123/issue/SNYK-JS-PACRESOLVER-1564857/paths?perPage=100&page=1':
          return fs.readFileSync(
            fixturesFolderPath +
              'apiResponses/SNYK-JS-PACRESOLVER-1564857-issue-paths.json',
          );
          break;
        case '/api/v1/org/123/project/123/issue/SNYK-JS-DOTPROP-543489/paths?perPage=100&page=1':
          return fs.readFileSync(
            fixturesFolderPath +
              'apiResponses/SNYK-JS-DOTPROP-543489-issue-paths-page2.json',
          );
          break;
        case '/api/v1/org/123/project/123/issue/SNYK-JS-DOTPROP-543489/paths?perPage=100&page=2':
          return fs.readFileSync(
            fixturesFolderPath +
              'apiResponses/SNYK-JS-DOTPROP-543489-issue-paths-page1.json',
          );
          break;
        case '/api/v1/org/123/project/123/issue/snyk:lic:npm:goof:GPL-2.0/paths?perPage=100&page=1':
          return fs.readFileSync(
            fixturesFolderPath +
              'apiResponses/snyk-lic-npm-goof-GPL-2-0-issue-paths.json',
          );
          break;

        default:
      }
    });

  nock('https://api.snyk.io')
    .persist()
    .get(/^(?!.*xyz).*$/)
    .reply(200, (uri) => {
      switch (uri) {
        case '/rest/orgs/689ce7f9-7943-4a71-b704-2ba575f01089/projects?version=2023-05-29&limit=10':
          return fs.readFileSync(
            fixturesFolderPath + 'apiResponses/projectsV3.json',
          );
        case '/rest/orgs/361fd3c0-41d4-4ea4-ba77-09bb17890967/projects?version=2023-05-29&limit=10&starting_after=v1.eyJpZCI6MzU2NTI5Mzd9':
          return fs.readFileSync(
            fixturesFolderPath + 'apiResponses/projectsV3-page2.json',
          );
        case '/rest/orgs/361fd3c0-41d4-4ea4-ba77-09bb17890967/projects?version=2023-05-29&limit=10&starting_after=v1.eyJpZCI6NjQyMjIxfQ%3D%3D':
          return fs.readFileSync(
            fixturesFolderPath + 'apiResponses/projectsV3-page3.json',
          );
        default:
      }
    });
});

describe('Test endpoint functions', () => {
  it('Test GetProject', async () => {
    const project = await getProject('123', '123');
    expect(project).toEqual('project');
  });

  it('Test GetProjectUUID', async () => {
    const project = await getProjectUUID(
      '689ce7f9-7943-4a71-b704-2ba575f01089',
      'atokeneduser/goof',
      'cli',
      'npm',
    );
    expect(project).toEqual('6d5813be-7e6d-4ab8-80c2-1e3e2a454545');
  });

  it('Test GetProjectUUID not found', async () => {
    const project = await getProjectUUID(
      '689ce7f9-7943-4a71-b704-2ba575f01089',
      'whatever',
      'cli',
      'npm',
    );
    expect(project).toEqual('');
  });

  it('Test GetProjectUUID not unique found', async () => {
    try {
      const project = await getProjectUUID(
        '689ce7f9-7943-4a71-b704-2ba575f01089',
        'atokeneduser/clojure',
        'github',
        'maven',
      );
      expect(project).toThrow();
    } catch (err) {
      expect(err).toBeInstanceOf(Error.NotFoundError);
      expect(err.message).toContain(
        `Searched through all projects in organization 689ce7f9-7943-4a71-b704-2ba575f01089 and could not match to an individual monitored CLI maven project with a name of 'atokeneduser/clojure'`,
      );
    }
  });

  it('Test GetProjectIssues', async () => {
    const project = await getProjectIssues('123', '123');
    expect(project).toMatchSnapshot();
  });

  it('Test GetProjectDepGraph', async () => {
    const project = await getProjectDepGraph('123', '123');
    expect(
      _.isEqual(
        project,
        JSON.parse(
          fs
            .readFileSync(fixturesFolderPath + 'apiResponses/depGraphGoof.json')
            .toString(),
        ),
      ),
    ).toBeTruthy();
  });
});
