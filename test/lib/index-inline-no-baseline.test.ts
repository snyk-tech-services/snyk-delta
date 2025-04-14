import { stdin, MockSTDIN } from 'mock-stdin';
import { mockProcessExit } from 'jest-mock-process';
import nock from 'nock';
import * as path from 'path';
import * as fs from 'fs';
import { getDelta } from '../../src/lib/index';
const fixturesFolderPath = path.resolve(__dirname, '..') + '/fixtures/';

process.argv.push('--setPassIfNoBaseline true');

describe('Test End 2 End - Inline mode - no baseline', () => {
  const stdinMock: MockSTDIN = stdin();
  const mockExit = mockProcessExit();
  const originalLog = console.log;
  let consoleOutput: Array<string> = [];
  const mockedLog = (output: string): void => {
    consoleOutput.push(output);
  };
  beforeAll(() => {
    console.log = mockedLog;
  });
  afterEach(() => {
    stdinMock.reset();
  });

  beforeEach(() => {
    consoleOutput = [];
  });
  afterAll(() => {
    jest.resetAllMocks();
    setTimeout(() => {
      console.log = originalLog;
    }, 500);
  });

  beforeEach(() => {
    nock('https://api.snyk.io')
      .persist()
      .get(/^(?!.*xyz).*$/)
      .reply(200, (uri) => {
        switch (uri) {
          case '/rest/orgs/361fd3c0-41d4-4ea4-ba77-09bb17890967/projects?version=2023-05-29&limit=10':
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
          case '/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/ab9e037f-9020-4f77-9c48-b1cb0295a4b6/issues':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/test-goof.json',
            );
          default:
        }
      })
      .post(/.*/)
      .reply(200, (uri) => {
        switch (uri) {
          case '/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/ab9e037f-9020-4f77-9c48-b1cb0295a4b6/issues':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/test-goof.json',
            );
          case '/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/c51c80c2-66a1-442a-91e2-4f55b4256a72/issues':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/test-goof.json',
            );
          case '/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/09235fa4-c241-42c6-8c63-c053bd272786/issues':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/test-gomod.json',
            );
          case '/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/37a29fe9-c342-4d70-8efc-df96a8d730b3/issues':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/java-goof.json',
            );
          case '/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/projects':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponsesForProjects/list-all-projects-org-361fd3c0-41d4-4ea4-ba77-09bb17890967.json',
            );
          default:
        }
      });
    nock('https://api.snyk.io')
      .persist()
      .post(/.*/)
      .reply(200, (uri) => {
        switch (uri) {
          case '/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/ab9e037f-9020-4f77-9c48-b1cb0295a4b6/issues':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/test-goof.json',
            );
          case '/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/c51c80c2-66a1-442a-91e2-4f55b4256a72/issues':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/test-goof.json',
            );
          case '/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/09235fa4-c241-42c6-8c63-c053bd272786/issues':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/test-gomod.json',
            );
          case '/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/37a29fe9-c342-4d70-8efc-df96a8d730b3/issues':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/java-goof.json',
            );
          case '/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/projects':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponsesForProjects/list-all-projects-org-361fd3c0-41d4-4ea4-ba77-09bb17890967.json',
            );
          default:
        }
      })
      .get(/.*/)
      .reply(200, (uri) => {
        switch (uri) {
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/ab9e037f-9020-4f77-9c48-b1cb0295a4b6/issues':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/test-goof.json',
            );
          default:
        }
      });
  });

  it('Test Inline mode - new issues from snyk test', async () => {
    setTimeout(() => {
      stdinMock.send(
        fs
          .readFileSync(
            fixturesFolderPath + 'snykTestsOutputs/test-unmonitored-goof.json',
          )
          .toString(),
      );
      stdinMock.send(null);
    }, 100);

    await getDelta();

    const expectedOutput = [
      'New issue introduced !',
      'Security Vulnerability',
      '  1/1: SNYK-JS-ACORN-559469:Regular Expression Denial of Service (ReDoS) [High Severity][cvssScore: 7.5]',
      '    Via: @snyk/nodejs-runtime-agent@1.14.0 => acorn@5.7.3',
      '    Fixed in: acorn 5.7.4, 6.4.1, 7.1.1',
      '    Fixable by upgrade:  @snyk/nodejs-runtime-agent@1.14.0=>acorn@5.7.4',
      'New issue introduced !',
      'License Issue',
      '  1/1: GPL-2.0 license [Medium Severity]',
    ];
    expectedOutput.forEach((line: string) => {
      expect(consoleOutput.join()).toContain(line);
    });
    expect(mockExit).toHaveBeenCalledWith(1);
  });
});
