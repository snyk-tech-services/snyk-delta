import { stdin, MockSTDIN } from 'mock-stdin';
import { mockProcessExit } from 'jest-mock-process';
import nock from 'nock';
import * as path from 'path';
import * as fs from 'fs';
//process.argv.push('-d');
process.argv.push('--baselineOrg=f6999a85-c519-4ee7-ae55-3269b9bfa4b6');
process.argv.push('--baselineProject=f51c925b-2abe-4c07-8a0d-21b834aa3074');

const stdinMock: MockSTDIN = stdin();
const mockExit = mockProcessExit();
import { getDelta } from '../../src/lib/index';
const fixturesFolderPath = path.resolve(__dirname, '..') + '/fixtures/';

describe('Test End 2 End - Inline mode with project coordinates', () => {
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
          case '/v1/org/f6999a85-c519-4ee7-ae55-3269b9bfa4b6/project/f51c925b-2abe-4c07-8a0d-21b834aa3074/issues':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/test-poetry.json',
            );
          case '/v1/org/f6999a85-c519-4ee7-ae55-3269b9bfa4b6/project/f51c925b-2abe-4c07-8a0d-21b834aa3074/dep-graph':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/poetry-depgraph.json',
            );
          default:
        }
      })
      .post(/.*/)
      .reply(200, (uri) => {
        switch (uri) {
          case '/v1/org/f6999a85-c519-4ee7-ae55-3269b9bfa4b6/project/f51c925b-2abe-4c07-8a0d-21b834aa3074/issues':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/test-poetry.json',
            );
          case '/v1/org/f6999a85-c519-4ee7-ae55-3269b9bfa4b6/projects':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponsesForProjects/list-all-projects-platform.json',
            );
          default:
        }
      });
    nock('https://snyk.io')
      .persist()
      .post(/.*/)
      .reply(200, (uri) => {
        switch (uri) {
          case '/api/v1/org/f6999a85-c519-4ee7-ae55-3269b9bfa4b6/project/f51c925b-2abe-4c07-8a0d-21b834aa3074/issues':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/test-poetry.json',
            );
          case '/api/v1/org/f6999a85-c519-4ee7-ae55-3269b9bfa4b6/projects':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponsesForProjects/list-all-projects-platform.json',
            );
          default:
        }
      })
      .get(/.*/)
      .reply(200, (uri) => {
        switch (uri) {
          case '/api/v1/org/f6999a85-c519-4ee7-ae55-3269b9bfa4b6/project/f51c925b-2abe-4c07-8a0d-21b834aa3074/issues':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/test-poetry.json',
            );
          case '/api/v1/org/f6999a85-c519-4ee7-ae55-3269b9bfa4b6/project/f51c925b-2abe-4c07-8a0d-21b834aa3074/dep-graph':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/poetry-depgraph.json',
            );
          default:
        }
      });
  });
  it('Test Inline mode with specified project coordinates - no new issue', async () => {
    setTimeout(() => {
      stdinMock.send(
        fs
          .readFileSync(fixturesFolderPath + 'snykTestsOutputs/poetry.json')
          .toString(),
      );
      stdinMock.send(null);
    }, 100);

    await getDelta();

    const expectedOutput = [
      'Direct deps:',
      'Added 0',
      'Removed 0',
      'Indirect deps:',
      'Added 0',
      'Paths',
      'Removed 0',
      'No new issues found !',
    ];

    expectedOutput.forEach((line: string) => {
      expect(consoleOutput.join()).toContain(line);
    });
    // => When testing, loaded as module therefore returning code === process.exitCode
    expect(mockExit).toHaveBeenCalledWith(0);
  });
});
