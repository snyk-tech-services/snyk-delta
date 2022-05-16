import { stdin, MockSTDIN } from 'mock-stdin';
import { mockProcessExit } from 'jest-mock-process';
import * as nock from 'nock';
import * as path from 'path';
import * as fs from 'fs';
process.argv.push('--baselineOrg=f6999a85-c519-4ee7-ae55-3269b9bfa4b6');
process.argv.push('--baselineProject=f51c925b-2abe-4c07-8a0d-21b834aa3074');

const stdinMock: MockSTDIN = stdin();
const mockExit = mockProcessExit();

const fixturesFolderPath = path.resolve(__dirname, '..') + '/fixtures/';

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
  setTimeout(() => {
    console.log = originalLog;
  }, 500);
});
beforeEach(() => {
  return nock('https://snyk.io')
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
describe('Test End 2 End - Inline mode with project coordinates', () => {
  it('Test Inline mode with specified project coordinates - no new issue', async () => {
    setTimeout(() => {
      stdinMock.send(
        fs
          .readFileSync(fixturesFolderPath + 'snykTestsOutputs/poetry.json')
          .toString(),
      );
      stdinMock.send(null);
    }, 100);

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
