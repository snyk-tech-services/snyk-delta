import { stdin, MockSTDIN } from 'mock-stdin';
import { mockProcessExit } from 'jest-mock-process';
import * as nock from 'nock';
import * as path from 'path';
import * as fs from 'fs';
//process.argv.push('-d');
process.argv.push('--baselineOrg=playground');
process.argv.push('--baselineProject=c51c80c2-66a1-442a-91e2-4f55b4256a72');

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
    return nock('https://snyk.io')
      .persist()
      .post(/.*/)
      .reply(200, (uri) => {
        switch (uri) {
          case '/api/v1/org/playground/project/ab9e037f-9020-4f77-9c48-b1cb0295a4b6/aggregated-issues':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/test-goof-aggregated-one-vuln.json',
            );
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a72/aggregated-issues':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/test-goof-aggregated-one-vuln.json',
            );
          case '/api/v1/org/playground/projects':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponsesForProjects/list-all-projects-org-playground.json',
            );
          default:
        }
      })
      .get(/.*/)
      .reply(200, (uri) => {
        switch (uri) {
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a72/issue/SNYK-JS-ACORN-559469/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/SNYK-JS-ACORN-559469-issue-paths.json',
            );
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a72/dep-graph':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/goof-depgraph-from-api.json',
            );
          default:
        }
      });
  });

  it('Test Inline mode with specified project coordinates - no new issue', async () => {
    setTimeout(() => {
      stdinMock.send(
        fs
          .readFileSync(
            fixturesFolderPath + 'snykTestsOutputs/test-goof-one-vuln.json',
          )
          .toString(),
      );
      stdinMock.send(null);
    }, 100);

    await getDelta();
    expect(consoleOutput).toContain('No new issues found !');
    // => When testing, loaded as module therefore returning code === process.exitCode
    expect(mockExit).toHaveBeenCalledWith(0);
    //expect(result).toEqual(0);
  });

  it('Test Inline mode with specified project coordinates - 1 new issue', async () => {
    setTimeout(() => {
      stdinMock.send(
        fs
          .readFileSync(
            fixturesFolderPath + 'snykTestsOutputs/test-goof-two-vuln.json',
          )
          .toString(),
      );
      stdinMock.send(null);
    }, 100);

    await getDelta();

    const expectedOutput = [
      'New issue introduced !',
      'Security Vulnerability:',
      '  1/1: Prototype Pollution [Medium Severity]',
      '    Via: snyk@1.228.3 => configstore@3.1.2 => dot-prop@4.2.0',
      '    Fixed in: dot-prop 5.1.1',
      '    Fixable by upgrade:  snyk@1.290.1',
    ];

    expectedOutput.forEach((line: string) => {
      expect(consoleOutput.join()).toContain(line);
    });
    // => When testing, loaded as module therefore returning code === process.exitCode
    expect(mockExit).toHaveBeenCalledWith(1);
    //expect(result).toEqual(1);
  });
});
