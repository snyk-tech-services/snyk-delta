import { stdin, MockSTDIN } from 'mock-stdin';
import { mockProcessExit } from 'jest-mock-process';
import * as nock from 'nock';
import * as path from 'path';
import * as fs from 'fs';

const stdinMock: MockSTDIN = stdin();
const mockExit = mockProcessExit();
import { getDelta } from '../../src/lib/index';

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
        case '/api/v1/org/playground/project/ab9e037f-9020-4f77-9c48-b1cb0295a4b6/aggregated-issues':
          return fs.readFileSync(
            fixturesFolderPath +
              'apiResponses/test-goof-aggregated-one-vuln-one-license.json',
          );
        case '/api/v1/org/playground/project/09235fa4-c241-42c6-8c63-c053bd272786/aggregated-issues':
          return fs.readFileSync(
            fixturesFolderPath + 'apiResponses/test-gomod-aggregated.json',
          );
        case '/api/v1/org/playground/project/37a29fe9-c342-4d70-8efc-df96a8d730b3/aggregated-issues':
          return fs.readFileSync(
            fixturesFolderPath +
              'apiResponses/java-goof-aggregated-two-vuln.json',
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
        case '/api/v1/org/playground/project/ab9e037f-9020-4f77-9c48-b1cb0295a4b6/dep-graph':
          return fs.readFileSync(
            fixturesFolderPath + 'apiResponses/goof-depgraph-from-api.json',
          );
        case '/api/v1/org/playground/project/09235fa4-c241-42c6-8c63-c053bd272786/dep-graph':
          return fs.readFileSync(
            fixturesFolderPath + 'apiResponses/goof-depgraph-from-api.json',
          );
        case '/api/v1/org/playground/project/37a29fe9-c342-4d70-8efc-df96a8d730b3/dep-graph':
          return fs.readFileSync(
            fixturesFolderPath +
              'apiResponses/test-goof-aggregated-two-vuln.json',
          );
        case '/api/v1/org/playground/project/ab9e037f-9020-4f77-9c48-b1cb0295a4b6/issue/SNYK-JS-ACORN-559469/paths?perPage=100&page=1':
          return fs.readFileSync(
            fixturesFolderPath +
              'apiResponses/SNYK-JS-ACORN-559469-issue-paths.json',
          );
        case '/api/v1/org/playground/project/ab9e037f-9020-4f77-9c48-b1cb0295a4b6/issue/snyk:lic:npm:goof:GPL-2.0/paths?perPage=100&page=1':
          return fs.readFileSync(
            fixturesFolderPath +
              'apiResponses/snyk-lic-npm-goof-GPL-2-0-issue-paths.json',
          );
        default:
      }
    });
});

describe('Test End 2 End - Inline mode', () => {
  it('Test Inline mode - no new issue', async () => {
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

    const result = await getDelta();
    expect(consoleOutput).toContain('No new issues found !');

    expect(mockExit).toHaveBeenCalledWith(0);
  });

  it('Test Inline mode - 1 new issue', async () => {
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
    const result = await getDelta();

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
    expect(mockExit).toHaveBeenCalledWith(1);
  });

  it('Test Inline mode - 2 new issue - 1 vuln - 1 license', async () => {
    setTimeout(() => {
      stdinMock.send(
        fs
          .readFileSync(
            fixturesFolderPath +
              'snykTestsOutputs/test-goof-two-vuln-two-license.json',
          )
          .toString(),
      );
      stdinMock.send(null);
    }, 100);
    const result = await getDelta();

    const expectedOutput = [
      'New issue introduced !',
      'Security Vulnerability:',
      '  1/1: Prototype Pollution [Medium Severity]',
      '    Via: snyk@1.228.3 => configstore@3.1.2 => dot-prop@4.2.0',
      '    Fixed in: dot-prop 5.1.1',
      '    Fixable by upgrade:  snyk@1.290.1',
    ];

    console.log(result);
    expectedOutput.forEach((line: string) => {
      expect(consoleOutput.join()).toContain(line);
    });
    expect(mockExit).toHaveBeenCalledWith(1);
  });

  it('Test Inline mode - no new issue gomod project', async () => {
    setTimeout(() => {
      stdinMock.send(
        fs
          .readFileSync(fixturesFolderPath + 'snykTestsOutputs/test-gomod.json')
          .toString(),
      );
      stdinMock.send(null);
    }, 100);

    const result = await getDelta();
    expect(consoleOutput).toContain('No new issues found !');

    expect(mockExit).toHaveBeenCalledWith(0);
  });

  it('Test Inline mode - no new issue following version upgrade without vuln fix - npm', async () => {
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

    const result = await getDelta();
    expect(consoleOutput).toContain('No new issues found !');

    expect(mockExit).toHaveBeenCalledWith(0);
  });

  it.skip('Test Inline mode - no new issue following version upgrade without vuln fix - java', async () => {
    setTimeout(() => {
      stdinMock.send(
        fs
          .readFileSync(
            fixturesFolderPath +
              'snykTestsOutputs/test-java-goof-two-vuln.json',
          )
          .toString(),
      );
      stdinMock.send(null);
    }, 100);

    const result = await getDelta();
    expect(consoleOutput).toContain('No new issues found !');

    expect(mockExit).toHaveBeenCalledWith(0);
  });

  it('Test Inline mode strict mode - no monitored project found - return vulns and 1 exit code', async () => {
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

    const result = await getDelta();

    const expectedOutput = [
      'New issue introduced !',
      'Security Vulnerability:',
      '  1/1: Regular Expression Denial of Service (ReDoS) [High Severity]',
      '    Via: @snyk/nodejs-runtime-agent@1.14.0 => acorn@5.7.3',
      '    Fixed in: acorn 5.7.4, 6.4.1, 7.1.1',
      '    Fixable by upgrade:  @snyk/nodejs-runtime-agent@1.14.0=>acorn@5.7.4',
      '   ',
      'New issue introduced !',
      'License Issue:',
      '  1/1: GPL-2.0 license [Medium Severity]',
    ];
    expectedOutput.forEach((line: string) => {
      expect(consoleOutput.join()).toContain(line);
    });
    expect(mockExit).toHaveBeenCalledWith(0);
  });

});
