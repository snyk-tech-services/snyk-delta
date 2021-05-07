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
        case '/api/v1/org/playground/project/ab9e037f-9020-4f77-9c48-b1cb0295a4b6/issues':
          return fs.readFileSync(
            fixturesFolderPath + 'apiResponses/test-goof.json',
          );
        case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a72/issues':
          return fs.readFileSync(
            fixturesFolderPath + 'apiResponses/test-goof.json',
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
        case '/api/v1/org/playground/project/ab9e037f-9020-4f77-9c48-b1cb0295a4b6/issues':
          return fs.readFileSync(
            fixturesFolderPath + 'apiResponses/test-goof.json',
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
          .readFileSync(fixturesFolderPath + 'snykTestsOutputs/test-goof.json')
          .toString(),
      );
      stdinMock.send(null);
    }, 100);

    const result = await getDelta();
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
            fixturesFolderPath +
              'snykTestsOutputs/test-goof-with-one-more-vuln.json',
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
      '    Via: express-fileupload@0.0.5 => @snyk/nodejs-runtime-agent@1.14.0 => acorn@5.7.3',
      '    Fixed in: acorn 5.7.4, 6.4.1, 7.1.1',
      '    Fixable by upgrade:  @snyk/nodejs-runtime-agent@1.14.0=>acorn@5.7.4',
    ];

    expectedOutput.forEach((line: string) => {
      expect(consoleOutput.join()).toContain(line);
    });
    // => When testing, loaded as module therefore returning code === process.exitCode
    expect(mockExit).toHaveBeenCalledWith(1);
    //expect(result).toEqual(1);
  });
});
