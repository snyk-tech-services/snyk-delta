import { mockProcessExit } from 'jest-mock-process';
import * as nock from 'nock';
import * as path from 'path';
import * as fs from 'fs';
process.argv.push('-d');
process.argv.push('--baselineOrg=playground');
process.argv.push('--baselineProject=c51c80c2-66a1-442a-91e2-4f55b4256a73');
process.argv.push('--currentOrg=playground');
process.argv.push('--currentProject=c51c80c2-66a1-442a-91e2-4f55b4256a72');
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

beforeEach(() => {
  consoleOutput = [];
});
afterAll(() => {
  setTimeout(() => {
    console.log = originalLog;
  }, 500);
});

afterEach(() => {
  nock.cleanAll();
});

describe('Test End 2 End - Standalone mode', () => {
  it('Test standalone mode - no new issue', async () => {
    nock('https://snyk.io')
      .persist()
      .post(/.*/)
      .reply(200, (uri) => {
        switch (uri) {
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a72/aggregated-issues':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/test-goof-aggregated-one-vuln.json',
            );
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a73/aggregated-issues':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/test-goof-aggregated-one-vuln.json',
            );
          // case '/api/v1/org/playground/projects':
          //   return fs.readFileSync(fixturesFolderPath+'apiResponsesForProjects/list-all-projects-org-playground.json')
          default:
        }
      })
      .get(/.*/)
      .reply(200, (uri) => {
        switch (uri) {
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a73/dep-graph':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/goof-depgraph-from-api.json',
            );
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a72/dep-graph':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/goof-depgraph-from-api.json',
            );
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a72/issue/SNYK-JS-ACORN-559469/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/SNYK-JS-ACORN-559469-issue-paths.json',
            );
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a73/issue/SNYK-JS-ACORN-559469/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/SNYK-JS-ACORN-559469-issue-paths.json',
            );
          default:
        }
      });

    const result = await getDelta();

    console.log('result: ', result);

    const expectedOutput = [
      '_____________________________',
      'Direct deps:',
      'Added 0 \n',
      '===============',
      'Removed 0\n',
      '##################',
      'Indirect deps:',
      'Added 0 \n',
      '===============',
      'Paths',
      '===============',
      'Removed 0\n',
      '_____________________________',
      'No new issues found !',
    ];

    expectedOutput.forEach((line: string) => {
      expect(consoleOutput.join()).toContain(line);
    });

    expect(mockExit).toHaveBeenCalledWith(0);
  });

  it('Test standalone mode - 1 new issue', async () => {
    nock('https://snyk.io')
      .persist()
      .post(/.*/)
      .reply(200, (uri) => {
        switch (uri) {
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a72/aggregated-issues':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/test-goof-aggregated-two-vuln-no-license.json',
            );
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a73/aggregated-issues':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/test-goof-aggregated-one-vuln.json',
            );
          // case '/api/v1/org/playground/projects':
          //   return fs.readFileSync(fixturesFolderPath+'apiResponsesForProjects/list-all-projects-org-playground.json')
          default:
        }
      })
      .get(/.*/)
      .reply(200, (uri) => {
        switch (uri) {
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a73/dep-graph':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/goof-depgraph-from-api.json',
            );
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a72/dep-graph':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/goof-depgraph-from-api.json',
            );
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a72/issue/SNYK-JS-ACORN-559469/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/SNYK-JS-ACORN-559469-issue-paths.json',
            );
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a73/issue/SNYK-JS-ACORN-559469/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/SNYK-JS-ACORN-559469-issue-paths.json',
            );
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a72/issue/SNYK-JS-DOTPROP-543489/paths?perPage=100&page=1':
            console.log('uri good');
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/SNYK-JS-DOTPROP-543489-issue-paths-page1.json',
            );
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a73/issue/SNYK-JS-DOTPROP-543489/paths?perPage=100&page=1':
            console.log('uri good');
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/SNYK-JS-DOTPROP-543489-issue-paths-page2.json',
            );
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a73/issue/SNYK-JS-DOTPROP-543489/paths?perPage=100&page=2':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/SNYK-JS-DOTPROP-543489-issue-paths-page1.json',
            );
          default:
        }
      });

    const result = await getDelta();

    const expectedOutput = [
      '_____________________________',
      'Direct deps:',
      'Added 0 \n',
      '===============',
      'Removed 0\n',
      '##################',
      'Indirect deps:',
      'Added 0 \n',
      '===============',
      'Paths',
      '===============',
      'Removed 0\n',
      '_____________________________',
      //'\n                                uuuuuuuuuuuuuuuuuuuu\n                              u" uuuuuuuuuuuuuuuuuu "u\n                            u" u$$$$$$$$$$$$$$$$$$$$u "u\n                          u" u$$$$$$$$$$$$$$$$$$$$$$$$u "u\n                        u" u$$$$$$$$$$$$$$$$$$$$$$$$$$$$u "u\n                      u" u$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$u "u\n                    u" u$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$u "u\n                    $ $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ $\n                    $ $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ $\n                    $ $$$" ... "$...  ...$" ... "$$$  ... "$$$ $\n                    $ $$$u `"$$$$$$$  $$$  $$$$$  $$  $$$  $$$ $\n                    $ $$$$$$uu "$$$$  $$$  $$$$$  $$  """ u$$$ $\n                    $ $$$""$$$  $$$$  $$$u "$$$" u$$  $$$$$$$$ $\n                    $ $$$$....,$$$$$..$$$$$....,$$$$..$$$$$$$$ $\n                    $ $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ $\n                    "u "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" u"\n                      "u "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" u"\n                        "u "$$$$$$$$$$$$$$$$$$$$$$$$$$$$" u"\n                          "u "$$$$$$$$$$$$$$$$$$$$$$$$" u"\n                            "u "$$$$$$$$$$$$$$$$$$$$" u"\n                              "u """""""""""""""""" u"\n                                """"""""""""""""""""\n                    ',
      'New issues introduced !',
      'Security Vulnerabilities:',
      '1/2: Prototype Pollution [Medium Severity]',
      '    Via: snyk@1.228.3 => configstore@3.1.2 => dot-prop@4.2.0',
      '\n',
      '2/2: Prototype Pollution [Medium Severity]',
      '    Via: snyk@1.228.3 => update-notifier@2.5.0 => configstore@3.1.2 => dot-prop@4.2.0',
      '\n',
    ];

    expectedOutput.forEach((line: string) => {
      expect(consoleOutput.join()).toContain(line);
    });

    expect(mockExit).toHaveBeenCalledWith(1);
  });

  it('Test standalone mode - 1 new issue 1 new direct dep', async () => {
    nock('https://snyk.io')
      .persist()
      .post(/.*/)
      .reply(200, (uri) => {
        switch (uri) {
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a72/aggregated-issues':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/test-goof-aggregated-two-vuln-no-license.json',
            );
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a73/aggregated-issues':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/test-goof-aggregated-one-vuln.json',
            );
          // case '/api/v1/org/playground/projects':
          //   return fs.readFileSync(fixturesFolderPath+'apiResponsesForProjects/list-all-projects-org-playground.json')
          default:
        }
      })
      .get(/.*/)
      .reply(200, (uri) => {
        switch (uri) {
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a72/dep-graph':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/goof-depgraph-from-api-with-one-more-direct-dep.json',
            );
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a72/issue/SNYK-JS-ACORN-559469/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/SNYK-JS-ACORN-559469-issue-paths.json',
            );
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a73/issue/SNYK-JS-ACORN-559469/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/SNYK-JS-ACORN-559469-issue-paths.json',
            );
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a73/dep-graph':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/goof-depgraph-from-api.json',
            );
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a72/issue/SNYK-JS-DOTPROP-543489/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/SNYK-JS-DOTPROP-543489-issue-paths-page1.json',
            );
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a73/issue/SNYK-JS-DOTPROP-543489/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/SNYK-JS-DOTPROP-543489-issue-paths-page1.json',
            );
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a73/issue/SNYK-JS-DOTPROP-543489/paths?perPage=100&page=2':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/SNYK-JS-DOTPROP-543489-issue-paths-page2.json',
            );
          default:
        }
      });

    const result = await getDelta();
    const expectedOutput = [
      '_____________________________',
      'Direct deps:',
      'Added 1 \nadded-dep@1.0.0',
      '===============',
      'Removed 0\n',
      '##################',
      'Indirect deps:',
      'Added 0 \n',
      '===============',
      'Paths',
      '===============',
      'Removed 0\n',
      '_____________________________',
      //'\n                                uuuuuuuuuuuuuuuuuuuu\n                              u" uuuuuuuuuuuuuuuuuu "u\n                            u" u$$$$$$$$$$$$$$$$$$$$u "u\n                          u" u$$$$$$$$$$$$$$$$$$$$$$$$u "u\n                        u" u$$$$$$$$$$$$$$$$$$$$$$$$$$$$u "u\n                      u" u$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$u "u\n                    u" u$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$u "u\n                    $ $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ $\n                    $ $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ $\n                    $ $$$" ... "$...  ...$" ... "$$$  ... "$$$ $\n                    $ $$$u `"$$$$$$$  $$$  $$$$$  $$  $$$  $$$ $\n                    $ $$$$$$uu "$$$$  $$$  $$$$$  $$  """ u$$$ $\n                    $ $$$""$$$  $$$$  $$$u "$$$" u$$  $$$$$$$$ $\n                    $ $$$$....,$$$$$..$$$$$....,$$$$..$$$$$$$$ $\n                    $ $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ $\n                    "u "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" u"\n                      "u "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" u"\n                        "u "$$$$$$$$$$$$$$$$$$$$$$$$$$$$" u"\n                          "u "$$$$$$$$$$$$$$$$$$$$$$$$" u"\n                            "u "$$$$$$$$$$$$$$$$$$$$" u"\n                              "u """""""""""""""""" u"\n                                """"""""""""""""""""\n                    ',
      'New issues introduced !',
      'Security Vulnerabilities:',
      '1/2: Prototype Pollution [Medium Severity]',
      '    Via: snyk@1.228.3 => configstore@3.1.2 => dot-prop@4.2.0',
      '\n',
      '2/2: Prototype Pollution [Medium Severity]',
      '    Via: snyk@1.228.3 => update-notifier@2.5.0 => configstore@3.1.2 => dot-prop@4.2.0',
      '\n',
    ];

    expectedOutput.forEach((line: string) => {
      expect(consoleOutput.join()).toContain(line);
    });

    expect(mockExit).toHaveBeenCalledWith(1);
  });

  it('Test standalone mode - 1 new issue 1 new direct and 1 new indirect dep', async () => {
    nock('https://snyk.io')
      .persist()
      .post(/.*/)
      .reply(200, (uri) => {
        switch (uri) {
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a72/aggregated-issues':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/test-goof-aggregated-two-vuln-no-license.json',
            );
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a73/aggregated-issues':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/test-goof-aggregated-one-vuln.json',
            );
          // case '/api/v1/org/playground/projects':
          //   return fs.readFileSync(fixturesFolderPath+'apiResponsesForProjects/list-all-projects-org-playground.json')
          default:
        }
      })
      .get(/.*/)
      .reply(200, (uri) => {
        switch (uri) {
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a72/dep-graph':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/goof-depgraph-from-api-with-one-more-direct-and-indirect-dep.json',
            );
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a73/dep-graph':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/goof-depgraph-from-api.json',
            );
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a72/issue/SNYK-JS-ACORN-559469/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/SNYK-JS-ACORN-559469-issue-paths.json',
            );
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a73/issue/SNYK-JS-ACORN-559469/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/SNYK-JS-ACORN-559469-issue-paths.json',
            );
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a72/issue/SNYK-JS-DOTPROP-543489/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/SNYK-JS-DOTPROP-543489-issue-paths-page1.json',
            );
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a73/issue/SNYK-JS-DOTPROP-543489/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/SNYK-JS-DOTPROP-543489-issue-paths-page1.json',
            );
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a73/issue/SNYK-JS-DOTPROP-543489/paths?perPage=100&page=2':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/SNYK-JS-DOTPROP-543489-issue-paths-page2.json',
            );
          default:
        }
      });

    const result = await getDelta();
    const expectedOutput = [
      '_____________________________',
      'Direct deps:',
      'Added 1 \nadded-dep@1.0.0',
      '===============',
      'Removed 0\n',
      '##################',
      'Indirect deps:',
      'Added 1 \nadded-indirectdep@1.0.0',
      '===============',
      'Paths',
      '   added-indirectdep@1.0.0 no issue:\n\u001b[34m     added-dep@1.0.0=>added-indirectdep@1.0.0\u001b[39m',
      '===============',
      'Removed 0\n',
      '_____________________________',
      //'\n                                uuuuuuuuuuuuuuuuuuuu\n                              u" uuuuuuuuuuuuuuuuuu "u\n                            u" u$$$$$$$$$$$$$$$$$$$$u "u\n                          u" u$$$$$$$$$$$$$$$$$$$$$$$$u "u\n                        u" u$$$$$$$$$$$$$$$$$$$$$$$$$$$$u "u\n                      u" u$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$u "u\n                    u" u$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$u "u\n                    $ $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ $\n                    $ $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ $\n                    $ $$$" ... "$...  ...$" ... "$$$  ... "$$$ $\n                    $ $$$u `"$$$$$$$  $$$  $$$$$  $$  $$$  $$$ $\n                    $ $$$$$$uu "$$$$  $$$  $$$$$  $$  """ u$$$ $\n                    $ $$$""$$$  $$$$  $$$u "$$$" u$$  $$$$$$$$ $\n                    $ $$$$....,$$$$$..$$$$$....,$$$$..$$$$$$$$ $\n                    $ $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ $\n                    "u "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" u"\n                      "u "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" u"\n                        "u "$$$$$$$$$$$$$$$$$$$$$$$$$$$$" u"\n                          "u "$$$$$$$$$$$$$$$$$$$$$$$$" u"\n                            "u "$$$$$$$$$$$$$$$$$$$$" u"\n                              "u """""""""""""""""" u"\n                                """"""""""""""""""""\n                    ',
      'New issues introduced !',
      'Security Vulnerabilities:',
      '1/2: Prototype Pollution [Medium Severity]',
      '    Via: snyk@1.228.3 => configstore@3.1.2 => dot-prop@4.2.0',
      '\n',
      '2/2: Prototype Pollution [Medium Severity]',
      '    Via: snyk@1.228.3 => update-notifier@2.5.0 => configstore@3.1.2 => dot-prop@4.2.0',
      '\n',
    ];

    expectedOutput.forEach((line: string) => {
      expect(consoleOutput.join()).toContain(line);
    });

    expect(mockExit).toHaveBeenCalledWith(1);
  });

  it('Test standalone mode - all projects - one project', async () => {
    nock('https://snyk.io')
      .persist()
      .post(/.*/)
      .reply(200, (uri) => {
        switch (uri) {
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a72/aggregated-issues':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/test-goof-aggregated-two-vuln-no-license.json',
            );
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a73/aggregated-issues':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/test-goof-aggregated-one-vuln.json',
            );
          // case '/api/v1/org/playground/projects':
          //   return fs.readFileSync(fixturesFolderPath+'apiResponsesForProjects/list-all-projects-org-playground.json')
          default:
        }
      })
      .get(/.*/)
      .reply(200, (uri) => {
        switch (uri) {
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a72/dep-graph':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/goof-depgraph-from-api-with-one-more-direct-and-indirect-dep.json',
            );
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a73/dep-graph':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/goof-depgraph-from-api.json',
            );
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a72/issue/SNYK-JS-ACORN-559469/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/SNYK-JS-ACORN-559469-issue-paths.json',
            );
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a73/issue/SNYK-JS-ACORN-559469/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/SNYK-JS-ACORN-559469-issue-paths.json',
            );
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a72/issue/SNYK-JS-DOTPROP-543489/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/SNYK-JS-DOTPROP-543489-issue-paths-page1.json',
            );
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a73/issue/SNYK-JS-DOTPROP-543489/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/SNYK-JS-DOTPROP-543489-issue-paths-page1.json',
            );
          case '/api/v1/org/playground/project/c51c80c2-66a1-442a-91e2-4f55b4256a73/issue/SNYK-JS-DOTPROP-543489/paths?perPage=100&page=2':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/SNYK-JS-DOTPROP-543489-issue-paths-page2.json',
            );
          default:
        }
      });

    const result = await getDelta();
    const expectedOutput = [
      '_____________________________',
      'Direct deps:',
      'Added 1 \nadded-dep@1.0.0',
      '===============',
      'Removed 0\n',
      '##################',
      'Indirect deps:',
      'Added 1 \nadded-indirectdep@1.0.0',
      '===============',
      'Paths',
      '   added-indirectdep@1.0.0 no issue:\n\u001b[34m     added-dep@1.0.0=>added-indirectdep@1.0.0\u001b[39m',
      '===============',
      'Removed 0\n',
      '_____________________________',
      //'\n                                uuuuuuuuuuuuuuuuuuuu\n                              u" uuuuuuuuuuuuuuuuuu "u\n                            u" u$$$$$$$$$$$$$$$$$$$$u "u\n                          u" u$$$$$$$$$$$$$$$$$$$$$$$$u "u\n                        u" u$$$$$$$$$$$$$$$$$$$$$$$$$$$$u "u\n                      u" u$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$u "u\n                    u" u$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$u "u\n                    $ $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ $\n                    $ $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ $\n                    $ $$$" ... "$...  ...$" ... "$$$  ... "$$$ $\n                    $ $$$u `"$$$$$$$  $$$  $$$$$  $$  $$$  $$$ $\n                    $ $$$$$$uu "$$$$  $$$  $$$$$  $$  """ u$$$ $\n                    $ $$$""$$$  $$$$  $$$u "$$$" u$$  $$$$$$$$ $\n                    $ $$$$....,$$$$$..$$$$$....,$$$$..$$$$$$$$ $\n                    $ $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ $\n                    "u "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" u"\n                      "u "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" u"\n                        "u "$$$$$$$$$$$$$$$$$$$$$$$$$$$$" u"\n                          "u "$$$$$$$$$$$$$$$$$$$$$$$$" u"\n                            "u "$$$$$$$$$$$$$$$$$$$$" u"\n                              "u """""""""""""""""" u"\n                                """"""""""""""""""""\n                    ',
      'New issues introduced !',
      'Security Vulnerabilities:',
      '1/2: Prototype Pollution [Medium Severity]',
      '    Via: snyk@1.228.3 => configstore@3.1.2 => dot-prop@4.2.0',
      '\n',
      '2/2: Prototype Pollution [Medium Severity]',
      '    Via: snyk@1.228.3 => update-notifier@2.5.0 => configstore@3.1.2 => dot-prop@4.2.0',
      '\n',
    ];

    expectedOutput.forEach((line: string) => {
      expect(consoleOutput.join()).toContain(line);
    });

    expect(mockExit).toHaveBeenCalledWith(1);
  });
});
