import { mockProcessExit } from 'jest-mock-process';
import * as nock from 'nock';
import * as path from 'path';
import * as fs from 'fs';
process.argv.push('-d');
process.argv.push('--baselineOrg=361fd3c0-41d4-4ea4-ba77-09bb17890967');
process.argv.push('--baselineProject=c51c80c2-66a1-442a-91e2-4f55b4256a72');
process.argv.push('--currentOrg=361fd3c0-41d4-4ea4-ba77-09bb17890967');
process.argv.push('--currentProject=c51c80c2-66a1-442a-91e2-4f55b4256a73');

const mockExit = mockProcessExit();
import { getDelta } from '../../src/lib/index';

const fixturesFolderPath = path.resolve(__dirname, '..') + '/fixtures/';

const originalLog = console.log;
let consoleOutput: Array<string> = [];
const mockedLog = (output: string): void => {
  consoleOutput.push(output);
};
beforeAll(() => {
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
        default:
      }
    });
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

describe('Test End 2 End - Standalone mode without baseline', () => {
  it('Test standalone mode - no new issue', async () => {
    nock('https://snyk.io')
      .persist()
      .post(/.*/)
      .reply(200, (uri) => {
        switch (uri) {
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/c51c80c2-66a1-442a-91e2-4f55b4256a72/issues':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/test-goof.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/c51c80c2-66a1-442a-91e2-4f55b4256a73/issues':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/test-goof.json',
            );
          // case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/projects':
          //   return fs.readFileSync(fixturesFolderPath+'apiResponsesForProjects/list-all-projects-org-361fd3c0-41d4-4ea4-ba77-09bb17890967.json')
          default:
        }
      })
      .get(/.*/)
      .reply(200, (uri) => {
        switch (uri) {
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/c51c80c2-66a1-442a-91e2-4f55b4256a73/dep-graph':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/goof-depgraph-from-api.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/c51c80c2-66a1-442a-91e2-4f55b4256a72/dep-graph':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/goof-depgraph-from-api.json',
            );
          default:
        }
      });

    await getDelta();

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
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/c51c80c2-66a1-442a-91e2-4f55b4256a72/issues':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/test-goof.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/c51c80c2-66a1-442a-91e2-4f55b4256a73/issues':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/test-goof-with-one-more-vuln.json',
            );
          // case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/projects':
          //   return fs.readFileSync(fixturesFolderPath+'apiResponsesForProjects/list-all-projects-org-361fd3c0-41d4-4ea4-ba77-09bb17890967.json')
          default:
        }
      })
      .get(/.*/)
      .reply(200, (uri) => {
        switch (uri) {
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/c51c80c2-66a1-442a-91e2-4f55b4256a73/dep-graph':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/goof-depgraph-from-api.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/c51c80c2-66a1-442a-91e2-4f55b4256a72/dep-graph':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/goof-depgraph-from-api.json',
            );
          default:
        }
      });

    await getDelta();

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
      'New issue introduced !',
      'Security Vulnerability:\n',
      '1/1: Denial of Service (DoS) [Medium Severity][cvssScore: 6.3]',
      '    Via: ms@1.0.0 => ejs-locals@1.0.2 => ejs@0.8.8',
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
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/c51c80c2-66a1-442a-91e2-4f55b4256a72/issues':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/test-goof.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/c51c80c2-66a1-442a-91e2-4f55b4256a73/issues':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/test-goof-with-one-more-vuln.json',
            );
          // case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/projects':
          //   return fs.readFileSync(fixturesFolderPath+'apiResponsesForProjects/list-all-projects-org-361fd3c0-41d4-4ea4-ba77-09bb17890967.json')
          default:
        }
      })
      .get(/.*/)
      .reply(200, (uri) => {
        switch (uri) {
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/c51c80c2-66a1-442a-91e2-4f55b4256a73/dep-graph':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/goof-depgraph-from-api-with-one-more-direct-dep.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/c51c80c2-66a1-442a-91e2-4f55b4256a72/dep-graph':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/goof-depgraph-from-api.json',
            );
          default:
        }
      });

    await getDelta();
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
      'New issue introduced !',
      'Security Vulnerability:\n',
      '1/1: Denial of Service (DoS) [Medium Severity][cvssScore: 6.3]',
      '    Via: ms@1.0.0 => ejs-locals@1.0.2 => ejs@0.8.8',
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
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/c51c80c2-66a1-442a-91e2-4f55b4256a72/issues':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/test-goof.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/c51c80c2-66a1-442a-91e2-4f55b4256a73/issues':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/test-goof-with-one-more-vuln.json',
            );
          // case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/projects':
          //   return fs.readFileSync(fixturesFolderPath+'apiResponsesForProjects/list-all-projects-org-361fd3c0-41d4-4ea4-ba77-09bb17890967.json')
          default:
        }
      })
      .get(/.*/)
      .reply(200, (uri) => {
        switch (uri) {
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/c51c80c2-66a1-442a-91e2-4f55b4256a73/dep-graph':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/goof-depgraph-from-api-with-one-more-direct-and-indirect-dep.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/c51c80c2-66a1-442a-91e2-4f55b4256a72/dep-graph':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/goof-depgraph-from-api.json',
            );
          default:
        }
      });

    await getDelta();
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
      'New issue introduced !',
      'Security Vulnerability:\n',
      '1/1: Denial of Service (DoS) [Medium Severity][cvssScore: 6.3]',
      '    Via: ms@1.0.0 => ejs-locals@1.0.2 => ejs@0.8.8',
      '\n',
    ];

    expectedOutput.forEach((line: string) => {
      expect(consoleOutput.join()).toContain(line);
    });

    expect(mockExit).toHaveBeenCalledWith(1);
  });
});
