import { stdin, MockSTDIN } from 'mock-stdin';
import { mockProcessExit } from 'jest-mock-process';
import * as nock from 'nock';
import * as path from 'path';
import * as fs from 'fs';

const stdinMock: MockSTDIN = stdin();
let mockExit = mockProcessExit();
import { getDelta } from '../../src/lib/index';

const fixturesFolderPath = path.resolve(__dirname, '..') + '/fixtures/';

describe('Test End 2 End - Inline mode', () => {
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
    mockExit.mockClear();
  });

  beforeEach(() => {
    consoleOutput = [];
    mockExit = mockProcessExit();
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
          case '/rest/orgs?version=2023-06-22~beta&limit=10&slug=customerorg':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/customerorgSlugToUUID.json',
            );
          default:
        }
      });

    nock('https://snyk.io')
      .persist()
      .post(/.*/)
      .reply(200, (uri) => {
        switch (uri) {
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/ab9e037f-9020-4f77-9c48-b1cb0295a4b6/aggregated-issues':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/test-goof-aggregated-one-vuln-one-license.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/09235fa4-c241-42c6-8c63-c053bd272786/aggregated-issues':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/test-gomod-aggregated.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/62b136c4-eaf7-46b1-ae76-ded54bc19a5a/aggregated-issues':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/java-goof-todolist-core-aggregated-issues.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/projects':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponsesForProjects/list-all-projects-org-361fd3c0-41d4-4ea4-ba77-09bb17890967.json',
            );
          case '/api/v1/org/1234-1234-1234-1234-123456789012/project/37a29fe9-c342-4d70-8efc-df96a8d730b6/aggregated-issues':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/projectId-aggregated-issues.json',
            );

          default:
        }
      })
      .get(/.*/)
      .reply(200, (uri) => {
        switch (uri) {
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/ab9e037f-9020-4f77-9c48-b1cb0295a4b6/dep-graph':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/goof-depgraph-from-api.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/09235fa4-c241-42c6-8c63-c053bd272786/dep-graph':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/goof-depgraph-from-api.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/62b136c4-eaf7-46b1-ae76-ded54bc19a5a/dep-graph':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/java-goof-todolist-core-depgraph.json',
            );
          case '/api/v1/org/1234-1234-1234-1234-123456789012/project/37a29fe9-c342-4d70-8efc-df96a8d730b6/dep-graph':
            return fs.readFileSync(
              fixturesFolderPath + 'dependencies/projectId-depgraph.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/ab9e037f-9020-4f77-9c48-b1cb0295a4b6/issue/SNYK-JS-ACORN-559469/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/SNYK-JS-ACORN-559469-issue-paths.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/ab9e037f-9020-4f77-9c48-b1cb0295a4b6/issue/snyk:lic:npm:goof:GPL-2.0/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/snyk-lic-npm-goof-GPL-2-0-issue-paths.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/62b136c4-eaf7-46b1-ae76-ded54bc19a5a/issue/SNYK-JAVA-ORGSPRINGFRAMEWORK-2436751/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/vuln-path-SNYK-JAVA-ORGSPRINGFRAMEWORK-2436751.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/62b136c4-eaf7-46b1-ae76-ded54bc19a5a/issue/SNYK-JAVA-ORGHIBERNATE-1041788/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/vuln-path-SNYK-JAVA-ORGHIBERNATE-1041788.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/62b136c4-eaf7-46b1-ae76-ded54bc19a5a/issue/SNYK-JAVA-ORGHIBERNATE-584563/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/vuln-path-SNYK-JAVA-ORGHIBERNATE-584563.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/62b136c4-eaf7-46b1-ae76-ded54bc19a5a/issue/SNYK-JAVA-ORGSPRINGFRAMEWORK-2689634/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/vuln-path-SNYK-JAVA-ORGSPRINGFRAMEWORK-2689634.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/62b136c4-eaf7-46b1-ae76-ded54bc19a5a/issue/SNYK-JAVA-C3P0-461017/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/vuln-path-SNYK-JAVA-C3P0-461017.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/62b136c4-eaf7-46b1-ae76-ded54bc19a5a/issue/SNYK-JAVA-DOM4J-174153/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/vuln-path-SNYK-JAVA-DOM4J-174153.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/62b136c4-eaf7-46b1-ae76-ded54bc19a5a/issue/SNYK-JAVA-C3P0-461018/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/vuln-path-SNYK-JAVA-C3P0-461018.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/62b136c4-eaf7-46b1-ae76-ded54bc19a5a/issue/SNYK-JAVA-ORGSPRINGFRAMEWORK-31325/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/vuln-path-SNYK-JAVA-ORGSPRINGFRAMEWORK-31325.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/62b136c4-eaf7-46b1-ae76-ded54bc19a5a/issue/SNYK-JAVA-ORGSPRINGFRAMEWORK-2823313/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/vuln-path-SNYK-JAVA-ORGSPRINGFRAMEWORK-2823313.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/62b136c4-eaf7-46b1-ae76-ded54bc19a5a/issue/SNYK-JAVA-ORGSPRINGFRAMEWORK-2434828/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/vuln-path-SNYK-JAVA-ORGSPRINGFRAMEWORK-2434828.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/62b136c4-eaf7-46b1-ae76-ded54bc19a5a/issue/SNYK-JAVA-ORGSPRINGFRAMEWORK-2330878/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/vuln-path-SNYK-JAVA-ORGSPRINGFRAMEWORK-2330878.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/62b136c4-eaf7-46b1-ae76-ded54bc19a5a/issue/SNYK-JAVA-ORGSPRINGFRAMEWORK-2329097/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/vuln-path-SNYK-JAVA-ORGSPRINGFRAMEWORK-2329097.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/62b136c4-eaf7-46b1-ae76-ded54bc19a5a/issue/snyk:lic:maven:org.hibernate.javax.persistence:hibernate-jpa-2.1-api:EPL-1.0/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/vuln-path-snyk:lic:maven:org.hibernate.javax.persistence:hibernate-jpa-2.1-api:EPL-1.0.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/62b136c4-eaf7-46b1-ae76-ded54bc19a5a/issue/snyk:lic:maven:org.hibernate:hibernate-entitymanager:LGPL-2.0/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/vuln-path-snyk:lic:maven:org.hibernate:hibernate-entitymanager:LGPL-2.0.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/62b136c4-eaf7-46b1-ae76-ded54bc19a5a/issue/snyk:lic:maven:org.hibernate:hibernate-core:LGPL-2.0/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/vuln-path-snyk:lic:maven:org.hibernate:hibernate-core:LGPL-2.0.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/62b136c4-eaf7-46b1-ae76-ded54bc19a5a/issue/snyk:lic:maven:org.hibernate.common:hibernate-commons-annotations:LGPL-2.1/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/vuln-path-snyk:lic:maven:org.hibernate.common:hibernate-commons-annotations:LGPL-2.1.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/62b136c4-eaf7-46b1-ae76-ded54bc19a5a/issue/snyk:lic:maven:org.aspectj:aspectjweaver:EPL-1.0/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/vuln-path-snyk:lic:maven:org.aspectj:aspectjweaver:EPL-1.0.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/62b136c4-eaf7-46b1-ae76-ded54bc19a5a/issue/snyk:lic:maven:c3p0:c3p0:LGPL-3.0/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/vuln-path-snyk:lic:maven:c3p0:c3p0:LGPL-3.0.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/62b136c4-eaf7-46b1-ae76-ded54bc19a5a/issue/SNYK-JAVA-DOM4J-2812975/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/vuln-path-SNYK-JAVA-DOM4J-2812975.json',
            );
          default:
        }
      });
  });
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

    await getDelta();
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
    await getDelta();

    const expectedOutput = [
      'New issue introduced !',
      'Security Vulnerability:',
      '  1/1: SNYK-JS-DOTPROP-543489:Prototype Pollution [Medium Severity][cvssScore: 6.3]',
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
    await getDelta();

    const expectedOutput = [
      'New issue introduced !',
      'Security Vulnerability:',
      '  1/1: SNYK-JS-DOTPROP-543489:Prototype Pollution [Medium Severity][cvssScore: 6.3]',
      '    Via: snyk@1.228.3 => configstore@3.1.2 => dot-prop@4.2.0',
      '    Fixed in: dot-prop 5.1.1',
      '    Fixable by upgrade:  snyk@1.290.1',
    ];

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

    await getDelta();
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

    await getDelta();
    expect(consoleOutput).toContain('No new issues found !');

    expect(mockExit).toHaveBeenCalledWith(0);
  });

  it('Test Inline mode - no new issue following version upgrade without vuln fix - java', async () => {
    setTimeout(() => {
      stdinMock.send(
        fs
          .readFileSync(
            fixturesFolderPath +
              'snykTestsOutputs/test-java-goof-todolist-core-with-version-upgrade-but-same-vuln-still.json',
          )
          .toString(),
      );
      stdinMock.send(null);
    }, 100);

    await getDelta();
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

    await getDelta();

    const expectedOutput = [
      'New issue introduced !',
      'Security Vulnerability:',
      '  1/1: SNYK-JS-ACORN-559469:Regular Expression Denial of Service (ReDoS) [High Severity][cvssScore: 7.5]',
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
    expect(mockExit).toHaveBeenCalledWith(1);
  });

  it('Test Inline mode - use project ID', async () => {
    setTimeout(() => {
      stdinMock.send(
        fs
          .readFileSync(fixturesFolderPath + 'snykTestsOutputs/projectId.json')
          .toString(),
      );
      stdinMock.send(null);
    }, 100);

    await getDelta();
    expect(consoleOutput).toContain('No new issues found !');

    expect(mockExit).toHaveBeenCalledWith(0);
  });

  it('Test Inline mode - no new issue if license filter on', async () => {
    process.env.TYPE = 'license';
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
      '  1/1: Prototype Pollution [Medium Severity][]',
      '    Via: snyk@1.228.3 => configstore@3.1.2 => dot-prop@4.2.0',
      '    Fixed in: dot-prop 5.1.1',
      '    Fixable by upgrade:  snyk@1.290.1',
    ];

    expect(consoleOutput).toContain('No new issues found !');

    expect(mockExit).toHaveBeenCalledWith(0);
  });

  it('Test Inline mode - no new issue if license filter on', async () => {
    process.env.TYPE = 'vuln';
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
      '  1/1: SNYK-JS-DOTPROP-543489:Prototype Pollution [Medium Severity][cvssScore: 6.3]',
      '    Via: snyk@1.228.3 => configstore@3.1.2 => dot-prop@4.2.0',
      '    Fixed in: dot-prop 5.1.1',
      '    Fixable by upgrade:  snyk@1.290.1',
    ];

    expectedOutput.forEach((line: string) => {
      expect(consoleOutput.join()).toContain(line);
    });

    expect(mockExit).toHaveBeenCalledWith(1);
  });
});
