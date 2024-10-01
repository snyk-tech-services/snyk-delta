import nock from 'nock';
import * as path from 'path';
import * as fs from 'fs';
import debug from 'debug';

import { getDelta } from '../../src/lib/index';
const fixturesFolderPath = path.resolve(__dirname, '..') + '/fixtures/';
describe('Test End 2 End - Module', () => {
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
                'apiResponses/test-goof-aggregated-one-vuln.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/c51c80c2-66a1-442a-91e2-4f55b4256a72/aggregated-issues':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/test-goof-aggregated-one-vuln.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/projects':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponsesForProjects/list-all-projects-org-playground.json',
            );
          default:
        }
      })
      .get(/.*/)
      .reply(200, (uri) => {
        console.log(uri);
        switch (uri) {
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/ab9e037f-9020-4f77-9c48-b1cb0295a4b6/dep-graph':
            return fs.readFileSync(
              fixturesFolderPath + 'apiResponses/goof-depgraph-from-api.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/ab9e037f-9020-4f77-9c48-b1cb0295a4b6/issue/SNYK-JS-ACORN-559469/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/SNYK-JS-ACORN-559469-issue-paths.json',
            );
          case '/api/v1/org/361fd3c0-41d4-4ea4-ba77-09bb17890967/project/ab9e037f-9020-4f77-9c48-b1cb0295a4b6/issue/SNYK-JS-DOTPROP-543489/paths?perPage=100&page=1':
            return fs.readFileSync(
              fixturesFolderPath +
                'apiResponses/SNYK-JS-DOTPROP-543489-issue-paths-page1.json',
            );
          default:
        }
      });
  });

  it('Test module mode - no new issue', async () => {
    const result = await getDelta(
      fs
        .readFileSync(
          fixturesFolderPath + 'snykTestsOutputs/test-goof-one-vuln.json',
        )
        .toString(),
    );
    const expectedResult = {
      result: 0,
      newVulns: [],
      newLicenseIssues: [],
      passIfNoBaseline: false,
      noBaseline: false,
    };
    expect(result).toEqual(expectedResult);
  });

  it('Test module debug mode - no new issue', async () => {
    const result = await getDelta(
      fs
        .readFileSync(
          fixturesFolderPath + 'snykTestsOutputs/test-goof-one-vuln.json',
        )
        .toString(),
      true,
    );
    expect(debug('snyk')).toBeTruthy();
    const expectedResult = {
      result: 0,
      newVulns: [],
      newLicenseIssues: [],
      passIfNoBaseline: false,
      noBaseline: false,
    };
    expect(result).toEqual(expectedResult);
  });

  it('Test module mode - 1 new issue', async () => {
    const result = await getDelta(
      fs
        .readFileSync(
          fixturesFolderPath + 'snykTestsOutputs/test-goof-two-vuln.json',
        )
        .toString(),
    );

    const expectedResult = {
      result: 1,
      newVulns: [
        {
          CVSSv3: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L/E:P/RL:O/RC:C',
          alternativeIds: [],
          creationTime: '2020-01-28T15:18:37.743372Z',
          credit: ['aaron_costello'],
          cvssScore: 6.3,
          description:
            '## Overview\n\n[dot-prop](https://github.com/sindresorhus/dot-prop#readme) is a package to get, set, or delete a property from a nested object using a dot path.\n\n\nAffected versions of this package are vulnerable to Prototype Pollution.\nIt is possible for a user to modify the prototype of a base object.\r\n\r\n## PoC by aaron_costello \r\n```\r\nvar dotProp = require("dot-prop")\r\nconst object = {};\r\nconsole.log("Before " + object.b); //Undefined\r\ndotProp.set(object, \'__proto__.b\', true);\r\nconsole.log("After " + {}.b); //true\r\n```\n\n## Remediation\n\nUpgrade `dot-prop` to version 5.1.1 or higher.\n\n\n## References\n\n- [GitHub Commit](https://github.com/sindresorhus/dot-prop/commit/3039c8c07f6fdaa8b595ec869ae0895686a7a0f2)\n\n- [HackerOne Report](https://hackerone.com/reports/719856)\n',
          disclosureTime: '2020-01-28T10:17:51Z',
          exploit: 'Proof of Concept',
          fixedIn: ['5.1.1'],
          functions: [],
          // eslint-disable-next-line @typescript-eslint/camelcase
          functions_new: [],
          id: 'SNYK-JS-DOTPROP-543489',
          identifiers: { CVE: ['CVE-2020-8116'], CWE: ['CWE-400'] },
          language: 'js',
          modificationTime: '2020-01-31T17:21:49.331710Z',
          moduleName: 'dot-prop',
          packageManager: 'npm',
          packageName: 'dot-prop',
          patches: [],
          publicationTime: '2020-01-28T16:23:39Z',
          references: [
            {
              title: 'GitHub Commit',
              url:
                'https://github.com/sindresorhus/dot-prop/commit/3039c8c07f6fdaa8b595ec869ae0895686a7a0f2',
            },
            {
              title: 'HackerOne Report',
              url: 'https://hackerone.com/reports/719856',
            },
          ],
          semver: { vulnerable: ['<5.1.1'] },
          severity: 'medium',
          title: 'Prototype Pollution',
          from: [
            'goof@0.0.3',
            'snyk@1.228.3',
            'configstore@3.1.2',
            'dot-prop@4.2.0',
          ],
          upgradePath: [false, 'snyk@1.290.1'],
          isUpgradable: true,
          isPatchable: false,
          name: 'dot-prop',
          version: '4.2.0',
        },
      ],
      newLicenseIssues: [],
      passIfNoBaseline: false,
      noBaseline: false,
    };

    expect(result).toEqual(expectedResult);
  });
  it('Test module mode - invalid json input', async () => {
    const result = await getDelta(JSON.stringify({}));
    expect(result).toEqual({
      newLicenseIssues: undefined,
      newVulns: undefined,
      noBaseline: true,
      passIfNoBaseline: false,
      result: 2,
    });
  });

  it('Test module mode - 1 new issue fail --fail-on upgradable only', async () => {
    const result = await getDelta(
      fs
        .readFileSync(
          fixturesFolderPath + 'snykTestsOutputs/test-goof-two-vuln.json',
        )
        .toString(),
      false,
      false,
      'upgradable',
    );

    const expectedResult = {
      result: 1,
      newVulns: [
        {
          CVSSv3: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L/E:P/RL:O/RC:C',
          alternativeIds: [],
          creationTime: '2020-01-28T15:18:37.743372Z',
          credit: ['aaron_costello'],
          cvssScore: 6.3,
          description:
            '## Overview\n\n[dot-prop](https://github.com/sindresorhus/dot-prop#readme) is a package to get, set, or delete a property from a nested object using a dot path.\n\n\nAffected versions of this package are vulnerable to Prototype Pollution.\nIt is possible for a user to modify the prototype of a base object.\r\n\r\n## PoC by aaron_costello \r\n```\r\nvar dotProp = require("dot-prop")\r\nconst object = {};\r\nconsole.log("Before " + object.b); //Undefined\r\ndotProp.set(object, \'__proto__.b\', true);\r\nconsole.log("After " + {}.b); //true\r\n```\n\n## Remediation\n\nUpgrade `dot-prop` to version 5.1.1 or higher.\n\n\n## References\n\n- [GitHub Commit](https://github.com/sindresorhus/dot-prop/commit/3039c8c07f6fdaa8b595ec869ae0895686a7a0f2)\n\n- [HackerOne Report](https://hackerone.com/reports/719856)\n',
          disclosureTime: '2020-01-28T10:17:51Z',
          exploit: 'Proof of Concept',
          fixedIn: ['5.1.1'],
          functions: [],
          // eslint-disable-next-line @typescript-eslint/camelcase
          functions_new: [],
          id: 'SNYK-JS-DOTPROP-543489',
          identifiers: { CVE: ['CVE-2020-8116'], CWE: ['CWE-400'] },
          language: 'js',
          modificationTime: '2020-01-31T17:21:49.331710Z',
          moduleName: 'dot-prop',
          packageManager: 'npm',
          packageName: 'dot-prop',
          patches: [],
          publicationTime: '2020-01-28T16:23:39Z',
          references: [
            {
              title: 'GitHub Commit',
              url:
                'https://github.com/sindresorhus/dot-prop/commit/3039c8c07f6fdaa8b595ec869ae0895686a7a0f2',
            },
            {
              title: 'HackerOne Report',
              url: 'https://hackerone.com/reports/719856',
            },
          ],
          semver: { vulnerable: ['<5.1.1'] },
          severity: 'medium',
          title: 'Prototype Pollution',
          from: [
            'goof@0.0.3',
            'snyk@1.228.3',
            'configstore@3.1.2',
            'dot-prop@4.2.0',
          ],
          upgradePath: [false, 'snyk@1.290.1'],
          isUpgradable: true,
          isPatchable: false,
          name: 'dot-prop',
          version: '4.2.0',
        },
      ],
      newLicenseIssues: [],
      passIfNoBaseline: false,
      noBaseline: false,
    };

    expect(result).toEqual(expectedResult);
  });

  it('Test module mode - 1 new issue no fail - fail-on patchable only', async () => {
    const result = await getDelta(
      fs
        .readFileSync(
          fixturesFolderPath + 'snykTestsOutputs/test-goof-two-vuln.json',
        )
        .toString(),
      false,
      false,
      'patchable',
    );

    const expectedResult = {
      result: 0,
      newVulns: [
        {
          CVSSv3: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L/E:P/RL:O/RC:C',
          alternativeIds: [],
          creationTime: '2020-01-28T15:18:37.743372Z',
          credit: ['aaron_costello'],
          cvssScore: 6.3,
          description:
            '## Overview\n\n[dot-prop](https://github.com/sindresorhus/dot-prop#readme) is a package to get, set, or delete a property from a nested object using a dot path.\n\n\nAffected versions of this package are vulnerable to Prototype Pollution.\nIt is possible for a user to modify the prototype of a base object.\r\n\r\n## PoC by aaron_costello \r\n```\r\nvar dotProp = require("dot-prop")\r\nconst object = {};\r\nconsole.log("Before " + object.b); //Undefined\r\ndotProp.set(object, \'__proto__.b\', true);\r\nconsole.log("After " + {}.b); //true\r\n```\n\n## Remediation\n\nUpgrade `dot-prop` to version 5.1.1 or higher.\n\n\n## References\n\n- [GitHub Commit](https://github.com/sindresorhus/dot-prop/commit/3039c8c07f6fdaa8b595ec869ae0895686a7a0f2)\n\n- [HackerOne Report](https://hackerone.com/reports/719856)\n',
          disclosureTime: '2020-01-28T10:17:51Z',
          exploit: 'Proof of Concept',
          fixedIn: ['5.1.1'],
          functions: [],
          // eslint-disable-next-line @typescript-eslint/camelcase
          functions_new: [],
          id: 'SNYK-JS-DOTPROP-543489',
          identifiers: { CVE: ['CVE-2020-8116'], CWE: ['CWE-400'] },
          language: 'js',
          modificationTime: '2020-01-31T17:21:49.331710Z',
          moduleName: 'dot-prop',
          packageManager: 'npm',
          packageName: 'dot-prop',
          patches: [],
          publicationTime: '2020-01-28T16:23:39Z',
          references: [
            {
              title: 'GitHub Commit',
              url:
                'https://github.com/sindresorhus/dot-prop/commit/3039c8c07f6fdaa8b595ec869ae0895686a7a0f2',
            },
            {
              title: 'HackerOne Report',
              url: 'https://hackerone.com/reports/719856',
            },
          ],
          semver: { vulnerable: ['<5.1.1'] },
          severity: 'medium',
          title: 'Prototype Pollution',
          from: [
            'goof@0.0.3',
            'snyk@1.228.3',
            'configstore@3.1.2',
            'dot-prop@4.2.0',
          ],
          upgradePath: [false, 'snyk@1.290.1'],
          isUpgradable: true,
          isPatchable: false,
          name: 'dot-prop',
          version: '4.2.0',
        },
      ],
      newLicenseIssues: [],
      passIfNoBaseline: false,
      noBaseline: false,
    };

    expect(result).toEqual(expectedResult);
  });

  it('Test module mode - 1 new issue fail - fail-on all', async () => {
    const result = await getDelta(
      fs
        .readFileSync(
          fixturesFolderPath + 'snykTestsOutputs/test-goof-two-vuln.json',
        )
        .toString(),
      false,
      false,
      'all',
    );

    const expectedResult = {
      result: 1,
      newVulns: [
        {
          CVSSv3: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L/E:P/RL:O/RC:C',
          alternativeIds: [],
          creationTime: '2020-01-28T15:18:37.743372Z',
          credit: ['aaron_costello'],
          cvssScore: 6.3,
          description:
            '## Overview\n\n[dot-prop](https://github.com/sindresorhus/dot-prop#readme) is a package to get, set, or delete a property from a nested object using a dot path.\n\n\nAffected versions of this package are vulnerable to Prototype Pollution.\nIt is possible for a user to modify the prototype of a base object.\r\n\r\n## PoC by aaron_costello \r\n```\r\nvar dotProp = require("dot-prop")\r\nconst object = {};\r\nconsole.log("Before " + object.b); //Undefined\r\ndotProp.set(object, \'__proto__.b\', true);\r\nconsole.log("After " + {}.b); //true\r\n```\n\n## Remediation\n\nUpgrade `dot-prop` to version 5.1.1 or higher.\n\n\n## References\n\n- [GitHub Commit](https://github.com/sindresorhus/dot-prop/commit/3039c8c07f6fdaa8b595ec869ae0895686a7a0f2)\n\n- [HackerOne Report](https://hackerone.com/reports/719856)\n',
          disclosureTime: '2020-01-28T10:17:51Z',
          exploit: 'Proof of Concept',
          fixedIn: ['5.1.1'],
          functions: [],
          // eslint-disable-next-line @typescript-eslint/camelcase
          functions_new: [],
          id: 'SNYK-JS-DOTPROP-543489',
          identifiers: { CVE: ['CVE-2020-8116'], CWE: ['CWE-400'] },
          language: 'js',
          modificationTime: '2020-01-31T17:21:49.331710Z',
          moduleName: 'dot-prop',
          packageManager: 'npm',
          packageName: 'dot-prop',
          patches: [],
          publicationTime: '2020-01-28T16:23:39Z',
          references: [
            {
              title: 'GitHub Commit',
              url:
                'https://github.com/sindresorhus/dot-prop/commit/3039c8c07f6fdaa8b595ec869ae0895686a7a0f2',
            },
            {
              title: 'HackerOne Report',
              url: 'https://hackerone.com/reports/719856',
            },
          ],
          semver: { vulnerable: ['<5.1.1'] },
          severity: 'medium',
          title: 'Prototype Pollution',
          from: [
            'goof@0.0.3',
            'snyk@1.228.3',
            'configstore@3.1.2',
            'dot-prop@4.2.0',
          ],
          upgradePath: [false, 'snyk@1.290.1'],
          isUpgradable: true,
          isPatchable: false,
          name: 'dot-prop',
          version: '4.2.0',
        },
      ],
      newLicenseIssues: [],
      passIfNoBaseline: false,
      noBaseline: false,
    };

    expect(result).toEqual(expectedResult);
  });

  it('Test module mode - 1 new issue no fail - fail-on all', async () => {
    const result = await getDelta(
      fs
        .readFileSync(
          fixturesFolderPath +
            'snykTestsOutputs/test-goof-two-vuln-no-upgradable-or-patchable.json',
        )
        .toString(),
      false,
      false,
      'all',
    );

    const expectedResult = {
      result: 0,
      newVulns: [
        {
          CVSSv3: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L/E:P/RL:O/RC:C',
          alternativeIds: [],
          creationTime: '2020-01-28T15:18:37.743372Z',
          credit: ['aaron_costello'],
          cvssScore: 6.3,
          description:
            '## Overview\n\n[dot-prop](https://github.com/sindresorhus/dot-prop#readme) is a package to get, set, or delete a property from a nested object using a dot path.\n\n\nAffected versions of this package are vulnerable to Prototype Pollution.\nIt is possible for a user to modify the prototype of a base object.\r\n\r\n## PoC by aaron_costello \r\n```\r\nvar dotProp = require("dot-prop")\r\nconst object = {};\r\nconsole.log("Before " + object.b); //Undefined\r\ndotProp.set(object, \'__proto__.b\', true);\r\nconsole.log("After " + {}.b); //true\r\n```\n\n## Remediation\n\nUpgrade `dot-prop` to version 5.1.1 or higher.\n\n\n## References\n\n- [GitHub Commit](https://github.com/sindresorhus/dot-prop/commit/3039c8c07f6fdaa8b595ec869ae0895686a7a0f2)\n\n- [HackerOne Report](https://hackerone.com/reports/719856)\n',
          disclosureTime: '2020-01-28T10:17:51Z',
          exploit: 'Proof of Concept',
          fixedIn: ['5.1.1'],
          functions: [],
          // eslint-disable-next-line @typescript-eslint/camelcase
          functions_new: [],
          id: 'SNYK-JS-DOTPROP-543489',
          identifiers: { CVE: ['CVE-2020-8116'], CWE: ['CWE-400'] },
          language: 'js',
          modificationTime: '2020-01-31T17:21:49.331710Z',
          moduleName: 'dot-prop',
          packageManager: 'npm',
          packageName: 'dot-prop',
          patches: [],
          publicationTime: '2020-01-28T16:23:39Z',
          references: [
            {
              title: 'GitHub Commit',
              url:
                'https://github.com/sindresorhus/dot-prop/commit/3039c8c07f6fdaa8b595ec869ae0895686a7a0f2',
            },
            {
              title: 'HackerOne Report',
              url: 'https://hackerone.com/reports/719856',
            },
          ],
          semver: { vulnerable: ['<5.1.1'] },
          severity: 'medium',
          title: 'Prototype Pollution',
          from: [
            'goof@0.0.3',
            'snyk@1.228.3',
            'configstore@3.1.2',
            'dot-prop@4.2.0',
          ],
          upgradePath: [false, 'snyk@1.290.1'],
          isUpgradable: false,
          isPatchable: false,
          name: 'dot-prop',
          version: '4.2.0',
        },
      ],
      newLicenseIssues: [],
      passIfNoBaseline: false,
      noBaseline: false,
    };

    expect(result).toEqual(expectedResult);
  });
});
