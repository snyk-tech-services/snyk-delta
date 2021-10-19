import { stdin, MockSTDIN } from 'mock-stdin';

import * as nock from 'nock';
import * as path from 'path';
import * as fs from 'fs';

const stdinMock: MockSTDIN = stdin();

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
        case '/api/v1/org/playground/project/09235fa4-c241-42c6-8c63-c053bd272786/issues':
          return fs.readFileSync(
            fixturesFolderPath + 'apiResponses/test-gomod.json',
          );
        case '/api/v1/org/playground/project/37a29fe9-c342-4d70-8efc-df96a8d730b3/issues':
          return fs.readFileSync(
            fixturesFolderPath + 'apiResponses/java-goof.json',
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

describe('Test End 2 End - Inline mode', () => {
  it('Test module - no monitored project found - return vulns and 0 exit code', async () => {
    const result = await getDelta(
      fs
        .readFileSync(
          fixturesFolderPath + 'snykTestsOutputs/test-unmonitored-goof.json',
        )
        .toString(),
      false,
      true,
    );

    const expectedResult = [
      {
        result: 0,
        newVulns: [
          {
            CVSSv3: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
            alternativeIds: [],
            creationTime: '2020-03-07T00:18:41.509507Z',
            credit: ['Peter van der Zee'],
            cvssScore: 7.5,
            description:
              '## Overview\n' +
              '\n' +
              '[acorn](https://github.com/acornjs/acorn) is a tiny, fast JavaScript parser written in JavaScript.\n' +
              '\n' +
              '\n' +
              'Affected versions of this package are vulnerable to Regular Expression Denial of Service (ReDoS)\n' +
              'via a regex in the form of `/[x-\\ud800]/u`, which causes the parser to enter an infinite loop. \r\n' +
              '\r\n' +
              'This string is not a valid `UTF16` and is therefore not sanitized before reaching the parser. An application which processes untrusted input and passes it directly to `acorn`, will allow attackers to leverage the vulnerability leading to a Denial of Service.\n' +
              '\n' +
              '## Details\n' +
              'Denial of Service (DoS) describes a family of attacks, all aimed at making a system inaccessible to its original and legitimate users. There are many types of DoS attacks, ranging from trying to clog the network pipes to the system by generating a large volume of traffic from many machines (a Distributed Denial of Service - DDoS - attack) to sending crafted requests that cause a system to crash or take a disproportional amount of time to process.\r\n' +
              '\r\n' +
              "The Regular expression Denial of Service (ReDoS) is a type of Denial of Service attack. Regular expressions are incredibly powerful, but they aren't very intuitive and can ultimately end up making it easy for attackers to take your site down.\r\n" +
              '\r\n' +
              'Let’s take the following regular expression as an example:\r\n' +
              '```js\r\n' +
              'regex = /A(B|C+)+D/\r\n' +
              '```\r\n' +
              '\r\n' +
              'This regular expression accomplishes the following:\r\n' +
              "- `A` The string must start with the letter 'A'\r\n" +
              "- `(B|C+)+` The string must then follow the letter A with either the letter 'B' or some number of occurrences of the letter 'C' (the `+` matches one or more times). The `+` at the end of this section states that we can look for one or more matches of this section.\r\n" +
              "- `D` Finally, we ensure this section of the string ends with a 'D'\r\n" +
              '\r\n' +
              'The expression would match inputs such as `ABBD`, `ABCCCCD`, `ABCBCCCD` and `ACCCCCD`\r\n' +
              '\r\n' +
              "It most cases, it doesn't take very long for a regex engine to find a match:\r\n" +
              '\r\n' +
              '```bash\r\n' +
              `$ time node -e '/A(B|C+)+D/.test("ACCCCCCCCCCCCCCCCCCCCCCCCCCCCD")'\r\n` +
              '0.04s user 0.01s system 95% cpu 0.052 total\r\n' +
              '\r\n' +
              `$ time node -e '/A(B|C+)+D/.test("ACCCCCCCCCCCCCCCCCCCCCCCCCCCCX")'\r\n` +
              '1.79s user 0.02s system 99% cpu 1.812 total\r\n' +
              '```\r\n' +
              '\r\n' +
              'The entire process of testing it against a 30 characters long string takes around ~52ms. But when given an invalid string, it takes nearly two seconds to complete the test, over ten times as long as it took to test a valid string. The dramatic difference is due to the way regular expressions get evaluated.\r\n' +
              '\r\n' +
              'Most Regex engines will work very similarly (with minor differences). The engine will match the first possible way to accept the current character and proceed to the next one. If it then fails to match the next one, it will backtrack and see if there was another way to digest the previous character. If it goes too far down the rabbit hole only to find out the string doesn’t match in the end, and if many characters have multiple valid regex paths, the number of backtracking steps can become very large, resulting in what is known as _catastrophic backtracking_.\r\n' +
              '\r\n' +
              `Let's look at how our expression runs into this problem, using a shorter string: "ACCCX". While it seems fairly straightforward, there are still four different ways that the engine could match those three C's:\r\n` +
              '1. CCC\r\n' +
              '2. CC+C\r\n' +
              '3. C+CC\r\n' +
              '4. C+C+C.\r\n' +
              '\r\n' +
              "The engine has to try each of those combinations to see if any of them potentially match against the expression. When you combine that with the other steps the engine must take, we can use [RegEx 101 debugger](https://regex101.com/debugger) to see the engine has to take a total of 38 steps before it can determine the string doesn't match.\r\n" +
              '\r\n' +
              'From there, the number of steps the engine must use to validate a string just continues to grow.\r\n' +
              '\r\n' +
              "| String | Number of C's | Number of steps |\r\n" +
              '| -------|-------------:| -----:|\r\n' +
              '| ACCCX | 3 | 38\r\n' +
              '| ACCCCX | 4 | 71\r\n' +
              '| ACCCCCX | 5 | 136\r\n' +
              '| ACCCCCCCCCCCCCCX | 14 | 65,553\r\n' +
              '\r\n' +
              '\r\n' +
              "By the time the string includes 14 C's, the engine has to take over 65,000 steps just to see if the string is valid. These extreme situations can cause them to work very slowly (exponentially related to input size, as shown above), allowing an attacker to exploit this and can cause the service to excessively consume CPU, resulting in a Denial of Service.\n" +
              '\n' +
              '## Remediation\n' +
              '\n' +
              'Upgrade `acorn` to version 5.7.4, 6.4.1, 7.1.1 or higher.\n' +
              '\n' +
              '\n' +
              '## References\n' +
              '\n' +
              '- [GitHub Commit](https://github.com/acornjs/acorn/commit/793c0e569ed1158672e3a40aeed1d8518832b802)\n' +
              '\n' +
              '- [GitHub Issue 6.x Branch](https://github.com/acornjs/acorn/issues/929)\n' +
              '\n' +
              '- [NPM Security Advisory](https://www.npmjs.com/advisories/1488)\n',
            disclosureTime: '2020-03-02T19:21:25Z',
            exploit: 'Not Defined',
            fixedIn: ['5.7.4', '6.4.1', '7.1.1'],
            functions: [],
            // eslint-disable-next-line @typescript-eslint/camelcase
            functions_new: [],
            id: 'SNYK-JS-ACORN-559469',
            identifiers: {
              CVE: [],
              CWE: ['CWE-400'],
              GHSA: ['GHSA-6chw-6frg-f759'],
              NSP: [1488],
            },
            language: 'js',
            modificationTime: '2020-03-10T10:19:13.616093Z',
            moduleName: 'acorn',
            packageManager: 'npm',
            packageName: 'acorn',
            patches: [],
            publicationTime: '2020-03-07T00:19:23Z',
            references: [
              {
                title: 'GitHub Commit',
                url:
                  'https://github.com/acornjs/acorn/commit/793c0e569ed1158672e3a40aeed1d8518832b802',
              },
              {
                title: 'GitHub Issue 6.x Branch',
                url: 'https://github.com/acornjs/acorn/issues/929',
              },
              {
                title: 'NPM Security Advisory',
                url: 'https://www.npmjs.com/advisories/1488',
              },
            ],
            semver: {
              vulnerable: [
                '>=5.5.0 <5.7.4',
                '>=6.0.0 <6.4.1',
                '>=7.0.0 <7.1.1',
              ],
            },
            severity: 'high',
            title: 'Regular Expression Denial of Service (ReDoS)',
            from: [
              'goof@0.0.3',
              '@snyk/nodejs-runtime-agent@1.14.0',
              'acorn@5.7.3',
            ],
            upgradePath: [
              false,
              '@snyk/nodejs-runtime-agent@1.14.0',
              'acorn@5.7.4',
            ],
            isUpgradable: true,
            isPatchable: false,
            name: 'acorn',
            version: '5.7.3',
          },
        ],
        newLicenseIssues: [
          {
            license: 'GPL-2.0',
            semver: {
              vulnerable: ['>=0'],
            },
            id: 'snyk:lic:npm:goof:GPL-2.0',
            type: 'license',
            packageManager: 'npm',
            language: 'js',
            packageName: 'goof',
            title: 'GPL-2.0 license',
            description: 'GPL-2.0 license',
            publicationTime: '2020-04-09T19:48:50.751Z',
            creationTime: '2020-04-09T19:48:50.751Z',
            patches: [],
            licenseTemplateUrl:
              'https://raw.githubusercontent.com/spdx/license-list/master/GPL-2.0.txt',
            severity: 'medium',
            from: ['goof@0.0.3'],
            upgradePath: [],
            isUpgradable: false,
            isPatchable: false,
            name: 'goof',
            version: '0.0.3',
          },
        ],
        passIfNoBaseline: true,
        noBaseline: true,
        projectNameOrId: 'unmonitored-goof',
      },
    ];

    expect(result).toEqual(expectedResult);
  });
  it('Test module - no monitored project found - return vulns and 1 exit code', async () => {
    const result = await getDelta(
      fs
        .readFileSync(
          fixturesFolderPath + 'snykTestsOutputs/test-unmonitored-goof.json',
        )
        .toString(),
      false,
      false,
    );

    const expectedResult = [
      {
        result: 1,
        newVulns: [
          {
            CVSSv3: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
            alternativeIds: [],
            creationTime: '2020-03-07T00:18:41.509507Z',
            credit: ['Peter van der Zee'],
            cvssScore: 7.5,
            description:
              '## Overview\n' +
              '\n' +
              '[acorn](https://github.com/acornjs/acorn) is a tiny, fast JavaScript parser written in JavaScript.\n' +
              '\n' +
              '\n' +
              'Affected versions of this package are vulnerable to Regular Expression Denial of Service (ReDoS)\n' +
              'via a regex in the form of `/[x-\\ud800]/u`, which causes the parser to enter an infinite loop. \r\n' +
              '\r\n' +
              'This string is not a valid `UTF16` and is therefore not sanitized before reaching the parser. An application which processes untrusted input and passes it directly to `acorn`, will allow attackers to leverage the vulnerability leading to a Denial of Service.\n' +
              '\n' +
              '## Details\n' +
              'Denial of Service (DoS) describes a family of attacks, all aimed at making a system inaccessible to its original and legitimate users. There are many types of DoS attacks, ranging from trying to clog the network pipes to the system by generating a large volume of traffic from many machines (a Distributed Denial of Service - DDoS - attack) to sending crafted requests that cause a system to crash or take a disproportional amount of time to process.\r\n' +
              '\r\n' +
              "The Regular expression Denial of Service (ReDoS) is a type of Denial of Service attack. Regular expressions are incredibly powerful, but they aren't very intuitive and can ultimately end up making it easy for attackers to take your site down.\r\n" +
              '\r\n' +
              'Let’s take the following regular expression as an example:\r\n' +
              '```js\r\n' +
              'regex = /A(B|C+)+D/\r\n' +
              '```\r\n' +
              '\r\n' +
              'This regular expression accomplishes the following:\r\n' +
              "- `A` The string must start with the letter 'A'\r\n" +
              "- `(B|C+)+` The string must then follow the letter A with either the letter 'B' or some number of occurrences of the letter 'C' (the `+` matches one or more times). The `+` at the end of this section states that we can look for one or more matches of this section.\r\n" +
              "- `D` Finally, we ensure this section of the string ends with a 'D'\r\n" +
              '\r\n' +
              'The expression would match inputs such as `ABBD`, `ABCCCCD`, `ABCBCCCD` and `ACCCCCD`\r\n' +
              '\r\n' +
              "It most cases, it doesn't take very long for a regex engine to find a match:\r\n" +
              '\r\n' +
              '```bash\r\n' +
              `$ time node -e '/A(B|C+)+D/.test("ACCCCCCCCCCCCCCCCCCCCCCCCCCCCD")'\r\n` +
              '0.04s user 0.01s system 95% cpu 0.052 total\r\n' +
              '\r\n' +
              `$ time node -e '/A(B|C+)+D/.test("ACCCCCCCCCCCCCCCCCCCCCCCCCCCCX")'\r\n` +
              '1.79s user 0.02s system 99% cpu 1.812 total\r\n' +
              '```\r\n' +
              '\r\n' +
              'The entire process of testing it against a 30 characters long string takes around ~52ms. But when given an invalid string, it takes nearly two seconds to complete the test, over ten times as long as it took to test a valid string. The dramatic difference is due to the way regular expressions get evaluated.\r\n' +
              '\r\n' +
              'Most Regex engines will work very similarly (with minor differences). The engine will match the first possible way to accept the current character and proceed to the next one. If it then fails to match the next one, it will backtrack and see if there was another way to digest the previous character. If it goes too far down the rabbit hole only to find out the string doesn’t match in the end, and if many characters have multiple valid regex paths, the number of backtracking steps can become very large, resulting in what is known as _catastrophic backtracking_.\r\n' +
              '\r\n' +
              `Let's look at how our expression runs into this problem, using a shorter string: "ACCCX". While it seems fairly straightforward, there are still four different ways that the engine could match those three C's:\r\n` +
              '1. CCC\r\n' +
              '2. CC+C\r\n' +
              '3. C+CC\r\n' +
              '4. C+C+C.\r\n' +
              '\r\n' +
              "The engine has to try each of those combinations to see if any of them potentially match against the expression. When you combine that with the other steps the engine must take, we can use [RegEx 101 debugger](https://regex101.com/debugger) to see the engine has to take a total of 38 steps before it can determine the string doesn't match.\r\n" +
              '\r\n' +
              'From there, the number of steps the engine must use to validate a string just continues to grow.\r\n' +
              '\r\n' +
              "| String | Number of C's | Number of steps |\r\n" +
              '| -------|-------------:| -----:|\r\n' +
              '| ACCCX | 3 | 38\r\n' +
              '| ACCCCX | 4 | 71\r\n' +
              '| ACCCCCX | 5 | 136\r\n' +
              '| ACCCCCCCCCCCCCCX | 14 | 65,553\r\n' +
              '\r\n' +
              '\r\n' +
              "By the time the string includes 14 C's, the engine has to take over 65,000 steps just to see if the string is valid. These extreme situations can cause them to work very slowly (exponentially related to input size, as shown above), allowing an attacker to exploit this and can cause the service to excessively consume CPU, resulting in a Denial of Service.\n" +
              '\n' +
              '## Remediation\n' +
              '\n' +
              'Upgrade `acorn` to version 5.7.4, 6.4.1, 7.1.1 or higher.\n' +
              '\n' +
              '\n' +
              '## References\n' +
              '\n' +
              '- [GitHub Commit](https://github.com/acornjs/acorn/commit/793c0e569ed1158672e3a40aeed1d8518832b802)\n' +
              '\n' +
              '- [GitHub Issue 6.x Branch](https://github.com/acornjs/acorn/issues/929)\n' +
              '\n' +
              '- [NPM Security Advisory](https://www.npmjs.com/advisories/1488)\n',
            disclosureTime: '2020-03-02T19:21:25Z',
            exploit: 'Not Defined',
            fixedIn: ['5.7.4', '6.4.1', '7.1.1'],
            functions: [],
            // eslint-disable-next-line @typescript-eslint/camelcase
            functions_new: [],
            id: 'SNYK-JS-ACORN-559469',
            identifiers: {
              CVE: [],
              CWE: ['CWE-400'],
              GHSA: ['GHSA-6chw-6frg-f759'],
              NSP: [1488],
            },
            language: 'js',
            modificationTime: '2020-03-10T10:19:13.616093Z',
            moduleName: 'acorn',
            packageManager: 'npm',
            packageName: 'acorn',
            patches: [],
            publicationTime: '2020-03-07T00:19:23Z',
            references: [
              {
                title: 'GitHub Commit',
                url:
                  'https://github.com/acornjs/acorn/commit/793c0e569ed1158672e3a40aeed1d8518832b802',
              },
              {
                title: 'GitHub Issue 6.x Branch',
                url: 'https://github.com/acornjs/acorn/issues/929',
              },
              {
                title: 'NPM Security Advisory',
                url: 'https://www.npmjs.com/advisories/1488',
              },
            ],
            semver: {
              vulnerable: [
                '>=5.5.0 <5.7.4',
                '>=6.0.0 <6.4.1',
                '>=7.0.0 <7.1.1',
              ],
            },
            severity: 'high',
            title: 'Regular Expression Denial of Service (ReDoS)',
            from: [
              'goof@0.0.3',
              '@snyk/nodejs-runtime-agent@1.14.0',
              'acorn@5.7.3',
            ],
            upgradePath: [
              false,
              '@snyk/nodejs-runtime-agent@1.14.0',
              'acorn@5.7.4',
            ],
            isUpgradable: true,
            isPatchable: false,
            name: 'acorn',
            version: '5.7.3',
          },
        ],
        newLicenseIssues: [
          {
            license: 'GPL-2.0',
            semver: {
              vulnerable: ['>=0'],
            },
            id: 'snyk:lic:npm:goof:GPL-2.0',
            type: 'license',
            packageManager: 'npm',
            language: 'js',
            packageName: 'goof',
            title: 'GPL-2.0 license',
            description: 'GPL-2.0 license',
            publicationTime: '2020-04-09T19:48:50.751Z',
            creationTime: '2020-04-09T19:48:50.751Z',
            patches: [],
            licenseTemplateUrl:
              'https://raw.githubusercontent.com/spdx/license-list/master/GPL-2.0.txt',
            severity: 'medium',
            from: ['goof@0.0.3'],
            upgradePath: [],
            isUpgradable: false,
            isPatchable: false,
            name: 'goof',
            version: '0.0.3',
          },
        ],
        passIfNoBaseline: false,
        noBaseline: true,
        projectNameOrId: 'unmonitored-goof',
      },
    ];

    expect(result).toEqual(expectedResult);
  });
});
