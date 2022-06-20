import {
  displayDependenciesChangeDetails,
  consolidateIndirectDepsPaths,
} from '../../../src/lib/snyk/dependencies';
import * as depgraph from '@snyk/dep-graph';
import * as fs from 'fs';
import * as path from 'path';
import * as _ from 'lodash';
import * as chalk from 'chalk';

const fixturesFolderPath = path.resolve(__dirname, '../..') + '/fixtures/';

const originalLog = console.log;
afterEach(() => (console.log = originalLog));
let consoleOutput: Array<string> = [];
const mockedLog = (output: string): void => {
  consoleOutput.push(output);
};
beforeEach(() => {
  console.log = mockedLog;
  consoleOutput = [];
});

describe('Test Snyk Utils make request properly', () => {
  it('Test consolidateIndirectDepsPaths', async () => {
    const addedIndirectDeps = JSON.parse(
      fs
        .readFileSync(
          fixturesFolderPath + 'dependencies/goof-indirect-deps.json',
        )
        .toString(),
    ).pkgs;
    const depGraphFromApi = JSON.parse(
      fs
        .readFileSync(
          fixturesFolderPath + 'dependencies/goof-depgraph-from-api.json',
        )
        .toString(),
    ).depGraph as depgraph.DepGraphData;
    const snykTestGraph = await depgraph.createFromJSON(depGraphFromApi);

    const consolidatedIndirectlyAddedDepsPaths = consolidateIndirectDepsPaths(
      addedIndirectDeps,
      snykTestGraph,
    );

    const fixture = new Map(
      JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'dependencies/goof-indirect-deps-consolidated.json',
          )
          .toString(),
      ),
    );
    expect(
      _.isEqual(fixture, consolidatedIndirectlyAddedDepsPaths),
    ).toBeTruthy();
  });

  it('Test displayDependenciesChangeDetails - no change', async () => {
    const snykTestJsonDependencies = JSON.parse(
      fs
        .readFileSync(fixturesFolderPath + 'goof-depgraph-from-api.json')
        .toString(),
    );
    const monitoredProjectDepGraph = JSON.parse(
      fs
        .readFileSync(fixturesFolderPath + 'goof-depgraph-from-api.json')
        .toString(),
    );
    await displayDependenciesChangeDetails(
      snykTestJsonDependencies,
      monitoredProjectDepGraph,
      'npm',
      [],
    );
    const expectedResult = [
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
    ];

    expect(consoleOutput).toEqual(expectedResult);
  });

  it('Test displayDependenciesChangeDetails - 1 direct dep added', async () => {
    const monitoredProjectDepGraph = JSON.parse(
      fs
        .readFileSync(
          fixturesFolderPath + 'dependencies/goof-depgraph-from-api.json',
        )
        .toString(),
    );
    const snykTestJsonDependencies = JSON.parse(
      fs
        .readFileSync(
          fixturesFolderPath +
            'dependencies/goof-depgraph-from-api-one-more-direct-dep.json',
        )
        .toString(),
    );
    await displayDependenciesChangeDetails(
      snykTestJsonDependencies,
      monitoredProjectDepGraph,
      'npm',
      [],
    );
    const expectedResult = [
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
    ];
    expect(consoleOutput).toEqual(expectedResult);
  });

  it('Test displayDependenciesChangeDetails - 1 direct dep and 1 transitive added', async () => {
    const monitoredProjectDepGraph = JSON.parse(
      fs
        .readFileSync(
          fixturesFolderPath + 'dependencies/goof-depgraph-from-api.json',
        )
        .toString(),
    );
    const snykTestJsonDependencies = JSON.parse(
      fs
        .readFileSync(
          fixturesFolderPath +
            'dependencies/goof-depgraph-from-api-one-more-direct-and-indirect-dep.json',
        )
        .toString(),
    );
    await displayDependenciesChangeDetails(
      snykTestJsonDependencies,
      monitoredProjectDepGraph,
      'npm',
      [],
    );
    const expectedResult = [
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
      '   added-indirectdep@1.0.0 no issue:\n' +
        chalk.blue('     added-dep@1.0.0=>added-indirectdep@1.0.0'),
      '===============',
      'Removed 0\n',
      '_____________________________',
    ];
    expect(consoleOutput).toEqual(expectedResult);
  });

  it('Test displayDependenciesChangeDetails - 1 direct dep and 1 transitive with vuln added ', async () => {
    const monitoredProjectDepGraph = JSON.parse(
      fs
        .readFileSync(
          fixturesFolderPath + 'dependencies/goof-depgraph-from-api.json',
        )
        .toString(),
    );
    const snykTestJsonDependencies = JSON.parse(
      fs
        .readFileSync(
          fixturesFolderPath +
            'dependencies/goof-depgraph-from-api-one-more-direct-and-indirect-dep.json',
        )
        .toString(),
    );

    const newVulns = [
      {
        CVSSv3: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
        alternativeIds: [],
        creationTime: '2020-03-07T00:18:41.509507Z',
        credit: ['Peter van der Zee'],
        cvssScore: 7.5,
        description:
          "## Overview\n\n[acorn](https://github.com/acornjs/acorn) is a tiny, fast JavaScript parser written in JavaScript.\n\n\nAffected versions of this package are vulnerable to Regular Expression Denial of Service (ReDoS)\nvia a regex in the form of `/[x-\\ud800]/u`, which causes the parser to enter an infinite loop. \r\n\r\nThis string is not a valid `UTF16` and is therefore not sanitized before reaching the parser. An application which processes untrusted input and passes it directly to `acorn`, will allow attackers to leverage the vulnerability leading to a Denial of Service.\n\n## Details\nDenial of Service (DoS) describes a family of attacks, all aimed at making a system inaccessible to its original and legitimate users. There are many types of DoS attacks, ranging from trying to clog the network pipes to the system by generating a large volume of traffic from many machines (a Distributed Denial of Service - DDoS - attack) to sending crafted requests that cause a system to crash or take a disproportional amount of time to process.\r\n\r\nThe Regular expression Denial of Service (ReDoS) is a type of Denial of Service attack. Regular expressions are incredibly powerful, but they aren't very intuitive and can ultimately end up making it easy for attackers to take your site down.\r\n\r\nLet’s take the following regular expression as an example:\r\n```js\r\nregex = /A(B|C+)+D/\r\n```\r\n\r\nThis regular expression accomplishes the following:\r\n- `A` The string must start with the letter 'A'\r\n- `(B|C+)+` The string must then follow the letter A with either the letter 'B' or some number of occurrences of the letter 'C' (the `+` matches one or more times). The `+` at the end of this section states that we can look for one or more matches of this section.\r\n- `D` Finally, we ensure this section of the string ends with a 'D'\r\n\r\nThe expression would match inputs such as `ABBD`, `ABCCCCD`, `ABCBCCCD` and `ACCCCCD`\r\n\r\nIt most cases, it doesn't take very long for a regex engine to find a match:\r\n\r\n```bash\r\n$ time node -e '/A(B|C+)+D/.test(\"ACCCCCCCCCCCCCCCCCCCCCCCCCCCCD\")'\r\n0.04s user 0.01s system 95% cpu 0.052 total\r\n\r\n$ time node -e '/A(B|C+)+D/.test(\"ACCCCCCCCCCCCCCCCCCCCCCCCCCCCX\")'\r\n1.79s user 0.02s system 99% cpu 1.812 total\r\n```\r\n\r\nThe entire process of testing it against a 30 characters long string takes around ~52ms. But when given an invalid string, it takes nearly two seconds to complete the test, over ten times as long as it took to test a valid string. The dramatic difference is due to the way regular expressions get evaluated.\r\n\r\nMost Regex engines will work very similarly (with minor differences). The engine will match the first possible way to accept the current character and proceed to the next one. If it then fails to match the next one, it will backtrack and see if there was another way to digest the previous character. If it goes too far down the rabbit hole only to find out the string doesn’t match in the end, and if many characters have multiple valid regex paths, the number of backtracking steps can become very large, resulting in what is known as _catastrophic backtracking_.\r\n\r\nLet's look at how our expression runs into this problem, using a shorter string: \"ACCCX\". While it seems fairly straightforward, there are still four different ways that the engine could match those three C's:\r\n1. CCC\r\n2. CC+C\r\n3. C+CC\r\n4. C+C+C.\r\n\r\nThe engine has to try each of those combinations to see if any of them potentially match against the expression. When you combine that with the other steps the engine must take, we can use [RegEx 101 debugger](https://regex101.com/debugger) to see the engine has to take a total of 38 steps before it can determine the string doesn't match.\r\n\r\nFrom there, the number of steps the engine must use to validate a string just continues to grow.\r\n\r\n| String | Number of C's | Number of steps |\r\n| -------|-------------:| -----:|\r\n| ACCCX | 3 | 38\r\n| ACCCCX | 4 | 71\r\n| ACCCCCX | 5 | 136\r\n| ACCCCCCCCCCCCCCX | 14 | 65,553\r\n\r\n\r\nBy the time the string includes 14 C's, the engine has to take over 65,000 steps just to see if the string is valid. These extreme situations can cause them to work very slowly (exponentially related to input size, as shown above), allowing an attacker to exploit this and can cause the service to excessively consume CPU, resulting in a Denial of Service.\n\n## Remediation\n\nUpgrade `acorn` to version 5.7.4, 6.4.1, 7.1.1 or higher.\n\n\n## References\n\n- [GitHub Commit](https://github.com/acornjs/acorn/commit/793c0e569ed1158672e3a40aeed1d8518832b802)\n\n- [GitHub Issue 6.x Branch](https://github.com/acornjs/acorn/issues/929)\n\n- [NPM Security Advisory](https://www.npmjs.com/advisories/1488)\n",
        disclosureTime: '2020-03-02T19:21:25Z',
        exploit: 'Not Defined',
        fixedIn: ['5.7.4', '6.4.1', '7.1.1'],
        functions: [],
        functions_new: [], // eslint-disable-line
        id: 'SNYK-JS-ACORN-559469',
        identifiers: {
          CVE: [],
          CWE: ['CWE-400'],
          GHSA: ['GHSA-6chw-6frg-f759'],
          NSP: [1488],
        },
        language: 'js',
        modificationTime: '2020-03-10T10:19:13.616093Z',
        moduleName: 'added-indirectdep',
        packageManager: 'npm',
        packageName: 'added-indirectdep',
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
          vulnerable: ['>=5.5.0 <5.7.4', '>=6.0.0 <6.4.1', '>=7.0.0 <7.1.1'],
        },
        severity: 'high',
        title: 'Regular Expression Denial of Service (ReDoS)',
        from: ['goof@0.0.3', 'added-dep@1.0.0', 'added-indirectdep@1.0.0'],
        upgradePath: [],
        isUpgradable: false,
        isPatchable: false,
        name: 'added-indirectdep',
        version: '1.0.0',
      },
    ];

    await displayDependenciesChangeDetails(
      snykTestJsonDependencies,
      monitoredProjectDepGraph,
      'npm',
      newVulns,
    );
    const expectedResult = [
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
      '   added-indirectdep@1.0.0 ' +
        chalk.redBright('1 issue') +
        ':\n' +
        chalk.redBright('     added-dep@1.0.0=>added-indirectdep@1.0.0'),
      '===============',
      'Removed 0\n',
      '_____________________________',
    ];
    expect(chalk.white(consoleOutput)).toEqual(chalk.white(expectedResult));
  });

  it('Test displayDependenciesChangeDetails - no change - Graph in different order', async () => {
    const snykTestJsonDependencies = JSON.parse(
      fs
        .readFileSync(fixturesFolderPath + 'dependencies/SnykTestDepgraph.json')
        .toString(),
    );
    const monitoredProjectDepGraph = JSON.parse(
      fs
        .readFileSync(
          fixturesFolderPath + 'dependencies/snykProjectGraphForDepsTest.json',
        )
        .toString(),
    );
    await displayDependenciesChangeDetails(
      snykTestJsonDependencies,
      monitoredProjectDepGraph,
      'npm',
      [],
    );
    const expectedResult = [
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
    ];

    expect(consoleOutput).toEqual(expectedResult);
  });

  it('Test displayDependenciesChangeDetails - one more deps change - Graph in different order', async () => {
    const snykTestJsonDependencies = JSON.parse(
      fs
        .readFileSync(
          fixturesFolderPath +
            'dependencies/SnykTestDepgraph-one-more-deps.json',
        )
        .toString(),
    );
    const monitoredProjectDepGraph = JSON.parse(
      fs
        .readFileSync(
          fixturesFolderPath + 'dependencies/snykProjectGraphForDepsTest.json',
        )
        .toString(),
    );
    await displayDependenciesChangeDetails(
      snykTestJsonDependencies,
      monitoredProjectDepGraph,
      'npm',
      [],
    );
    const expectedResult = [
      '_____________________________',
      'Direct deps:',
      'Added 1 \nadding-one-deps@1.0.0',
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
    ];

    expect(consoleOutput).toEqual(expectedResult);
  });
});
