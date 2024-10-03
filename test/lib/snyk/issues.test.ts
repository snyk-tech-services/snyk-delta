import * as path from 'path';
import * as fs from 'fs';
import nock from 'nock';

import {
  getNewIssues,
  getIssuesDetailsPerPackage,
} from '../../../src/lib/snyk/issues';
import {
  displayNewVulns,
  displayNewLicenseIssues,
} from '../../../src/lib/snyk/displayOutput';
import * as utils from '../../../src/lib/utils/utils';
import {
  SnykCliTestOutput,
  IssuesPostResponseType,
} from '../../../src/lib/types';
import { convertIntoIssueWithPath } from '../../../src/lib/utils/issuesUtils';

const fixturesFolderPath = path.resolve(__dirname, '../..') + '/fixtures/';

describe('Test issues functions', () => {
  beforeAll(() => {
    jest.resetAllMocks();
  });
  describe('Test getNewVulns', () => {
    it('Test getNewVulns - inline mode - no new vuln', async () => {
      utils.init();
      const snykProject = JSON.parse(
        fs
          .readFileSync(fixturesFolderPath + 'apiResponses/test-goof.json')
          .toString(),
      );
      const snykTestJsonResults: SnykCliTestOutput = JSON.parse(
        fs
          .readFileSync(fixturesFolderPath + 'snykTestsOutputs/test-goof.json')
          .toString(),
      );

      const newVulns = getNewIssues(
        snykProject.issues.vulnerabilities,
        snykTestJsonResults.vulnerabilities.filter((x) => x.type != 'license'),
        'low',
        'inline',
      );
      expect(newVulns.length).toEqual(0);
    });

    it('Test getNewVulns - inline mode - no new vuln - test arguments', async () => {
      const snykProject = JSON.parse(
        fs
          .readFileSync(fixturesFolderPath + 'apiResponses/test-goof.json')
          .toString(),
      );
      const snykTestJsonResults: SnykCliTestOutput = JSON.parse(
        fs
          .readFileSync(fixturesFolderPath + 'snykTestsOutputs/test-goof.json')
          .toString(),
      );

      const newVulns = getNewIssues(
        snykProject.issues.vulnerabilities,
        snykTestJsonResults.vulnerabilities.filter((x) => x.type != 'license'),
        'low',
        'inline',
      );
      expect(newVulns.length).toEqual(0);
    });

    it('Test getNewVulns - inline mode - 1 new vuln', async () => {
      utils.init();
      const snykProject = JSON.parse(
        fs
          .readFileSync(fixturesFolderPath + 'apiResponses/test-goof.json')
          .toString(),
      );
      const snykTestJsonResults: SnykCliTestOutput = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'snykTestsOutputs/test-goof-with-one-more-vuln.json',
          )
          .toString(),
      );
      const newVulns = getNewIssues(
        snykProject.issues.vulnerabilities,
        snykTestJsonResults.vulnerabilities.filter((x) => x.type != 'license'),
        'low',
        'inline',
      );
      expect(newVulns.length).toEqual(1);
    });
    it('Test getNewVulns - inline mode - 10 new vulns', async () => {
      utils.init();
      const snykProject = JSON.parse(
        fs
          .readFileSync(fixturesFolderPath + 'apiResponses/test-goof.json')
          .toString(),
      );
      const snykTestJsonResults: SnykCliTestOutput = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'snykTestsOutputs/test-goof-with-ten-more-vulns.json',
          )
          .toString(),
      );
      const newVulns = getNewIssues(
        snykProject.issues.vulnerabilities,
        snykTestJsonResults.vulnerabilities.filter((x) => x.type != 'license'),
        'low',
        'inline',
      );
      expect(newVulns.length).toEqual(10);
    });

    it('Test getNewVulns - standalone mode - no new vuln', async () => {
      utils.init();
      const snykBaselineProject = JSON.parse(
        fs
          .readFileSync(fixturesFolderPath + 'apiResponses/test-goof.json')
          .toString(),
      );
      const snykCurrentProject: IssuesPostResponseType = JSON.parse(
        fs
          .readFileSync(fixturesFolderPath + 'apiResponses/test-goof.json')
          .toString(),
      );
      const newVulns = getNewIssues(
        snykBaselineProject.issues.vulnerabilities,
        snykCurrentProject.issues.vulnerabilities,
        'low',
        'standalone',
      );
      expect(newVulns.length).toEqual(0);
    });

    it('Test getNewVulns - standalone mode - 1 new vuln', async () => {
      utils.init();
      const snykBaselineProject = JSON.parse(
        fs
          .readFileSync(fixturesFolderPath + 'apiResponses/test-goof.json')
          .toString(),
      );
      const snykCurrentProject: IssuesPostResponseType = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'apiResponses/test-goof-with-one-more-vuln.json',
          )
          .toString(),
      );
      const newVulns = getNewIssues(
        snykBaselineProject.issues.vulnerabilities,
        snykCurrentProject.issues.vulnerabilities,
        'low',
        'standalone',
      );
      expect(newVulns.length).toEqual(1);
    });

    it('Test getNewVulns - standalone mode - 10 new vulns', async () => {
      utils.init();
      const snykBaselineProject = JSON.parse(
        fs
          .readFileSync(fixturesFolderPath + 'apiResponses/test-goof.json')
          .toString(),
      );
      const snykCurrentProject: IssuesPostResponseType = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'apiResponses/test-goof-with-ten-more-vulns.json',
          )
          .toString(),
      );
      const newVulns = getNewIssues(
        snykBaselineProject.issues.vulnerabilities,
        snykCurrentProject.issues.vulnerabilities,
        'low',
        'standalone',
      );
      expect(newVulns.length).toEqual(10);
    });
  });

  describe('Test getNewLicenseIssues', () => {
    it('Test getNewLicenseIssues - inline mode - no new issue', async () => {
      utils.init();
      const snykProject = JSON.parse(
        fs
          .readFileSync(fixturesFolderPath + 'apiResponses/test-goof.json')
          .toString(),
      );
      const snykTestJsonResults: SnykCliTestOutput = JSON.parse(
        fs
          .readFileSync(fixturesFolderPath + 'snykTestsOutputs/test-goof.json')
          .toString(),
      );
      const newLicenseIssues = getNewIssues(
        snykProject.issues.licenses,
        snykTestJsonResults.vulnerabilities.filter((x) => x.type == 'license'),
        'low',
        'inline',
      );
      expect(newLicenseIssues.length).toEqual(0);
    });

    it('Test getNewLicenseIssues - inline mode - 1 new issue', async () => {
      utils.init();
      const snykProject = JSON.parse(
        fs
          .readFileSync(fixturesFolderPath + 'apiResponses/test-goof.json')
          .toString(),
      );
      const snykTestJsonResults: SnykCliTestOutput = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'snykTestsOutputs/test-goof-with-one-more-license-issue.json',
          )
          .toString(),
      );
      const newLicenseIssues = getNewIssues(
        snykProject.issues.licenses,
        snykTestJsonResults.vulnerabilities.filter((x) => x.type == 'license'),
        'low',
        'inline',
      );
      expect(newLicenseIssues.length).toEqual(1);
    });

    it('Test getNewLicenseIssues - inline mode - 2 new issues', async () => {
      utils.init();
      const snykProject = JSON.parse(
        fs
          .readFileSync(fixturesFolderPath + 'apiResponses/test-goof.json')
          .toString(),
      );
      const snykTestJsonResults: SnykCliTestOutput = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'snykTestsOutputs/test-goof-with-two-more-license-issues.json',
          )
          .toString(),
      );
      const newLicenseIssues = getNewIssues(
        snykProject.issues.licenses,
        snykTestJsonResults.vulnerabilities.filter((x) => x.type == 'license'),
        'low',
        'inline',
      );
      expect(newLicenseIssues.length).toEqual(2);
    });

    it('Test getNewLicenseIssues - standalone mode - no new issue', async () => {
      utils.init();
      const snykBaselineProject = JSON.parse(
        fs
          .readFileSync(fixturesFolderPath + 'apiResponses/test-goof.json')
          .toString(),
      );
      const snykCurrentProject: IssuesPostResponseType = JSON.parse(
        fs
          .readFileSync(fixturesFolderPath + 'apiResponses/test-goof.json')
          .toString(),
      );
      const newLicenseIssues = getNewIssues(
        snykBaselineProject.issues.licenses,
        snykCurrentProject.issues.licenses,
        'low',
        'standalone',
      );
      expect(newLicenseIssues.length).toEqual(0);
    });

    it('Test getNewLicenseIssues - standalone mode - 1 new issue', async () => {
      utils.init();
      const snykBaselineProject = JSON.parse(
        fs
          .readFileSync(fixturesFolderPath + 'apiResponses/test-goof.json')
          .toString(),
      );
      const snykCurrentProject: IssuesPostResponseType = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'apiResponses/test-goof-with-one-more-license-issue.json',
          )
          .toString(),
      );

      const newLicenseIssues = getNewIssues(
        snykBaselineProject.issues.licenses,
        snykCurrentProject.issues.licenses,
        'low',
        'standalone',
      );
      expect(newLicenseIssues.length).toEqual(1);
    });

    it('Test getNewLicenseIssues - standalone mode - 2 new issues', async () => {
      utils.init();
      const snykBaselineProject = JSON.parse(
        fs
          .readFileSync(fixturesFolderPath + 'apiResponses/test-goof.json')
          .toString(),
      );
      const snykCurrentProject: IssuesPostResponseType = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'apiResponses/test-goof-with-two-more-license-issues.json',
          )
          .toString(),
      );
      const newLicenseIssues = getNewIssues(
        snykBaselineProject.issues.licenses,
        snykCurrentProject.issues.licenses,
        'low',
        'standalone',
      );
      expect(newLicenseIssues.length).toEqual(2);
    });
  });

  describe('Test displayNewVulns', () => {
    const originalLog = console.log;
    afterEach(() => (console.log = originalLog));
    let consoleOutput: Array<string> = [];
    const mockedLog = (output: string): void => {
      consoleOutput.push(output);
    };
    beforeEach((): void => {
      console.log = mockedLog;
      consoleOutput = [];
    });

    it('Test displayNewVulns - inline mode - no new vuln', async () => {
      displayNewVulns([], 'inline');
      expect(consoleOutput).toEqual([]);
    });

    it('Test displayNewVulns - inline mode - 1 new vuln', async () => {
      utils.init();
      const snykProject = JSON.parse(
        fs
          .readFileSync(fixturesFolderPath + 'apiResponses/test-goof.json')
          .toString(),
      );
      const snykTestJsonResults: SnykCliTestOutput = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'snykTestsOutputs/test-goof-with-one-more-vuln.json',
          )
          .toString(),
      );
      const newVulns = getNewIssues(
        snykProject.issues.vulnerabilities,
        snykTestJsonResults.vulnerabilities.filter((x) => x.type != 'license'),
        'low',
        'inline',
      );
      displayNewVulns(newVulns, 'inline');

      const expectedOutput = [
        'New issue introduced !',
        'Security Vulnerability:',
        '1/1: SNYK-JS-ACORN-559469:Regular Expression Denial of Service (ReDoS) [High Severity][cvssScore: 7.5]',
        'Via: express-fileupload@0.0.5 => @snyk/nodejs-runtime-agent@1.14.0 => acorn@5.7.3',
        'Fixed in: acorn 5.7.4, 6.4.1, 7.1.1',
        'Fixable by upgrade:  @snyk/nodejs-runtime-agent@1.14.0=>acorn@5.7.4',
      ];

      expectedOutput.forEach((line) => {
        expect(consoleOutput.join()).toContain(line);
      });
    });

    it('Test displayNewVulns - inline mode - 10 new vulns', async () => {
      utils.init();
      const snykProject = JSON.parse(
        fs
          .readFileSync(fixturesFolderPath + 'apiResponses/test-goof.json')
          .toString(),
      );
      const snykTestJsonResults: SnykCliTestOutput = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'snykTestsOutputs/test-goof-with-ten-more-vulns.json',
          )
          .toString(),
      );
      const newVulns = getNewIssues(
        snykProject.issues.vulnerabilities,
        snykTestJsonResults.vulnerabilities.filter((x) => x.type != 'license'),
        'low',
        'inline',
      );
      displayNewVulns(newVulns, 'inline');

      const expectedOutput = [
        'New issues introduced !',
        'Security Vulnerabilities:',
        '1/10: SNYK-JS-ACORN-559469:Regular Expression Denial of Service (ReDoS) [Medium Severity][cvssScore: 7.5]',
        'Via: express-fileupload@0.0.5 => whatevermodule@1.0.0 => @snyk/nodejs-runtime-agent@1.14.0 => acorn@5.7.3',
        'Fixed in: acorn 5.7.4, 6.4.1, 7.1.1',
        'Fixable by upgrade:  @snyk/nodejs-runtime-agent@1.14.0=>acorn@5.7.4',
        '2/10: SNYK-JS-ACORN-559469:Regular Expression Denial of Service (ReDoS) [Low Severity][cvssScore: 7.5]',
        'Via: whatevermodule@2.0.0 => express-fileupload@0.0.5 => @snyk/nodejs-runtime-agent@1.14.0 => acorn@5.7.3',
        'Fixed in: acorn 5.7.4, 6.4.1, 7.1.1',
        'Fixable by upgrade:  @snyk/nodejs-runtime-agent@1.14.0=>acorn@5.7.4',
        '3/10: SNYK-JS-ACORN-559469:Regular Expression Denial of Service (ReDoS) [High Severity][cvssScore: 7.5]',
        'Via: whatevermodule@3.0.0 => express-fileupload@0.0.5 => @snyk/nodejs-runtime-agent@1.14.0 => acorn@5.7.3',
        'Fixed in: acorn 5.7.4, 6.4.1, 7.1.1',
        'Fixable by upgrade:  @snyk/nodejs-runtime-agent@1.14.0=>acorn@5.7.4',
        '4/10: SNYK-JS-ACORN-559469:Regular Expression Denial of Service (ReDoS) [High Severity][cvssScore: 7.5]',
        'Via: whatevermodule@4.0.0 => express-fileupload@0.0.5 => @snyk/nodejs-runtime-agent@1.14.0 => acorn@5.7.3',
        'Fixed in: acorn 5.7.4, 6.4.1, 7.1.1',
        'Fixable by upgrade:  @snyk/nodejs-runtime-agent@1.14.0=>acorn@5.7.4',
        '5/10: SNYK-JS-ACORN-559469:Regular Expression Denial of Service (ReDoS) [High Severity][cvssScore: 7.5]',
        'Via: whatevermodule@5.0.0 => express-fileupload@0.0.5 => @snyk/nodejs-runtime-agent@1.14.0 => acorn@5.7.3',
        'Fixed in: acorn 5.7.4, 6.4.1, 7.1.1',
        'Fixable by upgrade:  @snyk/nodejs-runtime-agent@1.14.0=>acorn@5.7.4',
        '6/10: SNYK-JS-ACORN-559469:Regular Expression Denial of Service (ReDoS) [High Severity][cvssScore: 7.5]',
        'Via: whatevermodule@6.0.0 => express-fileupload@0.0.5 => @snyk/nodejs-runtime-agent@1.14.0 => acorn@5.7.3',
        'Fixed in: acorn 5.7.4, 6.4.1, 7.1.1',
        'Fixable by upgrade:  @snyk/nodejs-runtime-agent@1.14.0=>acorn@5.7.4',
        '7/10: SNYK-JS-ACORN-559469:Regular Expression Denial of Service (ReDoS) [High Severity][cvssScore: 7.5]',
        'Via: whatevermodule@7.0.0 => express-fileupload@0.0.5 => @snyk/nodejs-runtime-agent@1.14.0 => acorn@5.7.3',
        'Fixed in: acorn 5.7.4, 6.4.1, 7.1.1',
        'Fixable by upgrade:  @snyk/nodejs-runtime-agent@1.14.0=>acorn@5.7.4',
        '8/10: SNYK-JS-ACORN-559469:Regular Expression Denial of Service (ReDoS) [High Severity][cvssScore: 7.5]',
        'Via: whatevermodule@8.0.0 => express-fileupload@0.0.5 => @snyk/nodejs-runtime-agent@1.14.0 => acorn@5.7.3',
        'Fixed in: acorn 5.7.4, 6.4.1, 7.1.1',
        'Fixable by upgrade:  @snyk/nodejs-runtime-agent@1.14.0=>acorn@5.7.4',
        '9/10: SNYK-JS-ACORN-559469:Regular Expression Denial of Service (ReDoS) [High Severity][cvssScore: 7.5]',
        'Via: whatevermodule@9.0.0 => express-fileupload@0.0.5 => @snyk/nodejs-runtime-agent@1.14.0 => acorn@5.7.3',
        'Fixed in: acorn 5.7.4, 6.4.1, 7.1.1',
        'Fixable by upgrade:  @snyk/nodejs-runtime-agent@1.14.0=>acorn@5.7.4',
        '10/10: SNYK-JS-ACORN-559469:Regular Expression Denial of Service (ReDoS) [High Severity][cvssScore: 7.5]',
        'Via: whatevermodule@10.0.0 => express-fileupload@0.0.5 => @snyk/nodejs-runtime-agent@1.14.0 => acorn@5.7.3',
        'Fixed in: acorn 5.7.4, 6.4.1, 7.1.1',
        'Fixable by upgrade:  @snyk/nodejs-runtime-agent@1.14.0=>acorn@5.7.4',
      ];

      expectedOutput.forEach((line) => {
        expect(consoleOutput.join()).toContain(line);
      });
    });

    it('Test displayNewVulns - standalone mode - no new vuln', async () => {
      displayNewVulns([], 'standalone');
      expect(consoleOutput).toEqual([]);
    });

    it('Test displayNewVulns - standalone mode - 1 new vuln', async () => {
      utils.init();
      const snykBaselineProject = JSON.parse(
        fs
          .readFileSync(fixturesFolderPath + 'apiResponses/test-goof.json')
          .toString(),
      );
      const snykCurrentProject: IssuesPostResponseType = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'apiResponses/test-goof-with-one-more-vuln.json',
          )
          .toString(),
      );

      const newVulns = getNewIssues(
        snykBaselineProject.issues.vulnerabilities,
        snykCurrentProject.issues.vulnerabilities,
        'low',
        'standalone',
      );
      displayNewVulns(newVulns, 'standalone');

      const expectedOutput = [
        'New issue introduced !',
        'Security Vulnerability:',
        '1/1: npm:ejs:20161130-1:Denial of Service (DoS) [Medium Severity][cvssScore: 5.9]',
        'Via: ms@1.0.0 => ejs-locals@1.0.2 => ejs@0.8.8',
      ];

      expectedOutput.forEach((line) => {
        expect(consoleOutput.join()).toContain(line);
      });
    });

    it('Test displayNewVulns - standalone mode - 10 new vulns', async () => {
      utils.init();
      const snykBaselineProject = JSON.parse(
        fs
          .readFileSync(fixturesFolderPath + 'apiResponses/test-goof.json')
          .toString(),
      );
      const snykCurrentProject: IssuesPostResponseType = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'apiResponses/test-goof-with-ten-more-vulns.json',
          )
          .toString(),
      );
      const newVulns = getNewIssues(
        snykBaselineProject.issues.vulnerabilities,
        snykCurrentProject.issues.vulnerabilities,
        'low',
        'standalone',
      );
      displayNewVulns(newVulns, 'standalone');

      const expectedOutput = [
        'New issues introduced !',
        'Security Vulnerabilities:',
        '1/10: npm:ejs:20161130-1:Denial of Service (DoS) [Medium Severity][cvssScore: 5.9]',
        'Via: ms@1.0.0 => ejs-locals@1.0.2 => ejs@0.8.8',
        '2/10: npm:ejs:20161130-1:Denial of Service (DoS) [Medium Severity][cvssScore: 5.9]',
        'Via: ms@1.1.0 => ejs-locals@1.0.2 => ejs@0.8.8',
        '3/10: npm:ejs:20161130-1:Denial of Service (DoS) [Medium Severity][cvssScore: 5.9]',
        'Via: ms@1.2.0 => ejs-locals@1.0.2 => ejs@0.8.8',
        '4/10: npm:ejs:20161130-1:Denial of Service (DoS) [Medium Severity][cvssScore: 5.9]',
        'Via: ms@1.4.0 => ejs-locals@1.0.2 => ejs@0.8.8',
        '5/10: npm:ejs:20161130-1:Denial of Service (DoS) [Medium Severity][cvssScore: 5.9]',
        'Via: ms@1.5.0 => ejs-locals@1.0.2 => ejs@0.8.8',
        '6/10: npm:ejs:20161130-1:Denial of Service (DoS) [Medium Severity][cvssScore: 5.9]',
        'Via: ms@1.6.0 => ejs-locals@1.0.2 => ejs@0.8.8',
        '7/10: npm:ejs:20161130-1:Denial of Service (DoS) [Medium Severity][cvssScore: 5.9]',
        'Via: ms@1.7.0 => ejs-locals@1.0.2 => ejs@0.8.8',
        '8/10: npm:ejs:20161130-1:Denial of Service (DoS) [Medium Severity][cvssScore: 5.9]',
        'Via: ms@1.8.0 => ejs-locals@1.0.2 => ejs@0.8.8',
        '9/10: npm:ejs:20161130-1:Denial of Service (DoS) [Medium Severity][cvssScore: 5.9]',
        'Via: ms@1.9.0 => ejs-locals@1.0.2 => ejs@0.8.8',
        '10/10: npm:ejs:20161130-1:Denial of Service (DoS) [Medium Severity][cvssScore: 5.9]',
        'Via: ms@1.10.0 => ejs-locals@1.0.2 => ejs@0.8.8',
      ];

      expectedOutput.forEach((line) => {
        expect(consoleOutput.join()).toContain(line);
      });
    });
  });

  describe('Test displayNewLicenseIssues', () => {
    const originalLog = console.log;
    afterEach(() => (console.log = originalLog));
    let consoleOutput: Array<string> = [];
    const mockedLog = (output: string): void => {
      consoleOutput.push(output);
    };
    beforeEach((): void => {
      console.log = mockedLog;
      consoleOutput = [];
    });
    it('Test getNewLicenseIssues - inline mode - no new issue', async () => {
      displayNewLicenseIssues([], 'inline');
      expect(consoleOutput).toEqual([]);
    });

    it('Test displayNewLicenseIssues - inline mode - 1 new issue', async () => {
      utils.init();
      const snykProject = JSON.parse(
        fs
          .readFileSync(fixturesFolderPath + 'apiResponses/test-goof.json')
          .toString(),
      );
      const snykTestJsonResults: SnykCliTestOutput = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'snykTestsOutputs/test-goof-with-one-more-license-issue.json',
          )
          .toString(),
      );

      const newLicenseIssues = getNewIssues(
        snykProject.issues.licenses,
        snykTestJsonResults.vulnerabilities.filter((x) => x.type == 'license'),
        'low',
        'inline',
      );
      displayNewLicenseIssues(newLicenseIssues, 'inline');

      const expectedOutput = [
        'New issue introduced !',
        'License Issue:',
        '1/1: GPL-2.0 license [Medium Severity]',
        'Via: whatever@1.0.0',
      ];
      expectedOutput.forEach((line) => {
        expect(consoleOutput.join()).toContain(line);
      });
    });

    it('Test displayNewLicenseIssues - standalone mode - no new issue', async () => {
      displayNewLicenseIssues([], 'standalone');
      expect(consoleOutput).toEqual([]);
    });

    it('Test displayNewLicenseIssues - standalone mode - 1 new issue', async () => {
      utils.init();
      const snykBaselineProject = JSON.parse(
        fs
          .readFileSync(fixturesFolderPath + 'apiResponses/test-goof.json')
          .toString(),
      );
      const snykCurrentProject: IssuesPostResponseType = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'apiResponses/test-goof-with-one-more-license-issue.json',
          )
          .toString(),
      );

      const newLicenseIssues = getNewIssues(
        snykBaselineProject.issues.licenses,
        snykCurrentProject.issues.licenses,
        'low',
        'standalone',
      );

      displayNewLicenseIssues(newLicenseIssues, 'standalone');
      const expectedOutput = [
        'New issue introduced !',
        'License Issue:',
        '1/1: GPL-2.0 license [High Severity]',
        'Via: whatever@1.0.0',
      ];
      expectedOutput.forEach((line) => {
        expect(consoleOutput.join()).toContain(line);
      });
    });
  });

  describe('Test getIssuesDetailsPerPackage', () => {
    it('Test getIssuesDetailsPerPackage - no package version', async () => {
      utils.init();
      const snykProject = JSON.parse(
        fs
          .readFileSync(fixturesFolderPath + 'apiResponses/test-goof.json')
          .toString(),
      );
      const snykTestJsonResults: SnykCliTestOutput = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'snykTestsOutputs/test-goof-with-one-more-vuln.json',
          )
          .toString(),
      );
      const newVulns = getNewIssues(
        snykProject.issues.vulnerabilities,
        snykTestJsonResults.vulnerabilities.filter((x) => x.type != 'license'),
        'low',
        'inline',
      );
      const output = getIssuesDetailsPerPackage(newVulns, 'package');
      expect(output).toEqual([]);
    });
    it('Test getIssuesDetailsPerPackage - no issue for that package', async () => {
      utils.init();
      const snykProject = JSON.parse(
        fs
          .readFileSync(fixturesFolderPath + 'apiResponses/test-goof.json')
          .toString(),
      );
      const snykTestJsonResults: SnykCliTestOutput = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'snykTestsOutputs/test-goof-with-one-more-vuln.json',
          )
          .toString(),
      );
      const newVulns = getNewIssues(
        snykProject.issues.vulnerabilities,
        snykTestJsonResults.vulnerabilities.filter((x) => x.type != 'license'),
        'low',
        'inline',
      );
      const output = getIssuesDetailsPerPackage(newVulns, 'package', '1.0.0');
      expect(output).toEqual([]);
    });
    it('Test getIssuesDetailsPerPackage - 1 new issue', async () => {
      utils.init();
      const snykProject = JSON.parse(
        fs
          .readFileSync(fixturesFolderPath + 'apiResponses/test-goof.json')
          .toString(),
      );
      const snykTestJsonResults: SnykCliTestOutput = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'snykTestsOutputs/test-goof-with-one-more-vuln.json',
          )
          .toString(),
      );
      const newVulns = getNewIssues(
        snykProject.issues.vulnerabilities,
        snykTestJsonResults.vulnerabilities.filter((x) => x.type != 'license'),
        'low',
        'inline',
      );
      const output = getIssuesDetailsPerPackage(newVulns, 'acorn', '5.7.3');
      const issueDetailsForPackage = newVulns[0];
      expect(output).toEqual([issueDetailsForPackage]);
    });
  });

  describe('Test convertIntoIssueWithPath', () => {
    it('Test convertIntoIssueWithPath - one issue (1 vuln, 0 license) - one path', async () => {
      // eslint-disable-next-line
      nock('https://snyk.io')
        .persist()
        .get(/.*/)
        .reply(200, (uri) => {
          switch (uri) {
            case '/api/v1/org/123/project/123/issue/SNYK-JS-ACORN-559469/paths?perPage=100&page=1':
              return fs.readFileSync(
                fixturesFolderPath +
                  'apiResponses/SNYK-JS-ACORN-559469-issue-paths.json',
              );
            default:
          }
        });

      const aggregatedIssues = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'apiResponses/test-goof-aggregated-one-vuln.json',
          )
          .toString(),
      );

      const legacyIssue = await convertIntoIssueWithPath(
        aggregatedIssues,
        '123',
        '123',
      );

      //  Expecting 1 vulnerabilities
      //SNYK-JS-ACORN-559469
      // path ["@snyk/nodejs-runtime-agent@1.14.0", "acorn@5.7.3"]

      expect(legacyIssue).toMatchSnapshot();
      legacyIssue.issues.vulnerabilities.forEach((vuln) => {
        expect(vuln['from'].length).toBeGreaterThan(0);
      });
      nock.cleanAll();
    });

    it('Test convertIntoIssueWithPath - 3 issues (3 vuln, 0 license) - 3 paths', async () => {
      // eslint-disable-next-line
      nock('https://snyk.io')
        .persist()
        .get(/.*/)
        .reply(200, (uri) => {
          switch (uri) {
            case '/api/v1/org/123/project/123/issue/SNYK-JS-ACORN-559469/paths?perPage=100&page=1':
              return fs.readFileSync(
                fixturesFolderPath +
                  'apiResponses/SNYK-JS-ACORN-559469-issue-paths.json',
              );
            case '/api/v1/org/123/project/123/issue/SNYK-JS-DOTPROP-543489/paths?perPage=100&page=1':
              return fs.readFileSync(
                fixturesFolderPath +
                  'apiResponses/SNYK-JS-DOTPROP-543489-issue-paths-page1.json',
              );
            default:
          }
        });

      const aggregatedIssues = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'apiResponses/test-goof-aggregated-two-vuln-no-license.json',
          )
          .toString(),
      );

      const legacyIssue = await convertIntoIssueWithPath(
        aggregatedIssues,
        '123',
        '123',
      );

      //  Expecting 3 vulnerabilities
      //SNYK-JS-ACORN-559469
      // path ["@snyk/nodejs-runtime-agent@1.14.0", "acorn@5.7.3"]
      // SNYK-JS-DOTPROP-543489
      //path ["snyk@1.228.3", "configstore@3.1.2", "dot-prop@4.2.0"],
      //upgradePath ["snyk@1.228.3"]
      // SNYK-JS-DOTPROP-543489
      //path ["snyk@1.228.3", "update-notifier@2.5.0", "configstore@3.1.2","dot-prop@4.2.0"]
      //upgradePath ["snyk@1.228.3"]

      expect(legacyIssue).toMatchSnapshot();
      legacyIssue.issues.vulnerabilities.forEach((vuln) => {
        expect(vuln['from'].length).toBeGreaterThan(0);
      });
      nock.cleanAll();
    });

    it('Test convertIntoIssueWithPath - 4 issues (3 vuln, 1 license) - 4 paths', async () => {
      // eslint-disable-next-line
      nock('https://snyk.io')
        .persist()
        .get(/.*/)
        .reply(200, (uri) => {
          switch (uri) {
            case '/api/v1/org/123/project/123/issue/SNYK-JS-PACRESOLVER-1564857/paths?perPage=100&page=1':
              return fs.readFileSync(
                fixturesFolderPath +
                  'apiResponses/SNYK-JS-ACORN-559469-issue-paths.json',
              );
            case '/api/v1/org/123/project/123/issue/SNYK-JS-DOTPROP-543489/paths?perPage=100&page=1':
              return fs.readFileSync(
                fixturesFolderPath +
                  'apiResponses/SNYK-JS-DOTPROP-543489-issue-paths-page1.json',
              );
            case '/api/v1/org/123/project/123/issue/snyk:lic:npm:goof:GPL-2.0/paths?perPage=100&page=1':
              return fs.readFileSync(
                fixturesFolderPath +
                  'apiResponses/snyk-lic-npm-goof-GPL-2-0-issue-paths.json',
              );
            default:
          }
        });

      const aggregatedIssues = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'apiResponses/test-goof-aggregated-two-vuln-one-license.json',
          )
          .toString(),
      );

      const legacyIssue = await convertIntoIssueWithPath(
        aggregatedIssues,
        '123',
        '123',
      );

      //  Expecting 3 vulnerabilities
      //SNYK-JS-PACRESOLVER-1564857
      // path ["@snyk/nodejs-runtime-agent@1.14.0", "acorn@5.7.3"]
      // SNYK-JS-DOTPROP-543489
      //path ["snyk@1.228.3", "configstore@3.1.2", "dot-prop@4.2.0"],
      //upgradePath ["snyk@1.228.3"]
      // SNYK-JS-DOTPROP-543489
      //path ["snyk@1.228.3", "update-notifier@2.5.0", "configstore@3.1.2","dot-prop@4.2.0"]
      // upgradePath ["snyk@1.228.3"]
      // snyk:lic:npm:goof:GPL-2.0
      // path ["goof@0.0.3"]

      expect(legacyIssue).toMatchSnapshot();
      legacyIssue.issues.vulnerabilities.forEach((vuln) => {
        expect(vuln['from'].length).toBeGreaterThan(0);
      });
      nock.cleanAll();
    });

    it('Test convertIntoIssueWithPath - 1 issue (0 vuln, 1 license) ', async () => {
      // eslint-disable-next-line
      nock('https://snyk.io')
        .persist()
        .get(/.*/)
        .reply(200, (uri) => {
          switch (uri) {
            case '/api/v1/org/123/project/123/issue/snyk:lic:npm:goof:GPL-2.0/paths?perPage=100&page=1':
              return fs.readFileSync(
                fixturesFolderPath +
                  'apiResponses/snyk-lic-npm-goof-GPL-2-0-issue-paths.json',
              );
            default:
          }
        });

      const aggregatedIssues = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'apiResponses/test-goof-aggregated-one-license.json',
          )
          .toString(),
      );

      const legacyIssue = await convertIntoIssueWithPath(
        aggregatedIssues,
        '123',
        '123',
      );

      //  Expecting 1 licenses
      // snyk:lic:npm:goof:GPL-2.0
      // path ["goof@0.0.3"]

      expect(legacyIssue).toMatchSnapshot();
      legacyIssue.issues.vulnerabilities.forEach((vuln) => {
        expect(vuln['from'].length).toBeGreaterThan(0);
      });
      nock.cleanAll();
    });

    it('Test convertIntoIssueWithPath - test pagination ', async () => {
      // eslint-disable-next-line
      nock('https://snyk.io')
        .persist()
        .get(/.*/)
        .reply(200, (uri) => {
          switch (uri) {
            case '/api/v1/org/123/project/123/issue/SNYK-JS-DOTPROP-543489/paths?perPage=100&page=1':
              return fs.readFileSync(
                fixturesFolderPath +
                  'apiResponses/SNYK-JS-DOTPROP-543489-issue-paths-page2.json',
              );
            case '/api/v1/org/123/project/123/issue/SNYK-JS-DOTPROP-543489/paths?perPage=100&page=2':
              return fs.readFileSync(
                fixturesFolderPath +
                  'apiResponses/SNYK-JS-DOTPROP-543489-issue-paths-page1.json',
              );
            default:
          }
        });

      const aggregatedIssues = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'apiResponses/test-goof-aggregated-one-vuln-pagination.json',
          )
          .toString(),
      );

      const legacyIssue = await convertIntoIssueWithPath(
        aggregatedIssues,
        '123',
        '123',
      );

      expect(legacyIssue.issues.vulnerabilities.length).toEqual(102);
      legacyIssue.issues.vulnerabilities.forEach((vuln) => {
        expect(vuln['from'].length).toBeGreaterThan(0);
      });
      expect(legacyIssue).toMatchSnapshot();
      nock.cleanAll();
    });
  });
});
