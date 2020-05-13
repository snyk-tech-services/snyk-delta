import {
  getNewVulns,
  getNewLicenseIssues,
  displayNewVulns,
  displayNewLicenseIssues,
  getIssuesDetailsPerPackage,
} from '../../../src/lib/snyk/issues';
import * as path from 'path';
import * as fs from 'fs';
import * as utils from '../../../src/lib/utils/utils';

const fixturesFolderPath = path.resolve(__dirname, '../..') + '/fixtures/';

describe('Test issues functions', () => {
  describe('Test getNewVulns', () => {
    it('Test getNewVulns - inline mode - no new vuln', async () => {
      utils.init();
      const snykProject = JSON.parse(
        fs
          .readFileSync(fixturesFolderPath + 'apiResponses/test-goof.json')
          .toString(),
      );
      const snykTestJsonResults = JSON.parse(
        fs
          .readFileSync(fixturesFolderPath + 'snykTestsOutputs/test-goof.json')
          .toString(),
      );
      // eslint-disable-next-line
      const newVulns: Array<any> = getNewVulns(
        snykProject,
        snykTestJsonResults,
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
      const snykTestJsonResults = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'snykTestsOutputs/test-goof-with-one-more-vuln.json',
          )
          .toString(),
      );
      // eslint-disable-next-line
      const newVulns: Array<any> = getNewVulns(
        snykProject,
        snykTestJsonResults,
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
      const snykTestJsonResults = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'snykTestsOutputs/test-goof-with-ten-more-vulns.json',
          )
          .toString(),
      );
      // eslint-disable-next-line
      const newVulns: Array<any> = getNewVulns(
        snykProject,
        snykTestJsonResults,
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
      const snykCurrentProject = JSON.parse(
        fs
          .readFileSync(fixturesFolderPath + 'apiResponses/test-goof.json')
          .toString(),
      );
      // eslint-disable-next-line
      const newVulns: Array<any> = getNewVulns(
        snykBaselineProject,
        snykCurrentProject.issues,
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
      const snykCurrentProject = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'apiResponses/test-goof-with-one-more-vuln.json',
          )
          .toString(),
      );
      // eslint-disable-next-line
      const newVulns: Array<any> = getNewVulns(
        snykBaselineProject,
        snykCurrentProject.issues,
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
      const snykCurrentProject = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'apiResponses/test-goof-with-ten-more-vulns.json',
          )
          .toString(),
      );
      // eslint-disable-next-line
      const newVulns: Array<any> = getNewVulns(
        snykBaselineProject,
        snykCurrentProject.issues,
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
      const snykTestJsonResults = JSON.parse(
        fs
          .readFileSync(fixturesFolderPath + 'snykTestsOutputs/test-goof.json')
          .toString(),
      );
      // eslint-disable-next-line
      const newLicenseIssues: Array<any> = getNewLicenseIssues(
        snykProject,
        snykTestJsonResults,
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
      const snykTestJsonResults = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'snykTestsOutputs/test-goof-with-one-more-license-issue.json',
          )
          .toString(),
      );
      // eslint-disable-next-line
      const newLicenseIssues: Array<any> = getNewLicenseIssues(
        snykProject,
        snykTestJsonResults,
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
      const snykTestJsonResults = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'snykTestsOutputs/test-goof-with-two-more-license-issues.json',
          )
          .toString(),
      );
      // eslint-disable-next-line
      const newLicenseIssues: Array<any> = getNewLicenseIssues(
        snykProject,
        snykTestJsonResults,
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
      const snykCurrentProject = JSON.parse(
        fs
          .readFileSync(fixturesFolderPath + 'apiResponses/test-goof.json')
          .toString(),
      );
      // eslint-disable-next-line
      const newLicenseIssues: Array<any> = getNewLicenseIssues(
        snykBaselineProject,
        snykCurrentProject.issues,
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
      const snykCurrentProject = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'apiResponses/test-goof-with-one-more-license-issue.json',
          )
          .toString(),
      );
      // eslint-disable-next-line
      const newLicenseIssues: Array<any> = getNewLicenseIssues(
        snykBaselineProject,
        snykCurrentProject.issues,
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
      const snykCurrentProject = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'apiResponses/test-goof-with-two-more-license-issues.json',
          )
          .toString(),
      );
      // eslint-disable-next-line
      const newLicenseIssues: Array<any> = getNewLicenseIssues(
        snykBaselineProject,
        snykCurrentProject.issues,
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
      // eslint-disable-next-line
      const newVulns: Array<any> = [];
      displayNewVulns(newVulns, 'inline');
      expect(consoleOutput).toEqual([]);
    });

    it('Test displayNewVulns - inline mode - 1 new vuln', async () => {
      utils.init();
      const snykProject = JSON.parse(
        fs
          .readFileSync(fixturesFolderPath + 'apiResponses/test-goof.json')
          .toString(),
      );
      const snykTestJsonResults = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'snykTestsOutputs/test-goof-with-one-more-vuln.json',
          )
          .toString(),
      );
      // eslint-disable-next-line
      const newVulns: Array<any> = getNewVulns(
        snykProject,
        snykTestJsonResults,
        'inline',
      );
      displayNewVulns(newVulns, 'inline');

      const expectedOutput = [
        'New issue introduced !',
        'Security Vulnerability:',
        '1/1: Regular Expression Denial of Service (ReDoS) [High Severity]',
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
      const snykTestJsonResults = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'snykTestsOutputs/test-goof-with-ten-more-vulns.json',
          )
          .toString(),
      );
      // eslint-disable-next-line
      const newVulns: Array<any> = getNewVulns(
        snykProject,
        snykTestJsonResults,
        'inline',
      );
      displayNewVulns(newVulns, 'inline');

      const expectedOutput = [
        'New issues introduced !',
        'Security Vulnerabilities:',
        '1/10: Regular Expression Denial of Service (ReDoS) [Medium Severity]',
        'Via: express-fileupload@0.0.5 => whatevermodule@1.0.0 => @snyk/nodejs-runtime-agent@1.14.0 => acorn@5.7.3',
        'Fixed in: acorn 5.7.4, 6.4.1, 7.1.1',
        'Fixable by upgrade:  @snyk/nodejs-runtime-agent@1.14.0=>acorn@5.7.4',
        '2/10: Regular Expression Denial of Service (ReDoS) [Low Severity]',
        'Via: whatevermodule@2.0.0 => express-fileupload@0.0.5 => @snyk/nodejs-runtime-agent@1.14.0 => acorn@5.7.3',
        'Fixed in: acorn 5.7.4, 6.4.1, 7.1.1',
        'Fixable by upgrade:  @snyk/nodejs-runtime-agent@1.14.0=>acorn@5.7.4',
        '3/10: Regular Expression Denial of Service (ReDoS) [High Severity]',
        'Via: whatevermodule@3.0.0 => express-fileupload@0.0.5 => @snyk/nodejs-runtime-agent@1.14.0 => acorn@5.7.3',
        'Fixed in: acorn 5.7.4, 6.4.1, 7.1.1',
        'Fixable by upgrade:  @snyk/nodejs-runtime-agent@1.14.0=>acorn@5.7.4',
        '4/10: Regular Expression Denial of Service (ReDoS) [High Severity]',
        'Via: whatevermodule@4.0.0 => express-fileupload@0.0.5 => @snyk/nodejs-runtime-agent@1.14.0 => acorn@5.7.3',
        'Fixed in: acorn 5.7.4, 6.4.1, 7.1.1',
        'Fixable by upgrade:  @snyk/nodejs-runtime-agent@1.14.0=>acorn@5.7.4',
        '5/10: Regular Expression Denial of Service (ReDoS) [High Severity]',
        'Via: whatevermodule@5.0.0 => express-fileupload@0.0.5 => @snyk/nodejs-runtime-agent@1.14.0 => acorn@5.7.3',
        'Fixed in: acorn 5.7.4, 6.4.1, 7.1.1',
        'Fixable by upgrade:  @snyk/nodejs-runtime-agent@1.14.0=>acorn@5.7.4',
        '6/10: Regular Expression Denial of Service (ReDoS) [High Severity]',
        'Via: whatevermodule@6.0.0 => express-fileupload@0.0.5 => @snyk/nodejs-runtime-agent@1.14.0 => acorn@5.7.3',
        'Fixed in: acorn 5.7.4, 6.4.1, 7.1.1',
        'Fixable by upgrade:  @snyk/nodejs-runtime-agent@1.14.0=>acorn@5.7.4',
        '7/10: Regular Expression Denial of Service (ReDoS) [High Severity]',
        'Via: whatevermodule@7.0.0 => express-fileupload@0.0.5 => @snyk/nodejs-runtime-agent@1.14.0 => acorn@5.7.3',
        'Fixed in: acorn 5.7.4, 6.4.1, 7.1.1',
        'Fixable by upgrade:  @snyk/nodejs-runtime-agent@1.14.0=>acorn@5.7.4',
        '8/10: Regular Expression Denial of Service (ReDoS) [High Severity]',
        'Via: whatevermodule@8.0.0 => express-fileupload@0.0.5 => @snyk/nodejs-runtime-agent@1.14.0 => acorn@5.7.3',
        'Fixed in: acorn 5.7.4, 6.4.1, 7.1.1',
        'Fixable by upgrade:  @snyk/nodejs-runtime-agent@1.14.0=>acorn@5.7.4',
        '9/10: Regular Expression Denial of Service (ReDoS) [High Severity]',
        'Via: whatevermodule@9.0.0 => express-fileupload@0.0.5 => @snyk/nodejs-runtime-agent@1.14.0 => acorn@5.7.3',
        'Fixed in: acorn 5.7.4, 6.4.1, 7.1.1',
        'Fixable by upgrade:  @snyk/nodejs-runtime-agent@1.14.0=>acorn@5.7.4',
        '10/10: Regular Expression Denial of Service (ReDoS) [High Severity]',
        'Via: whatevermodule@10.0.0 => express-fileupload@0.0.5 => @snyk/nodejs-runtime-agent@1.14.0 => acorn@5.7.3',
        'Fixed in: acorn 5.7.4, 6.4.1, 7.1.1',
        'Fixable by upgrade:  @snyk/nodejs-runtime-agent@1.14.0=>acorn@5.7.4',
      ];

      expectedOutput.forEach((line) => {
        expect(consoleOutput.join()).toContain(line);
      });
    });

    it('Test displayNewVulns - standalone mode - no new vuln', async () => {
      // eslint-disable-next-line
      const newVulns: Array<any> = [];
      displayNewVulns(newVulns, 'standalone');
      expect(consoleOutput).toEqual([]);
    });

    it('Test displayNewVulns - standalone mode - 1 new vuln', async () => {
      utils.init();
      const snykBaselineProject = JSON.parse(
        fs
          .readFileSync(fixturesFolderPath + 'apiResponses/test-goof.json')
          .toString(),
      );
      const snykCurrentProject = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'apiResponses/test-goof-with-one-more-vuln.json',
          )
          .toString(),
      );
      // eslint-disable-next-line
      const newVulns: Array<any> = getNewVulns(
        snykBaselineProject,
        snykCurrentProject.issues,
        'standalone',
      );
      displayNewVulns(newVulns, 'standalone');

      const expectedOutput = [
        'New issue introduced !',
        'Security Vulnerability:',
        '1/1: Denial of Service (DoS) [Medium Severity]',
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
      const snykCurrentProject = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'apiResponses/test-goof-with-ten-more-vulns.json',
          )
          .toString(),
      );
      // eslint-disable-next-line
      const newVulns: Array<any> = getNewVulns(
        snykBaselineProject,
        snykCurrentProject.issues,
        'standalone',
      );
      displayNewVulns(newVulns, 'standalone');

      const expectedOutput = [
        'New issues introduced !',
        'Security Vulnerabilities:',
        '1/10: Denial of Service (DoS) [Medium Severity]',
        'Via: ms@1.0.0 => ejs-locals@1.0.2 => ejs@0.8.8',
        '2/10: Denial of Service (DoS) [Medium Severity]',
        'Via: ms@1.1.0 => ejs-locals@1.0.2 => ejs@0.8.8',
        '3/10: Denial of Service (DoS) [Medium Severity]',
        'Via: ms@1.2.0 => ejs-locals@1.0.2 => ejs@0.8.8',
        '4/10: Denial of Service (DoS) [Medium Severity]',
        'Via: ms@1.4.0 => ejs-locals@1.0.2 => ejs@0.8.8',
        '5/10: Denial of Service (DoS) [Medium Severity]',
        'Via: ms@1.5.0 => ejs-locals@1.0.2 => ejs@0.8.8',
        '6/10: Denial of Service (DoS) [Medium Severity]',
        'Via: ms@1.6.0 => ejs-locals@1.0.2 => ejs@0.8.8',
        '7/10: Denial of Service (DoS) [Medium Severity]',
        'Via: ms@1.7.0 => ejs-locals@1.0.2 => ejs@0.8.8',
        '8/10: Denial of Service (DoS) [Medium Severity]',
        'Via: ms@1.8.0 => ejs-locals@1.0.2 => ejs@0.8.8',
        '9/10: Denial of Service (DoS) [Medium Severity]',
        'Via: ms@1.9.0 => ejs-locals@1.0.2 => ejs@0.8.8',
        '10/10: Denial of Service (DoS) [Medium Severity]',
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
      // eslint-disable-next-line
      const newLicenseIssues: Array<any> = [];
      displayNewLicenseIssues(newLicenseIssues, 'inline');
      expect(consoleOutput).toEqual([]);
    });

    it('Test displayNewLicenseIssues - inline mode - 1 new issue', async () => {
      utils.init();
      const snykProject = JSON.parse(
        fs
          .readFileSync(fixturesFolderPath + 'apiResponses/test-goof.json')
          .toString(),
      );
      const snykTestJsonResults = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'snykTestsOutputs/test-goof-with-one-more-license-issue.json',
          )
          .toString(),
      );
      // eslint-disable-next-line
      const newLicenseIssues: Array<any> = getNewLicenseIssues(
        snykProject,
        snykTestJsonResults,
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
      // eslint-disable-next-line
      const newLicenseIssues: Array<any> = [];
      displayNewLicenseIssues(newLicenseIssues, 'standalone');
      expect(consoleOutput).toEqual([]);
    });

    it('Test displayNewLicenseIssues - standalone mode - 1 new issue', async () => {
      utils.init();
      const snykBaselineProject = JSON.parse(
        fs
          .readFileSync(fixturesFolderPath + 'apiResponses/test-goof.json')
          .toString(),
      );
      const snykCurrentProject = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'apiResponses/test-goof-with-one-more-license-issue.json',
          )
          .toString(),
      );
      // eslint-disable-next-line
      const newLicenseIssues: Array<any> = getNewLicenseIssues(
        snykBaselineProject,
        snykCurrentProject.issues,
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
      const snykTestJsonResults = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'snykTestsOutputs/test-goof-with-one-more-vuln.json',
          )
          .toString(),
      );
      // eslint-disable-next-line
      const newVulns: Array<any> = getNewVulns(
        snykProject,
        snykTestJsonResults,
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
      const snykTestJsonResults = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'snykTestsOutputs/test-goof-with-one-more-vuln.json',
          )
          .toString(),
      );
      // eslint-disable-next-line
      const newVulns: Array<any> = getNewVulns(
        snykProject,
        snykTestJsonResults,
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
      const snykTestJsonResults = JSON.parse(
        fs
          .readFileSync(
            fixturesFolderPath +
              'snykTestsOutputs/test-goof-with-one-more-vuln.json',
          )
          .toString(),
      );
      // eslint-disable-next-line
      const newVulns: Array<any> = getNewVulns(
        snykProject,
        snykTestJsonResults,
        'inline',
      );
      const output = getIssuesDetailsPerPackage(newVulns, 'acorn', '5.7.3');
      const issueDetailsForPackage = newVulns[0];
      expect(output).toEqual([issueDetailsForPackage]);
    });
  });
});
