import { displayNewVulns } from '../../../src/lib/snyk/displayOutput';
import { IssueWithPaths } from '../../../src/lib/types';

describe('displayNewVulns - Fixed in line', () => {
  let logSpy: jest.SpyInstance;

  beforeEach(() => {
    logSpy = jest.spyOn(console, 'log').mockImplementation();
  });

  afterEach(() => {
    logSpy.mockRestore();
  });

  const baseVuln: IssueWithPaths = {
    id: 'SNYK-JS-ZOD-20510278',
    severity: 'high',
    title: 'Allocation of Resources Without Limits or Throttling',
    from: ['pkg@1.0.0', 'zod@3.25.76'],
    packageName: 'zod',
  };

  it('does not print a "Fixed in" line when no fixed version exists (empty array)', () => {
    const vuln: IssueWithPaths = {
      ...baseVuln,
      fixedIn: [],
      isUpgradable: false,
      isPatchable: false,
    };

    displayNewVulns([vuln], 'standalone');

    const printedLines = logSpy.mock.calls.map((call) => call.join(' '));
    expect(printedLines.some((line) => line.includes('Fixed in'))).toBe(
      false,
    );
  });

  it('still prints the "Fixed in" line with the version when a fix exists', () => {
    const vuln: IssueWithPaths = {
      ...baseVuln,
      fixedIn: ['3.26.0'],
      isUpgradable: true,
      upgradePath: ['pkg@1.0.1'],
    };

    displayNewVulns([vuln], 'standalone');

    const printedLines = logSpy.mock.calls.map((call) => call.join(' '));
    expect(
      printedLines.some(
        (line) => line.includes('Fixed in') && line.includes('3.26.0'),
      ),
    ).toBe(true);
  });
});
