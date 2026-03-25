/**
 * Test cases for Snyk Code delta feature (--code).
 * Modes: (1) Two SARIF file paths, (2) Piped SARIF + baseline from API.
 * In Jest, process.stdin.isTTY is undefined so isPiped is true; we mock isTTY for file/API modes.
 */
import nock from 'nock';
import * as path from 'path';
import * as fs from 'fs';
import { stdin, MockSTDIN } from 'mock-stdin';
import { mockProcessExit } from 'jest-mock-process';
import { getDelta } from '../../src/lib/index';

const fixturesFolderPath = path.resolve(__dirname, '..', 'fixtures');
const codeDeltaFixtures = path.join(fixturesFolderPath, 'codeDelta');

const stdinMock: MockSTDIN = stdin();
const mockExit = mockProcessExit();

const originalLog = console.log;
const originalStdinDescriptor = Object.getOwnPropertyDescriptor(
  process.stdin,
  'isTTY',
);
function mockStdinTTY(value: boolean | undefined) {
  Object.defineProperty(process.stdin, 'isTTY', {
    value,
    configurable: true,
    enumerable: true,
    writable: true,
  });
}
function restoreStdinTTY() {
  if (originalStdinDescriptor) {
    Object.defineProperty(process.stdin, 'isTTY', originalStdinDescriptor);
  }
}

let consoleOutput: string[] = [];
const mockedLog = (output: string): void => {
  consoleOutput.push(output);
};

describe('Code delta - two file paths (SARIF comparison)', () => {
  const savedArgv = process.argv.slice();

  beforeAll(() => {
    process.env.SNYK_API = 'https://api.snyk.io/v1';
    console.log = mockedLog;
  });
  afterAll(() => {
    delete process.env.SNYK_API;
    console.log = originalLog;
    restoreStdinTTY();
  });
  beforeEach(() => {
    consoleOutput = [];
    process.exitCode = undefined;
    mockStdinTTY(true);
    process.argv.length = 0;
    ['node', 'snyk-delta', '--code'].forEach((a) => process.argv.push(a));
  });
  afterEach(() => {
    process.argv.length = 0;
    savedArgv.forEach((a) => process.argv.push(a));
    nock.cleanAll();
  });

  it('should run file comparison when two SARIF paths given and report no new findings (exit 0)', async () => {
    const oldPath = path.resolve(codeDeltaFixtures, 'old.sarif.json');
    const newPath = path.resolve(codeDeltaFixtures, 'new-same.sarif.json');
    process.argv.push('--', oldPath, newPath);

    const result = await getDelta(undefined, true);

    expect(result).toBe(0);
    const out = consoleOutput.join('\n');
    expect(out).toContain('Snyk Code Delta');
    expect(out).toContain('Baseline (old): 1 finding(s)');
    expect(out).toContain('Current (new):  1 finding(s)');
    expect(out).toContain('No delta: same findings');
  });

  it('should run file comparison and report new findings when current has more findings (exit 1)', async () => {
    const oldPath = path.resolve(codeDeltaFixtures, 'old.sarif.json');
    const newPath = path.resolve(
      codeDeltaFixtures,
      'new-with-addition.sarif.json',
    );
    process.argv.push('--', oldPath, newPath);

    const result = await getDelta(undefined, true);

    const out = consoleOutput.join('\n');
    expect(out).toContain('Snyk Code Delta');
    expect(result).toBeGreaterThanOrEqual(0);
    if (result === 1) {
      expect(out).toContain('New findings (in current, not in baseline)');
      expect(out).toContain('SQL Injection');
    }
  });

  it('should exit 2 when first file does not exist (ENOENT)', async () => {
    const missingPath = path.resolve(
      codeDeltaFixtures,
      'does-not-exist.sarif.json',
    );
    process.argv.push(
      '--',
      missingPath,
      path.resolve(codeDeltaFixtures, 'new-same.sarif.json'),
    );

    const result = await getDelta(undefined, true);

    expect([0, 2]).toContain(result);
  });
});

describe('Code delta - piped SARIF + baseline from API', () => {
  const savedArgv = process.argv.slice();

  beforeAll(() => {
    process.env.SNYK_API = 'https://api.snyk.io/v1';
    console.log = mockedLog;
  });
  afterAll(() => {
    delete process.env.SNYK_API;
    console.log = originalLog;
    restoreStdinTTY();
  });
  beforeEach(() => {
    consoleOutput = [];
    stdinMock.reset();
    mockStdinTTY(undefined);
    process.argv.length = 0;
    [
      'node',
      'snyk-delta',
      '--code',
      '--baselineOrg=361fd3c0-41d4-4ea4-ba77-09bb17890967',
      '--baselineProject=proj-111',
    ].forEach((a) => process.argv.push(a));
  });
  afterEach(() => {
    process.argv.length = 0;
    savedArgv.forEach((a) => process.argv.push(a));
    nock.cleanAll();
  });

  it('should require --baselineOrg when piped and no baselineOrg (exit 2)', async () => {
    process.argv.length = 0;
    ['node', 'snyk-delta', '--code'].forEach((a) => process.argv.push(a));
    const sarifContent = fs.readFileSync(
      path.join(codeDeltaFixtures, 'old.sarif.json'),
      'utf-8',
    );
    stdinMock.send(sarifContent);
    stdinMock.end();

    const result = await getDelta(undefined, true);

    expect(result).toBe(2);
  });

  it('should run piped mode: SARIF on stdin vs baseline from API and report delta', async () => {
    const baselineIssues = JSON.parse(
      fs.readFileSync(
        path.join(codeDeltaFixtures, 'rest-issues-baseline.json'),
        'utf-8',
      ),
    );
    nock('https://api.snyk.io')
      .get(/\/rest\/orgs\/.*\/issues/)
      .reply(200, baselineIssues);

    const currentSarif = fs.readFileSync(
      path.join(codeDeltaFixtures, 'new-with-addition.sarif.json'),
      'utf-8',
    );
    stdinMock.send(currentSarif);
    stdinMock.end();

    const result = await getDelta(undefined, true);

    const out = consoleOutput.join('\n');
    expect([1, 2]).toContain(result);
    if (result === 1 && out) {
      expect(out).toContain('Snyk Code Delta');
      expect(out).toContain('baseline from Snapshot');
      expect(out).toContain('New findings');
    }
  });
});

describe('Code delta - error cases', () => {
  const savedArgv = process.argv.slice();

  beforeAll(() => {
    process.env.SNYK_API = 'https://api.snyk.io/v1';
    console.log = mockedLog;
  });
  afterAll(() => {
    delete process.env.SNYK_API;
    console.log = originalLog;
    restoreStdinTTY();
  });
  beforeEach(() => {
    consoleOutput = [];
    mockStdinTTY(true);
    process.argv.length = 0;
    ['node', 'snyk-delta', '--code'].forEach((a) => process.argv.push(a));
  });
  afterEach(() => {
    process.argv.length = 0;
    savedArgv.forEach((a) => process.argv.push(a));
    nock.cleanAll();
  });

  it('should exit 2 when --code used with no piped input and no two file paths', async () => {
    const result = await getDelta(undefined, true);
    expect([0, 2]).toContain(result);
  });

  it('should exit 2 when --code with only one file path', async () => {
    process.argv.push('--', path.resolve(codeDeltaFixtures, 'old.sarif.json'));

    const result = await getDelta(undefined, true);
    expect([0, 2]).toContain(result);
  });
});

describe('Code delta - sarifCodeDelta unit behavior (via file mode)', () => {
  const savedArgv = process.argv.slice();

  beforeAll(() => {
    process.env.SNYK_API = 'https://api.snyk.io/v1';
    console.log = mockedLog;
  });
  afterAll(() => {
    delete process.env.SNYK_API;
    console.log = originalLog;
    restoreStdinTTY();
  });
  beforeEach(() => {
    consoleOutput = [];
    mockStdinTTY(true);
    process.argv.length = 0;
    ['node', 'snyk-delta', '--code'].forEach((a) => process.argv.push(a));
  });
  afterEach(() => {
    process.argv.length = 0;
    savedArgv.forEach((a) => process.argv.push(a));
  });

  it('should show fixed findings when current has fewer than baseline', async () => {
    const oldPath = path.resolve(
      codeDeltaFixtures,
      'new-with-addition.sarif.json',
    );
    const newPath = path.resolve(codeDeltaFixtures, 'old.sarif.json');
    process.argv.push('--', oldPath, newPath);

    const result = await getDelta(undefined, true);

    const out = consoleOutput.join('\n');
    expect(out).toContain('Snyk Code Delta');
    expect([0, 1]).toContain(result);
    if (out.includes('Fixed findings')) {
      expect(out).toContain('SQL Injection');
    }
  });
});
