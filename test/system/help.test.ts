import { exec } from 'child_process';
import { sep } from 'path';
const stripAnsi = require('strip-ansi');
const main = './dist/index.js'.replace(/\//g, sep);

describe('`snyk-delta help <...>`', () => {
  it('Shows help text as expected', (done) => {
    // Fixed COLUMNS so help output is deterministic in CI (no TTY) and locally
    const env = { ...process.env, COLUMNS: '80' };
    exec(`node ${main} -h`, { env }, (err, stdout, stderr) => {
      if (err) {
        throw err;
      }
      expect(err).toBeNull();
      expect(stderr).toEqual('');
      expect(stripAnsi(stdout)).toMatchInlineSnapshot(`
        "snyk-delta has 3 modes of operations: Inline, Code delta and Standalone

        Mode: inline
        Description: Compares 'snyk test' output to a baseline Snyk project latest
        snapshot
        Example: $ snyk test --json | snyk-delta

        Mode: code delta
        Description: Compares 'snyk code test' output to a baseline Snyk project latest
        snapshot
        Example: $ snyk code test --sarif | snyk-delta --code --baselineOrg
        uuid-xxx-xxx-xxx --baselineProject uuid-xxx-xxx-xxx
        Example: $ snyk code test --sarif | snyk-delta --code --baselineOrg
        uuid-xxx-xxx-xxx --projectName \\"owner/repo\\" --targetReference \\"branchName\\"

        Mode: standalone
        Description: Compares 2 monitored project snapshots by coordinates
        (baseline-org/baseline-project vs org/project)
        Example: $ snyk-delta --baselineOrg uuid-xxx-xxx-xxx --baselineProject
        uuid-xxx-xxx-xxx --currentOrg uuid-xxx-xxx-xxx --currentProject uuid-xxx-xxx-xxx

        Options:
          -h, --help                 Show help                                 [boolean]
              --baselineOrg          Snyk baseline organization public ID (UUID)[string]
              --setPassIfNoBaseline  Do not fail with exit code \`1\` if a project is not
                                     monitored in Snyk and could not be compared. For
                                     use with snyk-prevent-gh-commit-status
                                                     [string] [choices: \\"true\\", \\"false\\"]
              --baselineProject      Snyk baseline project public ID (UUID)     [string]
              --currentOrg           Snyk organization public ID (UUID) to compare
                                     against                                    [string]
              --currentProject       Snyk project  public ID (UUID) to compare against
                                                                                [string]
              --targetReference      Snyk project target reference to compare against
                                                                                [string]
              --type                 Specify issue type - default all
                                                     [choices: \\"vuln\\", \\"license\\", \\"all\\"]
              --fail-on              Fail only if the detected issues are fixable
                                     (patchable / upgradable). Matches the behaviour of
                                     \`--fail-on\` in snyk CLI
                                             [choices: \\"all\\", \\"upgradable\\", \\"patchable\\"]
              --code                 Perform Snyk Code Analysis delta comparison
                                                                               [boolean]
              --projectName          Project name to compare against for Code Analysis
                                     delta comparison                           [string]
          -d, --debug                Show debug logs
              --version              Show version number                       [boolean]
        "
      `);
    }).on('exit', (code) => {
      expect(code).toEqual(0);
      done();
    });
  }, 10000);
});
