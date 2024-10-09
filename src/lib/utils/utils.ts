import debugModule from 'debug';

import * as fs from 'fs';
import * as path from 'path';
//const pkgJSON = require(require('app-root-path').resolve('package.json'))
import chalk from 'chalk';
import { BadInputError } from '../customErrors/inputError';

const DEBUG_DEFAULT_NAMESPACES = ['snyk'];

let debug: debugModule.Debugger;

const getDebugModule = ():debugModule.Debugger => {
  return debug;
};

export interface ModuleOptions {
  debug: boolean;
}

const init = (debugMode = false):any => {
  const yargs = require('yargs');
  const pkgJSONPath = fs.existsSync(__dirname + '/../../../package.json')
    ? __dirname + '/../../../package.json'
    : path.dirname(path.dirname(__dirname)) + '/package.json';
  const pkgJSON = JSON.parse(fs.readFileSync(pkgJSONPath).toString());
  const argv = yargs
    .usage(
      `${chalk.bold('snyk-delta')} has 2 modes of operations: ${chalk.bold(
        'Inline',
      )} and ${chalk.bold('Standalone')}

Mode: ${chalk.bold('inline')}
Description: Compares 'snyk test' output to a baseline Snyk project latest snapshot
Example: ${chalk.bold('$ snyk test --json | snyk-delta')}

Mode: ${chalk.bold('standalone')}
Description: Compares 2 monitored project snapshots by coordinates (baseline-org/baseline-project vs org/project)
Example: ${chalk.bold(
        '$ snyk-delta --baselineOrg uuid-xxx-xxx-xxx --baselineProject uuid-xxx-xxx-xxx --currentOrg uuid-xxx-xxx-xxx --currentProject uuid-xxx-xxx-xxx',
      )}`,
    )
    .help('h')
    .alias('h', 'help')
    .alias('d', 'debug')
    .options({
      baselineOrg: {
        type: 'string',
        describe: 'Snyk baseline organization public ID (UUID)',
        demandOption: false,
      },
      setPassIfNoBaseline: {
        type: 'string',
        describe:
          'Do not fail with exit code `1` if a project is not monitored in Snyk and could not be compared. For use with snyk-prevent-gh-commit-status',
        choices: ['true', 'false'],
        demandOption: false,
      },
      baselineProject: {
        type: 'string',
        describe: 'Snyk baseline project public ID (UUID)',
        demandOption: false,
      },
      currentOrg: {
        type: 'string',
        describe: 'Snyk organization public ID (UUID) to compare against',
        demandOption: false,
      },
      currentProject: {
        type: 'string',
        describe: 'Snyk project  public ID (UUID) to compare against',
        demandOption: false,
      },
      targetReference: {
        type: 'string',
        describe: 'Snyk project target reference to compare against',
        demandOption: false,
      },
      type: {
        describe: 'Specify issue type - default all',
        choices: ['vuln', 'license', 'all'],
        demandOption: false,
      },
      'fail-on': {
        describe:
          'Fail only if the detected issues are fixable (patchable / upgradable). Matches the behaviour of `--fail-on` in snyk CLI',
        choices: ['all', 'upgradable', 'patchable'],
        demandOption: false,
      },
    })
    .describe('d', 'Show debug logs')
    .version(pkgJSON.version).argv;
    
  if (argv.debug || argv.d || debugMode) {
    let enable = DEBUG_DEFAULT_NAMESPACES.join(',');
    if (process.env.DEBUG) {
      enable += ',' + process.env.DEBUG;
    }
    // Storing in the global state, because just "debugModule.enable" call won't affect different instances of `debug`
    // module imported by plugins, libraries etc.
    process.env.DEBUG = enable;
    debugModule.enable(enable);
  } else {
    debugModule.disable();
  }
  debug = debugModule('snyk');
  return argv; //debugModule('snyk');
};
const displaySplash = ():void => {
  if (process.env.DEBUG) {
    console.log(chalk.bgRedBright('\nDebug Mode\n'));
  }
};

const getPipedDataIn = ():Promise<string> => {
  return new Promise<string>((resolve, reject) => {
    let data = '';
    process.stdin.resume();
    process.stdin.setEncoding('utf8');
    try {
      process.stdin.on('data', (chunk) => {
        data += chunk;
      });

      process.stdin.on('end', () => {
        resolve(data);
      });

      if (process.stdin.isTTY) {
        throw new BadInputError(
          `In 'inline' mode expected to receive 'snyk test' input data.`,
        );
      }
    } catch (err) {
      reject(err);
    }
  });
};

export { displaySplash, init, getDebugModule, getPipedDataIn };
