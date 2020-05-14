import * as debugModule from 'debug'
const yargs = require('yargs');
import * as fs from 'fs'
import * as path from 'path'
//const pkgJSON = require(require('app-root-path').resolve('package.json'))
import * as chalk from 'chalk';
import { BadInputError } from '../customErrors/inputError';

const DEBUG_DEFAULT_NAMESPACES = [
    'snyk'
  ];

let debug: debugModule.Debugger

const getDebugModule = () => {
    return debug   
}

const init = () => {
  
    const pkgJSONPath = fs.existsSync(__dirname+'/../../../package.json')? __dirname+'/../../../package.json' : path.dirname(path.dirname(__dirname))+'/package.json'
    const pkgJSON = JSON.parse(fs.readFileSync(pkgJSONPath).toString())

    const argv = yargs
    .usage('============================')
    .usage('2 modes of operations - Inline or Standalone')
    .usage('_________')
    .usage('Inline: Compares snyk test output to a baseline snapshot')
    .usage('=> snyk test --json | snyk-delta')
    .usage('OR')
    .usage('Standalone: Compares 2 monitored project snapshots by coordinates')
    .usage('(baseline-org/baseline-project vs org/project)')
    .usage('=> snyk-delta --baseline-org 123 --baseline-project 456 --org 789 --project abc')
    .usage('============================')
    .help('h')
    .alias('h', 'help')
    .alias('d','debug')
    .options({
      baselineOrg: { type: 'string', describe: 'Snyk baseline organization ID/name', demandOption: false },
      baselineProject: { type: 'string', describe: 'Snyk baseline project ID/name', demandOption: false },
      currentOrg: { type: 'string', describe: 'Snyk organization ID/name to compare against', demandOption: false },
      currentProject: { type: 'string', describe: 'Snyk project ID/name to compare against', demandOption: false },
      type: { describe: "Specify issue type - default all", choices: ["vuln","license","all"], demandOption: false }
    })
    .describe('d', 'Show debug logs')
    .version(pkgJSON.version)
    .argv;

    if (argv.debug || argv.d) {
      let enable = DEBUG_DEFAULT_NAMESPACES.join(',');
      if (process.env.DEBUG) {
        enable += ',' + process.env.DEBUG;
      }
      // Storing in the global state, because just "debugModule.enable" call won't affect different instances of `debug`
      // module imported by plugins, libraries etc.
      process.env.DEBUG = enable;
      debugModule.enable(enable);
    }
    debug = debugModule('snyk')
    return argv; //debugModule('snyk');
}
const displaySplash = () => {
    const stopSign = `
                                uuuuuuuuuuuuuuuuuuuu
                              u" uuuuuuuuuuuuuuuuuu "u
                            u" u$$$$$$$$$$$$$$$$$$$$u "u
                          u" u$$$$$$$$$$$$$$$$$$$$$$$$u "u
                        u" u$$$$$$$$$$$$$$$$$$$$$$$$$$$$u "u
                      u" u$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$u "u
                    u" u$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$u "u
                    $ $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ $
                    $ $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ $
                    $ $$$" ... "$...  ...$" ... "$$$  ... "$$$ $
                    $ $$$u \`"$$$$$$$  $$$  $$$$$  $$  $$$  $$$ $
                    $ $$$$$$uu "$$$$  $$$  $$$$$  $$  """ u$$$ $
                    $ $$$""$$$  $$$$  $$$u "$$$" u$$  $$$$$$$$ $
                    $ $$$$....,$$$$$..$$$$$....,$$$$..$$$$$$$$ $
                    $ $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ $
                    "u "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" u"
                      "u "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" u"
                        "u "$$$$$$$$$$$$$$$$$$$$$$$$$$$$" u"
                          "u "$$$$$$$$$$$$$$$$$$$$$$$$" u"
                            "u "$$$$$$$$$$$$$$$$$$$$" u"
                              "u """""""""""""""""" u"
                                """"""""""""""""""""
                    `

    if(process.env.DEBUG) {
        console.log(chalk.bgRedBright("\nDebug Mode\n"))
    } else {
        console.log(stopSign)
    }
}

  const getPipedDataIn = () => {
    return new Promise<string>((resolve,reject) => {
    let data:string = "";

    process.stdin.resume();
    process.stdin.setEncoding('utf8');
    try {
      process.stdin.on('data', function(chunk) {
        data += chunk;
      });
    
      process.stdin.on('end', function() {
        resolve(data)    
      });

      if(process.stdin.isTTY) {
          throw new BadInputError('No input data detected. Check out the --help option')
      }
      
    } catch (err) {
      reject(err)
    }

  });
}

export {
    displaySplash,
    init,
    getDebugModule,
    getPipedDataIn
};