#!/usr/bin/env node
import 'source-map-support/register';
import * as snyk from './snyk/snyk';
import handleError from './error';
import * as utils from './utils/utils';
import * as issues from './snyk/issues'
import * as dependencies from './snyk/dependencies'
import * as isUUID from 'is-uuid'
import { BadInputError, BadSnykTestOutput, PrintDepsError } from './customErrors/inputError'
import { ProjectDeltaOutput, SnykCliTestOutput, SnykDeltaInput, SnykDeltaOutput, IssuesPostResponseType, GetSnykTestResult } from './types'
import { displayOutput, displaySummary } from './snyk/displayOutput';
import debugModule = require('debug');
import { Project } from 'snyk-api-ts-client/dist/client/generated/org';

export { SnykDeltaOutput } from './types'

const banner =  `
================================================                           
================================================
Snyk Tech Prevent Tool
================================================
================================================
`

const getArguments = async(snykTestOutput = '', debugMode = false, setPassIfNoBaselineFlag = false, passOnFail = true):Promise<SnykDeltaInput> => {
  
  const inputValues = {} as SnykDeltaInput
  const argv = utils.init(debugMode)
  
  inputValues.mode = argv.currentProject || argv.currentOrg ? "standalone" : "inline"
  
  inputValues.passIfNoBaseline = argv.setPassIfNoBaseline || setPassIfNoBaselineFlag

  inputValues.passOnFail = argv.passOnFail || passOnFail
  
  try {

    if(process.env.NODE_ENV == 'prod'){
      console.log(banner)
    }
    
    inputValues.baselineOrg = argv.baselineOrg ? argv.baselineOrg : ""
    inputValues.baselineProject = argv.baselineProject ? argv.baselineProject : ""
    inputValues.currentOrg = argv.currentOrg ? argv.currentOrg: ""
    inputValues.currentProject = argv.currentProject ? argv.currentProject: ""
    inputValues.snykTestOutput = snykTestOutput
    inputValues.type = argv.type 

  } catch (err) {
    
    handleError(err)
    process.exitCode = 2

  }

  return inputValues
}

// Parse at snyk test result
// Create a list of object containing snyk test result, snyk test dependencies and name per project
export const getSnykTestResult = async (options: SnykDeltaInput): Promise<GetSnykTestResult[]> => {

  let snykTestJsonDependencies, snykTestJsonResults
  let projectNameFromJson: any = ""

  const getSnykTestResult_: GetSnykTestResult[] = [] 
  const snykTestOutput = options.snykTestOutput

  const debug = debugModule('snyk')

  debug(options.mode,"mode")

  try {
    if(options.mode === "inline"){

      debug("baselineOrg %s", options.baselineOrg)
      debug("baselineProject %s", options.baselineProject)

      const pipedData: string = snykTestOutput == '' ? await utils.getPipedDataIn() : "" + snykTestOutput

      // Verify it's JSON data structure
      debug("Verify input data for JSON structure")
      let inputData: Array<any>
      const printDepsOutputFound = pipedData.search(/\}\n\[/g)

      // this combinaison is present only in all-project with print-deps
      if (printDepsOutputFound > -1) {
        throw new PrintDepsError("snyk-delta does not support -all-project and -print-deps at the same time")
      }

      if (pipedData.charAt(0) !== "[") {
        
        inputData = JSON.parse("["+pipedData.replace(/}\n{/g,"},\n{").replace("}\n[","},\n[")+"]")

        snykTestJsonDependencies = inputData.length > 1 ? inputData[0] : null
        snykTestJsonResults = inputData.length > 1 ? inputData[1]: inputData[0]
        projectNameFromJson = snykTestJsonResults.targetFile? 
                                    `${snykTestJsonResults.projectName}:${snykTestJsonResults.targetFile}` :
                                    `${snykTestJsonResults.projectName}`

        if (snykTestJsonResults === undefined) {
          debug("snykTestResults received: ", JSON.stringify(inputData))
          throw new BadSnykTestOutput("snykTest output unreadable")
        }

        getSnykTestResult_.push({snykTestJsonResults: snykTestJsonResults, snykTestJsonDependencies: snykTestJsonDependencies, projectNameFromJson: projectNameFromJson})

      } else {
        debug("all-project output detected")

        inputData = JSON.parse(pipedData.replace(/}\n{/g,"},\n{").replace("}\n[","},\n["))

        inputData.forEach(projectInputData => {
          const stringifyProjectInputData = JSON.stringify(projectInputData)
          const projectInputDataParsed = JSON.parse("["+stringifyProjectInputData.replace(/}\n{/g,"},\n{").replace("}\n[","},\n[")+"]")
          snykTestJsonDependencies = projectInputDataParsed.length > 1 ? projectInputDataParsed[0] : null
          snykTestJsonResults = projectInputDataParsed.length > 1 ? projectInputDataParsed[1]: projectInputDataParsed[0]
          projectNameFromJson = snykTestJsonResults.targetFile? 
                                      `${snykTestJsonResults.projectName}:${snykTestJsonResults.targetFile}` :
                                      `${snykTestJsonResults.projectName}`
          
          getSnykTestResult_.push({snykTestJsonResults: snykTestJsonResults, snykTestJsonDependencies: snykTestJsonDependencies, projectNameFromJson: projectNameFromJson})
        })
      }
    } else {
      // Pull data from currentOrg/currentProject for issues and dep graph and drop it into input data.
      if(!options.currentProject || !options.currentOrg || !options.baselineOrg || !options.baselineProject){
        throw new BadInputError("You must provide org AND project IDs for baseline project and current project")
      }

      debug(`Retrieve Snyk Project to compare %s in org %s`, options.currentOrg, options.currentProject)
      snykTestJsonDependencies = await snyk.getProjectDepGraph(options.currentOrg,options.currentProject)
      const projectIssuesFromAPI = await snyk.getProjectIssues(options.currentOrg,options.currentProject)
      snykTestJsonResults = projectIssuesFromAPI.issues as SnykCliTestOutput

      getSnykTestResult_.push({snykTestJsonResults: snykTestJsonResults, snykTestJsonDependencies: snykTestJsonDependencies, projectNameFromJson: ""})
    }
  } catch (err) {
    handleError(err)
    getSnykTestResult_.push({snykTestJsonResults: {}, snykTestJsonDependencies: {}, projectNameFromJson: ""})
  }

  return getSnykTestResult_
}

// generate delta per project
export const generateDelta = async(snykTestJsonResultsProperties: any, options: SnykDeltaInput):Promise<ProjectDeltaOutput> => {

  const debug = debugModule('snyk')
  const projectResult: ProjectDeltaOutput = {
    newVulns: [],
    newLicenseIssues: [],
    noBaseline: false, 
    passIfNoBaseline: false,
    projectNameOrId: "",
    error: 0,
  }

  try {
    
    if (!Object.keys(snykTestJsonResultsProperties.snykTestJsonResults).length) {
      debug("snykTestResults received: ", JSON.stringify(snykTestJsonResultsProperties.snykTestJsonResults))
      throw new BadSnykTestOutput("snykTest output unreadable")
    }
  
    const snykTestJsonResults = snykTestJsonResultsProperties.snykTestJsonResults
    const projectNameFromJson = snykTestJsonResultsProperties.projectNameFromJson
    const snykTestJsonDependencies = snykTestJsonResultsProperties.snykTestJsonDependencies

    let newVulns, newLicenseIssues
  
    if (options.mode == "inline") {
      debug("snykTestJsonResults.org %s",snykTestJsonResults.org)
      const baselineOrg: string = options.baselineOrg? options.baselineOrg : snykTestJsonResults.org
      const baselineProject: string = options.baselineProject? options.baselineProject : projectNameFromJson
  
      debug(options.baselineProject, isUUID.anyNonNil(options.baselineProject))
  
      if(options.baselineProject && !isUUID.anyNonNil(baselineProject)){
        debug(options.baselineProject)
        throw new BadInputError("Project ID must be valid UUID")
      }

      if(!isUUID.anyNonNil(options.baselineProject)){
        options.baselineProject = await snyk.getProjectUUID(baselineOrg,baselineProject)
        if(options.baselineProject == ''){
          console.warn(
            'Snyk API - Could not find a monitored project matching. \
                                              Make sure to specify the right org when snyk test using --org',
          );
          console.warn('snyk-delta will return exit code 1 if any vulns are found in the current project')
        }
      }
      options.baselineOrg = baselineOrg
    }
  
    //TODO: If baseline project is '' and strictMode is false, display current vulns
    debug(`Retrieve Snyk Project %s in org %s`, options.baselineProject, options.baselineOrg)
    const issueTypeFilter: string = options.type? options.type : "all"
    let snykProject: IssuesPostResponseType
    const typedSnykTestJsonResults = snykTestJsonResults as SnykCliTestOutput
  
    // if no baseline, return returned results straight from CLI
    if(options.baselineProject == ''){
      //snykProject = snykTestJsonResults 
      
      newVulns = typedSnykTestJsonResults.vulnerabilities.filter(x => x.type != "license")
      newLicenseIssues = typedSnykTestJsonResults.vulnerabilities.filter(x => x.type == "license")
  
      projectResult.noBaseline = true      
    } else {
  
      snykProject = await snyk.getProjectIssues(options.baselineOrg,options.baselineProject)
      
      const baselineVulnerabilitiesIssues = snykProject.issues.vulnerabilities
  
      const currentVulnerabilitiesIssues = typedSnykTestJsonResults.vulnerabilities.filter(x => x.type != 'license')
      newVulns = issues.getNewIssues(baselineVulnerabilitiesIssues,currentVulnerabilitiesIssues,snykTestJsonResults.severityThreshold, options.mode)
      
      const baselineLicenseIssues = snykProject.issues.licenses
      const currentLicensesIssues = typedSnykTestJsonResults.vulnerabilities.filter(x => x.type == 'license')
      newLicenseIssues = issues.getNewIssues(baselineLicenseIssues,currentLicensesIssues,snykTestJsonResults.severityThreshold, options.mode)
  
      debug(newLicenseIssues)
      
      debug(`New Vulns count =%d`,newVulns.length)
      debug(`New Licenses Issues count =%d`,newLicenseIssues.length)
  
      if(snykTestJsonDependencies){
        const monitoredProjectDepGraph = await snyk.getProjectDepGraph(options.baselineOrg,options.baselineProject)
        // TODO: Refactor function below
        await dependencies.displayDependenciesChangeDetails(snykTestJsonDependencies, monitoredProjectDepGraph, snykTestJsonResults.packageManager, newVulns, newLicenseIssues)
      }
    }
  
    if(!module.parent || (isJestTesting() && !expect.getState().currentTestName.includes('module'))){
      displayOutput(newVulns,newLicenseIssues,issueTypeFilter,options.mode)
    }
  
    projectResult.newLicenseIssues = newLicenseIssues
    projectResult.newVulns = newVulns
    projectResult.projectNameOrId = projectNameFromJson ? projectNameFromJson : options.currentProject
    projectResult.error = 0 // no error during processing

  } catch (err) {
    
    projectResult.newLicenseIssues = undefined
    projectResult.newVulns = undefined
    projectResult.projectNameOrId = undefined
    projectResult.error = handleError(err) 
  } 

  return projectResult
}

// Main function
// Loop over the projects
const getDelta = async(snykTestOutput = '', debugMode = false, setPassIfNoBaselineFlag = false, passOnFail = true):Promise<SnykDeltaOutput[]|number|SnykDeltaOutput|undefined> => {

  const options = await getArguments(snykTestOutput, debugMode, setPassIfNoBaselineFlag, passOnFail)
  let exitCode = 1
  
  const deltaResult: SnykDeltaOutput[] = []

  let snykTestResult = await getSnykTestResult(options)

  snykTestResult = snykTestResult as GetSnykTestResult[]
  await Promise.all(snykTestResult.map(async (snykTestResult_: GetSnykTestResult) => 
  {
    let resultProject = await generateDelta(snykTestResult_, options)

    resultProject = resultProject as ProjectDeltaOutput

    // error while calculating the delta
    if (resultProject.error != 0) {
      exitCode = resultProject.error
    } else if (resultProject.newVulns && resultProject.newLicenseIssues && (resultProject.newVulns.length + resultProject.newLicenseIssues.length > 0)) {
      if(!resultProject.noBaseline){
        exitCode = 1
      } else {
        if(options.passIfNoBaseline){
          exitCode = 0
        } else {
          exitCode = 1
        }
      }
    } else {
      exitCode = 0
    }

    deltaResult.push({result: exitCode, newVulns: resultProject.newVulns,newLicenseIssues: resultProject.newLicenseIssues, passIfNoBaseline: options.passIfNoBaseline, noBaseline: resultProject.noBaseline, projectNameOrId: resultProject.projectNameOrId})

  }));

  process.exitCode = 0
  let numberOfProjectWithNewIssue = 0

  deltaResult.forEach(result => {
    if (result.result != undefined) {
      if (result.result === 1) {
        numberOfProjectWithNewIssue ++
        process.exitCode = 1
      } else if (result.result > 1) {
        if (options.passOnFail) 
        {
          process.exitCode = 0
        } else {
          process.exitCode = 1
        }
      }
    }
  })

  displaySummary(deltaResult, numberOfProjectWithNewIssue)

  if(!module.parent || (isJestTesting() && !expect.getState().currentTestName.includes('module'))){
    process.exit(process.exitCode)
  } 

  if (deltaResult.length <= 1) {
    // Keep compatibility with snyk-prevent-commit-status
    return deltaResult[0]
  }

  return deltaResult
}

if(!module.parent){
  getDelta()
} 

export {
  getDelta
}







const isJestTesting = () => {
  return process.env.JEST_WORKER_ID !== undefined;
}