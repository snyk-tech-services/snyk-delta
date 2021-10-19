#!/usr/bin/env node
import 'source-map-support/register';
import * as snyk from './snyk/snyk';
import handleError from './error';
import * as utils from './utils/utils';
import * as issues from './snyk/issues'
import * as dependencies from './snyk/dependencies'
import * as isUUID from 'is-uuid'
import { BadInputError } from './customErrors/inputError'
import { ProjectDeltaOutput, SnykCliTestOutput, SnykDeltaInput, SnykDeltaOutput, IssuesPostResponseType, GetSnykTestResult } from './types'
import { displayOutput, displaySummary } from './snyk/displayOutput';
import debugModule = require('debug');

export { SnykDeltaOutput } from './types'

const banner =  `
================================================                           
================================================
Snyk Tech Prevent Tool
================================================
================================================
`

const getArguments = async(snykTestOutput = '', debugMode = false, setPassIfNoBaselineFlag = false, dontPassOnFail = true):Promise<SnykDeltaInput> => {
  
  const inputValues = {} as SnykDeltaInput
  const argv = utils.init(debugMode)
  
  inputValues.mode = argv.currentProject || argv.currentOrg ? "standalone" : "inline"
  
  inputValues.passIfNoBaseline = argv.setPassIfNoBaseline || setPassIfNoBaselineFlag

  inputValues.dontPassOnFail = argv.dontPassOnFail || dontPassOnFail
  
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
export const getSnykTestResult = async (options: SnykDeltaInput, dontPassOnFail = true): Promise<GetSnykTestResult[]> => {

  let snykTestJsonDependencies, snykTestJsonResults
  let projectNameFromJson: any = ""

  const getSnykTestResult_: GetSnykTestResult[] = [] 
  const snykTestOutput = options.snykTestOutput

  const debug = debugModule('snyk')

  debug(options.mode,"mode")

  if(options.mode === "inline"){

    debug("baselineOrg %s", options.baselineOrg)
    debug("baselineProject %s", options.baselineProject)

    const pipedData: string = snykTestOutput == '' ? await utils.getPipedDataIn() : "" + snykTestOutput

    // Verify it's JSON data structure
    debug("Verify input data for JSON structure")
    let inputData: Array<any>

    if (pipedData.charAt(0) !== "[") {
      
      inputData = JSON.parse("["+pipedData.replace(/}\n{/g,"},\n{").replace("}\n[","},\n[")+"]")

      snykTestJsonDependencies = inputData.length > 1 ? inputData[0] : null
      snykTestJsonResults = inputData.length > 1 ? inputData[1]: inputData[0]
      projectNameFromJson = snykTestJsonResults.targetFile? 
                                  `${snykTestJsonResults.projectName}:${snykTestJsonResults.targetFile}` :
                                  `${snykTestJsonResults.projectName}`

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
 
  return projectResult
}

// Main function
// Loop over the projects
const getDelta = async(snykTestOutput = '', debugMode = false, setPassIfNoBaselineFlag = false, dontPassOnFail = true):Promise<SnykDeltaOutput[]|number|undefined> => {

  const options = await getArguments(snykTestOutput, debugMode, setPassIfNoBaselineFlag, dontPassOnFail)
  let exitCode = 1
  
  const deltaResult: SnykDeltaOutput[] = []

  try{
      const snykTestResult = await getSnykTestResult(options)

      await Promise.all(snykTestResult.map(async (snykTestResult_: GetSnykTestResult) => 
      {
        const resultProject = await generateDelta(snykTestResult_, options)
        if (resultProject.newVulns && resultProject.newLicenseIssues && (resultProject.newVulns.length + resultProject.newLicenseIssues.length > 0)) {
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

      // when to exit with code 1?
      process.exitCode = 0

      let numberOfProjectWithNewIssue = 0

      deltaResult.forEach(result => {
        if (result.result === 1) {
          if (options.dontPassOnFail) 
          {
            process.exitCode = 1
          }
          numberOfProjectWithNewIssue ++
        } 
      })

      displaySummary(deltaResult, numberOfProjectWithNewIssue)

      if(!module.parent || (isJestTesting() && !expect.getState().currentTestName.includes('module'))){
        process.exit(process.exitCode)
      } 

    return deltaResult

  } catch (err){
    
    handleError(err)
    process.exitCode = 2
    return [{result: process.exitCode, newVulns: undefined,newLicenseIssues: undefined, passIfNoBaseline: undefined, noBaseline: undefined, projectNameOrId: undefined}]

  } 
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