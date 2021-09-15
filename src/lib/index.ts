#!/usr/bin/env node
import 'source-map-support/register';
import * as snyk from './snyk/snyk';
import handleError from './error';
import * as utils from './utils/utils';
import * as issues from './snyk/issues'
import * as dependencies from './snyk/dependencies'
import * as isUUID from 'is-uuid'
import { BadInputError } from './customErrors/inputError'
import { Project } from 'snyk-api-ts-client/dist/client/generated/org';
import { SnykCliTestOutput, SnykDeltaInput, SnykDeltaOutput } from './types'
import { displayOutput } from './snyk/displayOutput';
export { SnykDeltaOutput } from './types'

const banner =  `
================================================                           
================================================
Snyk Tech Prevent Tool
================================================
================================================
`

const getArguments = async(snykTestOutput = '', debugMode = false, setPassIfNoBaselineFlag = false):Promise<SnykDeltaInput> => {

  console.log('get arguments')
  
  const inputValues = {} as SnykDeltaInput
  const argv = utils.init(debugMode)

  const debug = utils.getDebugModule()
  
  inputValues.mode = argv.currentProject || argv.currentOrg ? "standalone" : "inline"
  
  inputValues.passIfNoBaseline = argv.setPassIfNoBaseline || setPassIfNoBaselineFlag
  
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

    debug("get arg snykTestOutput org", snykTestOutput)

  } catch (err) {
    
    handleError(err)
    process.exitCode = 2

  }

  return inputValues
}

// const doAllProject: any() => {

//   return
// }


const getDelta = async(snykTestOutput = '', debugMode = false, setPassIfNoBaselineFlag = false):Promise<SnykDeltaOutput|number> => {
   
  let snykTestJsonDependencies, snykTestJsonResults
  let newVulns, newLicenseIssues
  let noBaseline = false

  console.log("test")

  const options = await getArguments(snykTestOutput,debugMode,setPassIfNoBaselineFlag)

  try{
    const debug = utils.getDebugModule()

    debug(options.mode,"mode")

    if(options.mode == "inline"){

      debug("baselineOrg %s", options.baselineOrg)
      debug("baselineProject %s", options.baselineProject)

      const pipedData: string = snykTestOutput == '' ? await utils.getPipedDataIn() : ""+snykTestOutput
      // Verify it's JSON data structure
      debug("Verify input data for JSON structure")
      const inputData: Array<any> = JSON.parse("["+pipedData.replace(/}\n{/g,"},\n{").replace("}\n[","},\n[")+"]")

      // TODO: Handle --all-projects setups, bail for now
      if(inputData.length > 2){
        console.log("Sorry, I can't handle --all-projects commands right now, but soon !")
        process.exitCode = 2
      }
      
      snykTestJsonDependencies = inputData.length > 1 ? inputData[0] : null
      snykTestJsonResults = inputData.length > 1 ? inputData[1]: inputData[0]
      const projectNameFromJson = snykTestJsonResults.targetFile? 
                                  `${snykTestJsonResults.projectName}:${snykTestJsonResults.targetFile}` :
                                  `${snykTestJsonResults.projectName}`

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
    } else {
      // Pull data from currentOrg/currentProject for issues and dep graph and drop it into input data.
      if(!options.currentProject || !options.currentOrg || !options.baselineOrg || !options.baselineProject){
        throw new BadInputError("You must provide org AND project IDs for baseline project and current project")
      }

      debug(`Retrieve Snyk Project to compare %s in org %s`, options.currentOrg, options.currentProject)
      snykTestJsonDependencies = await snyk.getProjectDepGraph(options.currentOrg,options.currentProject)
      const projectIssuesFromAPI = await snyk.getProjectIssues(options.currentOrg,options.currentProject)
      snykTestJsonResults = projectIssuesFromAPI.issues
      
    }

    debug("options.baselineProject = %s", options.baselineProject)
    
    //TODO: If baseline project is '' and strictMode is false, display current vulns
    debug(`Retrieve Snyk Project %s in org %s`, options.baselineProject, options.baselineOrg)
    const issueTypeFilter: string = options.type? options.type : "all"
    let snykProject: Project.IssuesPostResponseType
    const typedSnykTestJsonResults = snykTestJsonResults as SnykCliTestOutput

    // if no baseline, return returned results straight from CLI
    if(options.baselineProject == ''){
      snykProject = snykTestJsonResults
      
      newVulns = typedSnykTestJsonResults.vulnerabilities.filter(x => x.type != "license")
      newLicenseIssues = typedSnykTestJsonResults.vulnerabilities.filter(x => x.type == "license")

      noBaseline = true      
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
    

    if(newVulns.length + newLicenseIssues.length > 0) {
      if(!noBaseline){
        process.exitCode = 1
      } else {
        if(options.passIfNoBaseline){
          process.exitCode = 0
        } else {
          process.exitCode = 1
        }
      }
    } else {
      process.exitCode = 0
    }
    
    
  } catch (err){
    
    handleError(err)
    process.exitCode = 2

  
  } finally {
    if(!module.parent || (isJestTesting() && !expect.getState().currentTestName.includes('module'))){
      process.exit(process.exitCode)
    } else {
      return {result: process.exitCode, newVulns: newVulns,newLicenseIssues: newLicenseIssues, passIfNoBaseline: options.passIfNoBaseline, noBaseline: noBaseline}
    }
  
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