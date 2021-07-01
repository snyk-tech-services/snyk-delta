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
import { SnykCliTestOutput, SnykDeltaOutput } from './types'
import { displayNewVulns, displayOutput } from './snyk/displayOutput';
export { SnykDeltaOutput } from './types'

const banner =  `
================================================                           
================================================
Snyk Tech Prevent Tool
================================================
================================================
`


const getDelta = async(snykTestOutput: string = '', debugMode = false):Promise<SnykDeltaOutput|number> => {
   const argv = utils.init(debugMode)
   const debug = utils.getDebugModule()
   const mode = argv.currentProject || argv.currentOrg ? "standalone" : "inline"
   let newVulns, newLicenseIssues
   let passIfNoBaseline = false

  try {
    if(process.env.NODE_ENV == 'prod'){
      console.log(banner)
    }
    
    debug(mode,"mode")

    let snykTestJsonDependencies, snykTestJsonResults
    let baselineOrg: string = argv.baselineOrg ? argv.baselineOrg : ""
    let baselineProject: string = argv.baselineProject ? argv.baselineProject : ""
    const currentOrg: string = argv.currentOrg ? argv.currentOrg: ""
    const currentProject: string = argv.currentProject ? argv.currentProject: ""
    if(mode == "inline"){

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

      baselineOrg = baselineOrg? baselineOrg : snykTestJsonResults.org
      baselineProject = baselineProject? baselineProject : projectNameFromJson

      if(argv.baselineProject && !isUUID.anyNonNil(baselineProject)){
        throw new BadInputError("Project ID must be valid UUID")
      }
      if(!isUUID.anyNonNil(baselineProject)){
        baselineProject = await snyk.getProjectUUID(baselineOrg,baselineProject)
        if(baselineProject == ''){
          console.warn(
            'Snyk API - Could not find a monitored project matching. \
                                              Make sure to specify the right org when snyk test using --org',
          );
          console.warn('snyk-delta will return exit code 1 if any vulns are found in the current project')
        }
      }
    } else {
      // Pull data from currentOrg/currentProject for issues and dep graph and drop it into input data.
      if(!argv.currentProject || !argv.currentOrg || !argv.baselineOrg || !argv.baselineProject){
        throw new BadInputError("You must provide org AND project IDs for baseline project and current project")
      }

      debug(`Retrieve Snyk Project to compare %s in org %s`, currentOrg, currentProject)
      snykTestJsonDependencies = await snyk.getProjectDepGraph(currentOrg,currentProject)
      const projectIssuesFromAPI = await snyk.getProjectIssues(currentOrg,currentProject)
      snykTestJsonResults = projectIssuesFromAPI.issues
      
    }
    
    //TODO: If baseline project is '' and strictMode is false, display current vulns
    debug(`Retrieve Snyk Project %s in org %s`, baselineProject, baselineOrg)
    const issueTypeFilter: string = argv.type? argv.type : "all"
    let snykProject: Project.IssuesPostResponseType
    const typedSnykTestJsonResults = snykTestJsonResults as SnykCliTestOutput

    

    // if no baseline, return returned results straight from CLI
    if(baselineProject == ''){
      snykProject = snykTestJsonResults
      
      newVulns = typedSnykTestJsonResults.vulnerabilities.filter(x => x.type != "license")
      newLicenseIssues = typedSnykTestJsonResults.vulnerabilities.filter(x => x.type == "license")

      passIfNoBaseline = true
      
    } else {
      snykProject = await snyk.getProjectIssues(baselineOrg,baselineProject)
      const baselineVulnerabilitiesIssues = snykProject.issues.vulnerabilities

      const currentVulnerabilitiesIssues = typedSnykTestJsonResults.vulnerabilities.filter(x => x.type != 'license')
      newVulns = issues.getNewIssues(baselineVulnerabilitiesIssues,currentVulnerabilitiesIssues,snykTestJsonResults.severityThreshold, mode)
      
      const baselineLicenseIssues = snykProject.issues.licenses
      const currentLicensesIssues = typedSnykTestJsonResults.vulnerabilities.filter(x => x.type == 'license')
      newLicenseIssues = issues.getNewIssues(baselineLicenseIssues,currentLicensesIssues,snykTestJsonResults.severityThreshold, mode)
      
      debug(`New Vulns count =%d`,newVulns.length)
      debug(`New Licenses Issues count =%d`,newLicenseIssues.length)
  
      if(snykTestJsonDependencies){
        const monitoredProjectDepGraph = await snyk.getProjectDepGraph(baselineOrg,baselineProject)
        // TODO: Refactor function below
        await dependencies.displayDependenciesChangeDetails(snykTestJsonDependencies, monitoredProjectDepGraph, snykTestJsonResults.packageManager, newVulns, newLicenseIssues)
      }
    }

    
    if(!module.parent || (isJestTesting() && !expect.getState().currentTestName.includes('module'))){
      displayOutput(newVulns,newLicenseIssues,issueTypeFilter,mode)
    }
    
    
    if(newVulns.length + newLicenseIssues.length > 0){
      process.exitCode = 1
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
      return {result: process.exitCode, newVulns: newVulns,newLicenseIssues: newLicenseIssues, passIfNoBaseline: passIfNoBaseline}
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