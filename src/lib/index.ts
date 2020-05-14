#!/usr/bin/env node
import 'source-map-support/register';
import * as snyk from './snyk/snyk';
import handleError from './error';
import * as utils from './utils/utils';
import * as issues from './snyk/issues'
import * as dependencies from './snyk/dependencies'
import * as isUUID from 'is-uuid'
import { BadInputError } from './customErrors/inputError'

const banner =  `
================================================                           
================================================
Snyk Tech Prevent Tool
================================================
================================================
`


const getDelta = async(snykTestOutput: string = '') => {
   const argv = utils.init()
   const debug = utils.getDebugModule()
   const mode = argv.currentProject || argv.currentOrg ? "standalone" : "inline"

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

      baselineOrg = baselineOrg? baselineOrg : snykTestJsonResults.org
      baselineProject = baselineProject? baselineProject : snykTestJsonResults.projectName

      if(argv.baselineProject && !isUUID.anyNonNil(baselineProject)){
        throw new BadInputError("Project ID must be valid UUID")
      }
      if(!isUUID.anyNonNil(baselineProject)){
        baselineProject = await snyk.getProjectUUID(baselineOrg,baselineProject)
      }
    } else {
      // Pull data from currentOrg/currentProject for issues and dep graph and drop it into input data.
      if(!argv.currentProject || !argv.currentOrg || !argv.baselineOrg || !argv.baselineProject){
        throw new BadInputError("You must provide org AND project IDs for baseline project and current project")
      }
      // if(!isUUID.anyNonNil(baselineProject) || (currentProject && !isUUID.anyNonNil(currentProject))){
      //   throw new BadInputError("Project IDs must be UUID")
      // }

      debug(`Retrieve Snyk Project to compare %s in org %s`, currentOrg, currentProject)
      snykTestJsonDependencies = await snyk.getProjectDepGraph(currentOrg,currentProject)
      const projectIssuesFromAPI = await snyk.getProjectIssues(currentOrg,currentProject)
      snykTestJsonResults = projectIssuesFromAPI.issues
      
    }
    
    debug(`Retrieve Snyk Project %s in org %s`, baselineProject, baselineOrg)
    const issueTypeFilter: string = argv.type? argv.type : "all"
    const snykProject = await snyk.getProjectIssues(baselineOrg,baselineProject)
    const newVulns: Array<any> = issues.getNewVulns(snykProject,snykTestJsonResults, mode)
    const newLicenseIssues: Array<any> = issues.getNewLicenseIssues(snykProject,snykTestJsonResults, mode)
    
    debug(`New Vulns count =%d`,newVulns.length)
    debug(`New Licenses Issues count =%d`,newLicenseIssues.length)
 
    if(snykTestJsonDependencies){
      const monitoredProjectDepGraph = await snyk.getProjectDepGraph(baselineOrg,baselineProject)
      await dependencies.displayDependenciesChangeDetails(snykTestJsonDependencies, monitoredProjectDepGraph, snykTestJsonResults.packageManager, newVulns, newLicenseIssues)
    }
    

    if((newVulns.length > 0 && issueTypeFilter != "license") || (newLicenseIssues.length > 0 && issueTypeFilter != "vuln")) {
      utils.displaySplash()
      if(newVulns.length > 0 && issueTypeFilter != "license"){
        issues.displayNewVulns(newVulns, mode)
      }
      if(newLicenseIssues.length > 0 && issueTypeFilter != "vuln"){
        issues.displayNewLicenseIssues(newLicenseIssues, mode)
      }
      process.exitCode = 1
    } else {
      console.log("No new issues found !")
      process.exitCode = 0
    }


  } catch (err){
    handleError(err)
    process.exitCode = 2
  } finally {
    process.exit(process.exitCode)
  }

}

if(process.env.NODE_ENV != 'test'){
  getDelta()
}



export {
  getDelta
}
