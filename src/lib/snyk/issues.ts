import {getDebugModule} from '../utils/utils'
import * as _ from 'lodash'
import * as chalk from 'chalk'
import * as terminalLink from 'terminal-link'
import * as snykTypes from './types'
import { isVulnerablePathNew } from '../utils/issuesUtils'
enum severityThresholds {
  "low" = 1,
  "medium" = 2,
  "high" = 3,
  "critical" = 4
}
const getNewVulns = (snykProject: any, snykTestJsonResults: any, mode: string): Array<any> => {
    
    const debug = getDebugModule()

    const MonitoredVulns = snykProject.issues.vulnerabilities as Array<any>
    debug(`Monitored snapshot had %d vulns`, MonitoredVulns.length)
    const inboundSevThreshold = snykTestJsonResults.severityThreshold? snykTestJsonResults.severityThreshold : "low"
    const severityThreshold = severityThresholds[inboundSevThreshold]
    let TestedVulns = snykTestJsonResults.vulnerabilities as Array<any>
    
    TestedVulns = TestedVulns.filter(vuln => !vuln.type || vuln.type == 'vuln')
    
    debug(`Tested project has %d vulns`, TestedVulns.length)

    let newVulns: Array<any> = TestedVulns
    MonitoredVulns.forEach(monitoredVuln => {
      newVulns = _.reject(newVulns, (vuln: any) => {
        let vulnFromArray = vuln.from as Array<string>
        if(mode == 'inline') {
          vulnFromArray = vulnFromArray.slice(1,vulnFromArray.length)
        }

        return (monitoredVuln.id == vuln.id) && !isVulnerablePathNew(monitoredVuln.from, vulnFromArray)

      })
    })
    
    
    debug("Severity threshold ",severityThresholds[inboundSevThreshold],inboundSevThreshold)

    return newVulns.filter(vuln => severityThresholds[vuln.severity] >= severityThreshold)
}

const getNewLicenseIssues = (snykProject: any, snykTestJsonResults: any, mode: string): Array<any> => {

    const debug = getDebugModule()

    const MonitoredLicenseIssues = snykProject.issues.licenses as Array<any>
    debug(`Monitored snapshot had %d license issues`, MonitoredLicenseIssues.length)
    const inboundSevThreshold = snykTestJsonResults.severityThreshold? snykTestJsonResults.severityThreshold : "low"
    const severityThreshold = severityThresholds[inboundSevThreshold]
    let TestedLicenseIssues: Array<any>
    if(mode == 'inline'){
      TestedLicenseIssues = snykTestJsonResults.vulnerabilities as Array<any>
      TestedLicenseIssues = TestedLicenseIssues.filter(vuln => vuln.type)
    } else {
      TestedLicenseIssues = snykTestJsonResults.licenses
    }
    debug(`Tested project has %d license issues`, TestedLicenseIssues.length)
    let newLicenseIssues: Array<any> = TestedLicenseIssues

    
    MonitoredLicenseIssues.forEach(monitoredLicenseIssue => {
        newLicenseIssues = _.reject(newLicenseIssues, (vuln: any) => {
          let licIssueFromArray = vuln.from as Array<string>
          if(mode == 'inline') {
            licIssueFromArray = licIssueFromArray.slice(1,licIssueFromArray.length)
          }
          return (monitoredLicenseIssue.id == vuln.id) && _.isEqual(monitoredLicenseIssue.from, licIssueFromArray)
        })
    })
    
    debug("Severity threshold ",severityThresholds[inboundSevThreshold],inboundSevThreshold)

    return newLicenseIssues.filter(issue => severityThresholds[issue.severity] >= severityThreshold)
}

const displayNewVulns = (newVulns: Array<any>, mode: string): void => {
    if(newVulns.length ==1){
        console.log(chalk.bgHex('#fc9803')("\nNew issue introduced !"))
        console.log("Security Vulnerability:\n")
      } else if(newVulns.length > 1) {
        console.log(chalk.bgMagentaBright("\nNew issues introduced !"))
        console.log("Security Vulnerabilities:")
      }
      newVulns.forEach((vuln,index) => {
        const typedVuln: snykTypes.SnykVuln = vuln as snykTypes.SnykVuln
        switch(vuln.severity){
          case "high":
            console.log(chalk.bold.red(`  ${index+1}/${newVulns.length}: ${vuln.title} [${_.capitalize(vuln.severity)} Severity]`))
            break;
          case "medium":
            console.log(chalk.bold.yellow(`  ${index+1}/${newVulns.length}: ${vuln.title} [${_.capitalize(vuln.severity)} Severity]`))
            break;
          case "low":
            console.log(chalk.bold.blue(`  ${index+1}/${newVulns.length}: ${vuln.title} [${_.capitalize(vuln.severity)} Severity]`))
            break;
          default:
            console.log(chalk.bold(`  ${index+1}/${newVulns.length}: ${vuln.title} [${_.capitalize(vuln.severity)} Severity]`))
        }
        
        let paths = vuln.from as Array<string>
        if(mode == 'inline'){
          paths.shift()
        }
        console.log(chalk("    Via:",paths.join(" => ")))
        if(vuln.fixedIn) {
          console.log(chalk.yellow("    Fixed in:", vuln.packageName, vuln.fixedIn.join(", ")))
          if(vuln.isUpgradable) {
            const upgradePaths: Array<string|boolean> = vuln.upgradePath
            console.log(chalk.green("    Fixable by upgrade: ", upgradePaths.filter(vulnPath => vulnPath != false).join("=>")))
          }
          if(vuln.isPatchable) {
            const patchLink = terminalLink('patch', 'https://support.snyk.io/hc/en-us/articles/360003891078-Snyk-patches-to-fix');
            //console.log("    Fixable by ",patchLink,": ", vuln.patches.map(patch => patch.id))
            console.log(chalk.green("    Fixable by",patchLink,": ", typedVuln.patches.map(patch => patch.id).join(", ")))
          }
        }
        console.log("\n")
      })
}

const displayNewLicenseIssues = (newLicenseIssues: Array<any>, mode: string): void => {
    if(newLicenseIssues.length ==1){
        console.log(chalk.bgHex('#fc9803')("\nNew issue introduced !"))
        console.log("License Issue:\n")
      } else if(newLicenseIssues.length > 1) {
        console.log(chalk.bgMagentaBright("\nNew issues introduced !"))
        console.log("License Issues:")
      }
      newLicenseIssues.forEach((issue,index) => {
        switch(issue.severity){
          case "high":
            console.log(chalk.bold.red(`  ${index+1}/${newLicenseIssues.length}: ${issue.title} [${_.capitalize(issue.severity)} Severity]`))
            break;
          case "medium":
            console.log(chalk.bold.yellow(`  ${index+1}/${newLicenseIssues.length}: ${issue.title} [${_.capitalize(issue.severity)} Severity]`))
            break;
          case "low":
            console.log(chalk.bold.blue(`  ${index+1}/${newLicenseIssues.length}: ${issue.title} [${_.capitalize(issue.severity)} Severity]`))
            break;
          default:
            console.log(chalk.bold(`  ${index+1}/${newLicenseIssues.length}: ${issue.title} [${_.capitalize(issue.severity)} Severity]`))
        }
        
        let paths = issue.from as Array<string>
        if(mode == 'inline'){
          paths.shift()
        }
        console.log(chalk("    Via:",paths.join(" => "),"\n"))
      })
}


const getIssuesDetailsPerPackage = (issuesArray: Array<any>, packageName: string, packageVersion?: string): Array<any> => {
  if(!packageVersion){
    return []
  }
  return issuesArray.filter(issues => (issues.name == packageName || issues.package == packageName) && issues.version == packageVersion)
}

export {
    getNewVulns,
    getNewLicenseIssues,
    displayNewVulns,
    displayNewLicenseIssues,
    getIssuesDetailsPerPackage
}