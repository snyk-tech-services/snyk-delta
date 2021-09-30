import * as _ from 'lodash'
import { getDebugModule } from './utils';
import { AggregatedIssuesWithVulnPaths } from 'snyk-api-ts-client/dist/client/abstraction/org/aggregatedissues'; 
import { IssuesPostResponseType } from '../types';
import { getUpgradePath } from '../snyk/snyk';

type Unpacked<T> = T extends (infer U)[]
  ? U
  : T extends (...args: any[]) => infer U
  ? U
  : T extends Promise<infer U>
  ? U
  : T;

interface LegacyVulnerability {
    from: string[],
    upgradePath: string[],
    package: string, 
    version: string,
    isPatched: boolean,
    isIgnored: boolean,
    cvssScore: number
}

const isVulnerablePathNew = (monitoredSnapshotPathArray: Array<string>, currentSnapshotPathArray: Array<string> ): boolean => {

    const debug = getDebugModule();
    const versionPatternRegex = /@[a-zA-Z0-9-_\.]+$/
    if(monitoredSnapshotPathArray.length != currentSnapshotPathArray.length){
        // debug('###')
        // debug('Existing path')
        // debug(monitoredSnapshotPathArray)
        // debug('Current path')
        // debug(currentSnapshotPathArray)
        // debug('###')
        return true
    }
    return !(_.isEqual(monitoredSnapshotPathArray, currentSnapshotPathArray) || currentSnapshotPathArray.every((path, index) => {
        if(monitoredSnapshotPathArray.length <= 0){
            return false
        }
        return path.split(versionPatternRegex)[0] == monitoredSnapshotPathArray[index].split(versionPatternRegex)[0]
    }))
}

type IssueDataWithMissingField = LegacyVulnerability & Omit<Unpacked<AggregatedIssuesWithVulnPaths['issues']>['issueData'], 'cvssScore'>

const convertIntoIssueWithPath = async (aggregatedIssues: AggregatedIssuesWithVulnPaths, orgId: string, projectId: string): Promise<IssuesPostResponseType> => {

    const issuesPostResponse: IssuesPostResponseType = {
        ok: false,
        deprecated: undefined,
        issues: {
            vulnerabilities: [],
            licenses: [],
        },
        dependencyCount: undefined,
        packageManager: undefined
    }

    issuesPostResponse.deprecated = "undefined"
    issuesPostResponse.dependencyCount = 0
    issuesPostResponse.packageManager = 'undefined'

    if (aggregatedIssues.issues) 
    {
        let i = 0
        let vulnIssueNumber  = 0
        let licenseIssueNumber = 0
        while (i < aggregatedIssues.issues.length)
        {
            const aggregatedIssueData = aggregatedIssues.issues[i].issueData 
            const issuePaths = await getUpgradePath(orgId, projectId, aggregatedIssueData.id)
            const {cvssScore, ...everythingElse} = aggregatedIssueData
            issuesPostResponse.ok = true

            let j = 0
            while (j < aggregatedIssues.issues[i].pkgVersions.length)
            {
                const versionKey = aggregatedIssues.issues[i].pkgVersions[j]
                if (aggregatedIssues.issues[i].issueType === 'vuln')
                {
                    let p = 0
                    
                    while (p < issuePaths.IssueFromLegacy.length)
                    {
                        const issueDataWithMissingField: IssueDataWithMissingField = { from : [], package: '', upgradePath: [], version: '', isPatched: false, isIgnored: false, cvssScore: parseInt(cvssScore), ...everythingElse }  

                        let sum = vulnIssueNumber + j + p

                        issuesPostResponse.issues.vulnerabilities.push(issueDataWithMissingField)
                        issuesPostResponse.issues.vulnerabilities[sum].package = aggregatedIssues.issues[i].pkgName
                        issuesPostResponse.issues.vulnerabilities[sum].version = versionKey
                        issuesPostResponse.issues.vulnerabilities[sum].from = issuePaths.IssueFromLegacy[p]
                        issuesPostResponse.issues.vulnerabilities[sum].upgradePath = issuePaths.UpgradePathLegacy[p]
                        p++
                    }
                    vulnIssueNumber ++ 
                         
                } else if (aggregatedIssues.issues[i].issueType === 'license')
                {
                    let p = 0
                    while (p < issuePaths.IssueFromLegacy.length)
                    {
                        const issueDataWithMissingField: IssueDataWithMissingField = { from : [], package: '', upgradePath: [], version: '', isPatched: false, isIgnored: false, cvssScore: parseInt(cvssScore), ...everythingElse }  

                        issuesPostResponse.issues.licenses.push(issueDataWithMissingField)
                        issuesPostResponse.issues.licenses[licenseIssueNumber + j + p].package = aggregatedIssues.issues[i].pkgName
                        issuesPostResponse.issues.licenses[licenseIssueNumber + j + p].version = versionKey
                        issuesPostResponse.issues.licenses[licenseIssueNumber + j + p].from = issuePaths.IssueFromLegacy[p]
                        p++
                    }
                    licenseIssueNumber ++
                }
                j++
            }
            i = i + 1
        }
    }
    return issuesPostResponse
}

export {
    isVulnerablePathNew,
    convertIntoIssueWithPath
}