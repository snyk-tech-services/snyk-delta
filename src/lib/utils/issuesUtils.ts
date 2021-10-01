import * as _ from 'lodash'
import { getDebugModule } from './utils';
import { AggregatedIssuesWithVulnPaths } from 'snyk-api-ts-client/dist/client/abstraction/org/aggregatedissues'; 
import { IssuesPostResponseType } from '../types';
import { getUpgradePath } from '../snyk/snyk';
import { debug } from 'console';

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
        let issueIndex = 0

        while (issueIndex < aggregatedIssues.issues.length)
        {
            const aggregatedIssueData = aggregatedIssues.issues[issueIndex].issueData 
            const issuePaths = await getUpgradePath(orgId, projectId, aggregatedIssueData.id)
            const {cvssScore, ...everythingElse} = aggregatedIssueData
            issuesPostResponse.ok = true

            let pkgVersionIndex = 0
            while (pkgVersionIndex < aggregatedIssues.issues[issueIndex].pkgVersions.length)
            {
                const versionKey = aggregatedIssues.issues[issueIndex].pkgVersions[pkgVersionIndex]
                if (aggregatedIssues.issues[issueIndex].issueType === 'vuln')
                {
                    let LegacyPathIndex = 0
                    
                    while (LegacyPathIndex < issuePaths.IssueFromLegacy.length)
                    {
                        const issueDataWithMissingField: IssueDataWithMissingField = { from : [], package: '', upgradePath: [], version: '', isPatched: false, isIgnored: false, cvssScore: parseInt(cvssScore), ...everythingElse }  

                        issueDataWithMissingField.package = aggregatedIssues.issues[issueIndex].pkgName
                        issueDataWithMissingField.version = versionKey
                        issueDataWithMissingField.from = issuePaths.IssueFromLegacy[LegacyPathIndex]
                        issueDataWithMissingField.upgradePath = issuePaths.UpgradePathLegacy[LegacyPathIndex]
                        issuesPostResponse.issues.vulnerabilities.push(issueDataWithMissingField)
                        LegacyPathIndex++
                    }
                         
                } else if (aggregatedIssues.issues[issueIndex].issueType === 'license')
                {
                    let LegacyPathIndex = 0
                    while (LegacyPathIndex < issuePaths.IssueFromLegacy.length)
                    {
                        const issueDataWithMissingField: IssueDataWithMissingField = { from : [], package: '', upgradePath: [], version: '', isPatched: false, isIgnored: false, cvssScore: parseInt(cvssScore), ...everythingElse }  

                        issueDataWithMissingField.package = aggregatedIssues.issues[issueIndex].pkgName
                        issueDataWithMissingField.version = versionKey
                        issueDataWithMissingField.from = issuePaths.IssueFromLegacy[LegacyPathIndex]
                        issuesPostResponse.issues.licenses.push(issueDataWithMissingField)
                        LegacyPathIndex++
                    }
                }
                pkgVersionIndex++
            }
            issueIndex = issueIndex + 1
        }
    }
    return issuesPostResponse
}

export {
    isVulnerablePathNew,
    convertIntoIssueWithPath
}