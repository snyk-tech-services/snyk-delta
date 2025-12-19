import * as _ from 'lodash'
import { IssuesPostResponseType } from '../types';
import { AggregatedIssuesWithVulnPaths } from '../snyk/aggregatedIssues';

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

    const versionPatternRegex = /@[a-zA-Z0-9-_.]+$/

    if (currentSnapshotPathArray.length === 0){
        return false
    }

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

type IssueDataWithMissingField = LegacyVulnerability & Omit<Unpacked<AggregatedIssuesWithVulnPaths['issues']>['issueData'], 'cvssScore'> & {
    isUpgradable?: boolean;
    isPatchable?: boolean;
    isPinnable?: boolean;
}

const convertIntoIssueWithPath = async (aggregatedIssues: AggregatedIssuesWithVulnPaths, _orgId: string, _projectId: string): Promise<IssuesPostResponseType> => {

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
            const aggregatedIssue = aggregatedIssues.issues[issueIndex]
            const aggregatedIssueData = aggregatedIssue.issueData 
            const {cvssScore, ...everythingElse} = aggregatedIssueData
            issuesPostResponse.ok = true

            const fixInfo = aggregatedIssue.fixInfo
            let pkgVersionIndex = 0
            while (pkgVersionIndex < aggregatedIssue.pkgVersions.length)
            {
                const versionKey = aggregatedIssue.pkgVersions[pkgVersionIndex]
                const pathsForVersionEntry = aggregatedIssue.pkgVersionsWithPaths?.find((entry) => Object.prototype.hasOwnProperty.call(entry, versionKey)) as { [key: string]: Array<Array<string>> } | undefined
                const pathsForVersion = pathsForVersionEntry?.[versionKey] ?? []
                const upgradePath = fixInfo?.fixedIn?.length ? fixInfo.fixedIn.map((fixedVersion) => `${aggregatedIssue.pkgName}@${fixedVersion}`) : []

                if (aggregatedIssue.issueType === 'vuln')
                {
                    let LegacyPathIndex = 0
                    
                    while (LegacyPathIndex < pathsForVersion.length)
                    {
                        const issueDataWithMissingField: IssueDataWithMissingField = { from : [], package: '', upgradePath: [], version: '', isPatched: aggregatedIssue.isPatched, isIgnored: aggregatedIssue.isIgnored,cvssScore: cvssScore, ...everythingElse }  

                        issueDataWithMissingField.package = aggregatedIssue.pkgName
                        issueDataWithMissingField.version = versionKey
                        issueDataWithMissingField.from = pathsForVersion[LegacyPathIndex]
                        issueDataWithMissingField.upgradePath = upgradePath
                        issueDataWithMissingField.isUpgradable = fixInfo?.isUpgradable
                        issueDataWithMissingField.isPatchable = fixInfo?.isPatchable
                        issueDataWithMissingField.isPinnable = fixInfo?.isPinnable
                        issuesPostResponse.issues.vulnerabilities.push(issueDataWithMissingField)
                        LegacyPathIndex++
                    }
                         
                } else if (aggregatedIssue.issueType === 'license')
                {
                    let LegacyPathIndex = 0
                    while (LegacyPathIndex < pathsForVersion.length)
                    {
                        const issueDataWithMissingField: IssueDataWithMissingField = { from : [], package: '', upgradePath: [], version: '', isPatched: aggregatedIssue.isPatched, isIgnored: aggregatedIssue.isIgnored, cvssScore: cvssScore, ...everythingElse }  

                        issueDataWithMissingField.package = aggregatedIssue.pkgName
                        issueDataWithMissingField.version = versionKey
                        issueDataWithMissingField.from = pathsForVersion[LegacyPathIndex]
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