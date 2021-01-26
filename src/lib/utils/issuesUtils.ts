import * as _ from 'lodash'

const isVulnerablePathNew = (monitoredSnapshotPathArray: Array<string>, currentSnapshotPathArray: Array<string> ): boolean => {
    const versionPatternRegex = /@[a-zA-Z0-9-_\.]+$/
    return !(_.isEqual(monitoredSnapshotPathArray, currentSnapshotPathArray) || monitoredSnapshotPathArray.every((path, index) => {
        return path.split(versionPatternRegex)[0] == currentSnapshotPathArray[index].split(versionPatternRegex)[0]
    }))
}

export {
    isVulnerablePathNew
}