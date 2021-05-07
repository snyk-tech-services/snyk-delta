import * as _ from 'lodash'

const isVulnerablePathNew = (monitoredSnapshotPathArray: Array<string>, currentSnapshotPathArray: Array<string> ): boolean => {

    const versionPatternRegex = /@[a-zA-Z0-9-_\.]+$/

    return !(_.isEqual(monitoredSnapshotPathArray, currentSnapshotPathArray) || currentSnapshotPathArray.every((path, index) => {
        if(monitoredSnapshotPathArray.length <= 0){
            return false
        }
        return path.split(versionPatternRegex)[0] == monitoredSnapshotPathArray[index].split(versionPatternRegex)[0]
    }))
}

export {
    isVulnerablePathNew
}