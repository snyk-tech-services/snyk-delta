import * as _ from 'lodash'
import { getDebugModule } from './utils';



const isVulnerablePathNew = (monitoredSnapshotPathArray: Array<string>, currentSnapshotPathArray: Array<string> ): boolean => {
    const debug = getDebugModule();
    const versionPatternRegex = /@[a-zA-Z0-9-_\.]+$/
    if(monitoredSnapshotPathArray.length != currentSnapshotPathArray.length){
        debug('###')
        debug('Existing path')
        debug(monitoredSnapshotPathArray)
        debug('Current path')
        debug(currentSnapshotPathArray)
        debug('###')
        return true
    }
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