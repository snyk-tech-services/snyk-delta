import * as depgraph from '@snyk/dep-graph'
import * as _ from 'lodash'
import * as chalk from 'chalk'
import {getIssuesDetailsPerPackage} from '../snyk/issues'
import { IssueWithPaths } from '../types'

const displayDependenciesChangeDetails = async (snykDepsJsonResults: any, monitoredProjectDepGraph: any, packageManager: string, newVulns: IssueWithPaths[], newLicenseIssues: IssueWithPaths[]) => {
    let snykTestGraph: depgraph.DepGraph
    if(snykDepsJsonResults && snykDepsJsonResults.depGraph){ // Getting graph
        snykTestGraph = depgraph.createFromJSON(snykDepsJsonResults.depGraph)
    } else { // Getting legacy dep tree
        snykTestGraph = await depgraph.legacy.depTreeToGraph(snykDepsJsonResults as depgraph.legacy.DepTree, packageManager)
    }
    
    //const snykTestDeps = snykTestGraph.getPkgs()
    const snykTestDirectDepsNodeIDs = snykTestGraph.toJSON().graph.nodes[0].deps.map(dep => dep.nodeId)
    const snykTestDirectDeps = snykTestGraph.toJSON().pkgs.filter(pkg => snykTestDirectDepsNodeIDs.indexOf(pkg.id) > 0)
    const snykTestIndirectDeps = snykTestGraph.toJSON().pkgs.filter(pkg => snykTestDirectDepsNodeIDs.indexOf(pkg.id) <= 0)
    
    
    const snykProjectGraph = depgraph.createFromJSON(monitoredProjectDepGraph.depGraph as depgraph.DepGraphData)
    //const snykProjectDeps = snykTestGraph.getPkgs()
    const snykProjectDirectDepsNodeIDs = snykProjectGraph.toJSON().graph.nodes[0].deps.map(dep => dep.nodeId)
    const snykProjectDirectDeps = snykProjectGraph.toJSON().pkgs.filter(pkg => snykProjectDirectDepsNodeIDs.indexOf(pkg.id) > 0)
    const snykProjectIndirectDeps =snykProjectGraph.toJSON().pkgs.filter(pkg => snykProjectDirectDepsNodeIDs.indexOf(pkg.id) <= 0)

    const addedDirectDeps = _.differenceWith(snykTestDirectDeps, snykProjectDirectDeps,_.isEqual)
    const removedDirectDeps = _.differenceWith(snykProjectDirectDeps, snykTestDirectDeps,_.isEqual)

    const addedIndirectDeps = _.differenceWith(snykTestIndirectDeps, snykProjectIndirectDeps,_.isEqual)
    const removedIndirectDeps = _.differenceWith(snykProjectIndirectDeps, snykTestIndirectDeps,_.isEqual)

    


    console.log("_____________________________")
    console.log("Direct deps:")
    console.log(`Added ${addedDirectDeps.length} \n`+addedDirectDeps.map(dep => dep.id))
    console.log("===============")
    console.log(`Removed ${removedDirectDeps.length}\n`+removedDirectDeps.map(dep => dep.id))
    console.log("##################")
    console.log("Indirect deps:")
    console.log(`Added ${addedIndirectDeps.length} \n`+addedIndirectDeps.map(dep => dep.id))
    console.log("===============")
    console.log("Paths")
    
    
    
    const consolidatedIndirectlyAddedDepsPaths = consolidateIndirectDepsPaths(addedIndirectDeps,snykTestGraph)
    addedIndirectDeps.forEach(addedDep => {
        
        //Display all the indirect deps and their paths
        let allPathsForGivenDep = consolidatedIndirectlyAddedDepsPaths.get(addedDep.id)
        //let depNameFormatted = arePathsRemoved? chalk.strikethrough(indirectDep.id): addedDep.id
        let vulnsForDep = getIssuesDetailsPerPackage(newVulns, addedDep.info.name, addedDep.info.version)
        
        const vulnsCount = vulnsForDep.length
         //let d =` - ${(vulnsForDep.length > 0? chalk.redBright(vulnsForDep.length+' vuln(s)'): '0 vuln')}`
        if(allPathsForGivenDep){
            let count = ''
            let paths = '     '+allPathsForGivenDep.map(pathArr=>pathArr.join('=>')).join('\n       ')
            switch(vulnsCount){
                case 0:
                    count = 'no issue'
                    paths = chalk.blue(paths)
                    break;
                case 1:
                    count = chalk.redBright('1 issue')
                default:
                    count = chalk.redBright(vulnsCount+' issue')
                    paths = chalk.redBright(paths)
            }
            
            console.log('   '+addedDep.id+' '+count+ ''+ ':\n'+paths)
        }
    })
    

    //console.log(snykTestAddedIndirectDepsPaths)
    console.log("===============")
    console.log(`Removed ${removedIndirectDeps.length}\n`,removedIndirectDeps.map(dep => dep.id))
    console.log("_____________________________")
    // console.log(chalk.strikethrough(addedDirectDeps))
     // TODO - Dep stats
      // health risk
      // internal usage

      // popularity
      // ranking
      // allowed/not allowed
     // displayIndirectDepsConsolidatedPath(removedIndirectDeps,snykProjectGraph, true)

     const consolidatedIndirectlyRemovedDepsPaths = consolidateIndirectDepsPaths(removedIndirectDeps,snykProjectGraph)
     addedIndirectDeps.forEach(removedDep => {
         //Display all the indirect deps and their paths
         let allPathsForGivenDep = consolidatedIndirectlyRemovedDepsPaths.get(removedDep.id)
         if(allPathsForGivenDep){
             console.log('   ',chalk.strikethrough(removedDep.id), ':\n',chalk.blue('     ',allPathsForGivenDep.map(pathArr=>pathArr.join('=>')).join('\n       ')))
         }
     })
}

const consolidateIndirectDepsPaths = (listOfDeps: Array<any>, snykTestGraph: depgraph.DepGraph): Map<string,string[][]> => {
    let snykIndirectDepsPaths = new Map<string,Array<Array<string>>>()
    listOfDeps.forEach(indirectDep => {
        snykTestGraph.pkgPathsToRoot(indirectDep.info).forEach(individualPath => {
            // Group all paths for a given indirect dep together in a map
            let individualPathFormatted = individualPath.reverse().slice(1).map(pkgInfo => pkgInfo.name+'@'+pkgInfo.version)
            if(snykIndirectDepsPaths.has(indirectDep.id)){
                let pathsArray = snykIndirectDepsPaths.get(indirectDep.id) as Array<Array<string>>
                pathsArray.push(individualPathFormatted)
                snykIndirectDepsPaths.set(indirectDep.id, pathsArray)
                
            } else{
                let pathsArray: Array<Array<string>> = new Array()
                pathsArray.push(individualPathFormatted)
                snykIndirectDepsPaths.set(indirectDep.id, pathsArray)
            }
            
        })
    
    })
    
    return snykIndirectDepsPaths    
}
export {
    displayDependenciesChangeDetails,
    consolidateIndirectDepsPaths,

}