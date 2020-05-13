import makeSnykRequest from './snyk_utils'
import * as Error from '../customErrors/apiError'

const getProject = async (orgID: string, projectID: string) => {

    const projectEndpoint = "/org/"+orgID+"/project/"+projectID
    const project = await makeSnykRequest("GET", projectEndpoint)    
    return project
}

const getProjectUUID = async (orgID: string, nonUUIDProjectID: string, projectType = 'cli') => {
    const allProjectsEndpoint = "/org/"+orgID+"/projects"
    const allProjects = await makeSnykRequest("POST", allProjectsEndpoint)
    const allProjectsArray = allProjects.projects as Array<any>
    const selectedProjectArray: Array<any> = allProjectsArray.filter(project => project.name == nonUUIDProjectID && project.origin == projectType)
    if(selectedProjectArray.length == 0 ) {
        throw new Error.NotFoundError('Snyk API - Could not find a monitored project matching. \
                                        Make sure to specify the right org when snyk test using --org')
    } else if(selectedProjectArray.length > 1 ){
        throw new Error.NotFoundError('Snyk API - Could not find a monitored project matching accurately. \
                                        Make sure to specify the right org when snyk test using --org. Branch support coming soon.')
    }
    return selectedProjectArray[0].id
}
const getProjectIssues = async (orgID: string, projectID: string) => {
    
    // No filter on patched or non patch issue, getting both
    const filters = `{
                        "filters": {
                            "severities": [
                                "high",
                                "medium",
                                "low"
                            ],
                            "exploitMaturity": [
                                "mature",
                                "proof-of-concept",
                                "no-known-exploit",
                                "no-data"
                            ],
                            "types": [
                                "vuln",
                                "license"
                            ],
                            "ignored": false
                        }
                    }
                `
    const projectIssuesEndpoint = "/org/"+orgID+"/project/"+projectID+"/issues"
    const projectIssues = await makeSnykRequest("POST", projectIssuesEndpoint, filters)    
    return projectIssues
}

const getProjectDepGraph = async (orgID: string, projectID: string) => {

    const projectDepGraphEndpoint = "/org/"+orgID+"/project/"+projectID+"/dep-graph"
    const projectDepGraph = await makeSnykRequest("GET", projectDepGraphEndpoint)    
    return projectDepGraph
}

export {
    getProject,
    getProjectIssues,
    getProjectDepGraph,
    getProjectUUID
};