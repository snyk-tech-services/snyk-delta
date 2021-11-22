import * as chalk from 'chalk'
import debugModule = require('debug');



const handleError = (error: Error):number => {
    const debug = debugModule('snyk')
    let errorCode = 0
    console.log(error.name)
    if(!process.env.DEBUG) {
        console.log(chalk.hex("#316fcc")("hint: Check debug mode -d"))
    }
    switch(error.name){
        case 'ApiError':
            console.log("Uh oh, seems like we messed something up?")
            debug(error)
            errorCode = 7
            break;
        case 'ApiAuthenticationError':
            console.log("Hum, looks like we have a wrong token?")
            debug(error)
            errorCode = 6
            break;
        case 'NotFoundError':
            console.log("Couldn't find find this resource")
            debug(error)
            errorCode = 5
            break;
        case 'BadInputError':
            console.log("Bad input. Please check the --help")
            debug(error)
            errorCode = 2
            break;
        case 'PrintDepsError':
            console.log("print deps option detected")
            debug(error)
            errorCode = 3
            break;
        case 'BadSnykTestOutput':
            console.log("Snyk test output is not readable")
            debug(error)
            errorCode = 4
            break;
        default:
            console.log("Unknown error")
            debug(error)
            errorCode = 8
    }
    return errorCode
}

export default handleError