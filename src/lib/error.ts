import * as chalk from 'chalk'
const debugModule = require('debug');



const handleError = (error: Error) => {
    const debug = debugModule('snyk')
    if(!process.env.DEBUG) {
        console.log(chalk.hex("#316fcc")("hint: Check debug mode -d"))
    }
    switch(error.name){
        case 'ApiError':
            console.log("Uh oh, seems like we messed something up?")
            debug(error)
            break;
        case 'ApiAuthenticationError':
            console.log("Hum, looks like we have a wrong token?")
            debug(error)
            break;
        case 'NotFoundError':
            console.log("Couldn't find find this resource")
            debug(error)
            break;
        case 'BadInputError':
            console.log("Bad input. Please check the --help")
            debug(error)
            break;
        default:
            //console.log("Unknown error")
            debug(error)
    }
}

export default handleError