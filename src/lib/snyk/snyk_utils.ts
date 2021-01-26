//import * as Configstore from '@snyk/configstore';
const Configstore = require('@snyk/configstore');

const getConfig = () => {
    
    const snykApiEndpoint: string = process.env.SNYK_API || new Configstore('snyk').get('endpoint') || 'https://snyk.io/api/v1'
    const snykToken = process.env.SNYK_TOKEN || new Configstore('snyk').get('api')
    return {endpoint: snykApiEndpoint, token: snykToken}
}

export {getConfig}