//import * as Configstore from '@snyk/configstore';
const Configstore = require('@snyk/configstore');
import axios from 'axios'
import * as Error from '../customErrors/apiError'

const makeSnykRequest = async (verb: string, url: string, body?: string) => {
    const userConfig = getConfig()
    

    const apiClient = axios.create({
        baseURL: userConfig.endpoint,
        responseType: 'json',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'token '+userConfig.token,
          'User-Agent': 'tech-services/snyk-delta/1.0'
        }
      });
      
    try {
        let res;
        if(verb == "GET"){
            res = await apiClient.get(url)
        } else if (verb == "POST"){
            res = await apiClient.post(url,body)
        } else {
            throw new Error.GenericError('Unexpected http command')
        }
        return res.data
        
    } catch (err) {
        if(!err.response){
            throw new Error.GenericError(err)
        }
        switch(err.response.status){
            case 401:
                throw new Error.ApiAuthenticationError(err)
            case 404:
                throw new Error.NotFoundError("Snyk API - Could not find this resource: "+verb+"-"+url)
            case 500:
                throw new Error.ApiError(err)
            default:
                throw new Error.GenericError(err)
        }
    }
    
    
}

const getConfig = () => {
    
    const snykApiEndpoint: string = process.env.SNYK_API || new Configstore('snyk').get('endpoint') || 'https://snyk.io/api/v1'
    const snykToken = process.env.SNYK_TOKEN || new Configstore('snyk').get('api')
    return {endpoint: snykApiEndpoint, token: snykToken}
}

export default makeSnykRequest

export {getConfig}