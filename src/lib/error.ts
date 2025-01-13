import chalk from 'chalk';
const debugModule = require('debug');

const debugModeMessage =
  'Re-run in debug mode for more information: DEBUG=* snyk-delta <...>';
const handleError = (error: Error):void => {
  const debug = debugModule('snyk');
  if (!process.env.DEBUG) {
    console.log(
      chalk.hex('#316fcc')('Hint: use debug mode -d for more information'),
    );
  }
  switch (error.name) {
    case 'ApiError':
      console.error(`${error.name}: ${error.message}\nAn unexpected error occurred. Check the request details and try again. Alternatively, use debug mode -d for more information. If the issue still occurs, contact support.`,
      );
      debug(error);
      break;
    case 'ApiAuthenticationError':
      console.error(
        `${error.name}: ${error.message}\nPlease review that the Snyk token is set and has access to the provided Snyk Organization and Snyk Project UUIDs. https://docs.snyk.io/snyk-api/rest-api/authentication-for-api/revoke-and-regenerate-a-snyk-api-token`,
      );
      debug(error);
      break;
    case 'NotFoundError':
      console.error(
        `${error.name}: ${error.message}\nCould not find the specified resource, please review the provided Snyk Organization and Snyk Project UUIDs and try again.`,
      );
      debug(error);
      break;
    case 'BadInputError':
      console.error(
        `${error.name}: ${error.message}\nPlease review the available documentation via -h or the README file.`,
      );
      debug(error);
      break;
    default:
      console.error(`Unexpected error: ${error.message}\nAn unexpected error occurred. Check the request details and try again. Alternatively, use debug mode -d for more information. If the issue still occurs, contact support.`);
      debug(error);
  }
};

export default handleError;
