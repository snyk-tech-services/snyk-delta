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
      console.error(`${error.name}: ${error.message}\n${debugModeMessage}`);
      debug(error);
      break;
    case 'ApiAuthenticationError':
      console.error(
        `${error.name}: ${error.message}\nPlease review that the Snyk token is set and has access to the provided Snyk Organzation and Snyk Project UUIDs`,
      );
      debug(error);
      break;
    case 'NotFoundError':
      console.error(
        `${error.name}: ${error.message}\nCould not find specified resource, please review provided Snyk Organzation and Snyk Project UUIDs`,
      );
      debug(error);
      break;
    case 'BadInputError':
      console.error(
        `${error.name}: ${error.message}\nPlease review the available documentation via -h or the README`,
      );
      debug(error);
      break;
    default:
      console.error(`Unexpected error: ${error.message}\n${debugModeMessage}`);
      debug(error);
  }
};

export default handleError;
