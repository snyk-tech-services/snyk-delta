import makeSnykRequest, { getConfig } from '../../../src/lib/snyk/snyk_utils';
import * as fs from 'fs';
import * as nock from 'nock';
import * as _ from 'lodash';
import * as path from 'path';
import {
  NotFoundError,
  ApiError,
  ApiAuthenticationError,
  GenericError,
} from '../../../src/lib/customErrors/apiError';

const fixturesFolderPath = path.resolve(__dirname, '../..') + '/fixtures/';
beforeEach(() => {
  return nock('https://snyk.io')
    .get(/\/xyz/)
    .reply(404, '404')
    .post(/\/xyz/)
    .reply(404, '404')
    .get(/\/apierror/)
    .reply(500, '500')
    .post(/\/apierror/)
    .reply(500, '500')
    .get(/\/genericerror/)
    .reply(512, '512')
    .post(/\/genericerror/)
    .reply(512, '512')
    .get(/\/apiautherror/)
    .reply(401, '401')
    .post(/\/apiautherror/)
    .reply(401, '401')
    .post(/^(?!.*xyz).*$/)
    .reply(200, (uri, requestBody) => {
      switch (uri) {
        case '/api/v1/':
          return requestBody;
          break;
        default:
      }
    })
    .get(/^(?!.*xyz).*$/)
    .reply(200, (uri) => {
      switch (uri) {
        case '/api/v1/':
          return fs.readFileSync(
            fixturesFolderPath + 'apiResponses/general-doc.json',
          );
          break;
        default:
      }
    });
});

const OLD_ENV = process.env;
beforeEach(() => {
  jest.resetModules(); // this is important - it clears the cache
  process.env = { ...OLD_ENV };
  delete process.env.SNYK_TOKEN;
});

afterEach(() => {
  process.env = OLD_ENV;
});

describe('Test Snyk Utils make request properly', () => {
  it('Test GET command on /', async () => {
    const response = await makeSnykRequest('GET', '/', '');
    const fixturesJSON = JSON.parse(
      fs
        .readFileSync(fixturesFolderPath + 'apiResponses/general-doc.json')
        .toString(),
    );

    expect(_.isEqual(response, fixturesJSON)).toBeTruthy();
  });
  it('Test POST command on /', async () => {
    const bodyToSend = {
      testbody: {},
    };
    const response = await makeSnykRequest(
      'POST',
      '/',
      JSON.stringify(bodyToSend),
    );
    expect(_.isEqual(response, bodyToSend)).toBeTruthy();
  });
});

describe('Test Snyk Utils error handling/classification', () => {
  it('Test NotFoundError on GET command', async () => {
    try {
      await makeSnykRequest('GET', '/xyz', '');
    } catch (err) {
      expect(err).toBeInstanceOf(NotFoundError);
    }
  });

  it('Test NotFoundError on POST command', async () => {
    try {
      const bodyToSend = {
        testbody: {},
      };
      await makeSnykRequest('POST', '/xyz', JSON.stringify(bodyToSend));
    } catch (err) {
      expect(err).toBeInstanceOf(NotFoundError);
    }
  });

  it('Test ApiError on GET command', async () => {
    try {
      await makeSnykRequest('GET', '/apierror', '');
    } catch (err) {
      expect(err).toBeInstanceOf(ApiError);
    }
  });
  it('Test ApiError on POST command', async () => {
    try {
      const bodyToSend = {
        testbody: {},
      };
      await makeSnykRequest('POST', '/apierror', JSON.stringify(bodyToSend));
    } catch (err) {
      expect(err).toBeInstanceOf(ApiError);
    }
  });

  it('Test ApiAuthenticationError on GET command', async () => {
    try {
      await makeSnykRequest('GET', '/apiautherror', '');
    } catch (err) {
      expect(err).toBeInstanceOf(ApiAuthenticationError);
    }
  });
  it('Test ApiAuthenticationError on POST command', async () => {
    try {
      const bodyToSend = {
        testbody: {},
      };
      await makeSnykRequest(
        'POST',
        '/apiautherror',
        JSON.stringify(bodyToSend),
      );
    } catch (err) {
      expect(err).toBeInstanceOf(ApiAuthenticationError);
    }
  });

  it('Test GenericError on GET command', async () => {
    try {
      await makeSnykRequest('GET', '/genericerror', '');
    } catch (err) {
      expect(err).toBeInstanceOf(GenericError);
    }
  });
  it('Test GenericError on POST command', async () => {
    try {
      const bodyToSend = {
        testbody: {},
      };
      await makeSnykRequest(
        'POST',
        '/genericerror',
        JSON.stringify(bodyToSend),
      );
    } catch (err) {
      expect(err).toBeInstanceOf(GenericError);
    }
  });
});

describe('Test getConfig function', () => {
  it('Get snyk token via env var', async () => {
    process.env.SNYK_TOKEN = '123';
    expect(getConfig().token).toEqual('123');
  });

  it('Get snyk.io api endpoint default', async () => {
    expect(getConfig().endpoint).toEqual('https://snyk.io/api/v1');
  });

  it('Get snyk api endpoint via env var', async () => {
    process.env.SNYK_API = 'API';
    expect(getConfig().endpoint).toEqual('API');
  });
});
