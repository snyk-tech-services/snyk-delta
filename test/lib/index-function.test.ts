import * as path from 'path';
import * as fs from 'fs';
import { getSnykTestResult, generateDelta } from '../../src/lib/index';
import * as nock from 'nock';

const fixturesFolderPath = path.resolve(__dirname, '..') + '/fixtures/';

beforeEach(() => {
  return nock('https://snyk.io')
    .persist()
    .post(/.*/)
    .reply(200, (uri) => {
      switch (uri) {
        case '/api/v1/org/playground/project/ab9e037f-9020-4f77-9c48-b1cb0295a4b6/aggregated-issues':
          return fs.readFileSync(
            fixturesFolderPath +
              'apiResponses/test-goof-aggregated-one-vuln-one-license.json',
          );
        default:
      }
    })
    .get(/.*/)
    .reply(200, (uri) => {
      switch (uri) {
        case '/api/v1/org/playground/project/ab9e037f-9020-4f77-9c48-b1cb0295a4b6/dep-graph':
          return fs.readFileSync(
            fixturesFolderPath + 'apiResponses/goof-depgraph-from-api.json',
          );
        case '/api/v1/org/playground/project/ab9e037f-9020-4f77-9c48-b1cb0295a4b6/issue/SNYK-JS-ACORN-559469/paths?perPage=100&page=1':
          return fs.readFileSync(
            fixturesFolderPath +
              'apiResponses/SNYK-JS-ACORN-559469-issue-paths.json',
          );
        case '/api/v1/org/playground/project/ab9e037f-9020-4f77-9c48-b1cb0295a4b6/issue/snyk:lic:npm:goof:GPL-2.0/paths?perPage=100&page=1':
          return fs.readFileSync(
            fixturesFolderPath +
              'apiResponses/snyk-lic-npm-goof-GPL-2-0-issue-paths.json',
          );
        default:
      }
    });
});

describe('Test index functions - getSnykTestResult', () => {
  it('Test getSnykTestResult - inline mode - one project', async () => {
    const snykDeltaInput = {
      mode: 'inline',
      passIfNoBaseline: false,
      baselineOrg: '',
      baselineProject: '',
      currentOrg: '',
      currentProject: '',
      snykTestOutput: fs
        .readFileSync(
          fixturesFolderPath + 'snykTestsOutputs/test-goof-one-vuln.json',
        )
        .toString(),
      type: '',
      passOnFail: true,
    };

    const snykTestResult = await getSnykTestResult(snykDeltaInput);

    expect(snykTestResult).toMatchSnapshot();
  });

  it('Test getSnykTestResult - inline mode - one project - with dependencies', async () => {
    const snykDeltaInput = {
      mode: 'inline',
      passIfNoBaseline: false,
      baselineOrg: '',
      baselineProject: '',
      currentOrg: '',
      currentProject: '',
      snykTestOutput: fs
        .readFileSync(
          fixturesFolderPath + 'snykTestsOutputs/goofSnykTestWithDeps.json',
        )
        .toString(),
      type: '',
      passOnFail: true,
    };

    const snykTestResult = await getSnykTestResult(snykDeltaInput);

    expect(snykTestResult).toMatchSnapshot();
  });

  it('Test getSnykTestResult - inline mode - all-project', async () => {
    const snykDeltaInput = {
      mode: 'inline',
      passIfNoBaseline: false,
      baselineOrg: '',
      baselineProject: '',
      currentOrg: '',
      currentProject: '',
      snykTestOutput: fs
        .readFileSync(
          fixturesFolderPath +
            'snykTestsOutputs/allProjects-test-goof-two-Projects-two-vuln.json',
        )
        .toString(),
      type: '',
      passOnFail: true,
    };

    const snykTestResult = await getSnykTestResult(snykDeltaInput);

    expect(snykTestResult).toMatchSnapshot();
  });
});

describe('Test index functions - generateDelta', () => {
  it('Test generateDelta - inline mode - one project - no new issue', async () => {
    const snykDeltaInput = {
      mode: 'inline',
      passIfNoBaseline: false,
      baselineOrg: 'playground',
      baselineProject: 'ab9e037f-9020-4f77-9c48-b1cb0295a4b6',
      currentOrg: 'playground',
      currentProject: 'ab9e037f-9020-4f77-9c48-b1cb0295a4b5',
      snykTestOutput: fs
        .readFileSync(
          fixturesFolderPath + 'snykTestsOutputs/test-goof-one-vuln.json',
        )
        .toString(),
      type: '',
      passOnFail: true,
    };

    const snykTestProperty = fs.readFileSync(
      fixturesFolderPath +
        'snykTestProperties/snykTestResultOneProjectOneVuln.json',
      'utf8',
    );

    const snykTestPropertyParsed = JSON.parse(snykTestProperty);

    const delta = await generateDelta(snykTestPropertyParsed, snykDeltaInput);
    expect(delta).toMatchSnapshot();
  });

  it('Test generateDelta - inline mode - one project - one new issue', async () => {
    const snykDeltaInput = {
      mode: 'inline',
      passIfNoBaseline: false,
      baselineOrg: 'playground',
      baselineProject: 'ab9e037f-9020-4f77-9c48-b1cb0295a4b6',
      currentOrg: 'playground',
      currentProject: 'ab9e037f-9020-4f77-9c48-b1cb0295a4b5',
      snykTestOutput: fs
        .readFileSync(
          fixturesFolderPath + 'snykTestsOutputs/test-goof-one-vuln.json',
        )
        .toString(),
      type: '',
      passOnFail: true,
    };

    const snykTestProperty = fs.readFileSync(
      fixturesFolderPath +
        'snykTestProperties/snykTestPropertiesTwoProject.json',
      'utf8',
    );

    const snykTestPropertyParsed = JSON.parse(snykTestProperty);

    const delta = await generateDelta(
      snykTestPropertyParsed[0],
      snykDeltaInput,
    );
    expect(delta).toMatchSnapshot();
  });

  // it.todo('Test generateDelta - standalone mode - one project', async () => {
  //   // todo
  // });
});
