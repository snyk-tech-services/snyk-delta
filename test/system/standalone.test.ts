import { exec } from 'child_process';
import { sep } from 'path';
const stripAnsi = require('strip-ansi');
const main = './dist/index.js'.replace(/\//g, sep);

describe('`snyk-delta <...>`', () => {
  it('Shows error when missing mandatory parameters', (done) => {
    exec(
      `node ${main} --currentOrg uuid --currentProject uuid`,
      (err, stdout, stderr) => {
        expect(err).not.toBeNull();
        expect(stripAnsi(stderr)).toMatchSnapshot();
        expect(stripAnsi(stdout)).toMatchSnapshot();
      },
    ).on('exit', (code) => {
      expect(code).toEqual(2);
      done();
    });
  }, 30000);
});
