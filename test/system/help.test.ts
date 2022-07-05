import { exec } from 'child_process';
import { sep } from 'path';
const stripAnsi = require('strip-ansi');
const main = './dist/index.js'.replace(/\//g, sep);

describe('`snyk-delta help <...>`', () => {
  it('Shows help text as expected', (done) => {
    exec(`node ${main} -h`, (err, stdout, stderr) => {
      if (err) {
        throw err;
      }
      expect(err).toBeNull();
      expect(stderr).toEqual('');
      expect(stripAnsi(stdout)).toMatchSnapshot();
    }).on('exit', (code) => {
      expect(code).toEqual(0);
      done();
    });
  }, 10000);
});
