/**
 * Unit tests for SARIF code delta (computeSarifCodeDelta, getBaselineKeyAssetSet, etc.)
 */
import * as path from 'path';
import * as fs from 'fs';
import {
  loadSarifFile,
  parseSarifContent,
  computeSarifCodeDelta,
  computeSarifCodeDeltaAgainstBaselineKeys,
  getBaselineKeyAssetSet,
  collectResults,
} from '../../../src/lib/snyk/sarifCodeDelta';

const fixturesPath = path.resolve(__dirname, '../../fixtures/codeDelta');

describe('sarifCodeDelta', () => {
  describe('loadSarifFile and collectResults', () => {
    it('should load old.sarif.json and collect 1 result', () => {
      const doc = loadSarifFile(path.join(fixturesPath, 'old.sarif.json'));
      const results = collectResults(doc);
      expect(results).toHaveLength(1);
      expect(results[0].fingerprints?.['snyk/asset/finding/v1']).toBe(
        'asset-finding-001',
      );
    });

    it('should load new-with-addition.sarif.json and collect 2 results', () => {
      const doc = loadSarifFile(
        path.join(fixturesPath, 'new-with-addition.sarif.json'),
      );
      const results = collectResults(doc);
      expect(results).toHaveLength(2);
      expect(results[0].fingerprints?.['snyk/asset/finding/v1']).toBe(
        'asset-finding-001',
      );
      expect(results[1].fingerprints?.['snyk/asset/finding/v1']).toBe(
        'asset-finding-002',
      );
    });
  });

  describe('computeSarifCodeDelta', () => {
    it('should report one new finding when new has an extra result', () => {
      const oldSarif = loadSarifFile(path.join(fixturesPath, 'old.sarif.json'));
      const newSarif = loadSarifFile(
        path.join(fixturesPath, 'new-with-addition.sarif.json'),
      );
      const delta = computeSarifCodeDelta(oldSarif, newSarif);

      expect(delta.oldTotal).toBe(1);
      expect(delta.newTotal).toBe(2);
      expect(delta.new).toHaveLength(1);
      expect(delta.new[0].ruleId).toBe('javascript/Sqli');
      expect(delta.new[0].shortDescription).toBe('SQL Injection');
      expect(delta.fixed).toHaveLength(0);
      expect(delta.unchanged).toHaveLength(1);
    });

    it('should report no delta when old and new have same findings', () => {
      const oldSarif = loadSarifFile(path.join(fixturesPath, 'old.sarif.json'));
      const newSarif = loadSarifFile(
        path.join(fixturesPath, 'new-same.sarif.json'),
      );
      const delta = computeSarifCodeDelta(oldSarif, newSarif);

      expect(delta.new).toHaveLength(0);
      expect(delta.fixed).toHaveLength(0);
      expect(delta.unchanged).toHaveLength(1);
    });

    it('should report fixed finding when new has fewer than old', () => {
      const oldSarif = loadSarifFile(
        path.join(fixturesPath, 'new-with-addition.sarif.json'),
      );
      const newSarif = loadSarifFile(path.join(fixturesPath, 'old.sarif.json'));
      const delta = computeSarifCodeDelta(oldSarif, newSarif);

      expect(delta.fixed).toHaveLength(1);
      expect(delta.fixed[0].ruleId).toBe('javascript/Sqli');
      expect(delta.fixed[0].shortDescription).toBe('SQL Injection');
      expect(delta.new).toHaveLength(0);
    });
  });

  describe('getBaselineKeyAssetSet and computeSarifCodeDeltaAgainstBaselineKeys', () => {
    it('should build baseline set from REST issues and mark only non-baseline findings as new', () => {
      const baselineResponse = JSON.parse(
        fs.readFileSync(
          path.join(fixturesPath, 'rest-issues-baseline.json'),
          'utf-8',
        ),
      );
      const set = getBaselineKeyAssetSet(baselineResponse);
      expect(set.has('asset-finding-001')).toBe(true);
      expect(set.size).toBe(1);

      const currentSarif = loadSarifFile(
        path.join(fixturesPath, 'new-with-addition.sarif.json'),
      );
      const delta = computeSarifCodeDeltaAgainstBaselineKeys(currentSarif, set);
      expect(delta.newTotal).toBe(2);
      expect(delta.baselineCount).toBe(1);
      expect(delta.new).toHaveLength(1);
      expect(delta.new[0].ruleId).toBe('javascript/Sqli');
      expect(delta.new[0].shortDescription).toBe('SQL Injection');
    });
  });
});
