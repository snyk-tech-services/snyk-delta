import { isVulnerablePathNew } from '../../../src/lib/utils/issuesUtils';

describe('isVulnerablePathNew', () => {
  it('ignores a version change on a node whose version has build metadata', () => {
    const monitored = ['root@1.0.0', 'lib@1.2.3-rc.4+20261023T094758Z', 'vuln@5.2.0'];
    const current = ['root@1.0.0', 'lib@1.2.4-rc.1+20261024T101010Z', 'vuln@5.2.0'];
    expect(isVulnerablePathNew(monitored, current)).toBe(false);
  });

  it('ignores a version change on a node whose version has no build metadata', () => {
    const monitored = ['root@1.0.0', 'lib@1.2.3', 'vuln@5.2.0'];
    const current = ['root@1.0.0', 'lib@1.2.4', 'vuln@5.2.0'];
    expect(isVulnerablePathNew(monitored, current)).toBe(false);
  });

  it('reports a path through a different package as new', () => {
    const monitored = ['root@1.0.0', 'lib@1.2.3+build1', 'vuln@5.2.0'];
    const current = ['root@1.0.0', 'other@1.2.3+build1', 'vuln@5.2.0'];
    expect(isVulnerablePathNew(monitored, current)).toBe(true);
  });
});
