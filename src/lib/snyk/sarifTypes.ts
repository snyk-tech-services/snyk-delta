/**
 * SARIF 2.1 types for Snyk Code results.
 * Used for code delta comparison between baseline and current scan.
 */

export interface SarifRegion {
  startLine?: number;
  endLine?: number;
  startColumn?: number;
  endColumn?: number;
}

export interface SarifArtifactLocation {
  uri: string;
  uriBaseId?: string;
}

export interface SarifPhysicalLocation {
  artifactLocation: SarifArtifactLocation;
  region?: SarifRegion;
}

export interface SarifLocation {
  id?: number;
  physicalLocation: SarifPhysicalLocation;
}

/** SARIF reportingDescriptorReference content (e.g. rule shortDescription). */
export interface SarifMultiformatMessageString {
  text?: string;
}

export interface SarifRule {
  id?: string;
  shortDescription?: SarifMultiformatMessageString;
}

export interface SarifResult {
  ruleId: string;
  ruleIndex?: number;
  level?: string;
  message: {
    text?: string;
    markdown?: string;
    arguments?: string[];
  };
  locations: SarifLocation[];
  fingerprints?: Record<string, string>;
  codeFlows?: unknown[];
  properties?: Record<string, unknown>;
}

export interface SarifRun {
  tool: {
    driver: {
      name: string;
      version?: string;
      rules?: SarifRule[];
    };
  };
  results?: SarifResult[];
}

export interface SarifDocument {
  version: string;
  $schema?: string;
  runs: SarifRun[];
}

export interface SarifCodeFinding {
  result: SarifResult;
  /** Unique key for matching (fingerprint "0" or ruleId+uri+region) */
  key: string;
  uri: string;
  region?: SarifRegion;
  ruleId: string;
  /** From driver rule shortDescription.text when present */
  shortDescription: string;
  message: string;
  level: string;
}
