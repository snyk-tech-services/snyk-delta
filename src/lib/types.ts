export interface Identifiers {
  CVE: any[];
  CWE: string[];
  NSP: number[];
}

export interface Patch {
  comments: any[];
  id: string;
  modificationTime: Date;
  urls: string[];
  version: string;
}

export interface Reference {
  title: string;
  url: string;
}

export interface Semver {
  vulnerable: string[];
}

export interface SnykVuln {
  CVSSv3: string;
  alternativeIds: any[];
  creationTime: Date;
  credit: string[];
  cvssScore: number;
  description: string;
  disclosureTime: Date;
  exploit: string;
  fixedIn: string[];
  functions: any[];
  functions_new: any[];
  id: string;
  identifiers: Identifiers;
  language: string;
  modificationTime: Date;
  moduleName: string;
  packageManager: string;
  packageName: string;
  patches: Patch[];
  publicationTime: Date;
  references: Reference[];
  semver: Semver;
  severity: string;
  title: string;
  type?: string;
  from: string[];
  upgradePath: any[];
  isUpgradable: boolean;
  isPatchable: boolean;
  name: string;
  version: string;
}

export type SnykCliTestOutput = {
  vulnerabilities: {
    id: string;
    from: Array<string>;
    severity: string;
    title: string;
    fixedIn?: Array<string>;
    packageName?: string;
    isUpgradable?: boolean;
    isPatchable?: boolean;
    upgradePath?: Array<string>;
    type?: string;
  }[];
};

export type IssueWithPaths = {
  id: string;
  from: Array<string>;
  severity: string;
  title: string;
  fixedIn?: Array<string>;
  packageName?: string;
  isUpgradable?: boolean;
  isPatchable?: boolean;
  upgradePath?: Array<string>;
};

export interface SnykDeltaOutput {
    result: number | undefined,
    newVulns: IssueWithPaths[] | undefined,
    newLicenseIssues: IssueWithPaths[] | undefined
    passIfNoBaseline: boolean | undefined,
    noBaseline: boolean | undefined,
    projectNameOrId: string| undefined,
}

export interface IssuesPostResponseType {
  /**
   * Whether the project has issues (which are not ignored or patched)
   */
  ok: boolean;
  /**
   * Shows a message on deprecation
   */
  deprecated?: string;
  issues: {
      /**
       * A list of vulnerability issues
       */
      vulnerabilities: {
          /**
           * The identifier of the issue
           */
          id: string;
          /**
           * URL to a page containing information about the issue
           */
          url: string;
          /**
           * The issue title
           */
          title: string;
          /**
           * The issue description
           */
          description: string;
          /**
           * The path that the issue was introduced by
           */
          from: string[];
          /**
           * The path to upgrade the package to a non-vulnerable version
           */
          upgradePath: string[];
          /**
           * The name of the package that the issue relates to
           */
          package: string;
          /**
           * The version of the package that the issue relates to
           */
          version: string;
          /**
           * The severity status of the issue, after policies are applied
           */
          severity: string;
          /**
           * The original severity status of the issue, as retrieved from Snyk Vulnerability database, before policies are applied
           */
          originalSeverity: string;
          /**
           * The exploit maturity of the issue
           */
          exploitMaturity: string;
          /**
           * Whether the issue can be fixed by upgrading to a later version of the dependency
           */
          isUpgradable?: boolean;
          /**
           * Whether the issue can be patched
           */
          isPatchable?: boolean;
          /**
           * Whether the issue can be fixed by pinning a transitive
           */
          isPinnable?: boolean;
          /**
           * The date that the vulnerability was first published by Snyk
           */
          publicationTime?: string;
          /**
           * The date that the vulnerability was first disclosed
           */
          disclosureTime?: string;
          /**
           * The language of the issue
           */
          language?: string;
          /**
           * The package manager of the issue
           */
          packageManager?: string;
          /**
           * External identifiers assigned to the issue
           */
          identifiers?: {
              /**
               * Common Vulnerability Enumeration identifiers
               */
              CVE?: string[];
              /**
               * Common Weakness Enumeration identifiers
               */
              CWE?: string[];
              /**
               * Identifiers assigned by the Open Source Vulnerability Database (OSVDB)
               */
              OSVDB?: string[];
          };
          /**
           * The list of people responsible for first uncovering or reporting the issue
           */
          credit?: string[];
          /**
           * The CVSS v3 string that signifies how the CVSS score was calculated
           */
          CVSSv3?: string;
          /**
           * The CVSS score that results from running the CVSSv3 string
           */
          cvssScore?: number;
          priorityScore?: number;
          /**
           * A list of patches available for the given issue
           */
          patches?: string[];
          /**
           * Whether the issue has been ignored
           */
          isIgnored: boolean;
          /**
           * Whether the issue has been patched
           */
          isPatched: boolean;
          /**
           * The ranges that are vulnerable and unaffected by the issue
           */
          semver?: {
              /**
               * The ranges that are vulnerable to the issue
               */
              vulnerable?: string;
              /**
               * The ranges that are unaffected by the issue
               */
              unaffected?: string;
          };
          /**
           * The list of reasons why the issue was ignored
           */
          ignored?: string[];
          /**
           * The list of patches applied to the issue
           */
          patched?: string[];
      }[];
      /**
       * A list of vulnerability issues
       */
      licenses: {
          /**
           * The identifier of the issue
           */
          id: string;
          /**
           * URL to a page containing information about the issue
           */
          url: string;
          /**
           * The issue title
           */
          title: string;
          /**
           * The path that the issue was introduced by
           */
          from: string[];
          /**
           * The name of the package that the issue relates to
           */
          package: string;
          /**
           * The version of the package that the issue relates to
           */
          version: string;
          /**
           * The severity status of the issue
           */
          severity: string;
          priorityScore?: number;
          /**
           * The language of the issue
           */
          language?: string;
          /**
           * The package manager of the issue
           */
          packageManager?: string;
          /**
           * Whether the issue has been ignored
           */
          isIgnored: boolean;
          /**
           * Whether the issue has been patched
           */
          isPatched: boolean;
          /**
           * The list of reasons why the issue was ignored
           */
          ignored?: string[];
          /**
           * The list of patches applied to the issue
           */
          patched?: string[];
      }[];
  };
  /**
   * The number of dependencies the package has
   */
  dependencyCount?: number;
  /**
   * The package manager of the project
   */
  packageManager?: string;
}
export interface ProjectDeltaOutput {
  projectNameOrId: any;
  newVulns: IssueWithPaths[] | undefined,
  newLicenseIssues: IssueWithPaths[] | undefined
  noBaseline: boolean
  passIfNoBaseline: boolean,
  error: number,
}

export interface SnykDeltaInput {
  mode: string | '',
  passIfNoBaseline: boolean | false,
  baselineOrg: string | '',
  baselineProject: string | '',
  currentOrg: string | '',
  currentProject: string | '',
  snykTestOutput: string | '',
  type: string | '',
  passOnFail: boolean | ''
}

export interface GetSnykTestResult {
  snykTestJsonResults: any,
  snykTestJsonDependencies: any,
  projectNameFromJson: any
}
