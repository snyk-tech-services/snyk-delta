export interface AggregatedissuesPostBodyType {
    /**
     * If set to `true`, Include issue's description, if set to `false` (by default), it won't (Non-IaC projects only)
     */
    includeDescription?: boolean;
    /**
     * If set to `true`, Include issue's introducedThrough, if set to `false` (by default), it won't. It's for container only projects (Non-IaC projects only)
     */
    includeIntroducedThrough?: boolean;
    filters?: {
        /**
         * The severity levels of issues to filter the results by
         */
        severities?: string[];
        /**
         * The exploit maturity levels of issues to filter the results by (Non-IaC projects only)
         */
        exploitMaturity?: string[];
        /**
         * The type of issues to filter the results by (Non-IaC projects only)
         */
        types?: string[];
        /**
         * If set to `true`, only include issues which are ignored, if set to `false`, only include issues which are not ignored
         */
        ignored?: boolean;
        /**
         * If set to `true`, only include issues which are patched, if set to `false`, only include issues which are not patched (Non-IaC projects only)
         */
        patched?: boolean;
        /**
         * The priority to filter the issues by (Non-IaC projects only)
         */
        priority?: {
            /**
             * Include issues where the priority score is between min and max
             */
            score?: {
                min?: number;
                max?: number;
            };
        };
    };
}

export interface AggregatedissuesPostResponseType {
    /**
     * An array of identified issues
     */
    issues?: {
        /**
         * The identifier of the issue
         */
        id: string;
        /**
         * type of the issue ('vuln', 'license' or 'configuration')
         */
        issueType: string;
        /**
         * The package name (Non-IaC projects only)
         */
        pkgName: string;
        /**
         * List of affected package versions (Non-IaC projects only)
         */
        pkgVersions: string[];
        /**
         * The details of the issue
         */
        issueData: {
            /**
             * The identifier of the issue
             */
            id: string;
            /**
             * The issue title
             */
            title: string;
            /**
             * The severity status of the issue, after policies are applied
             */
            severity: string;
            /**
             * The original severity status of the issue, as retrieved from Snyk Vulnerability database, before policies are applied
             */
            originalSeverity: string;
            /**
             * URL to a page containing information about the issue
             */
            url: string;
            description: string;
            /**
             * External identifiers assigned to the issue (Non-IaC projects only)
             */
            identifiers: {
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
             * The list of people responsible for first uncovering or reporting the issue (Non-IaC projects only)
             */
            credit: string[];
            /**
             * The exploit maturity of the issue
             */
            exploitMaturity: string;
            /**
             * The ranges that are vulnerable and unaffected by the issue (Non-IaC projects only)
             */
            semver: {
                /**
                 * The ranges that are vulnerable to the issue. May be an array or a string.
                 */
                vulnerable?: string[];
                /**
                 * The ranges that are unaffected by the issue
                 */
                unaffected?: string;
            };
            /**
             * The date that the vulnerability was first published by Snyk (Non-IaC projects only)
             */
            publicationTime: string;
            /**
             * The date that the vulnerability was first disclosed
             */
            disclosureTime: string;
            /**
             * The CVSS v3 string that signifies how the CVSS score was calculated (Non-IaC projects only)
             */
            CVSSv3: string;
            /**
             * The CVSS score that results from running the CVSSv3 string (Non-IaC projects only)
             */
            cvssScore: number;
            /**
             * The language of the issue (Non-IaC projects only)
             */
            language: string;
            /**
             * A list of patches available for the given issue (Non-IaC projects only)
             */
            patches: string[];
            /**
             * Nearest version which includes a fix for the issue. This is populated for container projects only. (Non-IaC projects only)
             */
            nearestFixedInVersion: string;
            /**
             * Path to the resource property violating the policy within the scanned project. (IaC projects only)
             */
            path: string;
            /**
             * The ID of the violated policy in the issue (IaC projects only)
             */
            violatedPolicyPublicId: string;
            /**
             * Whether the issue is intentional, indicating a malicious package
             */
            isMaliciousPackage: boolean;
        };
        /**
         * The list of what introduced the issue (it is available only for container project with Dockerfile)
         */
        introducedThrough?: string[];
        /**
         * Whether the issue has been patched (Non-IaC projects only)
         */
        isPatched: boolean;
        /**
         * Whether the issue has been ignored
         */
        isIgnored: boolean;
        /**
         * The list of reasons why the issue was ignored
         */
        ignoreReasons?: string[];
        /**
         * Information about fix/upgrade/pinnable options for the issue (Non-IaC projects only)
         */
        fixInfo?: {
            /**
             * Whether all of the issue's paths are upgradable
             */
            isUpgradable?: boolean;
            /**
             * Whether the issue can be fixed by pinning a transitive
             */
            isPinnable?: boolean;
            /**
             * Whether all the of issue's paths are patchable
             */
            isPatchable?: boolean;
            /**
             * Whether all of the issue's paths are fixable. Paths that are already patched are not considered fixable unless they have an alternative remediation (e.g. pinning or upgrading). An upgrade path where the only changes are in transitive dependencies is only considered fixable if the package manager supports it.
             */
            isFixable?: boolean;
            /**
             * Whether any of the issue's paths can be fixed. Paths that are already patched are not considered fixable unless they have an alternative remediation (e.g. pinning or upgrading).  An upgrade path where the only changes are in transitive dependencies is only considered fixable if the package manager supports it.
             */
            isPartiallyFixable?: boolean;
            /**
             * Nearest version which includes a fix for the issue. This is populated for container projects only.
             */
            nearestFixedInVersion?: string;
            /**
             * The set of versions in which this issue has been fixed. If the issue spanned multiple versions (i.e. `1.x` and `2.x`) then there will be multiple `fixedIn` entries
             */
            fixedIn?: string[];
        };
        /**
         * Information about the priority of the issue (Non-IaC projects only)
         */
        priority?: {
            /**
             * The priority score of the issue
             */
            score?: number;
            /**
             * The list of factors that contributed to the priority of the issue
             */
            factors?: string[];
        };
        /**
         * Onward links from this record (Non-IaC projects only)
         */
        links?: {
            /**
             * The URL for the dependency paths that introduce this issue
             */
            paths?: string;
        };
    }[];
}

export interface PathsGetResponseType {
    /**
     * The identifier of the snapshot for which the paths have been found
     */
    snapshotId?: string;
    /**
     * A list of the dependency paths that introduce the issue
     */
    paths?: {
        /**
         * The package name
         */
        name?: string;
        /**
         * The package version
         */
        version?: string;
        /**
         * The version to upgrade the package to in order to resolve the issue. This will only appear on the first element of the path, and only if the issue can be fixed by upgrading packages. Note that if the fix requires upgrading transitive dependencies, `fixVersion` will be the same as `version`.
         */
        fixVersion?: string;
    }[][];
    /**
     * The total number of results
     */
    total?: number;
    /**
     * Onward links from this record
     */
    links?: {
        /**
         * The URL of the previous page of paths for the issue, if not on the first page
         */
        prev?: string;
        /**
         * The URL of the next page of paths for the issue, if not on the last page
         */
        next?: string;
        /**
         * The URL of the last page of paths for the issue
         */
        last?: string;
    };
}