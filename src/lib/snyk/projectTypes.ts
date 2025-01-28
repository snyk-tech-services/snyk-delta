/* tslint:disable */
/* eslint-disable */

export interface AutoDependencyUpgradeSettings {
    /**
     * Dependencies which should NOT be included in an automatic upgrade operation.
     * @type {Array<string>}
     * @memberof AutoDependencyUpgradeSettings
     */
    ignoredDependencies?: Array<string>;
    /**
     * Automatically raise pull requests to update out-of-date dependencies.
     * @type {boolean}
     * @memberof AutoDependencyUpgradeSettings
     */
    isEnabled?: boolean;
    /**
     * Apply the auto dependency integration settings of the Organization to this project.
     * @type {boolean}
     * @memberof AutoDependencyUpgradeSettings
     */
    isInherited?: boolean;
    /**
     * Include major version in dependency upgrade recommendation.
     * @type {boolean}
     * @memberof AutoDependencyUpgradeSettings
     */
    isMajorUpgradeEnabled?: boolean;
    /**
     * Limit of dependency upgrade PRs which can be opened simultaneously. When the limit is reached, no new upgrade PRs are created. If specified, must be between 1 and 10.
     * @type {number}
     * @memberof AutoDependencyUpgradeSettings
     */
    limit?: number;
    /**
     * Minimum dependency maturity period in days. If specified, must be between 1 and 365.
     * @type {number}
     * @memberof AutoDependencyUpgradeSettings
     */
    minimumAge?: number;
  }
  
  export interface AutoRemediationPRsSettings {
    /**
     * Automatically create pull requests on scheduled tests for known (backlog) vulnerabilities.
     * @type {boolean}
     * @memberof AutoRemediationPRsSettings
     */
    isBacklogPrsEnabled?: boolean;
    /**
     * Automatically create pull requests on scheduled tests for new vulnerabilities.
     * @type {boolean}
     * @memberof AutoRemediationPRsSettings
     */
    isFreshPrsEnabled?: boolean;
    /**
     * Include vulnerability patches in automatic pull requests.
     * @type {boolean}
     * @memberof AutoRemediationPRsSettings
     */
    isPatchRemediationEnabled?: boolean;
  }
  
  export interface ManualRemediationPRsSettings {
    /**
     * Include vulnerability patches in manual pull requests.
     * @type {boolean}
     * @memberof ManualRemediationPRsSettings
     */
    isPatchRemediationEnabled?: boolean;
  }
  
  export interface PullRequestAssignmentSettings {
    /**
     * Manually specify users to assign (and all will be assigned).
     * @type {Array<string>}
     * @memberof PullRequestAssignmentSettings
     */
    assignees?: Array<string>;
    /**
     * Automatically assign pull requests created by Snyk.
     * @type {boolean}
     * @memberof PullRequestAssignmentSettings
     */
    isEnabled?: boolean;
    /**
     * Automatically assign the last user to change the manifest file (\"auto\"), or manually specify a list of users (\"manual\").
     * @type {string}
     * @memberof PullRequestAssignmentSettings
     */
    type?: PullRequestAssignmentSettingsTypeEnum;
  }
  
  /**
   * @export
   * @enum {string}
   */
  export enum PullRequestAssignmentSettingsTypeEnum {
    Auto = 'auto',
    Manual = 'manual',
  }
  
  export interface PullRequestsSettings {
    /**
     * Only fail when the issues found have a fix available.
     * @type {boolean}
     * @memberof PullRequestsSettings
     */
    failOnlyForIssuesWithFix?: boolean;
    /**
     * Fail if the project has any issues (\"all\"), or fail if a PR is introducing a new dependency with issues (\"only_new\").
     * @type {string}
     * @memberof PullRequestsSettings
     */
    policy?: PullRequestsSettingsPolicyEnum;
    /**
     * Only fail for issues greater than or equal to the specified severity.
     * @type {string}
     * @memberof PullRequestsSettings
     */
    severityThreshold?: PullRequestsSettingsSeverityThresholdEnum;
  }
  
  /**
   * @export
   * @enum {string}
   */
  export enum PullRequestsSettingsPolicyEnum {
    All = 'all',
    OnlyNew = 'only_new',
  }
  /**
   * @export
   * @enum {string}
   */
  export enum PullRequestsSettingsSeverityThresholdEnum {
    Low = 'low',
    Medium = 'medium',
    High = 'high',
    Critical = 'critical',
  }
  
  export interface RecurringTestsSettings {
    /**
     * Test frequency of a project. Also controls when automated PRs may be created.
     * @type {string}
     * @memberof RecurringTestsSettings
     */
    frequency?: RecurringTestsSettingsFrequencyEnum;
  }
  
  /**
   * @export
   * @enum {string}
   */
  export enum RecurringTestsSettingsFrequencyEnum {
    Daily = 'daily',
    Weekly = 'weekly',
    Never = 'never',
  }
  
  /**
   *
   * @export
   * @interface ProjectSettings
   */
  export interface ProjectSettings {
    /**
     *
     * @type {AutoDependencyUpgradeSettings}
     * @memberof ProjectSettings
     */
    autoDependencyUpgrade?: AutoDependencyUpgradeSettings;
    /**
     *
     * @type {AutoRemediationPRsSettings}
     * @memberof ProjectSettings
     */
    autoRemediationPrs?: AutoRemediationPRsSettings;
    /**
     *
     * @type {ManualRemediationPRsSettings}
     * @memberof ProjectSettings
     */
    manualRemediationPrs?: ManualRemediationPRsSettings;
    /**
     *
     * @type {PullRequestAssignmentSettings}
     * @memberof ProjectSettings
     */
    pullRequestAssignment?: PullRequestAssignmentSettings;
    /**
     *
     * @type {PullRequestsSettings}
     * @memberof ProjectSettings
     */
    pullRequests: PullRequestsSettings;
    /**
     *
     * @type {RecurringTestsSettings}
     * @memberof ProjectSettings
     */
    recurring_tests: RecurringTestsSettings;
  }
  
  export interface ProjectsMeta {
    /**
     * The date that the project was last uploaded and monitored using cli.
     * @type {Date}
     * @memberof ProjectsMeta
     */
    cliMonitoredAt?: Date | null;
  }
  
  export interface ContainerBuildArgs {
    /**
     *
     * @type {string}
     * @memberof ContainerBuildArgs
     */
    platform: string;
  }
  
  export interface NugetBuildArgs {
    /**
     *
     * @type {string}
     * @memberof NugetBuildArgs
     */
    targetFramework: string;
  }
  
  export interface PatchProjectRequestDataAttributesTags {
    /**
     *
     * @type {string}
     * @memberof PatchProjectRequestDataAttributesTags
     */
    key?: string;
    /**
     *
     * @type {string}
     * @memberof PatchProjectRequestDataAttributesTags
     */
    value?: string;
  }
  
  export interface YarnBuildArgs {
    /**
     *
     * @type {string}
     * @memberof YarnBuildArgs
     */
    rootWorkspace?: string;
  }
  
  /**
   *
   * @export
   * @interface ProjectAttributes
   */
  export interface ProjectAttributes {
    /**
     *
     * @type {YarnBuildArgs | ContainerBuildArgs | NugetBuildArgs}
     * @memberof ProjectAttributes
     */
    buildArgs?: YarnBuildArgs | ContainerBuildArgs | NugetBuildArgs;
    /**
     *
     * @type {Array<string>}
     * @memberof ProjectAttributes
     */
    businessCriticality?: Array<ProjectAttributesBusinessCriticalityEnum>;
    /**
     * The date that the project was created on
     * @type {Date}
     * @memberof ProjectAttributes
     */
    created: Date;
    /**
     *
     * @type {Array<string>}
     * @memberof ProjectAttributes
     */
    environment?: Array<ProjectAttributesEnvironmentEnum>;
    /**
     *
     * @type {Array<string>}
     * @memberof ProjectAttributes
     */
    lifecycle?: Array<ProjectAttributesLifecycleEnum>;
    /**
     * Project name.
     * @type {string}
     * @memberof ProjectAttributes
     */
    name: string;
    /**
     * The origin the project was added from.
     * @type {string}
     * @memberof ProjectAttributes
     */
    origin: string;
    /**
     *
     * @type {ProjectSettings}
     * @memberof ProjectAttributes
     */
    settings: ProjectSettings;
    /**
     * Describes if a project is currently monitored or it is de-activated.
     * @type {string}
     * @memberof ProjectAttributes
     */
    status: ProjectAttributesStatusEnum;
    /**
     *
     * @type {Array<PatchProjectRequestDataAttributesTags>}
     * @memberof ProjectAttributes
     */
    tags?: Array<PatchProjectRequestDataAttributesTags>;
    /**
     * Path within the target to identify a specific file/directory/image etc. when scanning just part  of the target, and not the entity.
     * @type {string}
     * @memberof ProjectAttributes
     */
    targetFile: string;
    /**
     * The additional information required to resolve which revision of the resource should be scanned.
     * @type {string}
     * @memberof ProjectAttributes
     */
    target_reference: string;
    /**
     * Dotnet Target, for relevant projects
     * @type {string}
     * @memberof ProjectAttributes
     */
    targetRuntime?: string;
    /**
     * The package manager of the project.
     * @type {string}
     * @memberof ProjectAttributes
     */
    type: string;
  }
  
  /**
   * @export
   * @enum {string}
   */
  export enum ProjectAttributesBusinessCriticalityEnum {
    Critical = 'critical',
    High = 'high',
    Medium = 'medium',
    Low = 'low',
  }
  /**
   * @export
   * @enum {string}
   */
  export enum ProjectAttributesEnvironmentEnum {
    Frontend = 'frontend',
    Backend = 'backend',
    Internal = 'internal',
    External = 'external',
    Mobile = 'mobile',
    Saas = 'saas',
    Onprem = 'onprem',
    Hosted = 'hosted',
    Distributed = 'distributed',
  }
  /**
   * @export
   * @enum {string}
   */
  export enum ProjectAttributesLifecycleEnum {
    Production = 'production',
    Development = 'development',
    Sandbox = 'sandbox',
  }
  /**
   * @export
   * @enum {string}
   */
  export enum ProjectAttributesStatusEnum {
    Active = 'active',
    Inactive = 'inactive',
  }
  
  export interface RelatedLink {
    /**
     *
     * @type {LinkProperty}
     * @memberof RelatedLink
     */
    related?: LinkProperty;
  }
  
  export interface TargetDataAttributes {
    /**
     * The human readable name that represents this target. These are generated based on the provided properties, and the source. In the future we may support updating this value.
     * @type {string}
     * @memberof TargetDataAttributes
     */
    displayName?: string;
    /**
     * The URL for the resource. We do not use this as part of our representation of the identity of the target, as it can      be changed externally to Snyk We are reliant on individual integrations providing us with this value. Currently it is only provided by the CLI
     * @type {string}
     * @memberof TargetDataAttributes
     */
    url?: string | null;
  }
  
  export interface TargetData {
    /**
     *
     * @type {TargetDataAttributes}
     * @memberof TargetData
     */
    attributes: TargetDataAttributes;
    /**
     * The Resource ID.
     * @type {string}
     * @memberof TargetData
     */
    id: string;
    /**
     * The Resource type.
     * @type {string}
     * @memberof TargetData
     */
    type: string;
  }
  
  export interface DeprecatedRelationshipData {
    /**
     *
     * @type {string}
     * @memberof DeprecatedRelationshipData
     */
    id: string;
    /**
     * Type of the related resource
     * @type {string}
     * @memberof DeprecatedRelationshipData
     */
    type: string;
  }
  export interface Relationship {
    /**
     *
     * @type {DeprecatedRelationshipData}
     * @memberof Relationship
     */
    data: DeprecatedRelationshipData;
    /**
     *
     * @type {RelatedLink}
     * @memberof Relationship
     */
    links: RelatedLink;
    /**
     *
     * @type {Meta}
     * @memberof Relationship
     */
  }
  export interface LinkProperty {}
  
  export interface RelatedLink {
    /**
     *
     * @type {LinkProperty}
     * @memberof RelatedLink
     */
    related?: LinkProperty;
  }
  
  export interface Target {
    /**
     *
     * @type {TargetData}
     * @memberof Target
     */
    data: TargetData;
    /**
     *
     * @type {RelatedLink}
     * @memberof Target
     */
    links: RelatedLink;
  }
  
  /**
   *
   * @export
   * @interface ProjectRelationships
   */
  export interface ProjectRelationships {
    /**
     *
     * @type {Relationship}
     * @memberof ProjectRelationships
     */
    importer?: Relationship;
    /**
     *
     * @type {Relationship}
     * @memberof ProjectRelationships
     */
    organization: Relationship;
    /**
     *
     * @type {Relationship}
     * @memberof ProjectRelationships
     */
    owner?: Relationship;
    /**
     *
     * @type {Relationship | Target}
     * @memberof ProjectRelationships
     */
    target: Relationship | Target;
  }
  
  /**
   *
   * @export
   * @interface ProjectsData
   */
  export interface ProjectsData {
    /**
     *
     * @type {ProjectAttributes}
     * @memberof ProjectsData
     */
    attributes: ProjectAttributes;
    /**
     * Resource ID.
     * @type {string}
     * @memberof ProjectsData
     */
    id: string;
    /**
     *
     * @type {ProjectsMeta}
     * @memberof ProjectsData
     */
    meta?: ProjectsMeta;
    /**
     *
     * @type {ProjectRelationships}
     * @memberof ProjectsData
     */
    relationships?: ProjectRelationships;
    /**
     * The Resource type.
     * @type {string}
     * @memberof ProjectsData
     */
    type: string;
  }

  export interface ProjectsPostResponseType {
    org?: {
        name?: string;
        /**
         * The identifier of the org
         */
        id?: string;
    };
    /**
     * A list of org's projects
     */
    projects?: {
        name?: string;
        /**
         * The project identifier
         */
        id?: string;
        /**
         * The date that the project was created on
         */
        created?: string;
        /**
         * The origin the project was added from
         */
        origin?: string;
        /**
         * The package manager of the project
         */
        type?: string;
        /**
         * Whether the project is read-only
         */
        readOnly?: boolean;
        /**
         * The frequency of automated Snyk re-test. Can be 'daily', 'weekly or 'never'
         */
        testFrequency?: string;
        /**
         * Number of dependencies of the project
         */
        totalDependencies?: number;
        /**
         * Number of known vulnerabilities in the project, not including ignored issues
         */
        issueCountsBySeverity?: {
            /**
             * Number of low severity vulnerabilities
             */
            low?: number;
            /**
             * Number of medium severity vulnerabilities
             */
            medium?: number;
            /**
             * Number of high severity vulnerabilities
             */
            high?: number;
            /**
             * Number of critical severity vulnerabilities
             */
            critical?: number;
        };
        /**
         * For docker projects shows the ID of the image
         */
        imageId?: string;
        /**
         * For docker projects shows the tag of the image
         */
        imageTag?: string;
        /**
         * For docker projects shows the base image
         */
        imageBaseImage?: string;
        /**
         * For docker projects shows the platform of the image
         */
        imagePlatform?: string;
        /**
         * For Kubernetes projects shows the origin cluster name
         */
        imageCluster?: string;
        /**
         * The project remote repository url. Only set for projects imported via the Snyk CLI tool.
         */
        remoteRepoUrl?: string;
        /**
         * The date on which the most recent test was conducted for this project
         */
        lastTestedDate?: string;
        /**
         * The user who owns the project, null if not set
         *
         * {
         *     "id": "e713cf94-bb02-4ea0-89d9-613cce0caed2",
         *     "name": "example-user@snyk.io",
         *     "username": "exampleUser",
         *     "email": "example-user@snyk.io"
         * }
         */
        owner?: object | null;
        /**
         * URL with project overview
         */
        browseUrl?: string;
        /**
         * The user who imported the project
         */
        importingUser?: {
            /**
             * The ID of the user.
             */
            id?: string;
            /**
             * The name of the user.
             */
            name?: string;
            /**
             * The username of the user.
             */
            username?: string;
            /**
             * The email of the user.
             */
            email?: string;
        };
        /**
         * Describes if a project is currently monitored or it is de-activated
         */
        isMonitored?: boolean;
        /**
         * The monitored branch (if available)
         */
        branch?: string | null;
        /**
         * The identifier for which revision of the resource is scanned by Snyk. For example this may be a branch for SCM project, or a tag for a container image
         */
        targetReference?: string | null;
        /**
         * List of applied tags
         */
        tags?: string[];
        /**
         * Applied project attributes
         */
        attributes?: {
            criticality?: string[];
            environment?: string[];
            lifecycle?: string[];
        };
    }[];
}
export interface ProjectGetResponseType {
    name?: string;
    /**
     * The project identifier
     */
    id?: string;
    /**
     * The date that the project was created on
     */
    created?: string;
    /**
     * The origin the project was added from
     */
    origin?: string;
    /**
     * The package manager of the project
     */
    type?: string;
    /**
     * Whether the project is read-only
     */
    readOnly?: boolean;
    /**
     * The frequency of automated Snyk re-test. Can be 'daily', 'weekly or 'never'
     */
    testFrequency?: string;
    /**
     * Number of dependencies of the project
     */
    totalDependencies?: number;
    /**
     * Number of known vulnerabilities in the project, not including ignored issues
     */
    issueCountsBySeverity?: {
        /**
         * Number of low severity vulnerabilities
         */
        low?: number;
        /**
         * Number of medium severity vulnerabilities
         */
        medium?: number;
        /**
         * Number of high severity vulnerabilities
         */
        high?: number;
        /**
         * Number of critical severity vulnerabilities
         */
        critical?: number;
    };
    /**
     * For docker projects shows the ID of the image
     */
    imageId?: string;
    /**
     * For docker projects shows the tag of the image
     */
    imageTag?: string;
    /**
     * For docker projects shows the base image
     */
    imageBaseImage?: string;
    /**
     * For docker projects shows the platform of the image
     */
    imagePlatform?: string;
    /**
     * For Kubernetes projects shows the origin cluster name
     */
    imageCluster?: string;
    /**
     * The hostname for a CLI project, null if not set
     */
    hostname?: string | null;
    /**
     * The project remote repository url. Only set for projects imported via the Snyk CLI tool.
     */
    remoteRepoUrl?: string;
    /**
     * The date on which the most recent test was conducted for this project
     */
    lastTestedDate?: string;
    /**
     * The user who owns the project, null if not set
     *
     * {
     *     "id": "e713cf94-bb02-4ea0-89d9-613cce0caed2",
     *     "name": "example-user@snyk.io",
     *     "username": "exampleUser",
     *     "email": "example-user@snyk.io"
     * }
     */
    owner?: object | null;
    /**
     * URL with project overview
     */
    browseUrl?: string;
    /**
     * The user who imported the project
     */
    importingUser?: {
        /**
         * The ID of the user.
         */
        id?: string;
        /**
         * The name of the user.
         */
        name?: string;
        /**
         * The username of the user.
         */
        username?: string;
        /**
         * The email of the user.
         */
        email?: string;
    };
    /**
     * Describes if a project is currently monitored or it is de-activated
     */
    isMonitored?: boolean;
    /**
     * The monitored branch (if available)
     */
    branch?: string | null;
    /**
     * The identifier for which revision of the resource is scanned by Snyk. For example this may be a branch for SCM project, or a tag for a container image
     */
    targetReference?: string | null;
    /**
     * List of applied tags
     */
    tags?: {
        [key: string]: any;
    }[];
    /**
     * Applied project attributes
     */
    attributes?: {
        criticality?: {
            [key: string]: any;
        }[];
        environment?: {
            [key: string]: any;
        }[];
        lifecycle?: {
            [key: string]: any;
        }[];
    };
    /**
     * Remediation data (if available)
     */
    remediation?: {
        /**
         * Recommended upgrades to apply to the project
         *
         * (object)
         *     + upgradeTo (string, required) - `package@version` to upgrade to
         *     + upgrades (array[string], required) -  List of `package@version` that will be upgraded as part of this upgrade
         *     + vulns (array[string], required) - List of vulnerability ids that will be fixed as part of this upgrade
         */
        upgrade?: {
            [key: string]: any;
        };
        /**
         * Recommended patches to apply to the project
         *
         * (object)
         *    paths (array) - List of paths to the vulnerable dependency that can be patched
         */
        patch?: {
            [key: string]: any;
        };
        /**
         * Recommended pins to apply to the project (Python only)
         *
         * (object)
         *     + upgradeTo (string, required) - `package@version` to upgrade to
         *     + vulns (array[string], required) - List of vulnerability ids that will be fixed as part of this upgrade
         *     + isTransitive (boolean) - Describes if the dependency to be pinned is a transitive dependency
         */
        pin?: {
            [key: string]: any;
        };
    };
}