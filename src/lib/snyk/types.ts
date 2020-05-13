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

