![Snyk logo](https://snyk.io/style/asset/logo/snyk-print.svg)

***

<!-- [![Known Vulnerabilities](https://snyk.io/test/github/snyk/snyk-delta/badge.svg)](https://snyk.io/test/github/snyk/snyk-delta) -->
[![CircleCI](https://circleci.com/gh/snyk-tech-services/snyk-delta.svg?style=svg&circle-token=bfb34e49aa301cfa4ef4272541360a475ff95ad4)](https://circleci.com/gh/snyk-tech-services/snyk-delta)

# Snyk snyk-delta
Prevent feature for CLI tests
Essentially provides the ability to get the delta between 2 Snyk snapshots.\
Particularly useful when running CLI-based scans, like in your local environment, git hooks, etc.\

Compares snapshots to give details about:
- New vulnerabilities not found in the baseline snapshot
- New license issues not found in the baseline snapshot
- Dependency delta between the 2 snaphots
    - Direct Dependencies added and removed
    - Indirect Dependencies added and removed
    - Flag path(s) carrying new vulnerabilities

## Prerequisites
- Snyk Paid Account - Since it requires API usage, it therefore requires a paid account.
- Your project to be monitored

## Installation
`npm i -g snyk-delta`

or

 Grab a binary of your choice from [the release page](https://github.com/snyk-tech-services/snyk-delta/releases)

## Pre-checks

1. Build the dependencies chart that will be the baseline using the ```npm install``` command

2. Run ```snyk test --json --print-deps ``` to confirm the dependency tree is built

## Script Parameters:

- To find the orgID, go to Snyk -> Settings

- To find the projectID go to Snyk -> Select the desired Project -> Grab the UUID from the URL

## How to Use this Script
### 2 modes of operations

1. Point to a specific snapshot by specifying org+project coordinates
   
```snyk test --json --print-deps | snyk-delta --baselineOrg <orgID> --baselineProject <projectID>```

>Use the --setPassIfNoBaseline if used with snyk prevent commit status and the project is not monitored. This will prevent snyk-prevent_commit_status to fail.

> setPassIfNoBaseline is false (by default)

```snyk test --json --print-deps | snyk-delta --baselineOrg <orgID> --baselineProject <projectID> --setPassIfNoBaseline true```

2. Standalone (Comparing a project in an org with a project in a different org)
> This usecase comes up when you have 2 same projects (with distinct project ID's) in 2 different orgs and you want to compare them 

```snyk-delta --baselineOrg <orgID> --baselineProject <projectID> --currentOrg <different orgID> --currentProject <different projectID> --setPassIfNoBaseline false```

>Note: The following is Deprecated
```snyk test --json --print-deps | snyk-delta ``` 

## Usage as module

```
import { getDelta } from 'snyk-delta'

const jsonResultsFromSnykTest = Read from file or pipe snyk test command

const result = await getDelta(jsonResultsFromSnykTest);
```
Result is a number:
- 0 for no new issue
- 1 for new issue(s) or when using strictMode and the unmonitored project has issues (see more details below in StrictMode)
- 2 for errors like invalid auth

Actual issue(s) details will be listed on stdout.\
JSON output will be added soon.

## Help
-h to list help

### StrictMode
When snyk-delta compares test results, it tries to find the same project, monitored on the Snyk platform.
If no monitored project is found, is will return all the issues found by the CLI scan, essentially acting as pass through.

The return code will be 0 if no issue, 1 if issues.

### Caution
Usage as a module requires list of issues coming from Snyk CLI.
Currently not compatible with data coming straight from Snyk APIs.

### all-projects
Snyk-delta doesn't currently support the --all-projects option, but you can try to use snyk_delta_all_projects.sh as a workaround until it does.

