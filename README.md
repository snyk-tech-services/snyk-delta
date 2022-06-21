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
- Snyk Business or Enterprise Account (requires API).
- Your project to be monitored

## Installation
`npm i -g snyk-delta`

or

 Grab a binary of your choice from [the release page](https://github.com/snyk-tech-services/snyk-delta/releases)

## Usage
### 2 mode of operations
- Inline
    - `snyk test --json --print-deps | snyk-delta`

    - Possibly point to a specific snapshot by specifying org+project coordinates\
    `snyk test --json --print-deps | snyk-delta --baselineOrg xxx --baselineProject xxx`
    - Use the --setPassIfNoBaseline if used with snyk prevent commit status and the project is not monitored. This will prevent snyk-prevent_commit_status to fail.
    setPassIfNoBaseline default to false.\
     `snyk test --json --print-deps | snyk-delta --baselineOrg xxx --baselineProject xxx --setPassIfNoBaseline true`

- Standalone
    - `snyk-delta --baselineOrg xxx --baselineProject xxx --currentOrg xxx --currentProject xxx --setPassIfNoBaseline false

> Note:\
> BaselineProject value is expected to be a UUID, not simply a name\
> Check your Snyk Web UI or API to retrieve those UUIDs.

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
Snyk-delta doesn't currently support the `--all-projects` option, but you can try to use [snyk_delta_all_projects.sh](/snyk_delta_all_projects.sh) as a workaround until it does.

