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

## Usage
### 2 mode of operations
- Inline
    - `snyk test --json --print-deps | snyk-delta`

    - Possibly point to a specific snapshot by specifying org+project coordinates\
    `snyk test --json --print-deps | snyk-delta --baselineOrg xxx --baselineProject xxx`

- Standalone
    - `snyk-delta --baselineOrg xxx --baselineProject xxx --currentOrg xxx --currentProject xxx

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
- 1 for new issue(s)
- 2 for errors like invalid auth or not found monitored project to compare against

Actual issue(s) details will be listed on stdout.\
JSON output will be added soon.

### Caution
Usage as a module requires list of issues coming from Snyk CLI.
Currently not compatible with data coming straight from Snyk APIs.
