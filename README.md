![Snyk logo](https://snyk.io/style/asset/logo/snyk-print.svg)

***

<!-- [![Known Vulnerabilities](https://snyk.io/test/github/snyk/snyk-delta/badge.svg)](https://snyk.io/test/github/snyk/snyk-delta) -->
[![CircleCI](https://circleci.com/gh/snyk-tech-services/snyk-delta.svg?style=svg&circle-token=dacfea87c8041e922f2bb391362b3bdb0fd57006)](https://circleci.com/gh/snyk-tech-services/snyk-delta)

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

## Installation
Grab a binary of your choice from [the release page](https://github.com/snyk-tech-services/snyk-delta/releases)

## Usage
### 2 mode of operations
- Inline
    - `snyk test --json --print-deps | snyk-delta`

    - Possibly point to a specific snapshot by specifying org+project coordinates\
    `snyk test --json --print-deps | snyk-delta --baselineOrg xxx --baselineProject xxx`

- Standalone
    - `snyk-delta --baselineOrg xxx --baselineProject xxx --currentOrg xxx --currentProject xxx\

> Note:\
> BaselineProject value is expected to be a UUID, not simply a name\
> Check your Snyk Web UI or API to retrieve those UUIDs.

