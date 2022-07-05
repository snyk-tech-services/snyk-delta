![Snyk logo](https://snyk.io/style/asset/logo/snyk-print.svg)

***

[![Known Vulnerabilities](https://snyk.io/test/github/snyk-tech-services/snyk-delta/badge.svg)](https://snyk.io/test/github/snyk/snyk-delta)
[![CircleCI](https://circleci.com/gh/snyk-tech-services/snyk-delta.svg?style=svg&circle-token=bfb34e49aa301cfa4ef4272541360a475ff95ad4)](https://circleci.com/gh/snyk-tech-services/snyk-delta)
[![Not Maintained](https://img.shields.io/badge/Maintenance%20Level-Not%20Maintained-yellow.svg)](https://gist.github.com/cheerfulstoic/d107229326a01ff0f333a1d3476e068d)

**This repository is not in active development and critical bug fixes only will be considered.**

# Snyk snyk-delta
Fail the [Snyk CLI](https://github.com/snyk/cli) scans during CI/CD only if there are new issues introduced (similar to Snyk PR checks).
Gets the delta between 2 Snyk project snapshots before failing the scan. Particularly useful when running [Snyk CLI](https://github.com/snyk/cli) scans in your local environment, git hooks, CI/CD etc.

Compares 2 Snyk project snapshots to provide details on:
- New vulnerabilities not found in the baseline snapshot
- New license issues not found in the baseline snapshot
- Dependencies delta between 2 snapshots:
    - direct dependencies added and removed
    - indirect dependencies added and removed
    - issue path(s) introducing new vulnerabilities

## Prerequisites
- Snyk Business or Enterprise Account (requires API access)
- Project must be monitored in Snyk to provide a baseline to compare against
- set the API token in the `SNYK_TOKEN` enviroment variable. Create a [service account](https://docs.snyk.io/features/user-and-group-management/managing-groups-and-organizations/service-accounts) in Snyk and use the provided token.

## Installation
`npm i -g snyk-delta` or grab a binary from [the release page](https://github.com/snyk-tech-services/snyk-delta/releases)

## Usage
- `--baselineOrg` *optional*

  Organization to use as baseline. Snyk organization ID can be located in the [organization settings](https://docs.snyk.io/products/snyk-code/cli-for-snyk-code/before-you-start-set-the-organization-for-the-cli-tests/finding-the-snyk-id-and-internal-name-of-an-organization)

  *Example*: `--orgID 0e9373a6-f858-11ec-b939-0242ac120002`

- `--baselineProject` *optional*

  Project to use as baseline. Public Snyk project ID can be located in [project settings](https://docs.snyk.io/introducing-snyk/introduction-to-snyk-projects/view-project-settings)

  *Example*: `--baselineProject 0e9373a6-f858-11ec-b939-0242ac120002`

- `--currentProject` *optional*

  Project to compare. Public Snyk project ID can be located in [project settings](https://docs.snyk.io/introducing-snyk/introduction-to-snyk-projects/view-project-settings)


  *Example*: `--currentProject 0e9373a6-f858-11ec-b939-0242ac120002`

- `currentOrg` *optional*

  Organization to compare. Snyk organization ID can be located in the [organization settings](https://docs.snyk.io/products/snyk-code/cli-for-snyk-code/before-you-start-set-the-organization-for-the-cli-tests/finding-the-snyk-id-and-internal-name-of-an-organization)

  *Example*: `--orgID 0e9373a6-f858-11ec-b939-0242ac120002`
- `--fail-on` *optional*

  [As in Snyk CLI](https://docs.snyk.io/snyk-cli/test-for-vulnerabilities/advanced-failing-of-builds-in-snyk-cli) with the `--fail-on` flag return non 0 error code when new issues are upgradable, patchable, or both (all)..

   *Example*: `--fail-on all`

- `--setPassIfNoBaseline` *optional*

  Do not fail with exit code `1` if the current project is not monitored in Snyk and could not be compared. When `snyk-delta` compares test results, it tries to find the same project monitored on the Snyk platform. If no monitored project is found, is will return all the issues found by the CLI scan, essentially acting as pass through if this is enabled.

   *Example*: `--setPassIfNoBaseline true`

- `--type` *optional*

  Specify Snyk issue type to compare. Defaults `all`, available options: `vuln`, `license`, `all`.

   *Example*: `--type vuln`
### Mode: Inline
- `snyk test --json --print-deps | snyk-delta`
- Point to a specific Snyk project  snapshot by specifying org+project coordinates

  `snyk test --json --print-deps | snyk-delta --baselineOrg xxx --baselineProject xxx`
- Use the `--setPassIfNoBaseline` if used with [snyk-prevent-gh-commit-status](https://github.com/snyk-tech-services/snyk-prevent-gh-commit-status) and the project is not monitored. This will prevent [snyk-prevent-gh-commit-status](https://github.com/snyk-tech-services/snyk-prevent-gh-commit-status) to fail. `setPassIfNoBaseline` defaults to `false`.

    `snyk test --json --print-deps | snyk-delta --baselineOrg xxx --baselineProject xxx --setPassIfNoBaseline true`

### Mode: Standalone
- `snyk-delta --baselineOrg xxx --baselineProject xxx --currentOrg xxx --currentProject xxx --setPassIfNoBaseline false`

## Usage as module

```
import { getDelta } from 'snyk-delta'

const jsonResultsFromSnykTest = Read from file or pipe snyk test command

const result = await getDelta(jsonResultsFromSnykTest);
```
Actual issue(s) details will be listed on stdout.

## Help
`snyk-delta -h` to see help documentation.

## Exit codes
- `0` - no new license/vulnerability issues introduced
- `1` - new license/vulnerability issues introduced
- `2` - error
### Caution
Usage as a module requires list of issues coming from Snyk CLI.
Currently not compatible with data coming straight from Snyk APIs.

### `snyk test --all-projects` support
Snyk-delta doesn't currently support the `--all-projects` option, but you can try to use [snyk_delta_all_projects.sh](./snyk_delta_all_projects.sh) as an example of how to work around this.

