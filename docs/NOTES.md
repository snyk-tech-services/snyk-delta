# Technical notes

## Snyk Delta main purpose

Snyk Delta is an utility that effectively compares Snyk result sets to give the **delta** between them.

The main idea is to answer the question: 
`Is there any new issue I'm introducing in this code change/PR.`

It is aimed to consume output from Snyk CLI (the current version of whatever is scanned, typically in a CI build) and compare the result set to the latest recorded result set available ("**baseline**") on the Snyk platform for the project.

If issue X is found in the current CLI output BUT not in the latest result set (aka snapshot), it is then deemed a new issue.

Additionally, when extracting additional details from Snyk CLI print-deps option, more dependency management related information are available of paths of given dependencies, with or without issue(s)

## More details

### Mode of operations

Snyk delta has a few modes which eventually all perform the same comparison takes, the difference being around the source of the "Current Scan" result set.

- [**Inline Mode**] The most used mode is "inline mode" which consumes a json output from the Snyk CLI.

- [**Standalone Mode**] The Standalone mode allow for result set comparison, but this time with the "Current Scan" result set coming from the Snyk platform API instead of the CLI output. It is aimed to compare the same project, monitored across different projects/orgs for any reason, to eventually extra the delta between a scan and a "baseline".

- [**Module**] Snyk-delta is also used as module by other packages to make this delta extraction mechanism available in other use cases, for example [Snyk Prevent Github Commit status](https://github.com/snyk-tech-services/snyk-prevent-gh-commit-status) to depend on the delta result, preventing new issues from being added to the codebase. In this case, the "Current Scan" result set is expected when calling the delta function.

### Overall flow

#### Current Scan

In Inline mode, the flow expects the current scan in json format, for the Snyk CLI directly or via a file that it then printed out+piped via cat command.

In the standalone case, it is retrieved from the Snyk API using the corresponding OrgID and ProjectID arguments.

#### Finding the baseline

The most delicate part is this process is to find the right projects in the midst of projects monitored on the Snyk platform. In order to compare result sets accurately, including taking account ignores and other tweaks made to a project, we need to identify the project precisely.

> **Prerequisite**: \
> Having a baseline. It means that unless a project is Snyk monitored and therefore visible in the Snyk UI, you will not be able to use snyk-delta.
>
> This particular point has been the reason why snyk-delta has historically been able to support only specific Snyk Products to date, instead of all Snyk products.

##### Nominal use case

If nothing is specified, the project ID is generally available in the Snyk CLI output and can be used directly.
Doing so presents the advantage of having a clear result set tightly aligned to a project on the snyk platform, so Snyk CLI settings from the cloud are honored, and the comparison to the baseline result set also trusts ignores that might have applied already.

> **Caution**:\
> In some situations, the Snyk CLI project ID might not be the one expected, or the default organization is different, resulting in a result set having non expected results. Make sure to pass parameters to the Snyk CLI to scan against the right organization and set of policies.
>
> Confusion during Snyk CLI scans around "selected" org and policies make the biggest share of issues reported to date.

##### Override use case

In some cases the baseline to scan against is different than the one reported in the Snyk CLI json result (different org/policy, test branch, etc).
For this kind of situations, snyk-delta takes argument allowing you to specify the exact baseline to compare the results again.

Overriding offers greater flexibility but **requires extra care**, as the delta reported delta might be greater than expected, or not really reflecting the different you want to look into.

#### Comparing the results

Once the baseline details extracted/identified, the Snyk API is used to retrieve the aggregated issues for baseline (and for current scan in standalone mode) as well as vulnerable paths.

The comparison is done precisely to not only understand the existence of an issue, but also is an existing issue also has (a) new vulnerable path(s).

The issues are enriched with the vulnerable paths to be fitting the [IssueWithPaths type](https://github.com/snyk-tech-services/snyk-delta/blob/2687d78e3cfe6382d5c32eda4922542c144b674b/src/lib/types.ts#L73) before being actually compared in [getNewIssues function](https://github.com/snyk-tech-services/snyk-delta/blob/2687d78e3cfe6382d5c32eda4922542c144b674b/src/lib/snyk/issues.ts#L13).
This function compares the issue ID as well as the list of vulnerable paths. New issues or existing issues with new paths will be returned.

Note: Some slight nuances exist between CLI paths and API return vuln paths which require removing the first items in each path in the API results.

#### Computing exit code

A pletora of use cases exists with various settings one can apply to fail on particular threshold for instance, or various other options. The Snyk CLI having lots of options, it is quite challenging to sometimes align them to Snyk delta to have a return code aligned with the Snyk CLI options.
[More details in code](https://github.com/snyk-tech-services/snyk-delta/blob/2687d78e3cfe6382d5c32eda4922542c144b674b/src/lib/snyk/snyk_utils.ts#L16)

#### Printing out the result

Displaying result is different whether or not deps information are passed on by Snyk CLI.

When using --print-deps --json, the Snyk CLI does not export valid JSON as the print deps part takes place before the actual scan, aimed to be for an interactive use. Snyk delta handles this to format proper input json with depgraph information.

Similar dep graph is retrieved from the Snyk API depgraph endpoint in order to compare the depgraphs between current scan and baseline.

Results then show the differences between the depgraphs, highlighting in colors the ones carrying issues, or simply highlighting the "movements" for one's information.
It does call out direct vs indirect dependencies changes, hopefully highlighting more clearly what actually happens under the water....

Reading the code is displayOutput and dependencies files is best to understand what it does.


### Snyk Api evolution

Since its inception, snyk-delta has seen changes resulting of the continuous evolution of Snyk extensive APIs.

One notable change was the decommissioning of the issues endpoint, replaced by the aggregated issues endpoint.
The main change resolved around the issues vulnerable paths on which snyk-delta relied critically.

Following this deprecation, snyk-delta had to adapt and recompose the former issues data model to include the vulnerable paths, computing from aggregated issues endpoints data, enriched with the issues paths endpoint data.

This [logic was encapsulated in the snyk-api-ts-client](https://github.com/snyk-labs/snyk-api-ts-client/blob/c36741731b503b96534777fa1fae68997b5bca54/src/lib/client/abstraction/org/aggregatedissues.ts#L13) which snyk-delta uses to interact with the Snyk API. This client itself is built on top of snyk-request-manager which ensures retries and respectful rates when calling the Snyk API.

To the same extent, in some cases the projects endpoint, now decommissioned in Snyk API v1, was called and is now replaced by REST api endpoint equivalent.


## What's next

[This post](https://github.com/snyk-tech-services/snyk-delta/issues/168#issuecomment-1670098122) might help understanding the current state of this project.

What's next for Snyk-delta is essentially not much. Most capabilities it offers today are planned to eventually be embedded into the Snyk products. When that happens, snyk-delta will be sunset.

In the meantime, it remains an open source project.