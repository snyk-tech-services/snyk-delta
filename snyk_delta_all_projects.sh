#!/bin/bash

# Call this script as you would call snyk test | snyk-delta, minus the --all-projects and --json flags
# This is an interim fix until snyk-delta supports all projects itself (or snyk supports a --new flag)
# example: /bin/bash snyk_delta_all_projects.sh --severity=high --exclude=tests,resources -- -s config.yaml
# runs snyk test --all-projects --json $*
# requires jq to be installed

set -euo pipefail

exit_code=0
snyk_test_json=''
formatted_json=''
args=("$*")

run_snyk_delta () {
    # add in any other aguments you would like to use
    snyk-delta
}

run_snyk_test () {
    echo "Running: snyk test --all-projects --json" $args
    local snyk_exit_code=0
    {

        snyk_test_json=`snyk test --all-projects --json $args`

        } || {
        snyk_exit_code=$?
        if [ $snyk_exit_code -eq 2 ]
        then
            echo 'snyk test command was not successful, retry with -d to see more information'
            exit 2
        fi
    }


}

format_snyk_test_output() {
    echo "Procesing snyk test --json output"
    {
        formatted_json=`echo $snyk_test_json | jq -r 'if type=="array" then .[] else . end | @base64'`
        } || {
        echo 'failed to process snyk-test result'
        exit 2
    }
}


#######
# 1. run snyk test
run_snyk_test

# 2. format results to support single & multiple results returned
format_snyk_test_output

# 3. call snyk-delta for each result
for test in `echo $formatted_json`; do
    single_result="$(echo ${test} | base64 -d)" # use "base64 -d -i" on Windows, which will ignore any "gardage" characters echoing may add
    project_name="$(echo ${single_result} | jq -r '.displayTargetFile')"
    echo 'Processing: '  ${project_name}
    if echo ${single_result} | run_snyk_delta
    then
        project_exit_code=$?
        echo 'Finished processing'
    else
        project_exit_code=$?
        if [ $project_exit_code -gt 1 ]
        then
            echo 'snyk-delta encountered an error, retrying.'
            echo ${single_result} | run_snyk_delta
        fi
        echo 'Finished processing'
    fi

    if [ $project_exit_code -gt $exit_code ]
    then
        exit_code=$project_exit_code
    fi
    echo "Project: ${project_name} | Exit code: ${project_exit_code}"
done

echo "Overall exit code for snyk-delta-all-projects.sh: ${exit_code}"
exit $exit_code
