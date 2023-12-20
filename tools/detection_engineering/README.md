[![Python 3.10](https://img.shields.io/badge/python-3.10-yellow.svg)](https://www.python.org/downloads/release/python-3100/)

# Example Code for Managing Detection Rules in Chronicle Security Operations

This directory contains example code that can be used to build a Detection-as-Code CI/CD pipeline to manage rules in
[Chronicle Security Operations](https://cloud.google.com/chronicle-security-operations).

<span style="color: red;">**Important**</span>: This code can modify rules in Chronicle. Please exercise caution and avoid running it in production without
first understanding the code, customizing it for your specific use cases, and testing it.

The example code interacts with Chronicle's [Detection Engine API](https://cloud.google.com/chronicle/docs/reference/detection-engine-api)
and can be used in a CI/CD pipeline (in GitHub, GitLab, CircleCI, etc) to do the following:

* Verify that a rule is a valid YARA-L 2.0 rule without creating a new rule or evaluating it over data
* Retrieve the latest version of all detection rules from Chronicle and write them to local `.yaral` files along with
their current state/configuration
* Update detection rules in Chronicle based on local rule files, e.g., create new rules, create a new rule version, or
enable/disable/archive rules.

Sample detection rules can be found in the [Chronicle Detection Rules](https://github.com/chronicle/detection-rules/tree/main)
repo. Additional example code for interacting with Chronicle's API can be found
[here](https://github.com/chronicle/api-samples-python).

## Setup

```console
# Create and activate a Python virtual environment after cloning this directory into a location of your choosing
$ python3.10 -m virtualenv venv
$ source venv/bin/activate

# Install the project's dependencies
(venv) $ pip install -r requirements.txt
```

Create a `.env` file in the root directory of the project and set the variables below. Alternatively, configure these
as environment variables.

```
# Set LOGGING_LEVEL to DEBUG for more verbose logging
LOGGING_LEVEL=INFO
# Set CHRONICLE_API_BASE_URL to your regional endpoint. Reference: https://cloud.google.com/chronicle/docs/reference/detection-engine-api#regional_endpoints
CHRONICLE_API_BASE_URL="https://backstory.googleapis.com"
AUTHORIZATION_SCOPES={"DETECTION_ENGINE_API":["https://www.googleapis.com/auth/chronicle-backstory"]}
# Your Chronicle representative can provide you with credentials to communicate with the API if needed. Reference: https://cloud.google.com/chronicle/docs/reference/detection-engine-api#getting_api_authentication_credentials
# Your Chronicle API service account key should be stored in the CHRONICLE_API_CREDENTIALS variable in JSON format 
on a single line
CHRONICLE_API_CREDENTIALS={"type":"service_account","project_id":"xxx","private_key_id":"xxx","private_key":"xxx",
"client_email":"xxx","client_id":"xxx","auth_uri":"xxx","token_uri":"xxx",
"auth_provider_x509_cert_url":"xxx","client_x509_cert_url":"xxx","universe_domain":"xxx"}
```

```console
# Verify that the CLI executes successfully
(venv) $ python -m detection_engineering -h
20-Dec-23 12:10:31 MST | INFO | <module> | detection engineering cli started
usage: __main__.py [-h] [--pull-latest-rules] [--update-remote-rules] [--verify-rules] {verify-rule} ...

detection_engineering cli

options:
  -h, --help            show this help message and exit
  --pull-latest-rules   Retrieves the latest version of all rules from Chronicle and updates the local files.
  --update-remote-rules
                        Update rules in Chronicle based on local rule files.
  --verify-rules        Verify that all rules are valid YARA-L 2.0 rules.

subcommands:
  {verify-rule}
    verify-rule         Verify that a rule is a valid YARA-L 2.0 rule.
```

To run the tests.

```console
(venv) $ pip install -r requirements_dev.txt
(venv) $ pytest
```

# Usage

As mentioned above, the example code in this POC can be customized to fit your needs. The CLI commands can be run
individually as shown below.

## Pull latest rules from Chronicle

The pull latest rules command retrieves the latest version of all rules from Chronicle and writes them to `.yaral`
files in the `rules` directory.

The rule state is written to the `rule_config.yaml` file. The rule state contains metadata about the state of each rule
such as whether it is live enabled/disabled, the rule ID, the rule version ID, etc.

Example output from pull latest rules command:

```console
(venv) $ python -m detection_engineering --pull-latest-rules
06-Dec-23 15:14:42 MST | INFO | <module> | Attempting to pull latest version of all Chronicle rules and update local files.
06-Dec-23 15:14:42 MST | INFO | get_remote_rules | Attempting to retrieve all rules from Chronicle.
06-Dec-23 15:14:43 MST | INFO | get_remote_rules | Retrieved a total of 5 rules
06-Dec-23 15:14:43 MST | INFO | dump_rules | Writing 5 rule files files to /Users/x/Documents/projects/detection-engineering/rules
06-Dec-23 15:14:43 MST | INFO | dump_rule_config | Writing rule config to /Users/x/Documents/projects/detection-engineering/rule_config.yaml
```

## Verify rule(s)

The `--verify-rule` and `--verify-rules` commands use Chronicle's API to verify that YARA-L 2.0 rules are valid without
creating a new rule or evaluating it over data.

Example output from verify rule command:

```console
(venv) $ python -m detection_engineering --verify-rule rules/dns_query_to_recently_created_domain.yaral 
06-Dec-23 15:16:07 MST | INFO | <module> | Attempting to verify rule rules/dns_query_to_recently_created_domain.yaral
06-Dec-23 15:16:07 MST | INFO | verify_rule_text | Rule verified successfully (rules/dns_query_to_recently_created_domain.yaral). Context: identified no known errors
```

## Update remote rules

The update remote rules command updates detection rules in Chronicle based on local rule (`.yaral`) files and the
`rule_config.yaml` file. Rule updates include:

* Create a new rule
* Create a new version for a rule
* Live enable/disable a rule (controlled by the `live_rule_enabled: true/false` option for a rule in `rule_config.yaml`)
* Enable/disable alerting for a rule (controlled by the `alerting_enabled: true/false` option for a rule in`rule_config.yaml`)
* Archive/unarchive a rule (controlled by the `archived: true/false` option for a rule in `rule_config.yaml`)

Example output from update remote rules command.

```console
python -m detection_engineering --update-remote-rules 
06-Dec-23 15:23:37 MST | INFO | update_remote_rules | Attempting to update rules in Chronicle based on local rule files.
06-Dec-23 15:23:37 MST | INFO | update_remote_rules | Loading local files from /Users/x/Documents/projects/detection-engineering/rules.
06-Dec-23 15:23:37 MST | INFO | load_rule_config | Loading rule config file from /Users/x/Documents/projects/detection-engineering/rule_config.yaml
06-Dec-23 15:23:37 MST | INFO | load_rules | Loaded 6 rules from /Users/x/Documents/projects/detection-engineering/rules
06-Dec-23 15:23:37 MST | INFO | update_remote_rules | Attempting to retrieve latest version of all rules from Chronicle.
06-Dec-23 15:23:38 MST | INFO | get_remote_rules | Retrieved a total of 5 rules
06-Dec-23 15:23:38 MST | INFO | update_remote_rules | Checking if any rule updates are required.
06-Dec-23 15:23:38 MST | INFO | update_remote_rules | Rule dns_query_to_recently_created_domain (ru_b92e79b0-1459-4927-bddd-8e16405966e6) - ruleText is different. Creating new rule version.
06-Dec-23 15:23:39 MST | INFO | update_remote_rule_state | Rule dns_query_to_recently_created_domain (ru_b92e79b0-1459-4927-bddd-8e16405966e6) - Disabling alerting for rule.
06-Dec-23 15:23:39 MST | INFO | update_remote_rule_state | Rule workspace_2step_verification_disabled (ru_ee15c43a-e295-487b-ae69-2db22d06b46e) - Disabling live rule.
06-Dec-23 15:23:40 MST | INFO | update_remote_rule_state | Rule workspace_2step_verification_disabled (ru_ee15c43a-e295-487b-ae69-2db22d06b46e) - Disabling alerting for rule.
06-Dec-23 15:23:40 MST | INFO | update_remote_rule_state | Rule workspace_2step_verification_disabled (ru_ee15c43a-e295-487b-ae69-2db22d06b46e) - Archiving rule.
06-Dec-23 15:23:41 MST | INFO | update_remote_rules | Local rule name workspace_phishing_alerts not found in remote rules.
06-Dec-23 15:23:41 MST | INFO | update_remote_rules | Local rule workspace_phishing_alerts has no ruleId value. Creating a new rule.
06-Dec-23 15:23:41 MST | INFO | update_remote_rules | Created new rule workspace_phishing_alerts (ru_351a7002-4e09-41e9-9584-f2d5692e447f)
06-Dec-23 15:23:41 MST | INFO | update_remote_rule_state | Rule workspace_phishing_alerts (ru_351a7002-4e09-41e9-9584-f2d5692e447f) - Enabling rule.
06-Dec-23 15:23:42 MST | INFO | update_remote_rule_state | Rule workspace_phishing_alerts (ru_351a7002-4e09-41e9-9584-f2d5692e447f) - Enabling alerting for rule.
06-Dec-23 15:23:42 MST | INFO | update_remote_rules | Logging summary of rule changes...
06-Dec-23 15:23:42 MST | INFO | update_remote_rules | Rules created: 1
06-Dec-23 15:23:42 MST | INFO | update_remote_rules | Rules new_version_created: 1
06-Dec-23 15:23:42 MST | INFO | update_remote_rules | Rules live_enabled: 1
06-Dec-23 15:23:42 MST | INFO | update_remote_rules | Rules live_disabled: 1
06-Dec-23 15:23:42 MST | INFO | update_remote_rules | Rules alerting_enabled: 1
06-Dec-23 15:23:42 MST | INFO | update_remote_rules | Rules alerting_disabled: 2
06-Dec-23 15:23:42 MST | INFO | update_remote_rules | Rules archived: 1
06-Dec-23 15:23:42 MST | INFO | update_remote_rules | Rules unarchived: 0
06-Dec-23 15:23:42 MST | INFO | get_remote_rules | Attempting to retrieve all rules from Chronicle.
06-Dec-23 15:23:43 MST | INFO | get_remote_rules | Retrieved a total of 6 rules
06-Dec-23 15:23:43 MST | INFO | dump_rules | Writing 6 rule files files to /Users/x/Documents/projects/detection-engineering/rules
06-Dec-23 15:23:43 MST | INFO | dump_rule_config | Writing rule config to /Users/x/Documents/projects/detection-engineering/rule_config.yaml
```

## Need help?

Please open an issue in this repo or reach out in the Google Cloud Security [community](https://www.googlecloudcommunity.com/gc/Chronicle/ct-p/security-chronicle).
