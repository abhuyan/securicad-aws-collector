# securiCAD AWS Collector

A Python package for collecting AWS data for use in [foreseeti's securiCAD](https://foreseeti.com/securicad/) products

<!-- Generated with https://github.com/ekalinin/github-markdown-toc -->
## Table of Contents

* [Installation](#installation)
* [Usage](#usage)
* [Quick Start](#quick-start)
* [Collecting AWS Data](#collecting-aws-data)
* [Configuration](#configuration)
   * [1. Directly on the Command-Line](#1-directly-on-the-command-line)
      * [IAM User](#iam-user)
      * [IAM Role](#iam-role)
   * [2. With a Profile Specified on the Command-Line](#2-with-a-profile-specified-on-the-command-line)
   * [3. With a Configuration File Specified on the Command-Line](#3-with-a-configuration-file-specified-on-the-command-line)
   * [4. From the Environment](#4-from-the-environment)
* [License](#license)

## Installation

You need at least python 3.8 for this to work.

Install `securicad-aws-collector` with pip:

```shell
pip install securicad-aws-collector
```

## Usage

The securiCAD AWS Collector collects environment information from the AWS APIs, and stores the result in a JSON file.
To gain access to the AWS APIs, the securiCAD AWS Collector needs to be configured with the credentials of an IAM user or an IAM role with this [IAM policy](iam_policy.json).
It also needs to be configured with an AWS region to know where to collect environment information from.

## Quick Start

Below are a few examples of how to run the securiCAD AWS Collector.
The script stores the collected data in a file named `aws.json`.
This can be overridden with the command-line argument `--output`.
See the full list of configuration options under [Configuration](#configuration).

* Use credentials of an IAM user and a region:

```shell
securicad-aws-collector --access-key 'ACCESS_KEY' --secret-key 'SECRET_KEY' --region 'REGION'
```

* Use a pre-configured profile from `~/.aws/credentials` or `~/.aws/config`:

```shell
securicad-aws-collector --profile securicad
```

* Use a [configuration file](#configuration):

```shell
securicad-aws-collector --config config.json
```

* Use the default profile to assume an IAM role:

```shell
securicad-aws-collector --role arn:aws:iam::123456789012:role/securicadaccess
```

* Use a specific profile to assume an IAM role:

```shell
securicad-aws-collector --profile securicad --role arn:aws:iam::123456789012:role/securicadaccess
```

## Collecting AWS Data

### Command line

The securiCAD AWS Collector stores the collected data in a file named `aws.json` by default.
This can be overridden with the command-line argument `--output`:

```shell
securicad-aws-collector --profile securicad --output securicad.json
```

By default, Amazon Inspector findings are not included in the collected data.
Use the command-line argument `--inspector` to include Amazon Inspector findings:

```shell
securicad-aws-collector --profile securicad --inspector
```

Information about other available command-line arguments can be found with the command-line argument `--help`:

```shell
securicad-aws-collector --help
```

### Python

You need to create a configuration for the scanner. If you have a number of accounts with a role in each of them for collecting information it might look like this.

```python
{ "accounts": [
    {
      "role": "arn:aws:iam::1234567891:role/aws-collector",
      "regions": [ "eu-central-1" ]
    }
  ]
}
```

For more examples of configurations please see [these examples](#3-with-a-configuration-file-specified-on-the-command-line).

This could be stored in a a systems manager parameter or somewhere else. However you store it, once you have it you can simply send it in as a parameter to the collector.

```python
data = aws_collector.collect(config)
```

So an entire example might look something like this:

```python
# fetch config
ssmclient = boto3.client("ssm")
config_param = ssmclient.get_parameter(Name="/SecuricadCollector/config")
text = config_param["Parameter"]["Value"]
config = json.loads(text)

# fetch environment
data = aws_collector.collect(config)

# upload data to securicad and build model
auth_data = retrieve_auth_config()
client = enterprise.client(
    "https://foreseeti.enterprise.securicad.com",
    username=auth_data["username"],
    password=auth_data["password"],
    organization=auth_data["organization"],
)
project = client.projects.get_project_by_name(name="automated")
model_info = client.parsers.generate_aws_model(project, name="automated_scan", cli_files=[data])
```

And from that point you have a securicad model and can use it. Note that it will not have consequences set, you will need to set those with tunings. See either [this way](https://github.com/foreseeti/securicad-enterprise-sdk#high-value-assets) or [through tunings](https://github.com/foreseeti/securicad-enterprise-sdk#consequence-setting-the-consequence-of-attack-steps) for more information. If you want to run multiple scenarios you can use [batch operations](https://github.com/foreseeti/securicad-enterprise-sdk#batch-scenario-operations).

## Configuration

The securiCAD AWS Collector can be configured with credentials and region in four ways:

1. Directly on the command-line
2. With a profile specified on the command-line
3. With a configuration file specified on the command-line
4. From the environment

### 1. Directly on the Command-Line

Configuring credentials directly on the command-line is not recommended, since the keys will be leaked into the process table and the shell's history file.

#### IAM User

[Create an IAM user](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_create.html) with this [IAM policy](iam_policy.json) and [generate an access key](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html) for the IAM user.

Pass the credentials of an IAM user directly on the command-line:

```shell
securicad-aws-collector \
  --access-key 'AKIAIOSFODNN7EXAMPLE' \
  --secret-key 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY' \
  --region 'us-east-1'
```

Use a configured IAM user to assume an IAM role:

```shell
securicad-aws-collector \
  --access-key 'AKIAIOSFODNN7EXAMPLE' \
  --secret-key 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY' \
  --role 'arn:aws:iam::123456789012:role/securicadaccess' \
  --region 'us-east-1'
```

#### IAM Role

[Create an IAM role](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user.html) with this [IAM policy](iam_policy.json).

Assume the role:

```shell
aws sts assume-role --role-arn arn:aws:iam::123456789012:role/securicadaccess --role-session-name securicad
```

This will output temporary credentials:

```json
{
    "AssumedRoleUser": {
        "AssumedRoleId": "AROA3XFRBF535PLBIFPI4:securicad",
        "Arn": "arn:aws:sts::123456789012:assumed-role/securicadaccess/securicad"
    },
    "Credentials": {
        "SecretAccessKey": "9drTJvcXLB89EXAMPLELB8923FB892xMFI",
        "SessionToken": "AQoXdzELDDY//////////wEaoAK1wvxJY12r2IrDFT2IvAzTCn3zHoZ7YNtpiQLF0MqZye/qwjzP2iEXAMPLEbw/m3hsj8VBTkPORGvr9jM5sgP+w9IZWZnU+LWhmg+a5fDi2oTGUYcdg9uexQ4mtCHIHfi4citgqZTgco40Yqr4lIlo4V2b2Dyauk0eYFNebHtYlFVgAUj+7Indz3LU0aTWk1WKIjHmmMCIoTkyYp/k7kUG7moeEYKSitwQIi6Gjn+nyzM+PtoA3685ixzv0R7i5rjQi0YE0lf1oeie3bDiNHncmzosRM6SFiPzSvp6h/32xQuZsjcypmwsPSDtTPYcs0+YN/8BRi2/IcrxSpnWEXAMPLEXSDFTAQAM6Dl9zR0tXoybnlrZIwMLlMi1Kcgo5OytwU=",
        "Expiration": "2016-03-15T00:05:07Z",
        "AccessKeyId": "ASIAJEXAMPLEXEG2JICEA"
    }
}
```

Pass `.Credentials.AccessKeyId`, `.Credentials.SecretAccessKey`, and `.Credentials.SessionToken` directly on the command-line:

```shell
securicad-aws-collector \
  --access-key 'ASIAJEXAMPLEXEG2JICEA' \
  --secret-key '9drTJvcXLB89EXAMPLELB8923FB892xMFI' \
  --session-token 'AQoXdzELDDY//////////wEaoAK1wvxJY12r2IrDFT2IvAzTCn3zHoZ7YNtpiQLF0MqZye/qwjzP2iEXAMPLEbw/m3hsj8VBTkPORGvr9jM5sgP+w9IZWZnU+LWhmg+a5fDi2oTGUYcdg9uexQ4mtCHIHfi4citgqZTgco40Yqr4lIlo4V2b2Dyauk0eYFNebHtYlFVgAUj+7Indz3LU0aTWk1WKIjHmmMCIoTkyYp/k7kUG7moeEYKSitwQIi6Gjn+nyzM+PtoA3685ixzv0R7i5rjQi0YE0lf1oeie3bDiNHncmzosRM6SFiPzSvp6h/32xQuZsjcypmwsPSDtTPYcs0+YN/8BRi2/IcrxSpnWEXAMPLEXSDFTAQAM6Dl9zR0tXoybnlrZIwMLlMi1Kcgo5OytwU=' \
  --region 'us-east-1'
```

Use a configured IAM role to assume another IAM role:

```shell
securicad-aws-collector \
  --access-key 'ASIAJEXAMPLEXEG2JICEA' \
  --secret-key '9drTJvcXLB89EXAMPLELB8923FB892xMFI' \
  --session-token 'AQoXdzELDDY//////////wEaoAK1wvxJY12r2IrDFT2IvAzTCn3zHoZ7YNtpiQLF0MqZye/qwjzP2iEXAMPLEbw/m3hsj8VBTkPORGvr9jM5sgP+w9IZWZnU+LWhmg+a5fDi2oTGUYcdg9uexQ4mtCHIHfi4citgqZTgco40Yqr4lIlo4V2b2Dyauk0eYFNebHtYlFVgAUj+7Indz3LU0aTWk1WKIjHmmMCIoTkyYp/k7kUG7moeEYKSitwQIi6Gjn+nyzM+PtoA3685ixzv0R7i5rjQi0YE0lf1oeie3bDiNHncmzosRM6SFiPzSvp6h/32xQuZsjcypmwsPSDtTPYcs0+YN/8BRi2/IcrxSpnWEXAMPLEXSDFTAQAM6Dl9zR0tXoybnlrZIwMLlMi1Kcgo5OytwU=' \
  --role 'arn:aws:iam::123456789012:role/securicadaccess' \
  --region 'us-east-1'
```

### 2. With a Profile Specified on the Command-Line

You can configure profiles in `~/.aws/credentials` or `~/.aws/config`.

Example for `~/.aws/credentials`:

```ini
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY
region = us-east-1

[securicad-user]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY
region = us-east-1

[securicad-role1]
aws_access_key_id = ASIAJEXAMPLEXEG2JICEA
aws_secret_access_key = 9drTJvcXLB89EXAMPLELB8923FB892xMFI
aws_session_token = AQoXdzELDDY//////////wEaoAK1wvxJY12r2IrDFT2IvAzTCn3zHoZ7YNtpiQLF0MqZye/qwjzP2iEXAMPLEbw/m3hsj8VBTkPORGvr9jM5sgP+w9IZWZnU+LWhmg+a5fDi2oTGUYcdg9uexQ4mtCHIHfi4citgqZTgco40Yqr4lIlo4V2b2Dyauk0eYFNebHtYlFVgAUj+7Indz3LU0aTWk1WKIjHmmMCIoTkyYp/k7kUG7moeEYKSitwQIi6Gjn+nyzM+PtoA3685ixzv0R7i5rjQi0YE0lf1oeie3bDiNHncmzosRM6SFiPzSvp6h/32xQuZsjcypmwsPSDtTPYcs0+YN/8BRi2/IcrxSpnWEXAMPLEXSDFTAQAM6Dl9zR0tXoybnlrZIwMLlMi1Kcgo5OytwU=
region = us-east-1
```

Example for `~/.aws/config`:

```ini
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY
region = us-east-1

[profile securicad-user]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY
region = us-east-1

[profile securicad-role1]
aws_access_key_id = ASIAJEXAMPLEXEG2JICEA
aws_secret_access_key = 9drTJvcXLB89EXAMPLELB8923FB892xMFI
aws_session_token = AQoXdzELDDY//////////wEaoAK1wvxJY12r2IrDFT2IvAzTCn3zHoZ7YNtpiQLF0MqZye/qwjzP2iEXAMPLEbw/m3hsj8VBTkPORGvr9jM5sgP+w9IZWZnU+LWhmg+a5fDi2oTGUYcdg9uexQ4mtCHIHfi4citgqZTgco40Yqr4lIlo4V2b2Dyauk0eYFNebHtYlFVgAUj+7Indz3LU0aTWk1WKIjHmmMCIoTkyYp/k7kUG7moeEYKSitwQIi6Gjn+nyzM+PtoA3685ixzv0R7i5rjQi0YE0lf1oeie3bDiNHncmzosRM6SFiPzSvp6h/32xQuZsjcypmwsPSDtTPYcs0+YN/8BRi2/IcrxSpnWEXAMPLEXSDFTAQAM6Dl9zR0tXoybnlrZIwMLlMi1Kcgo5OytwU=
region = us-east-1

[profile securicad-role2]
role_arn = arn:aws:iam::123456789012:role/securicadaccess
source_profile = securicad-user
role_session_name = securicad
region = us-east-1
```

Run the securiCAD AWS Collector without arguments to use the default profile:

```shell
securicad-aws-collector
```

Specify the profile on the command-line:

```shell
securicad-aws-collector --profile securicad-user
```

The region in the profile can be overridden with the command-line argument `--region`:

```shell
securicad-aws-collector --region us-east-2
securicad-aws-collector --profile securicad-user --region us-east-2
```

Use a configured profile to assume an IAM role:

```shell
securicad-aws-collector --role 'arn:aws:iam::123456789012:role/securicadaccess'
securicad-aws-collector --profile securicad-user --role 'arn:aws:iam::123456789012:role/securicadaccess'
```

### 3. With a Configuration File Specified on the Command-Line

You can configure credentials and region in a JSON file.
Using a JSON file for configuration allows you to specify multiple accounts and multiple regions per account.

Configure the credentials of an IAM user:

```json
{
  "accounts": [
    {
      "access_key": "AKIAIOSFODNN7EXAMPLE",
      "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY",
      "regions": ["us-east-1"]
    }
  ]
}
```

Configure the credentials of an IAM role:

```json
{
  "accounts": [
    {
      "access_key": "ASIAJEXAMPLEXEG2JICEA",
      "secret_key": "9drTJvcXLB89EXAMPLELB8923FB892xMFI",
      "session_token": "AQoXdzELDDY//////////wEaoAK1wvxJY12r2IrDFT2IvAzTCn3zHoZ7YNtpiQLF0MqZye/qwjzP2iEXAMPLEbw/m3hsj8VBTkPORGvr9jM5sgP+w9IZWZnU+LWhmg+a5fDi2oTGUYcdg9uexQ4mtCHIHfi4citgqZTgco40Yqr4lIlo4V2b2Dyauk0eYFNebHtYlFVgAUj+7Indz3LU0aTWk1WKIjHmmMCIoTkyYp/k7kUG7moeEYKSitwQIi6Gjn+nyzM+PtoA3685ixzv0R7i5rjQi0YE0lf1oeie3bDiNHncmzosRM6SFiPzSvp6h/32xQuZsjcypmwsPSDtTPYcs0+YN/8BRi2/IcrxSpnWEXAMPLEXSDFTAQAM6Dl9zR0tXoybnlrZIwMLlMi1Kcgo5OytwU=",
      "regions": ["us-east-1"]
    }
  ]
}
```

Use the default profile:

```json
{
  "accounts": [
    {
    }
  ]
}
```

Use a specific profile:

```json
{
  "accounts": [
    {
      "profile": "securicad-user"
    }
  ]
}
```

Override the region in the profile:

```json
{
  "accounts": [
    {
      "regions": ["us-east-2"]
    },
    {
      "profile": "securicad-user",
      "regions": ["us-east-2"]
    }
  ]
}
```

Use configured credentials to assume an IAM role:

```json
{
  "accounts": [
    {
      "access_key": "AKIAIOSFODNN7EXAMPLE",
      "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY",
      "role": "arn:aws:iam::123456789012:role/securicadaccess",
      "regions": ["us-east-1"]
    },
    {
      "access_key": "ASIAJEXAMPLEXEG2JICEA",
      "secret_key": "9drTJvcXLB89EXAMPLELB8923FB892xMFI",
      "session_token": "AQoXdzELDDY//////////wEaoAK1wvxJY12r2IrDFT2IvAzTCn3zHoZ7YNtpiQLF0MqZye/qwjzP2iEXAMPLEbw/m3hsj8VBTkPORGvr9jM5sgP+w9IZWZnU+LWhmg+a5fDi2oTGUYcdg9uexQ4mtCHIHfi4citgqZTgco40Yqr4lIlo4V2b2Dyauk0eYFNebHtYlFVgAUj+7Indz3LU0aTWk1WKIjHmmMCIoTkyYp/k7kUG7moeEYKSitwQIi6Gjn+nyzM+PtoA3685ixzv0R7i5rjQi0YE0lf1oeie3bDiNHncmzosRM6SFiPzSvp6h/32xQuZsjcypmwsPSDtTPYcs0+YN/8BRi2/IcrxSpnWEXAMPLEXSDFTAQAM6Dl9zR0tXoybnlrZIwMLlMi1Kcgo5OytwU=",
      "role": "arn:aws:iam::123456789012:role/securicadaccess",
      "regions": ["us-east-1"]
    },
    {
      "role": "arn:aws:iam::123456789012:role/securicadaccess"
    },
    {
      "profile": "securicad-user",
      "role": "arn:aws:iam::123456789012:role/securicadaccess"
    }
  ]
}
```

Specify the JSON file on the command-line:

```shell
securicad-aws-collector --config config.json
```

### 4. From the Environment

If no command-line arguments are used, your environment is searched.

First, the environment variables `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, and `AWS_DEFAULT_REGION` are checked.

If credentials were not found in your environment variables, the profile specified by the environment variable `AWS_PROFILE` is used.
If `AWS_PROFILE` is not set, the default profile is used.

## License

Copyright © 2019-2022 [Foreseeti AB](https://foreseeti.com)

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
