[![Gitpod Ready-to-Code](https://img.shields.io/badge/Gitpod-Ready--to--Code-blue?logo=gitpod)](https://gitpod.io/#https://github.com/shizacat/sh-helm-vault)

![Current Release](https://img.shields.io/github/v/release/shizacat/sh-helm-vault)
![License](https://img.shields.io/github/license/shizacat/sh-helm-vault)

[![CI](https://github.com/shizacat/sh-helm-vault/actions/workflows/main.yml/badge.svg)](https://github.com/shizacat/sh-helm-vault/actions/workflows/main.yml)

# SH Helm Vault

Helm-Vault stores private data from YAML files in Hashicorp Vault. Helm-Vault should be used if you want to publicize your YAML configuration files, without worrying about leaking secret information.

## Table of Contents

- [SH Helm Vault](#sh-helm-vault)
  - [Table of Contents](#table-of-contents)
- [About the Project](#about-the-project)
- [Getting Started](#getting-started)
  - [Dependencies](#dependencies)
  - [Installation](#installation)
    - [Using Helm plugin manager (\> 2.3.x)](#using-helm-plugin-manager--23x)
  - [Usage and Examples](#usage-and-examples)
    - [Environment Variables](#environment-variables)
      - [Variables for configure the library hvac (Vault client).](#variables-for-configure-the-library-hvac-vault-client)
      - [Variables for configure the plugin.](#variables-for-configure-the-plugin)
      - [More detailed information available below:](#more-detailed-information-available-below)
    - [Basic commands:](#basic-commands)
    - [Available Flags](#available-flags)
    - [Usage examples](#usage-examples)
      - [Encrypt](#encrypt)
      - [Decrypt](#decrypt)
      - [View](#view)
      - [Edit](#edit)
      - [Clean](#clean)
    - [vault path templating](#vault-path-templating)
    - [Wrapper Examples](#wrapper-examples)
      - [Install](#install)
      - [Template](#template)
      - [Upgrade](#upgrade)
      - [Lint](#lint)
      - [Diff](#diff)
- [Development](#development)
  - [Getting the Source](#getting-the-source)
  - [Running Tests](#running-tests)
    - [Other Tests](#other-tests)
  - [Release Process](#release-process)
    - [Versioning](#versioning)
- [How to Get Help](#how-to-get-help)
- [Contributing](#contributing)
- [Further Reading](#further-reading)
- [License](#license)
- [Authors](#authors)
- [Acknowledgments](#acknowledgments)
  - [Step 2](#step-2)
  - [Step 1](#step-1)

# About the Project

Helm-Vault supports the following features:

- [X] Encrypt/Decrypt YAML files
- [X] View/Edit decrypted YAML files
- [X] Clean up decrypted YAML files
- [X] Helm Wrapper, automatically decrypts and cleans up during helm commands
  - [X] Install
  - [X] Upgrade
  - [X] Template
  - [X] Lint
  - [X] Diff

Helm-Vault was created to provide a better way to manage secrets for Helm, with the ability to take existing public Helm Charts, and with minimal modification, provide a way to have production data that is not stored in a public location.

**[Back to top](#table-of-contents)**

# Getting Started

## Dependencies

- [ ] Python 3.8+
- [ ] pip3
- [ ] Working Hashicorp Vault environment
- [ ] Hashicorp Vault token
- [ ] Environment Variables for Vault
  - [ ] VAULT_ADDR: The HTTP Address of Vault
  - [ ] VAULT_TOKEN: The token for accessing Vault
- [ ] YAML files must be in a git repo or have the full path specified in the file. See [Vault Path Templating](#vault-path-templating).

## Installation

### Using Helm plugin manager (> 2.3.x)

1. Install the requirements

```bash
pip3 install -r https://raw.githubusercontent.com/shizacat/sh-helm-vault/main/requirements.txt
```

2. Install plugin

```bash
helm plugin install https://github.com/shizacat/sh-helm-vault
```

## Usage and Examples

```bash
$ helm vault --help
usage: vault.py [-h] {enc,dec,clean,view,edit} ...

Store secrets from Helm in Vault

Requirements:

Environment Variables:

VAULT_ADDR:     (The HTTP address of Vault, for example, http://localhost:8200)
VAULT_TOKEN:    (The token used to authenticate with Vault)

positional arguments:
  {enc,dec,clean,view,edit}
    enc                 Parse a YAML file and store user entered data in Vault
    dec                 Parse a YAML file and retrieve values from Vault
    clean               Remove decrypted files (in the current directory)
    view                View decrypted YAML file
    edit                Edit decrypted YAML file. DOES NOT CLEAN UP AUTOMATICALLY.

optional arguments:
  -h, --help            show this help message and exit
```

Any YAML file can be transparently "encrypted" as long as it has a deliminator for secret values.

Decrypted files have the suffix ".dec.yaml" by default

### Environment Variables

**Note:** Flags take precedence over Environment Variables.

#### Variables for configure the library hvac (Vault client).

|Environment Variable|Default Value<br>(if unset)|Overview|Required|
|--------------------|---------------------------|--------|--------|
|`VAULT_ADDR`|`null`|The HTTP(S) address fo Vault|Yes|
|`VAULT_TOKEN`|`null`|The token used to authenticate with Vault|Yes|
|`VAULT_NAMESPACE`|`null`|The Vault namespace used for the command||

#### Variables for configure the plugin.

|Environment Variable|Default Value<br>(if unset)|Overview|Required|
|--------------------|---------------------------|--------|--------|
|`HELM_VAULT_PATH`|`secret/helm`|The default path used within Vault||
|`HELM_VAULT_MOUNT_POINT`|`secret`|The default mountpoint used within Vault||
|`HELM_VAULT_DELIMINATOR`|`changeme`|The value which will be searched for within YAML to prompt for encryption/decryption||
|`HELM_VAULT_TEMPLATE`|`VAULT:`|Used for [Vault Path Templating](#vault-path-templating)||
|`HELM_VAULT_KVVERSION`|`v2`|The K/V secret engine version within Vault||
|`HELM_VAULT_EDITOR`| - Windows: `notepad` <br> - macOS/Linux: `vi`|The editor used when calling `helm vault edit`||

#### More detailed information available below:

<details>
<summary>VAULT_ADDR</summary>

The HTTP(S) address of Vault, for example, http://localhost:8200

Default when not set: `null`, the program will error and inform you that this address needs to be set as an environment variable.
</details>

<details>
<summary>VAULT_TOKEN</summary>

The token used to authenticate with Vault.

Default when not set: `null`, the program will error and inform you that this value needs to be set as an environment variable.
</details>

<details>
<summary>VAULT_NAMESPACE</summary>

The Vault namespace used for the command. Namespaces are isolated environments that functionally exist as "Vaults within a Vault." They have separate login paths and support creating and managing data isolated to their namespace. Namespaces are only available in Vault Enterprise.

Default when not set: `null`.
</details>

<details>
<summary>HELM_VAULT_PATH</summary>

This is the path within Vault that secrets are stored. It should start with the name of the secrets engine being used and an optional folder within that secrets engine that all Helm-Vault secrets will be stored and through dot name of key.

Default when not set: `secret/helm`, where `secret` is the secrets engine being used, and `helm` is the folder in which all secrets will be stored.
</details>

<details>
<summary>HELM_VAULT_MOUNT_POINT</summary>

This is the mountpoint within Vault that secrets are stored. Vault stores secrets in the following url format `/{mount_point}/data/{path}`. Mountpoint in this case could also include any namespaces, e.g. `namespace1/subnamespace/mountpoint` = `/namespace1/subnamespace/mountpoint/data/{path}`.

Default when not set: `secret`, where `secret` is the mountpoint being used.
</details>

<details>
<summary>HELM_VAULT_DELIMINATOR</summary>

This is the value which Helm-Vault will search for within the YAML files to prompt for encryption, or replace when decrypting.

Default when not set: `changeme`.
</details>

<details>
<summary>HELM_VAULT_TEMPLATE</summary>

This is the value that Helm-Vault will search for within the YAML files to denote [Vault Path Templating](#vault-path-templating).

Default when not set: `VAULT:`
</details>

<details>
<summary>HELM_VAULT_KVVERSION</summary>

This is the K/V secret engine version within Vault, currently `v1` and `v2` are supported.

Default when not set: `v1`

**Note:** Expect this to change in a later version, as Vault now defaults to `v2` K/V secrets engines.
</details>

<details>
<summary>HELM_VAULT_EDITOR</summary>

This is the editor that Helm-Vault will use when requesting `helm vault edit`.

Default when not set:

- Windows: `notepad`
- macOS/Linux: `vi`

</details>

### Basic commands:

```
  enc           Encrypt file
  dec           Decrypt file
  view          Print decrypted file
  edit          Edit file (decrypt before, manual cleanup)
  clean         Delete *.dec.yaml files in directory (recursively)
```

Each of these commands have their own help, referenced by `helm vault {enc,dec,clean,view,edit} --help`.

### Available Flags

|Flag|Usage|Default|Availability|
|----|-----|-------|------------|
|`-d`, `--deliminator`|The secret deliminator used when parsing|`changeme`|`enc`, `dec`, `view`, `edit`, `install`, `template`, `upgrade`, `lint`, `diff`|
|`-p`, `--path`|The Vault Path (secret mount location in Vault)|`secret/helm`|`enc`, `dec`, `view`, `edit`, `install`, `template`, `upgrade`, `lint`, `diff`|
|`-mp`, `--mount-point`|The Vault Mount Point|`secret`|`enc`, `dec`, `view`, `edit`, `install`, `template`, `upgrade`, `lint`, `diff`|
|`-t`, `--template`|Substring with path to vault key instead of deliminator.|`VAULT:`|`enc`, `dec`, `view`, `edit`, `install`, `template`, `upgrade`, `lint`, `diff`|
|`-kv`, `--kvversion`|The version of the KV secrets engine in Vault|`v2`|`enc`, `dec`, `view`, `edit`, `install`, `template`, `upgrade`, `lint`, `diff`|
|`-v`, `--verbose`|Verbose output||`enc`, `dec`, `clean`, `view`, `edit`, `install`, `template`, `upgrade`, `lint`, `diff`|
|`-f`, `--file`|The specific YAML file to be deleted, without `.dec.yaml`. This option can be specified more than once.||`clean`|
|`-f`, `--values`|The encrypted YAML file to decrypt on the fly. This option can be specified more than once.||`install`, `template`, `upgrade`, `lint`, `diff`|
|`-ed`, `--editor`|Editor name|Windows: `notepad`, macOS/Linux: `vi`|`edit`|
|`-e`, `--environment`|Environment that secrets should be stored under||`enc`, `dec`, `clean`, `install`|


### Usage examples

#### Encrypt

The encrypt operation encrypts a values.yaml file and saves the encrypted values in Vault:

```bash
$ helm vault enc -f values.yaml
Input a value for nextcloud.password: asdf1
Input a value for externalDatabase.user: asdf2
Input a value for .mariadb.db.password: asdf3
```

In addition, you can namespace your secrets to a desired environment by using the `-e` flag.

```bash
helm vault enc -f values.yaml -e prod
Input a value for nextcloud.password: asdf1
Input a value for externalDatabase.user: asdf2
Input a value for mariadb.db.password: asdf3
```

#### Decrypt

The decrypt operation decrypts a values.yaml file and saves the decrypted result in values.dec.yaml:

```bash
$ helm vault dec -f values.yaml
```

The values.dec.yaml file:
```yaml
...
nextcloud:
  host: nextcloud.example.com
  username: admin
  password: asdf1
...
mariadb:
parameters
  enabled: true

  db:
    name: nextcloud
    user: nextcloud
    password: asdf2
...
```

If leveraging environment specific secrets, you can decrypt the desired environment by specifying with the `-e` flag.

Doing so will result in a decrypted file that is stored as `my_file.{environment}.dec.yaml`

For example

```bash
$ helm vault dec -f values.yaml -e prod
```

Will result in your production environment secrets being dumped into a file named `values.prod.dec.yaml`

#### View

The view operation decrypts values.yaml and prints it to stdout:

```bash
$ helm vault view -f values.yaml
```

#### Edit

The edit operation will decrypt the values.yaml file and open it in an editor.

```bash
$ helm vault edit -f values.yaml
```

This will read a value from $HELM_VAULT_EDITOR, or be specified with the `-e, --editor` option, or will choose a default of `vi` for Linux/MacOS, and `notepad` for Windows.

Note: This will save a `.dec.yaml` file that is not automatically cleaned up.

#### Clean

The operation will delete all decrypted files in a directory:

```bash
$ helm vault clean
```

### vault path templating

It is possible to setup vault's path inside helm chart like this

```
key1: VAULT:helm1/test.key1
key2: VAULT:/helm2/test.key2
key_filename.txt: VAULT:/helm2/test.key_filename..txt
```

This mean that key1 will be storing into base_path/helm1/test (key1) and key2 into /helm2/test (key2).
If you need the dot in path or key, you can double it, example: key_filename.txt.
Where is helm2 is root path enabled via secrets enable. For example:

```
vault secrets enable  -path=helm2 kv-v2
```

To override default value of template path pattern use **SECRET_TEMPLATE** variable. By default this value is 'VAULT:'.
This is mean that all keys with values like VAULT:something will be stored inside vault.


### Wrapper Examples

#### Install

The operation wraps the default `helm install` command, automatically decrypting the `-f values.yaml` file and then cleaning up afterwards.

```bash
$ helm vault install stable/nextcloud --name nextcloud --namespace nextcloud -f values.yaml
```

Specifically, this command will do the following:

1. Run `helm install` with the following options:
  1. `stable/nextcloud` - the chart to install
  1. `--name nextcloud` - the Helm release name will be `nextcloud`
  1. `--namespace nextcloud` - Nextcloud will run in the nextcloud namespace on Kubernetes
  1. `-f values.yaml` - the (encrypted) values file to use

#### Template

The operation wraps the default `helm template` command, automatically decrypting the `-f values.yaml` file and then cleaning up afterwards.

```bash
$ helm vault template ./nextcloud --name nextcloud --namespace nextcloud -f values.yaml
```

1. Run `helm template` with the following options:
  1. `./nextcloud` - the chart to template
  1. `--name nextcloud` - the Helm release name will be `nextcloud`
  1. `--namespace nextcloud` - Nextcloud will run in the nextcloud namespace on Kubernetes
  1. `-f values.yaml` - the (encrypted) values file to use

#### Upgrade

The operation wraps the default `helm upgrade` command, automatically decrypting the `-f values.yaml` file and then cleaning up afterwards.

```bash
$ helm vault upgrade nextcloud stable/nextcloud -f values.yaml
```

1. Run `helm upgrade` with the following options:
  1. `nextcloud` - the Helm release name
  1. `stable/nextcloud` - the chart path
  1. `-f values.yaml` - the (encrypted) values file to use

#### Lint

The operation wraps the default `helm lint` command, automatically decrypting the `-f values.yaml` file and then cleaning up afterwards.

```bash
$ helm vault lint nextcloud -f values.yaml
```

1. Run `helm upgrade` with the following options:
  1. `nextcloud` - the Helm release name
  1. `-f values.yaml` - the (encrypted) values file to use

#### Diff

The operation wraps the `helm diff` command (diff is another Helm plugin), automatically decrypting the `-f values.yaml` file and then cleaning up afterwards.

```bash
$ helm vault diff upgrade nextcloud stable/nextcloud -f values.yaml
```

1. Run `helm diff upgrade` with the following options:
  1. `nextcloud` - the Helm release name
  1. `stable/nextcloud` - the Helm chart
  1. `-f values.yaml` - the (encrypted) values file to use

**[Back to top](#table-of-contents)**

# Development

## Getting the Source

This project is [hosted on GitHub](https://github.com/shizacat/sh-helm-vault). You can clone this project directly using this command:

```bash
git clone git@github.com:shizacat/sh-helm-vault.git
```

## Running Tests

Helm-Vault has built-in unit tests using pytest, you can run them with the command below:

```bash
pip3 install -r requirements-dev.txt
python3 -m pytest
```

for running tests using docker, you can use the following command:

```bash
./run-test.sh
```

### Other Tests

Unittesting and integration testing is automatically run via Github Actions on commit and PRs.

Additionally, code quality checking is handled by LGTM.com

Both of these checks must pass before PRs will be merged.

## Release Process

Releases are made for new features, and bugfixes.

To get a new release, run the following:

```bash
helm plugin upgrade vault
```

### Versioning

This project uses [Semantic Versioning](http://semver.org/). For a list of available versions, see the [repository tag list](https://github.com/Just-Insane/helm-vault/tags).

**[Back to top](#table-of-contents)**

# How to Get Help

If you need help or have questions, please open a new discussion Q&A section.

# Contributing

We encourage public contributions! Please review [CONTRIBUTING.md](docs/CONTRIBUTING.md) for details on our code of conduct and development process.

**[Back to top](#table-of-contents)**

# Further Reading

[Helm](https://helm.sh/)
[Hashicorp Vault](https://www.vaultproject.io/)

**[Back to top](#table-of-contents)**

# License

Copyright (c) 2025 Alexey Matveev

This project is licensed under GPLv3 - see [LICENSE.md](LICENSE.md) file for details.

**[Back to top](#table-of-contents)**

# Authors

* **[Justin Gauthier](https://github.com/Just-Insane)**
* **[Alexey Matveev](https://github.com/shizacat)**

**[Back to top](#table-of-contents)**

# Acknowledgments

## Step 2
The idea for this project comes from [helm-vault](https://github.com/Just-Insane/helm-vault).

Goal, to make the code more supported.

## Step 1
The idea for this project (helm-vault) comes from [Helm-Secrets](https://github.com/futuresimple/helm-secrets).

Special thanks to the [Python Discord](https://discord.gg/python) server.

**[Back to top](#table-of-contents)**
