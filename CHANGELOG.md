# CHANGELOG.md

## 1.3.0

- The path format has been updated
- Now, you can read the key from the specified version in the Vault.


## 1.2.2

### Fix
- The '-f' argument did not work correctly.

### Changed
- Arguments for cmd: enc, dec, clean, view, edit


## 1.2.1

### Changed
- return name of plugin to 'vault'


## 1.2.0

### Changed
- Options: '-f', '--values', '--files' can be specified more than once.
- Rename plugin to 'vault-sh'
- For hvac was set 'raise_on_deleted_version' to True
- Drop support python 3.7


## 1.1.0

### Feature
- Was is added support the dot in path or key.

## 1.0.1

### Fix
- Test with helm, test_install and rename to test_template.
- Exit code return, when raise exception

## 1.0.0

### Changed
- Change class Envs to Config
- Rename environment variable: DELIMINATOR, VAULT_TEMPLATE
- Rename arguments: -vmp, --vault-mount-path; vault-template
- Changed suffix name for files after decryption, from .dec to .dec.yaml
- All environment variables nas common prefix
- All code in one main class


## 0.3.0 (2021-03-17)

### Features
- Adds an option to set an environment for secrets, using the -e/--environment flag
- Moves the editor selection from -e to -ed

### Fix
- Moved from gitlab-ci to Github Actions for CI