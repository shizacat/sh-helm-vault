# CHANGELOG.md

## RC

### Fix:
- Test with helm, test_install.

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

### Fix:
- Moved from gitlab-ci to Github Actions for CI