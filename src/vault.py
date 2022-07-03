#!/usr/bin/env python3

import os
import sys
import glob
import argparse
import platform
import subprocess
from typing import Any, IO, Optional, Tuple, Callable
from dataclasses import dataclass, fields

import hvac
import ruamel.yaml

if sys.version_info[:2] < (3, 7):
    raise Exception("Python 3.7 or a more recent version is required.")


@dataclass
class Config:
    vault_addr: str
    editor: str
    vault_path: str = "secret/helm"
    vault_mount_point: str = "secret"
    vault_template: str = "VAULT:"
    deliminator: str = "changeme"
    kvversion: str = "v1"
    environment: str = ""

    @classmethod
    def create_from_env(cls, args) -> "Config":
        exclude = ["vault_addr"]
        exclude_env = ["environment"]
        kwargs = {
            "vault_addr": os.environ["VAULT_ADDR"],
            "editor": "vi" if platform.system() != "Windows" else "notepad.exe"
        }
        source = "DEFAULT"

        for f in fields(cls):
            if f.name in exclude:
                continue
            env_name = f.name.upper()

            if hasattr(args, f.name) and getattr(args, f.name):
                kwargs[f.name] = getattr(args, f.name)
                source = "ARG"
            elif env_name not in exclude_env and env_name in os.environ:
                kwargs[f.name] = os.environ[env_name]
                source = "ENVIRONMENT"

            if args.verbose:
                print(
                    f"The {source} {f.name} is:",
                    f"{kwargs.get(f.name, f.default)}"
                )
        return cls(**kwargs)

    def __post_init__(self):
        # add '/' before environment
        if self.environment and not self.environment.startswith("/"):
            self.environment = f"/{self.environment}"


class VaultHelm(object):
    SPLITER_KEY = "."
    leftoevers_actions = [
        "install",
        "template",
        "upgrade",
        "lint",
        "diff"
    ]

    def __init__(self, args, leftovers):
        self.args = args
        self.leftovers = leftovers

        self.envs = Config.create_from_env(self.args)
        self.__secrets = {}
        self.__current_walk_path = []

        # yaml config
        self.yaml = ruamel.yaml.YAML()
        self.yaml.preserve_quotes = True

        # vault config
        try:
            self.vault_client = hvac.Client(
                url=self.envs.vault_addr,
                namespace=os.environ.get("VAULT_NAMESPACE"),
                token=os.environ["VAULT_TOKEN"])
        except KeyError:
            print(
                "Vault not configured correctly,"
                "check VAULT_ADDR and VAULT_TOKEN env variables."
            )

    def action(self):
        """Run action"""
        if self.args.action == "dec":
            return self._action_dec()
        if self.args.action == "enc":
            return self._action_enc()
        if self.args.action == "clean":
            return self._action_cleanup()
        if self.args.action == "view":
            return self._action_view()
        if self.args.action == "edit":
            return self._action_edit()
        if self.args.action in self.leftoevers_actions:
            self._action_dec()
            return self._action_leftoevers()

    def _action_cleanup(self):
        try:
            os.remove(self.decode_file)
            if self.args.verbose:
                print(f"Deleted {self.decode_file}")
        except AttributeError:
            for fl in glob.glob("*.dec"):
                os.remove(fl)
                if self.args.verbose:
                    print(f"Deleted {fl}")

    def _action_dec(self, device: Optional[IO[str]] = None):
        data = self._load_yaml()
        data = self._json_walker(data, self._process_yaml)
        if device is not None:
            self.yaml.dump(data, device)
        else:
            with open(self.decode_file, "w") as device:
                self.yaml.dump(data, device)
        print("Done Decrypting")

    def _action_enc(self):
        self.__secrets = {}  # path: {key: value}
        self._json_walker(self._load_yaml(), self._process_yaml_enc, True)
        for path, secret in self.__secrets.items():
            self._vault_write_by_path(path, secret)
        self.__secrets = {}
        print("Done Encription")

    def _action_view(self):
        self._action_dec(device=sys.stdout)

    def _action_edit(self):
        self._action_dec()
        os.system(f"{self.envs.editor} {self.decode_file}")

    def _action_leftoevers(self):
        leftovers = ' '.join(self.leftovers)

        try:
            cmd = f"helm {self.args.action} {leftovers} -f {self.decode_file}"
            if self.args.verbose:
                print(f"About to execute command: {cmd}")
            subprocess.run(cmd, shell=True, check=True)
        except subprocess.CalledProcessError as ex:
            sys.exit(ex.returncode)
        finally:
            self._action_cleanup()

    def _load_yaml(self):
        """Load the YAML file

        Return
            json object
        """
        with open(self.args.yaml_file) as filepath:
            return self.yaml.load(filepath)

    # def _load_secret(self):
    #     if (
    #         self.args.secret_file and
    #         not re.search(r'\.yaml\.dec$', self.args.secret_file)
    #     ):
    #         raise RuntimeError(
    #             "ERROR: Secret file name must end with \".yaml.dec\"."
    #             f" {self.args.secret_file} was given instead."
    #         )
    #     return self.yaml.load(self.args.secret_file)

    def _json_walker(
        self, data, process: Callable[[Any], Any], is_root: bool = False
    ):
        """Walk through the loaded yaml file and call process

        Args
            data - json object

        Return
            new json object
        """
        if is_root:
            self.__current_walk_path = []

        if isinstance(data, dict):
            result = {}
            for key, value in data.items():
                if is_root:
                    self.__current_walk_path = []
                self.__current_walk_path.append(key)
                result[key] = self._json_walker(value, process)
                self.__current_walk_path.pop()
            return result
        elif isinstance(data, list):
            result = []
            for item in data:
                result.append(self._json_walker(item, process))
            return result
        return process(data)

    def _process_yaml(self, value):
        """Process data"""
        path = self._check_value_template(value)
        if path is not None:
            return self._vault_read_by_path(path)
        return value

    def _process_yaml_enc(self, value):
        """Process data"""
        path = self._check_value_template(value)
        if path is not None:
            self._add_to_secret(path)
        path = self._check_value_pattern(value)
        if path is not None:
            self._add_to_secret(path)
        return value

    def _add_to_secret(self, path: str):
        path, key = self._split_path(path)
        if path not in self.__secrets.keys():
            self.__secrets[path] = {}
        self.__secrets[path][key] = input(f"Input a value for {path}.{key}: ")

    def _vault_read_by_path(self, path: str) -> str:
        """Take data from Vault by path and return
        Analog vault read
        """
        path, key = self._split_path(path)

        if self.args.verbose:
            print(f"Using KV Version: {self.envs.kvversion}")
            print(
                "Attempting to write to url: {}/v1/{}/data{}".format(
                    self.envs.vault_addr, self.envs.vault_mount_point, path
                ),
            )

        try:
            if self.envs.kvversion == "v1":
                data = self.vault_client.read(path)
                value = data.get("data", {}).get(key)
            elif self.envs.kvversion == "v2":
                data = self.vault_client.secrets.kv.v2.read_secret_version(
                    path=path, mount_point=self.envs.vault_mount_point)
                value = data.get("data", {}).get("data", {}).get(key)
            else:
                raise RuntimeError(
                    "Wrong KV Version specified, either v1 or v2")
        except AttributeError as ex:
            raise RuntimeError(
                "Vault not configured correctly,"
                f"check VAULT_ADDR and VAULT_TOKEN env variables. {ex}"
            )
        return value

    def _vault_write_by_path(self, path: str, value: dict):
        """Wirite value to Vault"""

        if self.args.verbose:
            print(f"Using KV Version: {self.envs.kvversion}")
            print(
                "Attempting to write to url: {}/v1/{}/data{}".format(
                    self.envs.vault_addr, self.envs.vault_mount_point, path
                ),
            )

        try:
            if self.envs.kvversion == "v1":
                self.vault_client.write(
                    path, mount_point=self.envs.vault_mount_point, **value)
            elif self.envs.kvversion == "v2":
                self.vault_client.secrets.kv.v2.create_or_update_secret(
                    path=path,
                    secret=value,
                    mount_point=self.envs.vault_mount_point,
                )
            else:
                raise RuntimeError(
                    "Wrong KV Version specified, either v1 or v2")
        except AttributeError as ex:
            raise RuntimeError(
                "Vault not configured correctly,"
                f"check VAULT_ADDR and VAULT_TOKEN env variables. {ex}"
            )

        if self.args.verbose:
            print(f"Wrote {value} to: {path}")

    def _check_value_template(self, value: str) -> Optional[str]:
        """Check value on template

        Return
            path
        """
        if not isinstance(value, str):
            return
        value = value.strip()

        if value.startswith(self.envs.vault_template):
            value = value[len(self.envs.vault_template):]
            if not value:
                raise ValueError("Empty secret template")
            value = value.replace("{environment}", self.envs.environment)
            return value.replace("//", "/")

    def _check_value_pattern(self, value: str) -> Optional[str]:
        """Check pattern

        Return
            path
        """
        if not isinstance(value, str):
            return
        value = value.strip()

        if value != self.envs.deliminator:
            return

        if not self.__current_walk_path:
            raise ValueError("Current path isn't found")

        return "{}.{}".format(
            "/".join(self.__current_walk_path[:-1]),
            self.__current_walk_path[-1]
        )

    def _split_path(self, path: str) -> Tuple[str, str]:
        """
        Return
            path, key
            where:
                key is name of field in Vault
        """
        r = path.split(self.SPLITER_KEY)
        if len(r) != 2:
            raise ValueError(f"Wrong format path: {path}")
        return r[0], r[1]

    @property
    def decode_file(self):
        return '.'.join(filter(None, [
            self.args.yaml_file, self.envs.environment, 'dec']))


def parse_args():
    """Help text"""
    parser = argparse.ArgumentParser(
        description=(
            "Store secrets from Helm in Vault\n\n"
            "Requirements:\n\n"
            "Environment Variables:\n"
            "    VAULT_ADDR:         (The HTTP address of Vault,"
            " for example, http://localhost:8200)\n"
            "    VAULT_TOKEN:        "
            "(The token used to authenticate with Vault)\n"
            "    VAULT_NAMESPACE:    (The Vault Namespace to use "
            "(Vault enterprise only))\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="action", required=True)

    # Encrypt help
    encrypt = subparsers.add_parser("enc", help="Parse a YAML file and store user entered data in Vault")
    encrypt.add_argument("yaml_file", type=str, help="The YAML file to be worked on")
    encrypt.add_argument("-d", "--deliminator", type=str, help="The secret deliminator used when parsing. Default: \"changeme\"")
    encrypt.add_argument("-vmp", "--vault-mount-point", type=str, help="The Vault Mount Point Default: \"secret/data\"")
    encrypt.add_argument("-vp", "--vault-path", type=str, help="The Vault Path (secret mount location in Vault) Default: \"secret/helm\"")
    encrypt.add_argument("-vt", "--vault-template", type=str, help="Substring with path to vault key instead of deliminator. Default: \"VAULT:\"")
    encrypt.add_argument("-kv", "--kvversion", choices=['v1', 'v2'], type=str, help="The KV Version (v1, v2) Default: \"v2\"")
    encrypt.add_argument("-v", "--verbose", help="Verbose logs", action="store_true")
    encrypt.add_argument("-e", "--environment", type=str, help="Allows for secrets to be encoded on a per environment basis")
    encrypt.add_argument("-s", "--secret-file", type=str, help="File containing the secret for input. Must end in .yaml.dec")

    # Decrypt help
    decrypt = subparsers.add_parser("dec", help="Parse a YAML file and retrieve values from Vault")
    decrypt.add_argument("yaml_file", type=str, help="The YAML file to be worked on")
    decrypt.add_argument("-d", "--deliminator", type=str, help="The secret deliminator used when parsing. Default: \"changeme\"")
    decrypt.add_argument("-vmp", "--vault-mount-point", type=str, help="The Vault Mount Point Default: \"secret/data\"")
    decrypt.add_argument("-vp", "--vault-path", type=str, help="The Vault Path (secret mount location in Vault). Default: \"secret/helm\"")
    decrypt.add_argument("-vt", "--vault-template", type=str, help="Substring with path to vault key instead of deliminator. Default: \"VAULT:\"")
    decrypt.add_argument("-kv", "--kvversion", choices=['v1', 'v2'], type=str, help="The KV Version (v1, v2) Default: \"v1\"")
    decrypt.add_argument("-v", "--verbose", help="Verbose logs", action="store_true")
    decrypt.add_argument("-e", "--environment", type=str, help="Allows for secrets to be decoded on a per environment basis")

    # Clean help
    clean = subparsers.add_parser("clean", help="Remove decrypted files (in the current directory)")
    clean.add_argument("-f", "--file", type=str, help="The specific YAML file to be deleted, without .dec", dest="yaml_file")
    clean.add_argument("-v", "--verbose", help="Verbose logs", action="store_true")
    clean.add_argument("-e", "--environment", type=str, help="Decoded environment to clean")

    # View Help
    view = subparsers.add_parser("view", help="View decrypted YAML file")
    view.add_argument("yaml_file", type=str, help="The YAML file to be worked on")
    view.add_argument("-d", "--deliminator", type=str, help="The secret deliminator used when parsing. Default: \"changeme\"")
    view.add_argument("-vmp", "--vault-mount-point", type=str, help="The Vault Mount Point Default: \"secret/data\"")
    view.add_argument("-vp", "--vault-path", type=str, help="The Vault Path (secret mount location in Vault). Default: \"secret/helm\"")
    view.add_argument("-vt", "--vault-template", type=str, help="Substring with path to vault key instead of deliminator. Default: \"VAULT:\"")
    view.add_argument("-kv", "--kvversion", choices=['v1', 'v2'], type=str, help="The KV Version (v1, v2) Default: \"v1\"")
    view.add_argument("-v", "--verbose", help="Verbose logs", action="store_true")

    # Edit Help
    edit = subparsers.add_parser("edit", help="Edit decrypted YAML file. DOES NOT CLEAN UP AUTOMATICALLY.")
    edit.add_argument("yaml_file", type=str, help="The YAML file to be worked on")
    edit.add_argument("-d", "--deliminator", type=str, help="The secret deliminator used when parsing. Default: \"changeme\"")
    edit.add_argument("-vmp", "--vault-mount-point", type=str, help="The Vault Mount Point Default: \"secret/data\"")
    edit.add_argument("-vp", "--vault-path", type=str, help="The Vault Path (secret mount location in Vault). Default: \"secret/helm\"")
    edit.add_argument("-vt", "--vault-template", type=str, help="Substring with path to vault key instead of deliminator. Default: \"VAULT:\"")
    edit.add_argument("-kv", "--kvversion", choices=['v1', 'v2'], type=str, help="The KV Version (v1, v2) Default: \"v1\"")
    edit.add_argument("-v", "--verbose", help="Verbose logs", action="store_true")
    edit.add_argument("-ed", "--editor", help="Editor name. Default: (Linux/MacOS) \"vi\" (Windows) \"notepad\"", const=True, nargs="?")

    # Install Help
    install = subparsers.add_parser("install", help="Wrapper that decrypts YAML files before running helm install")
    install.add_argument("-f", "--values", type=str, dest="yaml_file", help="The encrypted YAML file to decrypt on the fly")
    install.add_argument("-d", "--deliminator", type=str, help="The secret deliminator used when parsing. Default: \"changeme\"")
    install.add_argument("-vmp", "--vault-mount-point", type=str, help="The Vault Mount Point Default: \"secret/data\"")
    install.add_argument("-vp", "--vaultpath", type=str, help="The Vault Path (secret mount location in Vault). Default: \"secret/helm\"")
    install.add_argument("-vt", "--vault-template", type=str, help="Substring with path to vault key instead of deliminator. Default: \"VAULT:\"")
    install.add_argument("-kv", "--kvversion", choices=['v1', 'v2'], type=str, help="The KV Version (v1, v2) Default: \"v1\"")
    install.add_argument("-v", "--verbose", help="Verbose logs", action="store_true")
    install.add_argument("-e", "--environment", type=str, help="Environment whose secrets to use")

    # Template Help
    template = subparsers.add_parser("template", help="Wrapper that decrypts YAML files before running helm install")
    template.add_argument("-f", "--values", type=str, dest="yaml_file", help="The encrypted YAML file to decrypt on the fly")
    template.add_argument("-d", "--deliminator", type=str, help="The secret deliminator used when parsing. Default: \"changeme\"")
    template.add_argument("-vmp", "--vault-mount-point", type=str, help="The Vault Mount Point Default: \"secret/data\"")
    template.add_argument("-vp", "--vault-path", type=str, help="The Vault Path (secret mount location in Vault). Default: \"secret/helm\"")
    template.add_argument("-vt", "--vault-template", type=str, help="Substring with path to vault key instead of deliminator. Default: \"VAULT:\"")
    template.add_argument("-kv", "--kvversion", choices=['v1', 'v2'], type=str, help="The KV Version (v1, v2) Default: \"v1\"")
    template.add_argument("-v", "--verbose", help="Verbose logs", action="store_true")

    # Upgrade Help
    upgrade = subparsers.add_parser("upgrade", help="Wrapper that decrypts YAML files before running helm install")
    upgrade.add_argument("-f", "--values", type=str, dest="yaml_file", help="The encrypted YAML file to decrypt on the fly")
    upgrade.add_argument("-d", "--deliminator", type=str, help="The secret deliminator used when parsing. Default: \"changeme\"")
    upgrade.add_argument("-vmp", "--vault-mount-point", type=str, help="The Vault Mount Point Default: \"secret/data\"")
    upgrade.add_argument("-vp", "--vault-path", type=str, help="The Vault Path (secret mount location in Vault). Default: \"secret/helm\"")
    upgrade.add_argument("-vt", "--vault-template", type=str, help="Substring with path to vault key instead of deliminator. Default: \"VAULT:\"")
    upgrade.add_argument("-kv", "--kvversion", choices=['v1', 'v2'], type=str, help="The KV Version (v1, v2) Default: \"v1\"")
    upgrade.add_argument("-v", "--verbose", help="Verbose logs", action="store_true")

    # Lint Help
    lint = subparsers.add_parser("lint", help="Wrapper that decrypts YAML files before running helm install")
    lint.add_argument("-f", "--values", type=str, dest="yaml_file", help="The encrypted YAML file to decrypt on the fly")
    lint.add_argument("-d", "--deliminator", type=str, help="The secret deliminator used when parsing. Default: \"changeme\"")
    lint.add_argument("-vmp", "--vault-mount-point", type=str, help="The Vault Mount Point Default: \"secret/data\"")
    lint.add_argument("-vp", "--vault-path", type=str, help="The Vault Path (secret mount location in Vault). Default: \"secret/helm\"")
    lint.add_argument("-vt", "--vault-template", type=str, help="Substring with path to vault key instead of deliminator. Default: \"VAULT:\"")
    lint.add_argument("-kv", "--kvversion", choices=['v1', 'v2'], type=str, help="The KV Version (v1, v2) Default: \"v1\"")
    lint.add_argument("-v", "--verbose", help="Verbose logs", action="store_true")

    # Diff Help
    diff = subparsers.add_parser("diff", help="Wrapper that decrypts YAML files before running helm diff")
    diff.add_argument("-f", "--values", type=str, dest="yaml_file", help="The encrypted YAML file to decrypt on the fly")
    diff.add_argument("-d", "--deliminator", type=str, help="The secret deliminator used when parsing. Default: \"changeme\"")
    diff.add_argument("-vmp", "--vault-mount-point", type=str, help="The Vault Mount Point Default: \"secret/data\"")
    diff.add_argument("-vp", "--vault-path", type=str, help="The Vault Path (secret mount location in Vault). Default: \"secret/helm\"")
    diff.add_argument("-vt", "--vault-template", type=str, help="Substring with path to vault key instead of deliminator. Default: \"VAULT:\"")
    diff.add_argument("-kv", "--kvversion", choices=['v1', 'v2'], type=str, help="The KV Version (v1, v2) Default: \"v1\"")
    diff.add_argument("-v", "--verbose", help="Verbose logs", action="store_true")

    return parser


def main(args: Optional[list] = None):
    parsed = parse_args()
    args, leftovers = parsed.parse_known_args(args)
    vault_helm = VaultHelm(args, leftovers)
    vault_helm.action()


if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        print(f"ERROR: {ex}")
    except SystemExit as ex:
        sys.exit(ex.code)
