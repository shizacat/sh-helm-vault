#!/usr/bin/env python3

import os
import sys
import glob
import argparse
import platform
import subprocess
import re
from enum import Enum
from typing import Any, IO, Optional, Tuple, Callable, Iterator, Sequence, List
from dataclasses import dataclass, fields

import hvac
import ruamel.yaml

if sys.version_info[:2] < (3, 7):
    raise Exception("Python 3.7 or a more recent version is required.")


class KVVersion(Enum):
    v1 = "v1"
    v2 = "v2"

    def __str__(self):
        return self.value


@dataclass
class Config:
    editor: str
    path: str = "secret/helm"
    mount_point: str = "secret"
    template: str = "VAULT:"
    deliminator: str = "changeme"
    kvversion: KVVersion = KVVersion.v2
    environment: str = ""

    @classmethod
    def create_from_env(cls, args, prefix: Optional[str] = "") -> "Config":
        exclude_env = ["environment"]
        kwargs = {
            "editor": "vi" if platform.system() != "Windows" else "notepad.exe"
        }
        source = "DEFAULT"

        for f in fields(cls):
            env_name = f"{prefix}{f.name.upper()}"

            if hasattr(args, f.name) and getattr(args, f.name):
                kwargs[f.name] = getattr(args, f.name)
                source = "ARG"
            elif env_name not in exclude_env and env_name in os.environ:
                kwargs[f.name] = f.type(os.environ[env_name])
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


class HelmVault(object):
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

        self.envs = Config.create_from_env(self.args, prefix="HELM_VAULT_")
        self.__secrets = {}
        self.__current_walk_path = []

        # yaml config
        self.yaml = ruamel.yaml.YAML()
        self.yaml.preserve_quotes = True

        # vault config
        self.vault_client = hvac.Client(
            namespace=os.environ.get("VAULT_NAMESPACE")
        )
        if not self.vault_client.is_authenticated():
            raise RuntimeError(
                "Vault not configured correctly, "
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
        if self.args.yaml_file:
            for filepath in self._get_decode_files():
                os.remove(filepath)
                if self.args.verbose:
                    print(f"Deleted {filepath}")
        else:
            for fl in glob.glob("*.dec.yaml"):
                os.remove(fl)
                if self.args.verbose:
                    print(f"Deleted {fl}")

    def _action_dec(self, device: Optional[IO[str]] = None):
        for index, data in self._load_yaml_multi():
            data = self._json_walker(data, self._process_yaml)
            if device is not None:
                self.yaml.dump(data, device)
            else:
                with open(
                    self._get_decode_filename_by_index(index), "w"
                ) as fd:
                    self.yaml.dump(data, fd)
        print("Done Decrypting")

    def _action_enc(self):
        for index, data in self._load_yaml_multi():
            self.__secrets = {}  # path: {key: value}
            self._json_walker(data, self._process_yaml_enc, True)
            for path, secret in self.__secrets.items():
                self._vault_write_by_path(path, secret)
            self.__secrets = {}
        print("Done Encription")

    def _action_view(self):
        self._action_dec(device=sys.stdout)

    def _action_edit(self):
        self._action_dec()
        for filepath in self._get_decode_files():
            os.system(f"{self.envs.editor} {filepath}")

    def _action_leftoevers(self):
        leftovers = ' '.join(self.leftovers)

        try:
            # Get all --value files
            opt_values = ""
            for index, _ in enumerate(self.args.yaml_file):
                opt_values += f" -f {self._get_decode_filename_by_index(index)}"

            cmd = f"helm {self.args.action} {leftovers} {opt_values}"
            if self.args.verbose:
                print(f"About to execute command: {cmd}")
            subprocess.run(cmd, shell=True, check=True)
        except subprocess.CalledProcessError as ex:
            sys.exit(ex.returncode)
        finally:
            self._action_cleanup()

    def _load_yaml_multi(self) -> Iterator[Tuple[Sequence, int]]:
        """Load the YAML files

        Return
            Iterator: index in yaml_file, json object
        """
        for index, filepath in enumerate(self.args.yaml_file):
            with open(filepath) as fd:
                yield index, self.yaml.load(fd)

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
                    self.vault_client.url, self.envs.mount_point, path
                ),
            )

        try:
            if self.envs.kvversion == KVVersion.v1:
                data = self.vault_client.read(path)
                return data.get("data", {}).get(key)
            if self.envs.kvversion == KVVersion.v2:
                data = self.vault_client.secrets.kv.v2.read_secret_version(
                    path=path,
                    mount_point=self.envs.mount_point,
                    raise_on_deleted_version=True,
                )
                return data.get("data", {}).get("data", {}).get(key)
            raise RuntimeError("Wrong KV Version specified, either v1 or v2")
        except AttributeError as ex:
            raise RuntimeError(
                "Vault not configured correctly,"
                f"check VAULT_ADDR and VAULT_TOKEN env variables. {ex}"
            )

    def _vault_write_by_path(self, path: str, value: dict):
        """Wirite value to Vault"""

        if self.args.verbose:
            print(f"Using KV Version: {self.envs.kvversion}")
            print(
                "Attempting to write to url: {}/v1/{}/data{}".format(
                    self.envs.vault_addr, self.envs.mount_point, path
                ),
            )

        try:
            if self.envs.kvversion == KVVersion.v1:
                self.vault_client.write(
                    path, mount_point=self.envs.mount_point, **value)
            elif self.envs.kvversion == KVVersion.v2:
                self.vault_client.secrets.kv.v2.create_or_update_secret(
                    path=path,
                    secret=value,
                    mount_point=self.envs.mount_point,
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

        if value.startswith(self.envs.template):
            value = value[len(self.envs.template):]
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

    def _split_path_regex(self, path: str) -> Tuple[str, str]:
        """
        Split path to Vault key/value using regex
        Format: "/path/a/b/c<SPLITER:.>key<SPLITER:.><version optional>"

        Split on single separator (double separators are skipped)
        Raises ValueError if path contains multiple dots

        Return
            path, key
            where:
                key is name of field in Vault
        """
        # pattern = re.compile(r'(.*?[^\.])\.([^\.].*)$')
        pattern = re.compile(
            rf'(.*?[^{re.escape(self.SPLITER_KEY)}])'
            rf'{re.escape(self.SPLITER_KEY)}'
            rf'([^{re.escape(self.SPLITER_KEY)}].*)$'
        )
        match = pattern.match(path)
        if not match:
            raise ValueError(f"Wrong format path: {path}")
        # Check second group
        if pattern.match(match.group(2)) is not None:
            raise ValueError(f"Wrong format path: {path}")

        v_path = match.group(1).replace(self.SPLITER_KEY * 2, self.SPLITER_KEY)
        v_key = match.group(2).replace(self.SPLITER_KEY * 2, self.SPLITER_KEY)
        return v_path, v_key

    def _split_path(
        self, path: str, use_regex: bool = False
    ) -> Tuple[str, str]:
        """
        Split path to Vault key/value
        Format: "/path/a/b/c<SPLITER:.>key<SPLITER:.><version optional>"

        Split only one symvol, if it double then will be skip

        Args:
            use_regex: If True, uses regex implementation for splitting

        Return
            path, key
            where:
                key is name of field in Vault
        """
        v_path: Optional[str] = None
        v_key: Optional[str] = None

        split_index = len(path) - 2  # from zero, and last - 1
        while split_index - 1:
            if path[split_index] == self.SPLITER_KEY:
                if path[split_index - 1] == self.SPLITER_KEY:
                    split_index = split_index - 1
                else:
                    if v_path is not None and v_key is not None:
                        raise ValueError(f"Wrong format path: {path}")
                    v_path, v_key = [path[:split_index], path[split_index + 1:]]
            split_index = split_index - 1
        if v_path is None or v_key is None:
            raise ValueError(f"Wrong format path: {path}")
        v_path = v_path.replace(self.SPLITER_KEY * 2, self.SPLITER_KEY)
        v_key = v_key.replace(self.SPLITER_KEY * 2, self.SPLITER_KEY)
        return v_path, v_key

    def _get_decode_filename_by_index(self, index: int) -> str:
        """
        Args
            index (int): index of path into args.yaml_file
        Return
            filename for decode file
        """
        if index >= len(self.args.yaml_file):
            raise ValueError(
                f"Index {index} is out of range for {self.args.yaml_file}")

        filename = os.path.split(self.args.yaml_file[index])[1]

        return '.'.join(filter(None, [
            os.path.splitext(filename)[0],
            self.envs.environment.replace("/", ""),
            'dec.yaml'
        ]))

    def _get_decode_files(self) -> List[str]:
        """
        Return
            list of decode files
        """
        if not self.args.yaml_file:
            return []
        return [
            self._get_decode_filename_by_index(index)
            for index in range(len(self.args.yaml_file))
        ]


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Store secrets from Helm in Vault\n\n"
            "Requirements:\n\n"
            "Environment Variables:\n"
            "    VAULT_ADDR:         "
            "(The HTTP address of Vault, for example, http://localhost:8200)\n"
            "    VAULT_TOKEN:        "
            "(The token used to authenticate with Vault)\n"
            "    VAULT_NAMESPACE:    "
            "(The Vault Namespace to use (Vault enterprise only))\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="action", required=True)

    # Common arguments
    # ----------------
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument(
        "-d",
        "--deliminator",
        type=str,
        help="The secret deliminator used when parsing. Default: \"changeme\""
    )
    parent_parser.add_argument(
        "-mp",
        "--mount-point",
        type=str,
        help="The Vault Mount Point Default: \"secret/data\""
    )
    parent_parser.add_argument(
        "-p",
        "--path",
        type=str,
        help=(
            "The Vault Path (secret mount location in Vault) "
            "Default: \"secret/helm\""
        )
    )
    parent_parser.add_argument(
        "-t",
        "--template",
        type=str,
        help=(
            "Substring with path to vault key instead of deliminator. "
            "Default: \"VAULT:\""
        )
    )
    parent_parser.add_argument(
        "-kv",
        "--kvversion",
        choices=list(KVVersion),
        type=KVVersion,
        help="The KV Version (v1, v2) Default: \"v2\""
    )

    # Common verbose
    pp_verbose = argparse.ArgumentParser(add_help=False)
    pp_verbose.add_argument(
        "-v", "--verbose", help="Verbose logs", action="store_true")
    # Common for helm action
    pp_helm = argparse.ArgumentParser(add_help=False)
    pp_helm.add_argument(
        "-f",
        "--values",
        type=str,
        action="append",
        dest="yaml_file",
        help="The encrypted YAML file to decrypt on the fly"
    )
    # Common yaml_file
    pp_yaml_file = argparse.ArgumentParser(add_help=False)
    pp_yaml_file.add_argument(
        "yaml_file",
        type=str,
        action="append",
        help="The YAML file to be worked on"
    )
    # Common environment
    pp_env = argparse.ArgumentParser(add_help=False)
    pp_env.add_argument(
        "-e",
        "--environment",
        type=str,
        help="Allows for secrets to be encoded on a per environment basis"
    )
    # ----------------

    # Encrypt help
    subparsers.add_parser(
        "enc",
        help="Parse a YAML file and store user entered data in Vault",
        parents=[pp_verbose, parent_parser, pp_helm, pp_env]
    )

    # Decrypt help
    subparsers.add_parser(
        "dec",
        help="Parse a YAML file and retrieve values from Vault",
        parents=[pp_verbose, parent_parser, pp_helm, pp_env]
    )

    # Clean help
    clean = subparsers.add_parser(
        "clean",
        help="Remove decrypted files (in the current directory)",
        parents=[pp_verbose, pp_env]
    )
    clean.add_argument(
        "-f",
        "--file",
        type=str,
        action="append",
        help="The specific YAML file to be deleted, without .dec",
        dest="yaml_file"
    )

    # View Help
    subparsers.add_parser(
        "view",
        help="View decrypted YAML file",
        parents=[pp_verbose, parent_parser, pp_helm]
    )

    # Edit Help
    edit = subparsers.add_parser(
        "edit",
        help="Edit decrypted YAML file. DOES NOT CLEAN UP AUTOMATICALLY.",
        parents=[pp_verbose, parent_parser, pp_yaml_file]
    )
    edit.add_argument(
        "-ed",
        "--editor",
        help="Editor name. Default: (Linux/MacOS) \"vi\" (Windows) \"notepad\"",
        const=True,
        nargs="?"
    )

    # Install Help
    subparsers.add_parser(
        "install",
        help="Wrapper that decrypts YAML files before running helm install",
        parents=[pp_verbose, parent_parser, pp_helm, pp_env]
    )

    # Template Help
    subparsers.add_parser(
        "template",
        help="Wrapper that decrypts YAML files before running helm install",
        parents=[pp_verbose, parent_parser, pp_helm]
    )

    # Upgrade Help
    subparsers.add_parser(
        "upgrade",
        help="Wrapper that decrypts YAML files before running helm install",
        parents=[pp_verbose, parent_parser, pp_helm]
    )

    # Lint Help
    subparsers.add_parser(
        "lint",
        help="Wrapper that decrypts YAML files before running helm install",
        parents=[pp_verbose, parent_parser, pp_helm]
    )

    # Diff Help
    subparsers.add_parser(
        "diff",
        help="Wrapper that decrypts YAML files before running helm diff",
        parents=[pp_verbose, parent_parser, pp_helm]
    )

    return parser


def main(args: Optional[list] = None):
    parsed = parse_args()
    args, leftovers = parsed.parse_known_args(args)
    vault_helm = HelmVault(args, leftovers)
    vault_helm.action()


if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        print(f"ERROR: {ex}")
        sys.exit(1)
    except SystemExit as ex:
        sys.exit(ex.code)
