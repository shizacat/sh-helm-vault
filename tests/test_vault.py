#!/usr/bin/env python3

import os
import subprocess
from shutil import copyfile

import pytest

import src.vault as vault


PATH_TEST_FILE = "./tests/data/test.yaml"
PATH_TEST_YAML_DEC = "./tests/data/test.yaml.dec"


def test_load_yaml():
    parsed = vault.parse_args()
    obj = vault.VaultHelm(
        *parsed.parse_known_args(["enc", "-f", PATH_TEST_FILE])
    )
    data = obj._load_yaml()
    assert isinstance(data, dict)


def test_parser():
    copyfile(PATH_TEST_FILE, "./tests/test.yaml.bak")
    parsed = vault.parse_args()
    parser = parsed.parse_known_args(["clean", "-f", PATH_TEST_FILE])
    assert(parser)
    copyfile("./tests/test.yaml.bak", PATH_TEST_FILE)
    os.remove("./tests/test.yaml.bak")


def filecheckfunc():
    raise FileNotFoundError


def test_enc():
    os.environ["KVVERSION"] = "v2"
    input_values = ["adfs1", "adfs2", "adfs3", "adfs4"]
    output = []

    def mock_input(s):
        output.append(s)
        return input_values.pop(0)
    vault.input = mock_input
    vault.print = lambda s: output.append(s)

    vault.main(["enc", PATH_TEST_FILE])

    assert output == [
        'Input a value for nextcloud.password: ',
        'Input a value for /secret/testdata.user: ',
        'Input a value for /secret/testdata.password: ',
        'Input a value for mariadb/db.password: ',
        'Done Encription',
    ]


def test_enc_with_env():
    os.environ["KVVERSION"] = "v2"
    input_values = ["adfs1", "adfs2", "adfs3", "adfs4"]
    output = []

    def mock_input(s):
        output.append(s)
        return input_values.pop(0)
    vault.input = mock_input
    vault.print = lambda s: output.append(s)

    vault.main(['enc', PATH_TEST_FILE, '-e', 'test'])

    assert output == [
        'Input a value for nextcloud.password: ',
        'Input a value for /secret/testdata.user: ',
        'Input a value for /secret/test/testdata.password: ',
        'Input a value for mariadb/db.password: ',
        'Done Encription',
    ]


def test_refuse_enc_from_file_with_bad_name():
    with pytest.raises(Exception) as e:
        vault.main(['enc', PATH_TEST_FILE, '-s', './tests/test.yaml.bad'])
        assert "ERROR: Secret file name must end with" in str(e.value)


def test_dec():
    os.environ["KVVERSION"] = "v2"
    input_values = ["adfs1", "adfs2"]
    output = []

    def mock_input(s):
        output.append(s)
        return input_values.pop(0)
    vault.input = mock_input
    vault.print = lambda s, *args: output.append(s)

    vault.main(['dec', PATH_TEST_FILE])

    assert output == [
        'Done Decrypting',
    ]


def test_clean():
    os.environ["KVVERSION"] = "v2"
    copyfile(PATH_TEST_YAML_DEC, "./tests/test.yaml.dec.bak")
    with pytest.raises(FileNotFoundError):
        vault.main(['clean', '-f .tests/test.yaml', '-v'])
    copyfile("./tests/test.yaml.dec.bak", PATH_TEST_YAML_DEC)
    os.remove("./tests/test.yaml.dec.bak")


@pytest.mark.skipif(
    subprocess.run("helm", shell=True),
    reason="No way of testing without Helm"
)
def test_install():
    os.environ["KVVERSION"] = "v2"
    input_values = []
    output = []

    def mock_input(s):
        output.append(s)
        return input_values.pop(0)
    vault.input = mock_input
    vault.print = lambda s: output.append(s)

    vault.main([
        'install',
        "stable/nextcloud",
        "--name",
        "nextcloud",
        "--namespace",
        "nextcloud",
        "-f",
        PATH_TEST_FILE,
        "--dry-run",
    ])

    assert output == [
        'NAME:   nextcloud',
    ]


def test_config():
    parsed = vault.parse_args()
    parser, _ = parsed.parse_known_args(
        ['clean', '-f ./tests/test.yaml', "-v", "--environment", "test"]
    )
    r = vault.Config.create_from_env(parser)
    assert r.environment == "/test"
