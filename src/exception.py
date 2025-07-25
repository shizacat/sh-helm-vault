class HelmVaultExcepion(Exception):
    """Base exception for HelmVault"""


class HVWrongPath(HelmVaultExcepion):
    """
    The path don't exist, or version in Vault
    """
