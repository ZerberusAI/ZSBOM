"""Name normalisation for NPM packages."""


def normalise_name(name: str) -> str:
    """Normalise a package name to a canonical form.

    The NPM ecosystem treats names case-insensitively and commonly uses hyphens
    instead of underscores.  This helper performs the minimal normalisation
    required by the tests.
    """

    return name.strip().lower().replace("_", "-")
