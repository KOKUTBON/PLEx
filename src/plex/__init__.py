from importlib.metadata import PackageNotFoundError, version

__all__ = ["__version__"]

try:
    __version__ = version("kokutbon-plex")
except PackageNotFoundError:  # pragma: no cover - fallback for editable source trees
    __version__ = "2.0.0-alpha.1"
