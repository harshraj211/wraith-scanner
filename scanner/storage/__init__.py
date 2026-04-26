"""Local storage package for Wraith scan artifacts."""

from scanner.storage.repository import StorageRepository, get_repository, init_db

__all__ = ["StorageRepository", "get_repository", "init_db"]

