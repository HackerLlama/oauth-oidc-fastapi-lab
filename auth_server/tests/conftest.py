"""
Pytest configuration for auth_server. Use in-memory SQLite so tests don't touch the filesystem.
"""
import os

# In-memory SQLite; database.py uses StaticPool so all connections share the same DB
os.environ["AUTH_DATABASE_URL"] = "sqlite:///:memory:"
# Avoid seed_from_env using long or unexpected env passwords during tests
if "OAUTH_SEED_PASSWORD" in os.environ:
    del os.environ["OAUTH_SEED_PASSWORD"]
if "OAUTH_SEED_USER" in os.environ:
    del os.environ["OAUTH_SEED_USER"]
