import os
import tempfile
import pytest
from pathlib import Path
from typing import Generator
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Setup test database path
_TEST_DIRECTORY = tempfile.TemporaryDirectory(prefix="docsign-tests-", dir="./data/db")
TEST_DB_PATH = str(Path(_TEST_DIRECTORY.name) / "test.db")
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB_PATH}"
os.environ["ENVIRONMENT"] = "testing"
os.environ["DEBUG"] = "false"

from backend.app.core.config import settings
from backend.app.core.database import Base, get_db
from backend.app.main import app
from backend.app.models.user import User
from backend.app.models.session import AuthSession
from backend.app.models.enums import UserRole, UserStatus
from backend.app.auth.hasher import hash_password

test_engine = create_engine(
    f"sqlite:///{TEST_DB_PATH}",
    connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    """Creates tables before tests and drops them when session finishes."""
    Path("./data/db").mkdir(parents=True, exist_ok=True)
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)
    if os.path.exists(TEST_DB_PATH):
        try:
            os.remove(TEST_DB_PATH)
        except Exception:
            pass


@pytest.fixture
def db_session() -> Generator:
    """Provides a transactional database session per test with clean tables."""
    # Fresh schema in the private test database; retention triggers prohibit DELETE.
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client(db_session) -> Generator[TestClient, None, None]:
    """TestClient that overrides the get_db dependency with test database session."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app, base_url="http://localhost:8000") as test_client:
        yield test_client
    app.dependency_overrides.clear()


from backend.app.api.v1.documents import get_storage
from backend.app.services.verification_service import _ip_request_history
from backend.app.storage.local import LocalStorageService


@pytest.fixture
def storage_p5():
    """Provides an isolated temporary LocalStorageService for verification tests."""
    with tempfile.TemporaryDirectory(prefix="p5-test-storage-", dir="data") as root:
        yield LocalStorageService(Path(root).resolve())


@pytest.fixture
def client_p5(client, storage_p5):
    """TestClient configured with overridden get_storage dependency and cleared rate limiters."""
    app.dependency_overrides[get_storage] = lambda: storage_p5
    _ip_request_history.clear()
    yield client
    app.dependency_overrides.pop(get_storage, None)
