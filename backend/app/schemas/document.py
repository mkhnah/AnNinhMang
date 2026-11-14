from datetime import datetime
from pydantic import BaseModel, ConfigDict
from backend.app.models.document import VersionState, Visibility


class VersionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    document_id: str
    version_no: int
    original_filename: str
    file_sha256: str
    file_size_bytes: int
    state: VersionState
    created_at: datetime
    locked_at: datetime | None


class UploadResponse(VersionResponse):
    version_id: str


class DocumentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    title: str
    visibility: Visibility
    created_at: datetime
    updated_at: datetime


class DocumentList(BaseModel):
    items: list[DocumentResponse]
    total: int
    limit: int
    offset: int
