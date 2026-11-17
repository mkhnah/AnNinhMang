from pydantic import BaseModel, ConfigDict

from backend.app.models.enums import UserStatus


class UserLookupItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    full_name: str
    email: str
    status: UserStatus


class UserLookupPage(BaseModel):
    items: list[UserLookupItem]
    total: int
    limit: int
    offset: int
