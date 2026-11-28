from typing import Literal

from pydantic import BaseModel, Field


class UploadSignIn(BaseModel):
    kind: Literal["audio", "image", "club_cover", "avatar"]
    podclub_id: int | None = Field(default=None, ge=1)
    filename: str = Field(min_length=1, max_length=255)
    content_type: str = Field(min_length=1, max_length=100)

    model_config = {"extra": "forbid"}


class UploadSignOut(BaseModel):
    signed_url: str
    token: str
    path: str
    public_url: str
    expires_in: int
    bucket: str
    max_bytes: int
