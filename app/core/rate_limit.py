from fastapi import Request
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.core.config import settings
from app.schema.response import ResponseModel

limiter = Limiter(
    key_func=get_remote_address,
    enabled=settings.RATE_LIMIT_ENABLED,
)


async def rate_limit_exception_handler(
    request: Request, exc: RateLimitExceeded
) -> JSONResponse:
    return JSONResponse(
        status_code=429,
        content=ResponseModel(
            success=False,
            message="Rate limit exceeded",
            errors={"detail": str(exc.detail)},
        ).model_dump(),
        headers={"Retry-After": str(getattr(exc, "retry_after", 60))},
    )
