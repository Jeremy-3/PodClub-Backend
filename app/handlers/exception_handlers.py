from fastapi import Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.schema.response import ResponseModel
from app.utils.logger import logger


# --- HTTPException handler ---
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    logger.warning(f"HTTP {exc.status_code}: {exc.detail}")
    message = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
    errors = getattr(exc.detail, "errors", None) if not isinstance(exc.detail, str) else None
    return JSONResponse(
        status_code=exc.status_code,
        content=ResponseModel(
            success=False,
            message=message,
            errors=errors,
        ).model_dump(),
    )


# --- Pydantic validation handler ---
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.warning("VALIDATION EXCEPTION")
    formatted_errors = [
        {
            "field": ".".join(str(x) for x in err.get("loc", []) if isinstance(x, (str, int))),
            "message": err.get("msg", "Invalid input"),
            "type": err.get("type", "validation_error"),
        }
        for err in exc.errors()
    ]
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=ResponseModel(
            success=False,
            message="Validation Error",
            errors={"details": formatted_errors},
        ).model_dump(),
    )


# --- Generic exceptions ---
async def generic_exception_handler(request: Request, exc: Exception):
    logger.exception("GENERIC EXCEPTION")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ResponseModel(
            success=False,
            message="An unexpected error occurred",
            errors=None,
        ).model_dump(),
    )


# --- SQLAlchemy exceptions ---
async def sqlalchemy_exception_handler(request: Request, exc: SQLAlchemyError):
    logger.exception("SQLALCHEMY EXCEPTION")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ResponseModel(
            success=False,
            message="A server error occurred",
            errors=None,
        ).model_dump(),
    )
