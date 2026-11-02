from fastapi import Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from sqlalchemy.exc import SQLAlchemyError
from app.schemas.response import ResponseModel
from app.utils.logger import logger

# --- HTTPException handler ---
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    logger.error("HTTP EXCEPTION", exc_info=True)
    message = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
    return JSONResponse(
        status_code=exc.status_code,
        content=ResponseModel(
            success=False,
            message=message,
            errors=getattr(exc.detail, "errors", None)
        ).model_dump()
    )

# --- Pydantic validation handler ---
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.error("VALIDATION EXCEPTION", exc_info=False)
    formatted_errors = [
        {
            "field": ".".join(str(x) for x in err.get("loc", []) if isinstance(x, (str, int))),
            "message": err.get("msg", "Invalid input"),
            "type": err.get("type", "validation_error")
        }
        for err in exc.errors()
    ]
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=ResponseModel(
            success=False,
            message="Validation Error",
            errors={"details": formatted_errors}
        ).model_dump()
    )

# --- Generic exceptions ---
async def generic_exception_handler(request: Request, exc: Exception):
    logger.error("GENERIC EXCEPTION", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ResponseModel(
            success=False,
            message=str(exc),
            errors=None
        ).model_dump()
    )

# --- SQLAlchemy exceptions ---
async def sqlalchemy_exception_handler(request: Request, exc: SQLAlchemyError):
    logger.error("SQLALCHEMY EXCEPTION", exc_info=True)
    return JSONResponse(
        status_code=500,
        content=ResponseModel(
            success=False,
            message="A server error occurred",
            errors=None
        ).model_dump()
    )