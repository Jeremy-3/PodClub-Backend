from fastapi import status, HTTPException, Query
from typing import Type, TypeVar, Generic, List, Any, Optional, Dict, Union
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import and_, func
from pydantic import BaseModel
from sqlalchemy.exc import SQLAlchemyError
from app.utils.logger import logger

ModelType = TypeVar("ModelType")
SchemaType = TypeVar("SchemaType", bound=BaseModel)


class CRUDBase(Generic[ModelType,SchemaType]):
    def __init__(self, model: Type[ModelType]):
        self.model = model

    # --------------------------------------------------
    # GET BY ID
    # --------------------------------------------------
    def get(self, db: Session, id: Any) -> Optional[ModelType]:
        logger.debug(f"Fetching {self.model.__name__} by id={id}")
        return db.query(self.model).filter(self.model.id == id).first()

    # --------------------------------------------------
    # GET BY SINGLE FIELD
    # --------------------------------------------------
    def get_record_by_field(
        self,
        db: Session,
        field: str,
        value: Any,
        case_insensitive: bool = True
    ) -> Optional[ModelType]:

        if not hasattr(self.model, field):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid field: {field}"
            )

        column = getattr(self.model, field)

        query = db.query(self.model)

        if isinstance(value, str) and case_insensitive:
            query = query.filter(func.lower(column) == value.lower())
        else:
            query = query.filter(column == value)

        return query.first()

    # --------------------------------------------------
    # GET BY MULTIPLE FIELDS (AND)
    # --------------------------------------------------
    def get_record_by_fields(
        self,
        db: Session,
        filters: Dict[str, Any]
    ) -> Optional[ModelType]:

        conditions = []
        for field, value in filters.items():
            if not hasattr(self.model, field):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid field: {field}"
                )
            conditions.append(getattr(self.model, field) == value)

        return db.query(self.model).filter(and_(*conditions)).first()

    # --------------------------------------------------
    # CREATE
    # --------------------------------------------------
    def create(self, db: Session, obj_in: SchemaType) -> ModelType:
        logger.info(f"Creating {self.model.__name__}")

        try:
            db_obj = self.model(**obj_in.model_dump())
            db.add(db_obj)
            db.commit()
            db.refresh(db_obj)
            return db_obj

        except SQLAlchemyError as e:
            db.rollback()
            logger.exception("Create failed")
            raise HTTPException(
                status_code=500,
                detail="Failed to create record"
            )

    # --------------------------------------------------
    # READ (LIST + PAGINATION + RELATIONS + FILTERS)
    # --------------------------------------------------
    def read(
        self,
        db: Session,
        page: int = 1,
        limit: int = 10,
        relationships: Optional[List[str]] = None,
        filters: Optional[List[Dict[str, Any]]] = None,
        order_by: Optional[Any] = None
    ) -> tuple[list[ModelType], int]:

        if page < 1 or limit < 1:
            raise HTTPException(
                status_code=400,
                detail="Page and limit must be positive"
            )

        query = db.query(self.model)

        # ---------- Relationships ----------
        if relationships:
            for rel in relationships:
                query = query.options(joinedload(getattr(self.model, rel)))

        # ---------- Filters ----------
        if filters:
            for f in filters:
                field = getattr(self.model, f["field"])
                op = f.get("op", "eq")
                value = f["value"]

                if op == "eq":
                    query = query.filter(field == value)
                elif op == "ne":
                    query = query.filter(field != value)
                elif op == "in":
                    query = query.filter(field.in_(value))
                elif op == "like":
                    query = query.filter(field.ilike(f"%{value}%"))
                else:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Unsupported filter operator: {op}"
                    )

        total = query.count()

        # ---------- Ordering ----------
        if order_by is not None:
            query = query.order_by(order_by)
        elif hasattr(self.model, "created_at"):
            query = query.order_by(self.model.created_at.desc())

        records = (
            query
            .offset((page - 1) * limit)
            .limit(limit)
            .all()
        )

        return records, total

    # --------------------------------------------------
    # UPDATE (PARTIAL SAFE)
    # --------------------------------------------------
    def update(
        self,
        db: Session,
        db_obj: ModelType,
        obj_in: Union[SchemaType, Dict[str, Any]]
    ) -> ModelType:

        if isinstance(obj_in, BaseModel):
            update_data = obj_in.model_dump(exclude_unset=True)
        else:
            update_data = obj_in

        for field, value in update_data.items():
            setattr(db_obj, field, value)

        try:
            db.commit()
            db.refresh(db_obj)
            return db_obj
        except SQLAlchemyError:
            db.rollback()
            raise HTTPException(
                status_code=500,
                detail="Update failed"
            )

    # --------------------------------------------------
    # DELETE (HARD)
    # --------------------------------------------------
    def delete(self, db: Session, id: Any) -> None:
        obj = self.get(db, id)
        if not obj:
            raise HTTPException(status_code=404, detail="Record not found")

        try:
            db.delete(obj)
            db.commit()
        except SQLAlchemyError:
            db.rollback()
            raise HTTPException(
                status_code=500,
                detail="Delete failed"
            )

    # --------------------------------------------------
    # SOFT DELETE (OPTIONAL)
    # --------------------------------------------------
    def soft_delete(self, db: Session, db_obj: ModelType) -> ModelType:
        if not hasattr(db_obj, "is_deleted"):
            raise HTTPException(
                status_code=400,
                detail="Model does not support soft delete"
            )

        db_obj.is_deleted = True
        db.commit()
        db.refresh(db_obj)
        return db_obj