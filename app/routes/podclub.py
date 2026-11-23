from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.crud.podclub import crud_podclub
from app.db.session import get_db
from app.dependencies.rbac import require_permission
from app.schema.podclub import PodClubCreate, PodClubOut, PodClubUpdate
from app.schema.response import ResponseModel

router = APIRouter(prefix="/podclubs", tags=["PodClubs"])


@router.post(
    "",
    response_model=ResponseModel[PodClubOut],
    dependencies=[Depends(require_permission("podclub.create"))],
)
def create_podclub(payload: PodClubCreate, db: Session = Depends(get_db)):
    podclub = crud_podclub.create_podclub(db, payload)
    return ResponseModel(data=podclub, message="PodClub created successfully")


@router.get(
    "",
    response_model=ResponseModel[list[PodClubOut]],
    dependencies=[Depends(require_permission("podclubs.view_all"))],
)
def get_all_podclubs(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
):
    podclubs, total = crud_podclub.read(db, page=page, limit=limit)
    return ResponseModel(
        data=podclubs, total=total, message="PodClubs retrieved successfully"
    )


@router.get(
    "/{uid}",
    response_model=ResponseModel[PodClubOut],
    dependencies=[Depends(require_permission("podclub.view_one"))],
)
def get_podclub(uid: UUID, db: Session = Depends(get_db)):
    podclub = crud_podclub.get_record_by_field(db, "uid", uid)
    if not podclub:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="PodClub not found"
        )
    return ResponseModel(data=podclub, message="PodClub retrieved successfully")


@router.put(
    "/{uid}",
    response_model=ResponseModel[PodClubOut],
    dependencies=[Depends(require_permission("podclub.update"))],
)
def update_podclub(uid: UUID, payload: PodClubUpdate, db: Session = Depends(get_db)):
    podclub = crud_podclub.update_podclub(db, uid, payload)
    return ResponseModel(data=podclub, message="PodClub updated successfully")


@router.delete(
    "/{uid}",
    response_model=ResponseModel[None],
    dependencies=[Depends(require_permission("podclub.delete"))],
)
def delete_podclub(uid: UUID, db: Session = Depends(get_db)):
    crud_podclub.delete_podclub(db, uid)
    return ResponseModel(message="PodClub deleted successfully")
