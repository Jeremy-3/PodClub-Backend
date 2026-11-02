from app.models.users import Users
from app.schema.user import UserCreate,UserUpdate, UserCreateDB
from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from app.crud.base import CRUDBase
# from app.core.constants import ROLE_GUEST_ID, ROLE_MANAGER_ID
# from app.core.security import hash_password
from uuid import UUID
# from app.models.manager import Managers


MODEL = Users


# class CRUDUser(CRUDBase[MODEL, UserCreate]):
#     """ CRUD     operations for User model"""
    
#     def create_user(self,db:Session,record_create:UserCreate):
#         # check if user exists
#         existing_record = self.get_record_by_field(db, "email", record_create.email)
#         if existing_record:
#             raise HTTPException(
#                 status_code=status.HTTP_400_BAD_REQUEST,
#                 detail="Email already registered",
#             )
    
#         record_data = record_create.model_dump()
#         record_data['password_hash'] = hash_password(record_data['password'])

#         record_data.pop("password")

#         if not record_data.get("role_id"):
#                 record_data["role_id"] = ROLE_GUEST_ID

#         db_obj = UserCreateDB(**record_data) 

#         new_user = self.create(db, db_obj)

#         # db.commit()
#         # db.refresh(new_user)

#         return new_user
    
#     def update_user(self, db:Session, uid:UUID, record_in:UserUpdate):
#         record = self.get_record_by_field(db, "uid", uid)
#         if not record:
#             raise HTTPException(
#                 status_code=status.HTTP_404_NOT_FOUND,
#                 detail="User not found",
#             )
#         if record_in.email and record_in.email != record.email:
#             existing_record = self.get_record_by_field(db, "email", record_in.email)
#             if existing_record:
#                 raise HTTPException(
#                     status_code=status.HTTP_400_BAD_REQUEST,
#                     detail="Email already registered",
#                 )
#         if record_in.password:
#             record_in.password_hash = hash_password(record_in.password)
#             delattr(record_in, "password")

#         return self.update(db, record, record_in)
    
    
    # def apply_manager_role(self, db: Session, user: Users):
    #     # Update role to manager
    #     user.role_id = ROLE_MANAGER_ID
    #     db.add(user)

    #     # Create manager profile if not exists
    #     existing_manager = db.query(Managers).filter(Managers.user_id == user.id).first()
    #     if not existing_manager:
    #         new_manager = Managers(user_id=user.id, status="available")
    #         db.add(new_manager)

    #     db.commit()
    #     db.refresh(user)
    #     return user



crud_user = CRUDUser(MODEL)