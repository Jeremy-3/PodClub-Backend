from fastapi import Depends, HTTPException, status
from jose import jwt, JWTError
from sqlalchemy.orm import Session, joinedload
from app.core.config import settings
from app.db.session import get_db
from app.models.users import Users
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> Users:
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        raw_sub = payload.get("sub")
        if not raw_sub:
            raise HTTPException(status_code=401, detail="Invalid token")
        user_id: int = int(raw_sub)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(Users).options(joinedload(Users.role)).filter(Users.id == user_id).first()
    
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    if not user.is_active:
        raise HTTPException(status_code=401, detail="Inactive user")

    return user