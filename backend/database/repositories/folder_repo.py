from typing import Optional, List
from sqlalchemy.orm import Session
from backend.models.folder import FolderModel

class FolderRepository:
    def __init__(self, db: Session):
        self.db = db

    def create(self, name: str, owner_id: int, parent_id: Optional[int] = None) -> FolderModel:
        folder = FolderModel(name=name.strip(), owner_id=owner_id, parent_id=parent_id)
        self.db.add(folder)
        self.db.commit()
        self.db.refresh(folder)
        return folder

    def get_by_id(self, folder_id: int, owner_id: int) -> Optional[FolderModel]:
        return self.db.query(FolderModel).filter(
            FolderModel.id == folder_id,
            FolderModel.owner_id == owner_id
        ).first()

    def list_for_user(self, owner_id: int, parent_id: Optional[int] = None) -> List[FolderModel]:
        query = self.db.query(FolderModel).filter(FolderModel.owner_id == owner_id)
        if parent_id is None:
            query = query.filter(FolderModel.parent_id == None)
        else:
            query = query.filter(FolderModel.parent_id == parent_id)
        return query.order_by(FolderModel.name).all()

    def rename(self, folder_id: int, owner_id: int, new_name: str) -> Optional[FolderModel]:
        folder = self.get_by_id(folder_id, owner_id)
        if folder:
            folder.name = new_name.strip()
            self.db.commit()
            self.db.refresh(folder)
        return folder

    def delete(self, folder_id: int, owner_id: int) -> bool:
        folder = self.get_by_id(folder_id, owner_id)
        if folder:
            self.db.delete(folder)
            self.db.commit()
            return True
        return False
