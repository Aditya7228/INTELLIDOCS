from typing import Optional, List
from sqlalchemy.orm import Session
from backend.models.category import CategoryModel

class CategoryRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_by_id(self, cat_id: int) -> Optional[CategoryModel]:
        return self.db.query(CategoryModel).filter(CategoryModel.id == cat_id).first()

    def get_by_name(self, name: str, owner_id: Optional[int] = None) -> Optional[CategoryModel]:
        query = self.db.query(CategoryModel).filter(CategoryModel.name == name)
        if owner_id is not None:
            query = query.filter(
                (CategoryModel.is_system == 1) | (CategoryModel.owner_id == owner_id)
            )
        return query.first()

    def list_all(self, owner_id: Optional[int] = None) -> List[CategoryModel]:
        query = self.db.query(CategoryModel)
        if owner_id is not None:
            query = query.filter(
                (CategoryModel.is_system == 1) | (CategoryModel.owner_id == owner_id)
            )
        return query.order_by(CategoryModel.is_system.desc(), CategoryModel.name).all()

    def create_user_category(self, name: str, owner_id: int, description: Optional[str] = None) -> CategoryModel:
        cat = CategoryModel(
            name=name.strip(),
            description=description,
            is_system=0,
            owner_id=owner_id
        )
        self.db.add(cat)
        self.db.commit()
        self.db.refresh(cat)
        return cat
