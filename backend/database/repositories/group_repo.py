from typing import Optional, List
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from backend.models.group import GroupModel, GroupMemberModel
from backend.models.user import User

class GroupRepository:
    def __init__(self, db: Session):
        self.db = db

    def create_group(self, name: str, owner_id: int) -> GroupModel:
        now = datetime.now(timezone.utc).isoformat()
        group = GroupModel(
            name=name.strip(),
            owner_id=owner_id,
            created_at=now,
            updated_at=now
        )
        self.db.add(group)
        self.db.commit()
        self.db.refresh(group)

        # Creator is automatically added as group owner
        self.add_member(group.id, owner_id, role="owner")
        return group

    def get_group_by_id(self, group_id: int) -> Optional[GroupModel]:
        return self.db.query(GroupModel).filter(GroupModel.id == group_id).first()

    def list_user_groups(self, user_id: int) -> List[GroupModel]:
        # Return groups where user is a member or owner
        group_ids = self.get_user_group_ids(user_id)
        if not group_ids:
            return []
        return self.db.query(GroupModel).filter(GroupModel.id.in_(group_ids)).all()

    def rename_group(self, group_id: int, new_name: str) -> Optional[GroupModel]:
        group = self.get_group_by_id(group_id)
        if group:
            group.name = new_name.strip()
            group.updated_at = datetime.now(timezone.utc).isoformat()
            self.db.commit()
            self.db.refresh(group)
        return group

    def delete_group(self, group_id: int):
        group = self.get_group_by_id(group_id)
        if group:
            # Delete members and group record
            self.db.query(GroupMemberModel).filter(GroupMemberModel.group_id == group_id).delete()
            self.db.delete(group)
            self.db.commit()

    def add_member(self, group_id: int, user_id: int, role: str = "member") -> Optional[GroupMemberModel]:
        existing = self.get_member(group_id, user_id)
        if existing:
            return existing

        now = datetime.now(timezone.utc).isoformat()
        member = GroupMemberModel(
            group_id=group_id,
            user_id=user_id,
            role=role,
            created_at=now
        )
        self.db.add(member)
        self.db.commit()
        self.db.refresh(member)
        return member

    def remove_member(self, group_id: int, user_id: int):
        member = self.get_member(group_id, user_id)
        if member:
            # If the same user is added back later, require them to review/activate
            # all existing group document grants again.
            from backend.models.group import GroupDocumentShare
            from backend.models.share_access_activation import ShareAccessActivation
            share_ids = [row[0] for row in self.db.query(GroupDocumentShare.id).filter(
                GroupDocumentShare.group_id == group_id
            ).all()]
            if share_ids:
                self.db.query(ShareAccessActivation).filter(
                    ShareAccessActivation.source_type == "group",
                    ShareAccessActivation.share_id.in_(share_ids),
                    ShareAccessActivation.user_id == user_id,
                ).delete(synchronize_session=False)
            self.db.delete(member)
            self.db.commit()

    def get_member(self, group_id: int, user_id: int) -> Optional[GroupMemberModel]:
        return self.db.query(GroupMemberModel).filter(
            GroupMemberModel.group_id == group_id,
            GroupMemberModel.user_id == user_id
        ).first()

    def count_members(self, group_id: int) -> int:
        return self.db.query(GroupMemberModel).filter(GroupMemberModel.group_id == group_id).count()

    def list_group_members(self, group_id: int) -> List[GroupMemberModel]:
        return self.db.query(GroupMemberModel).filter(GroupMemberModel.group_id == group_id).all()

    def get_user_group_ids(self, user_id: int) -> List[int]:
        memberships = self.db.query(GroupMemberModel.group_id).filter(
            GroupMemberModel.user_id == user_id
        ).all()
        return [m[0] for m in memberships]
