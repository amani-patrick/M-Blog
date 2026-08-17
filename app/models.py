from typing import Optional
from datetime import datetime, timezone
import sqlalchemy as sa
import sqlalchemy.orm as so
from app import db, login
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from hashlib import md5
import jwt
import secrets
from time import time
from flask import current_app


@login.user_loader
def load_user(id):
    return db.session.get(User, int(id))


# ─── Association Tables ───────────────────────────────────────────────────────

followers = sa.Table(
    'followers', db.metadata,
    sa.Column('follower_id', sa.Integer, sa.ForeignKey('user.id'), primary_key=True),
    sa.Column('followed_id', sa.Integer, sa.ForeignKey('user.id'), primary_key=True)
)

post_tags = sa.Table(
    'post_tags', db.metadata,
    sa.Column('post_id', sa.Integer, sa.ForeignKey('post.id'), primary_key=True),
    sa.Column('tag_id', sa.Integer, sa.ForeignKey('tag.id'), primary_key=True)
)


# ─── Tag Model ────────────────────────────────────────────────────────────────

class Tag(db.Model):
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    name: so.Mapped[str] = so.mapped_column(sa.String(50), index=True, unique=True)
    posts: so.Mapped[list['Post']] = so.relationship(
        'Post', secondary=post_tags, back_populates='tags'
    )

    def __repr__(self):
        return f'<Tag {self.name}>'


# ─── User Model ───────────────────────────────────────────────────────────────

class User(UserMixin, db.Model):
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    username: so.Mapped[str] = so.mapped_column(sa.String(64), index=True)
    email: so.Mapped[str] = so.mapped_column(sa.String(120), index=True, unique=True)
    password_hash: so.Mapped[Optional[str]] = so.mapped_column(sa.String(256))
    about_me: so.Mapped[Optional[str]] = so.mapped_column(sa.String(140))
    last_seen: so.Mapped[Optional[datetime]] = so.mapped_column(
        default=lambda: datetime.now(timezone.utc)
    )

    # ── New fields ──
    is_admin: so.Mapped[bool] = so.mapped_column(
        sa.Boolean, default=False, server_default=sa.text('0')
    )
    # Existing users default to verified; new registrations set explicitly to False
    is_email_verified: so.Mapped[bool] = so.mapped_column(
        sa.Boolean, default=False, server_default=sa.text('1')
    )
    verification_token: so.Mapped[Optional[str]] = so.mapped_column(sa.String(256))
    api_key: so.Mapped[Optional[str]] = so.mapped_column(
        sa.String(64), unique=True, index=True
    )
    github_id: so.Mapped[Optional[str]] = so.mapped_column(sa.String(64))

    # ── Relationships ──
    posts: so.WriteOnlyMapped['Post'] = so.relationship(
        'Post', back_populates='author'
    )
    comments: so.WriteOnlyMapped['Comment'] = so.relationship(
        'Comment', back_populates='author'
    )
    notifications: so.WriteOnlyMapped['Notification'] = so.relationship(
        'Notification', back_populates='user'
    )
    following: so.WriteOnlyMapped['User'] = so.relationship(
        'User', secondary=followers,
        primaryjoin=(followers.c.follower_id == id),
        secondaryjoin=(followers.c.followed_id == id),
        back_populates='followers'
    )
    followers: so.WriteOnlyMapped['User'] = so.relationship(
        'User', secondary=followers,
        primaryjoin=(followers.c.followed_id == id),
        secondaryjoin=(followers.c.follower_id == id),
        back_populates='following'
    )

    # ── Auth helpers ──
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_api_key(self):
        self.api_key = secrets.token_urlsafe(32)
        return self.api_key

    def generate_verification_token(self):
        self.verification_token = secrets.token_urlsafe(32)
        return self.verification_token

    # ── Social helpers ──
    def avatar(self, size):
        digest = md5(self.email.lower().encode('utf-8')).hexdigest()
        return f'https://www.gravatar.com/avatar/{digest}?d=identicon&s={size}'

    def follow(self, user):
        if not self.is_following(user):
            self.following.add(user)
            db.session.add(Notification(
                user_id=user.id,
                message=f'{self.username} started following you',
                notif_type='follow'
            ))

    def unfollow(self, user):
        if self.is_following(user):
            self.following.remove(user)

    def is_following(self, user):
        query = self.following.select().where(User.id == user.id)
        return db.session.scalar(query) is not None

    def followers_count(self):
        query = sa.select(sa.func.count()).select_from(
            self.followers.select().subquery())
        return db.session.scalar(query)

    def following_count(self):
        query = sa.select(sa.func.count()).select_from(
            self.following.select().subquery())
        return db.session.scalar(query)

    def following_posts(self):
        Author = so.aliased(User)
        Follower = so.aliased(User)
        return (
            sa.select(Post)
            .join(Post.author.of_type(Author))
            .join(Author.followers.of_type(Follower), isouter=True)
            .where(sa.or_(
                Follower.id == self.id,
                Author.id == self.id,
            ))
            .group_by(Post)
            .order_by(Post.timestamp.desc())
        )

    def unread_notifications_count(self):
        query = sa.select(sa.func.count()).select_from(
            self.notifications.select()
            .where(Notification.is_read == False).subquery()  # noqa: E712
        )
        return db.session.scalar(query)

    # ── Password reset ──
    def get_reset_password_token(self, expires_in=600):
        return jwt.encode(
            {'reset_password': self.id, 'exp': time() + expires_in},
            current_app.config['SECRET_KEY'], algorithm='HS256')

    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, current_app.config['SECRET_KEY'],
                            algorithms=['HS256'])['reset_password']
        except Exception:
            return None
        return db.session.get(User, id)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'about_me': self.about_me,
            'avatar': self.avatar(64),
            'followers_count': self.followers_count(),
            'following_count': self.following_count(),
        }

    def __repr__(self):
        return f'<User {self.username}>'


# ─── Post Model ───────────────────────────────────────────────────────────────

class Post(db.Model):
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    title: so.Mapped[Optional[str]] = so.mapped_column(sa.String(140))
    body: so.Mapped[str] = so.mapped_column(sa.Text)
    timestamp: so.Mapped[datetime] = so.mapped_column(
        index=True, default=lambda: datetime.now(timezone.utc)
    )
    user_id: so.Mapped[int] = so.mapped_column(sa.ForeignKey(User.id), index=True)
    view_count: so.Mapped[int] = so.mapped_column(
        sa.Integer, default=0, server_default=sa.text('0')
    )

    # ── Relationships ──
    author: so.Mapped[User] = so.relationship('User', back_populates='posts')
    tags: so.Mapped[list['Tag']] = so.relationship(
        'Tag', secondary=post_tags, back_populates='posts'
    )
    comments: so.WriteOnlyMapped['Comment'] = so.relationship(
        'Comment', back_populates='post', cascade='all, delete-orphan'
    )

    def comments_count(self):
        query = sa.select(sa.func.count()).select_from(
            self.comments.select().subquery())
        return db.session.scalar(query)

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'body': self.body,
            'timestamp': self.timestamp.isoformat() + 'Z',
            'author': self.author.username,
            'author_avatar': self.author.avatar(40),
            'view_count': self.view_count,
            'comments_count': self.comments_count(),
            'tags': [t.name for t in self.tags],
        }

    def __repr__(self):
        return f'<Post {self.title or self.body[:30]}>'


# ─── Comment Model ────────────────────────────────────────────────────────────

class Comment(db.Model):
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    body: so.Mapped[str] = so.mapped_column(sa.Text)
    timestamp: so.Mapped[datetime] = so.mapped_column(
        index=True, default=lambda: datetime.now(timezone.utc)
    )
    user_id: so.Mapped[int] = so.mapped_column(sa.ForeignKey(User.id), index=True)
    post_id: so.Mapped[int] = so.mapped_column(sa.ForeignKey(Post.id), index=True)

    author: so.Mapped[User] = so.relationship('User', back_populates='comments')
    post: so.Mapped[Post] = so.relationship('Post', back_populates='comments')

    def __repr__(self):
        return f'<Comment {self.body[:30]}>'


# ─── AuditLog Model ───────────────────────────────────────────────────────────

class AuditLog(db.Model):
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    user_id: so.Mapped[Optional[int]] = so.mapped_column(
        sa.ForeignKey(User.id), nullable=True
    )
    username: so.Mapped[Optional[str]] = so.mapped_column(sa.String(64))
    action: so.Mapped[str] = so.mapped_column(sa.String(100))
    ip_address: so.Mapped[Optional[str]] = so.mapped_column(sa.String(45))
    user_agent: so.Mapped[Optional[str]] = so.mapped_column(sa.String(256))
    timestamp: so.Mapped[datetime] = so.mapped_column(
        index=True, default=lambda: datetime.now(timezone.utc)
    )

    def __repr__(self):
        return f'<AuditLog {self.action} by {self.username}>'


# ─── Notification Model ───────────────────────────────────────────────────────

class Notification(db.Model):
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    user_id: so.Mapped[int] = so.mapped_column(sa.ForeignKey(User.id), index=True)
    message: so.Mapped[str] = so.mapped_column(sa.String(256))
    notif_type: so.Mapped[str] = so.mapped_column(sa.String(50))  # 'follow', 'comment'
    is_read: so.Mapped[bool] = so.mapped_column(
        sa.Boolean, default=False, server_default=sa.text('0')
    )
    timestamp: so.Mapped[datetime] = so.mapped_column(
        index=True, default=lambda: datetime.now(timezone.utc)
    )

    user: so.Mapped[User] = so.relationship('User', back_populates='notifications')

    def to_dict(self):
        return {
            'id': self.id,
            'message': self.message,
            'type': self.notif_type,
            'timestamp': self.timestamp.isoformat() + 'Z',
        }

    def __repr__(self):
        return f'<Notification {self.notif_type}: {self.message}>'
