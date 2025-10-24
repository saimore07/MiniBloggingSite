from flask_login import UserMixin
from datetime import datetime
from database import db

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    avatar = db.Column(db.String(200), default='')
    bio = db.Column(db.String(200), default='')
    role = db.Column(db.String(20), default='user')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    posts = db.relationship('Post', backref='author', lazy=True, cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='author', lazy=True, cascade='all, delete-orphan')
    likes = db.relationship('Like', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        from flask_bcrypt import Bcrypt
        bcrypt = Bcrypt()
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        from flask_bcrypt import Bcrypt
        bcrypt = Bcrypt()
        return bcrypt.check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'avatar': self.avatar,
            'bio': self.bio,
            'role': self.role,
            'created_at': self.created_at.isoformat()
        }

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    excerpt = db.Column(db.String(300))
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    tags = db.Column(db.String(200))  # Comma-separated tags
    is_published = db.Column(db.Boolean, default=True)
    view_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    comments = db.relationship('Comment', backref='post', lazy=True, cascade='all, delete-orphan')
    likes = db.relationship('Like', backref='post', lazy=True, cascade='all, delete-orphan')
    
    def get_tags_list(self):
        if self.tags:
            return [tag.strip() for tag in self.tags.split(',')]
        return []
    
    def set_tags_from_list(self, tags_list):
        self.tags = ', '.join(tags_list)
    
    def get_like_count(self):
        try:
            return len(self.likes) if self.likes else 0
        except:
            return 0
    
    def get_comment_count(self):
        try:
            return len(self.comments) if self.comments else 0
        except:
            return 0
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'content': self.content,
            'excerpt': self.excerpt,
            'author': self.author.username if self.author else None,
            'author_id': self.author_id,
            'tags': self.get_tags_list(),
            'is_published': self.is_published,
            'view_count': self.view_count,
            'like_count': self.get_like_count(),
            'comment_count': self.get_comment_count(),
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=True)
    is_approved = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    replies = db.relationship('Comment', backref=db.backref('parent', remote_side=[id]), lazy=True)
    likes = db.relationship('Like', backref='comment', lazy=True, cascade='all, delete-orphan')
    
    def get_like_count(self):
        try:
            return len(self.likes) if self.likes else 0
        except:
            return 0
    
    def to_dict(self):
        return {
            'id': self.id,
            'content': self.content,
            'author': self.author.username if self.author else None,
            'author_id': self.author_id,
            'post_id': self.post_id,
            'parent_id': self.parent_id,
            'is_approved': self.is_approved,
            'like_count': self.get_like_count(),
            'created_at': self.created_at.isoformat()
        }

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=True)
    comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Ensure a user can only like a post/comment once
    __table_args__ = (
        db.UniqueConstraint('user_id', 'post_id', name='unique_post_like'),
        db.UniqueConstraint('user_id', 'comment_id', name='unique_comment_like'),
    )
