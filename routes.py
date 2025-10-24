from flask import Blueprint, request, jsonify, redirect, url_for
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from flask_login import login_user, logout_user, login_required, current_user
from models import User, Post, Comment, Like
from database import db
from datetime import datetime

# Create blueprints
auth_bp = Blueprint('auth', __name__)
posts_bp = Blueprint('posts', __name__)
comments_bp = Blueprint('comments', __name__)
admin_bp = Blueprint('admin', __name__)

# Authentication routes
@auth_bp.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        # Validation
        if not username or len(username) < 3:
            return jsonify({'error': 'Username must be at least 3 characters'}), 400
        
        if not email or '@' not in email:
            return jsonify({'error': 'Valid email is required'}), 400
        
        if not password or len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already taken'}), 400
        
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already registered'}), 400
        
        # Create user
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        # Create JWT token
        access_token = create_access_token(identity=user.id)
        
        return jsonify({
            'message': 'User created successfully',
            'access_token': access_token,
            'user': user.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Registration failed'}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        user = User.query.filter_by(email=email).first()
        
        if not user or not user.check_password(password):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        if not user.is_active:
            return jsonify({'error': 'Account is deactivated'}), 401
        
        # Create JWT token
        access_token = create_access_token(identity=user.id)
        
        # Also log in with Flask-Login for session-based auth
        login_user(user)
        
        return jsonify({
            'message': 'Login successful',
            'access_token': access_token,
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Login failed'}), 500

@auth_bp.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    if request.method == 'GET':
        # For GET requests (from template links), redirect to home page
        return redirect(url_for('index'))
    else:
        # For POST requests (API calls), return JSON response
        return jsonify({'message': 'Logged out successfully'}), 200

@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({'user': user.to_dict()}), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get user info'}), 500

# Posts routes
@posts_bp.route('/', methods=['GET'])
def get_posts():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        search = request.args.get('search', '')
        tag = request.args.get('tag', '')
        
        query = Post.query.filter_by(is_published=True)
        
        if search:
            query = query.filter(
                db.or_(
                    Post.title.contains(search),
                    Post.content.contains(search)
                )
            )
        
        if tag:
            query = query.filter(Post.tags.contains(tag))
        
        posts = query.order_by(Post.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return jsonify({
            'posts': [post.to_dict() for post in posts.items],
            'total': posts.total,
            'pages': posts.pages,
            'current_page': page
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to fetch posts'}), 500

@posts_bp.route('/<int:post_id>', methods=['GET'])
def get_post(post_id):
    try:
        post = Post.query.get_or_404(post_id)
        
        if not post.is_published and (not current_user.is_authenticated or current_user.id != post.author_id):
            return jsonify({'error': 'Post not found'}), 404
        # Increment view count when post is fetched via API as well
        post.view_count = (post.view_count or 0) + 1
        db.session.commit()
        
        return jsonify({'post': post.to_dict()}), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to fetch post'}), 500

@posts_bp.route('/', methods=['POST'])
def create_post():
    try:
        data = request.get_json()
        
        # Try to get user from JWT token first, then from session
        user_id = None
        if request.headers.get('Authorization'):
            try:
                from flask_jwt_extended import get_jwt_identity
                user_id = get_jwt_identity()
            except:
                pass
        
        # If no JWT token, try session-based auth
        if not user_id and current_user.is_authenticated:
            user_id = current_user.id
        
        if not user_id:
            return jsonify({'error': 'Authentication required'}), 401
        
        title = data.get('title', '').strip()
        content = data.get('content', '').strip()
        tags = data.get('tags', [])
        
        if not title or not content:
            return jsonify({'error': 'Title and content are required'}), 400
        
        post = Post(
            title=title,
            content=content,
            author_id=user_id
        )
        
        if tags:
            post.set_tags_from_list(tags)
        
        # Create excerpt
        post.excerpt = content[:200] + '...' if len(content) > 200 else content
        
        db.session.add(post)
        db.session.commit()
        
        return jsonify({
            'message': 'Post created successfully',
            'post': post.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to create post'}), 500

@posts_bp.route('/<int:post_id>', methods=['PUT'])
def update_post(post_id):
    try:
        data = request.get_json()
        # Accept JWT or Flask-Login session
        user_id = None
        if request.headers.get('Authorization'):
            try:
                from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request
                verify_jwt_in_request(optional=True)
                identity = get_jwt_identity()
                if identity is not None:
                    try:
                        user_id = int(identity)
                    except (TypeError, ValueError):
                        user_id = identity
            except Exception:
                pass
        if not user_id and current_user.is_authenticated:
            user_id = current_user.id
        if not user_id:
            return jsonify({'error': 'Authentication required'}), 401
        
        post = Post.query.get_or_404(post_id)
        
        # Check if user can edit this post
        if post.author_id != user_id:
            user = User.query.get(user_id)
            if not user or user.role != 'admin':
                return jsonify({'error': 'Permission denied'}), 403
        
        title = data.get('title', '').strip()
        content = data.get('content', '').strip()
        tags = data.get('tags', [])
        is_published = data.get('is_published')
        
        if title:
            post.title = title
        if content:
            post.content = content
            post.excerpt = content[:200] + '...' if len(content) > 200 else content
        
        if tags:
            post.set_tags_from_list(tags)
        if isinstance(is_published, bool):
            post.is_published = is_published
        
        post.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'message': 'Post updated successfully',
            'post': post.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to update post'}), 500

@posts_bp.route('/<int:post_id>', methods=['DELETE'])
def delete_post(post_id):
    try:
        # Accept JWT or Flask-Login session
        user_id = None
        if request.headers.get('Authorization'):
            try:
                from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request
                verify_jwt_in_request(optional=True)
                identity = get_jwt_identity()
                if identity is not None:
                    try:
                        user_id = int(identity)
                    except (TypeError, ValueError):
                        user_id = identity
            except Exception:
                # Ignore JWT errors to allow session-based auth
                pass
        if not user_id and current_user.is_authenticated:
            user_id = current_user.id
        if not user_id:
            return jsonify({'error': 'Authentication required'}), 401
        
        post = Post.query.get_or_404(post_id)
        
        # Check if user can delete this post
        if post.author_id != user_id:
            user = User.query.get(user_id)
            if not user or user.role != 'admin':
                return jsonify({'error': 'Permission denied'}), 403
        
        db.session.delete(post)
        db.session.commit()
        
        return jsonify({'message': 'Post deleted successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to delete post: {str(e)}'}), 500

@posts_bp.route('/<int:post_id>/like', methods=['POST'])
def like_post(post_id):
    try:
        # Try to get user from JWT token first, then from session
        user_id = None
        if request.headers.get('Authorization'):
            try:
                from flask_jwt_extended import get_jwt_identity
                user_id = get_jwt_identity()
            except:
                pass
        
        # If no JWT token, try session-based auth
        if not user_id and current_user.is_authenticated:
            user_id = current_user.id
        
        if not user_id:
            return jsonify({'error': 'Authentication required'}), 401
        
        post = Post.query.get_or_404(post_id)
        
        # Check if user already liked this post
        existing_like = Like.query.filter_by(user_id=user_id, post_id=post_id).first()
        
        if existing_like:
            db.session.delete(existing_like)
            db.session.commit()
            # Re-fetch like count
            updated = Post.query.get(post_id)
            return jsonify({'message': 'Post unliked', 'liked': False, 'like_count': updated.get_like_count()}), 200
        
        # Create new like
        like = Like(user_id=user_id, post_id=post_id)
        db.session.add(like)
        db.session.commit()
        # Re-fetch like count
        updated = Post.query.get(post_id)
        
        return jsonify({'message': 'Post liked', 'liked': True, 'like_count': updated.get_like_count()}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to like post'}), 500

# Comments routes
@comments_bp.route('/post/<int:post_id>', methods=['GET'])
def get_comments(post_id):
    try:
        comments = Comment.query.filter_by(post_id=post_id, is_approved=True).order_by(Comment.created_at.desc()).all()
        
        return jsonify({
            'comments': [comment.to_dict() for comment in comments]
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to fetch comments'}), 500

@comments_bp.route('/', methods=['POST'])
def create_comment():
    try:
        data = request.get_json()
        
        # Try to get user from JWT token first, then from session
        user_id = None
        if request.headers.get('Authorization'):
            try:
                from flask_jwt_extended import get_jwt_identity
                user_id = get_jwt_identity()
            except:
                pass
        
        # If no JWT token, try session-based auth
        if not user_id and current_user.is_authenticated:
            user_id = current_user.id
        
        if not user_id:
            return jsonify({'error': 'Authentication required'}), 401
        
        content = data.get('content', '').strip()
        post_id = data.get('post_id')
        parent_id = data.get('parent_id')
        
        if not content or not post_id:
            return jsonify({'error': 'Content and post_id are required'}), 400
        
        # Verify post exists
        post = Post.query.get_or_404(post_id)
        
        comment = Comment(
            content=content,
            author_id=user_id,
            post_id=post_id,
            parent_id=parent_id
        )
        
        db.session.add(comment)
        db.session.commit()
        # Return updated post comment count as well
        updated_post = Post.query.get(post_id)
        
        return jsonify({
            'message': 'Comment created successfully',
            'comment': comment.to_dict(),
            'comment_count': updated_post.get_comment_count()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to create comment'}), 500

@comments_bp.route('/<int:comment_id>/like', methods=['POST'])
def like_comment(comment_id):
    try:
        # Try to get user from JWT token first, then from session
        user_id = None
        if request.headers.get('Authorization'):
            try:
                from flask_jwt_extended import get_jwt_identity
                user_id = get_jwt_identity()
            except:
                pass
        
        # If no JWT token, try session-based auth
        if not user_id and current_user.is_authenticated:
            user_id = current_user.id
        
        if not user_id:
            return jsonify({'error': 'Authentication required'}), 401
        
        comment = Comment.query.get_or_404(comment_id)
        
        # Check if user already liked this comment
        existing_like = Like.query.filter_by(user_id=user_id, comment_id=comment_id).first()
        
        if existing_like:
            db.session.delete(existing_like)
            db.session.commit()
            return jsonify({'message': 'Comment unliked', 'liked': False}), 200
        
        # Create new like
        like = Like(user_id=user_id, comment_id=comment_id)
        db.session.add(like)
        db.session.commit()
        
        return jsonify({'message': 'Comment liked', 'liked': True}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to like comment'}), 500

# Admin routes
@admin_bp.route('/users', methods=['GET'])
@jwt_required()
def get_all_users():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user or user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        users = User.query.all()
        
        return jsonify({
            'users': [user.to_dict() for user in users]
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to fetch users'}), 500

@admin_bp.route('/posts', methods=['GET'])
@jwt_required()
def get_all_posts():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user or user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        posts = Post.query.order_by(Post.created_at.desc()).all()
        
        return jsonify({
            'posts': [post.to_dict() for post in posts]
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to fetch posts'}), 500

@admin_bp.route('/comments', methods=['GET'])
@jwt_required()
def get_all_comments():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user or user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        comments = Comment.query.order_by(Comment.created_at.desc()).all()
        
        return jsonify({
            'comments': [comment.to_dict() for comment in comments]
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to fetch comments'}), 500

# Admin user management routes
@admin_bp.route('/users', methods=['POST'])
@jwt_required()
def create_user():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        
        if not user or user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        data = request.get_json()
        username = data.get('username', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        role = data.get('role', 'user')
        
        # Validation
        if not username or len(username) < 3:
            return jsonify({'error': 'Username must be at least 3 characters'}), 400
        
        if not email or '@' not in email:
            return jsonify({'error': 'Valid email is required'}), 400
        
        if not password or len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already taken'}), 400
        
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already registered'}), 400
        
        # Create user
        new_user = User(username=username, email=email, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({
            'message': 'User created successfully',
            'user': new_user.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to create user'}), 500

@admin_bp.route('/users/<int:user_id>/toggle-status', methods=['POST'])
@jwt_required()
def toggle_user_status(user_id):
    try:
        admin_id = get_jwt_identity()
        admin_user = User.query.get(admin_id)
        
        if not admin_user or admin_user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        user = User.query.get_or_404(user_id)
        
        # Prevent admin from deactivating themselves
        if user.id == admin_id:
            return jsonify({'error': 'Cannot modify your own account'}), 400
        
        user.is_active = not user.is_active
        db.session.commit()
        
        return jsonify({
            'message': f'User {"activated" if user.is_active else "deactivated"} successfully',
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to update user status'}), 500

@admin_bp.route('/posts/<int:post_id>/toggle-status', methods=['POST'])
@jwt_required()
def toggle_post_status(post_id):
    try:
        admin_id = get_jwt_identity()
        admin_user = User.query.get(admin_id)
        
        if not admin_user or admin_user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        post = Post.query.get_or_404(post_id)
        post.is_published = not post.is_published
        db.session.commit()
        
        return jsonify({
            'message': f'Post {"published" if post.is_published else "unpublished"} successfully',
            'post': post.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to update post status'}), 500

@admin_bp.route('/comments/<int:comment_id>/toggle-status', methods=['POST'])
@jwt_required()
def toggle_comment_status(comment_id):
    try:
        admin_id = get_jwt_identity()
        admin_user = User.query.get(admin_id)
        
        if not admin_user or admin_user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        comment = Comment.query.get_or_404(comment_id)
        comment.is_approved = not comment.is_approved
        db.session.commit()
        
        return jsonify({
            'message': f'Comment {"approved" if comment.is_approved else "disapproved"} successfully',
            'comment': comment.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to update comment status'}), 500

@admin_bp.route('/comments/<int:comment_id>', methods=['DELETE'])
@jwt_required()
def delete_comment(comment_id):
    try:
        admin_id = get_jwt_identity()
        admin_user = User.query.get(admin_id)
        
        if not admin_user or admin_user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        comment = Comment.query.get_or_404(comment_id)
        db.session.delete(comment)
        db.session.commit()
        
        return jsonify({'message': 'Comment deleted successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to delete comment'}), 500
