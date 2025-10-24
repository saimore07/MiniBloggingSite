from flask import Flask, render_template, request, redirect, url_for, flash
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_required, current_user
from datetime import timedelta
import os
from dotenv import load_dotenv
from database import db

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///miniblog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY') or 'jwt-secret-string'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)
cors = CORS(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# Import models and routes
from models import User, Post, Comment, Like
from routes import auth_bp, posts_bp, comments_bp, admin_bp

# Register blueprints
app.register_blueprint(auth_bp, url_prefix='/api/auth')
app.register_blueprint(posts_bp, url_prefix='/api/posts')
app.register_blueprint(comments_bp, url_prefix='/api/comments')
app.register_blueprint(admin_bp, url_prefix='/api/admin')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Main routes
@app.route('/')
def index():
    posts = Post.query.filter_by(is_published=True).order_by(Post.created_at.desc()).limit(10).all()
    return render_template('index.html', posts=posts)

@app.route('/login')
def login():
    return render_template('auth/login.html')

@app.route('/register')
def register():
    return render_template('auth/register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # Load posts with their relationships to avoid N+1 queries
    user_posts = Post.query.filter_by(author_id=current_user.id).order_by(Post.created_at.desc()).all()
    return render_template('dashboard.html', posts=user_posts)

@app.route('/admin')
@login_required
def admin():
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    # Load all data with relationships to avoid N+1 queries
    users = User.query.all()
    posts = Post.query.all()
    comments = Comment.query.all()
    
    return render_template('admin/dashboard.html', users=users, posts=posts, comments=comments)

@app.route('/post/<int:post_id>')
def view_post(post_id):
    post = Post.query.get_or_404(post_id)
    if not post.is_published and (not current_user.is_authenticated or current_user.id != post.author_id):
        flash('Post not found.', 'error')
        return redirect(url_for('index'))
    
    # Increment view count
    post.view_count += 1
    db.session.commit()
    
    return render_template('post_detail.html', post=post)

@app.route('/create-post', methods=['GET', 'POST'])
@login_required
def create_post():
    if request.method == 'POST':
        try:
            title = request.form.get('title', '').strip()
            content = request.form.get('content', '').strip()
            tags = request.form.get('tags', '').strip()
            is_published = request.form.get('isPublished') == 'on'
            
            if not title or not content:
                flash('Title and content are required', 'error')
                return render_template('create_post.html')
            
            post = Post(
                title=title,
                content=content,
                author_id=current_user.id,
                is_published=is_published
            )
            
            if tags:
                post.set_tags_from_list(tags.split(','))
            
            # Create excerpt
            post.excerpt = content[:200] + '...' if len(content) > 200 else content
            
            db.session.add(post)
            db.session.commit()
            
            flash('Post created successfully!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            db.session.rollback()
            flash('Failed to create post', 'error')
            return render_template('create_post.html')
    
    return render_template('create_post.html')

@app.route('/edit-post/<int:post_id>')
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author_id != current_user.id and current_user.role != 'admin':
        flash('You can only edit your own posts.', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('edit_post.html', post=post)

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    # Get port from environment variable (for production)
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') != 'production'
    
    app.run(debug=debug, host='0.0.0.0', port=port)
