# MiniBlog - Beautiful Blogging Platform

A modern, full-featured blogging platform built with Python Flask and beautiful UI design.

## Features

### 🎨 Beautiful UI
- Modern, responsive design with Tailwind CSS
- Gradient backgrounds and smooth animations
- Mobile-first approach
- Dark/light theme support

### 👤 User Management
- User registration and login
- JWT-based authentication
- User profiles with avatars and bios
- Role-based access control (User/Admin)

### 📝 Blog Features
- Create, edit, and delete posts
- Rich text content with markdown support
- Post categories and tags
- Featured images
- Post drafts and publishing
- View count tracking

### 💬 Social Features
- Like posts and comments
- Comment system with replies
- Real-time notifications
- Share posts functionality

### 🔧 Admin Panel
- User management
- Post moderation
- Comment approval system
- Analytics dashboard
- Content management

### 🚀 Additional Features
- Search functionality
- Responsive design
- SEO-friendly URLs
- Image upload support
- Email notifications (coming soon)

## Technology Stack

- **Backend**: Python Flask
- **Database**: SQLite (development) / PostgreSQL (production)
- **Frontend**: HTML5, CSS3, JavaScript, Tailwind CSS
- **Authentication**: JWT tokens
- **Icons**: Font Awesome
- **Deployment**: Gunicorn + Nginx

## Installation

### Prerequisites
- Python 3.8+
- pip (Python package installer)

### Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd miniblog
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set environment variables**
   ```bash
   export SECRET_KEY="your-secret-key-here"
   export JWT_SECRET_KEY="your-jwt-secret-here"
   export DATABASE_URL="sqlite:///miniblog.db"
   ```

5. **Run the application**
   ```bash
   python app.py
   ```

The application will be available at `http://localhost:5000`

## Usage

### Getting Started

1. **Register an account** at `/register`
2. **Login** at `/login`
3. **Create your first post** from the dashboard
4. **Explore** other users' posts on the homepage


### Admin Access

To create an admin user, you can modify the database directly or use the Flask shell:

```python
from app import app, db
from models import User

with app.app_context():
    admin_user = User(username='admin', email='your-admin-email@example.com', role='admin')
    admin_user.set_password('your-secure-password')
    db.session.add(admin_user)
    db.session.commit()
```

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout
- `GET /api/auth/me` - Get current user info

### Posts
- `GET /api/posts/` - Get all posts (with pagination)
- `GET /api/posts/<id>` - Get specific post
- `POST /api/posts/` - Create new post
- `PUT /api/posts/<id>` - Update post
- `DELETE /api/posts/<id>` - Delete post
- `POST /api/posts/<id>/like` - Like/unlike post

### Comments
- `GET /api/comments/post/<post_id>` - Get post comments
- `POST /api/comments/` - Create comment
- `POST /api/comments/<id>/like` - Like/unlike comment

### Admin
- `GET /api/admin/users` - Get all users
- `GET /api/admin/posts` - Get all posts
- `GET /api/admin/comments` - Get all comments

## Project Structure

```
miniblog/
├── app.py                 # Main Flask application
├── models.py              # Database models
├── routes.py              # API routes and blueprints
├── database.py            # Database configuration
├── requirements.txt       # Python dependencies
├── templates/             # HTML templates
│   ├── base.html         # Base template
│   ├── index.html        # Homepage
│   ├── dashboard.html    # User dashboard
│   ├── create_post.html  # Post creation form
│   ├── edit_post.html    # Post editing form
│   ├── post_detail.html  # Post view page
│   ├── auth/             # Authentication templates
│   └── admin/            # Admin panel templates
├── instance/              # Database files
└── README.md             # This file
```

## Styling
The UI uses Bootstrap 5. Customize by editing templates and the small custom styles in `templates/base.html`.

### Database
The application uses SQLAlchemy ORM. You can:
- Switch to PostgreSQL for production
- Add new models in `models.py`
- Modify existing models and run migrations

### Features
To add new features:
1. Create new routes in `routes.py`
2. Add corresponding templates
3. Update the navigation in `base.html`
4. Add new API endpoints as needed

## Deployment

### Production Setup

1. **Use a production WSGI server**
   ```bash
   pip install gunicorn
   gunicorn -w 4 -b 0.0.0.0:5000 app:app
   ```

2. **Set up a reverse proxy** (Nginx)
   ```nginx
   server {
       listen 80;
       server_name your-domain.com;
       
       location / {
           proxy_pass http://127.0.0.1:5000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
       }
   }
   ```

3. **Use environment variables** for production
   ```bash
   export FLASK_ENV=production
   export SECRET_KEY="your-production-secret-key"
   export DATABASE_URL="postgresql://user:password@localhost/miniblog"
   ```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

If you encounter any issues or have questions:
1. Check the documentation
2. Search existing issues
3. Create a new issue with detailed information

## Roadmap

- [ ] Email notifications
- [ ] Image upload functionality
- [ ] Advanced search filters
- [ ] Post scheduling
- [ ] User following system
- [ ] Dark mode toggle
- [ ] Mobile app (React Native)
- [ ] API rate limiting
- [ ] Content moderation tools
- [ ] Analytics dashboard

---

**MiniBlog** - Share your story with the world! 🌟
