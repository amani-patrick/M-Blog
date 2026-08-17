"""
REST API — /api/v1/
===================
Authentication: Bearer <api_key> in the Authorization header.
All endpoints return JSON.  Rate-limited via Flask-Limiter.
"""
from flask import Blueprint, jsonify, request, abort, current_app
from flask_login import current_user
import sqlalchemy as sa
from functools import wraps

from app import db, limiter
from app.models import Post, User, Tag, Comment

api_bp = Blueprint('api', __name__, url_prefix='/api/v1')


# ─── Auth helper ─────────────────────────────────────────────────────────────

def require_api_key(f):
    """Decorator: authenticate request via Bearer token (user.api_key)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            abort(401, description='Missing or invalid Authorization header.')
        token = auth_header[7:]
        user = db.session.scalar(sa.select(User).where(User.api_key == token))
        if not user:
            abort(401, description='Invalid API key.')
        request.api_user = user
        return f(*args, **kwargs)
    return decorated


def paginate_query(query, default_per_page=10):
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', default_per_page, type=int), 50)
    return db.paginate(query, page=page, per_page=per_page, error_out=False)


# ─── Health check ─────────────────────────────────────────────────────────────

@api_bp.route('/health', methods=['GET'])
@limiter.exempt
def health():
    """Public health-check endpoint — useful for container orchestration."""
    return jsonify({'status': 'ok', 'version': '1.0'})


# ─── Posts ────────────────────────────────────────────────────────────────────

@api_bp.route('/posts', methods=['GET'])
@limiter.limit('60 per minute')
def get_posts():
    """List all posts (paginated, most recent first)."""
    query = sa.select(Post).order_by(Post.timestamp.desc())
    pagination = paginate_query(query)
    return jsonify({
        'posts': [p.to_dict() for p in pagination.items],
        'total': pagination.total,
        'pages': pagination.pages,
        'page': pagination.page,
        'has_next': pagination.has_next,
        'has_prev': pagination.has_prev,
    })


@api_bp.route('/posts/<int:post_id>', methods=['GET'])
@limiter.limit('60 per minute')
def get_post(post_id):
    """Get a single post by ID."""
    post = db.get_or_404(Post, post_id)
    return jsonify(post.to_dict())


@api_bp.route('/posts', methods=['POST'])
@limiter.limit('10 per minute')
@require_api_key
def create_post():
    """Create a new post. Requires Bearer token auth."""
    data = request.get_json(silent=True) or {}
    if not data.get('body'):
        abort(400, description='Field "body" is required.')

    post = Post(
        title=data.get('title', ''),
        body=data['body'],
        author=request.api_user,
    )

    # Optional tags
    tag_names = [t.strip().lower() for t in data.get('tags', '').split(',') if t.strip()]
    for tag_name in tag_names:
        tag = db.session.scalar(sa.select(Tag).where(Tag.name == tag_name))
        if not tag:
            tag = Tag(name=tag_name)
            db.session.add(tag)
        post.tags.append(tag)

    db.session.add(post)
    db.session.commit()
    return jsonify(post.to_dict()), 201


@api_bp.route('/posts/<int:post_id>', methods=['DELETE'])
@limiter.limit('5 per minute')
@require_api_key
def delete_post(post_id):
    """Delete a post. Only the author may delete their own post."""
    post = db.get_or_404(Post, post_id)
    if post.author != request.api_user and not request.api_user.is_admin:
        abort(403, description='You do not own this post.')
    db.session.delete(post)
    db.session.commit()
    return jsonify({'message': 'Post deleted.'})


# ─── Search ───────────────────────────────────────────────────────────────────

@api_bp.route('/search', methods=['GET'])
@limiter.limit('30 per minute')
def search_posts():
    """Full-text search over post titles and bodies.  Returns up to 10 results."""
    q = request.args.get('q', '').strip()
    if not q:
        return jsonify({'posts': [], 'query': q})

    term = f'%{q}%'
    query = (
        sa.select(Post)
        .where(sa.or_(Post.title.ilike(term), Post.body.ilike(term)))
        .order_by(Post.timestamp.desc())
    )
    pagination = paginate_query(query, default_per_page=10)
    return jsonify({
        'posts': [p.to_dict() for p in pagination.items],
        'query': q,
        'total': pagination.total,
    })


# ─── Users ────────────────────────────────────────────────────────────────────

@api_bp.route('/users/<username>', methods=['GET'])
@limiter.limit('60 per minute')
def get_user(username):
    """Public user profile."""
    user = db.session.scalar(sa.select(User).where(User.username == username))
    if not user:
        abort(404, description='User not found.')
    return jsonify(user.to_dict())


@api_bp.route('/users/me/token', methods=['POST'])
@limiter.limit('5 per minute')
@require_api_key
def regenerate_token():
    """Regenerate the authenticated user's API key."""
    new_key = request.api_user.generate_api_key()
    db.session.commit()
    return jsonify({'api_key': new_key})


# ─── Notifications ────────────────────────────────────────────────────────────

@api_bp.route('/notifications', methods=['GET'])
@limiter.limit('60 per minute')
@require_api_key
def get_notifications():
    """Return unread notifications for the authenticated user."""
    from app.models import Notification
    notifs = db.session.scalars(
        request.api_user.notifications.select()
        .where(Notification.is_read == False)  # noqa: E712
        .order_by(Notification.timestamp.desc())
        .limit(20)
    ).all()
    return jsonify({
        'notifications': [n.to_dict() for n in notifs],
        'unread_count': len(notifs),
    })


# ─── Tags ─────────────────────────────────────────────────────────────────────

@api_bp.route('/tags', methods=['GET'])
@limiter.limit('60 per minute')
def get_tags():
    """Return all tags with their post count."""
    tags = db.session.scalars(sa.select(Tag)).all()
    return jsonify({
        'tags': [
            {'name': t.name, 'post_count': len(t.posts)}
            for t in tags
        ]
    })


# ─── Error handlers ───────────────────────────────────────────────────────────

@api_bp.errorhandler(400)
@api_bp.errorhandler(401)
@api_bp.errorhandler(403)
@api_bp.errorhandler(404)
@api_bp.errorhandler(429)
@api_bp.errorhandler(500)
def api_error(e):
    return jsonify({'error': str(e.description), 'code': e.code}), e.code
