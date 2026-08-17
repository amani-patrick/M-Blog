"""
routes.py — All web-facing routes for M-Blog
"""
import json
import time as _time
from datetime import datetime, timezone, timedelta
from urllib.parse import urlsplit
from functools import wraps

import sqlalchemy as sa
from flask import (
    render_template, flash, redirect, url_for,
    request, abort, Response, jsonify, current_app
)
from flask_login import current_user, login_user, logout_user, login_required

import markdown2
import bleach

from app import app, db, limiter, github_bp
from app.forms import (
    LoginForm, Registration, EditProfileForm, PostForm,
    EmptyForm, ResetPasswordRequestForm, ResetPasswordForm,
    CommentForm, SearchForm
)
from app.models import User, Post, Tag, Comment, AuditLog, Notification


# ─── Markdown helpers ─────────────────────────────────────────────────────────

ALLOWED_TAGS = [
    'p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'strong', 'em', 'u', 's', 'ul', 'ol', 'li',
    'a', 'blockquote', 'code', 'pre', 'img',
    'hr', 'br', 'table', 'thead', 'tbody', 'tr', 'th', 'td',
]
ALLOWED_ATTRS = {'a': ['href', 'title', 'rel'], 'img': ['src', 'alt']}


def render_markdown(text):
    """Convert markdown to sanitized HTML."""
    html = markdown2.markdown(
        text,
        extras=['fenced-code-blocks', 'tables', 'strike', 'task_list']
    )
    return bleach.clean(html, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS)


def strip_markdown(text, length=200):
    """
    Return a plain-text preview of a markdown string.
    Inserts a space before block-level closing tags so that
    headings and list items don't run into each other when
    all HTML is stripped.
    """
    import re as _re
    html = markdown2.markdown(text)
    # Add a space before each block boundary to prevent words merging
    html = _re.sub(r'</(p|h[1-6]|li|blockquote|pre)>', r' </\1>', html)
    plain = bleach.clean(html, tags=[], strip=True)
    # Collapse multiple spaces/newlines to single space
    plain = _re.sub(r'\s+', ' ', plain).strip()
    return plain[:length] + ('…' if len(plain) > length else '')


# Register as Jinja2 filters
app.jinja_env.filters['markdown'] = render_markdown
app.jinja_env.filters['strip_markdown'] = strip_markdown


# ─── Admin decorator ─────────────────────────────────────────────────────────

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated


# ─── View counter helper ──────────────────────────────────────────────────────

def increment_view(post):
    """
    Increment view count.
    - Skips if the viewer is the post's own author.
    - Uses Redis if available, otherwise falls back to the DB column.
    """
    # Don't count the author viewing their own post
    if current_user.is_authenticated and current_user.id == post.user_id:
        return

    from app import redis_client
    if redis_client:
        try:
            key = f'post:views:{post.id}'
            count = redis_client.incr(key)
            # Sync to DB every 10 views to reduce write load
            if count % 10 == 0:
                post.view_count = count
                db.session.commit()
            return
        except Exception:
            pass
    # DB fallback
    post.view_count = (post.view_count or 0) + 1
    db.session.commit()


# ─── Tag helper ───────────────────────────────────────────────────────────────

def get_or_create_tags(tag_string):
    """Parse comma-separated tag string, returning a list of Tag objects."""
    tag_names = {t.strip().lower() for t in tag_string.split(',') if t.strip()}
    tags = []
    for name in tag_names:
        tag = db.session.scalar(sa.select(Tag).where(Tag.name == name))
        if not tag:
            tag = Tag(name=name)
            db.session.add(tag)
        tags.append(tag)
    return tags


# ─── Audit helper ─────────────────────────────────────────────────────────────

def log_action(action, user=None):
    entry = AuditLog(
        user_id=user.id if user else None,
        username=user.username if user else 'anonymous',
        action=action,
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string[:256],
    )
    db.session.add(entry)
    db.session.commit()


# ─── Before-request ───────────────────────────────────────────────────────────

@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.now(timezone.utc)
        db.session.commit()


# ─── Health check ─────────────────────────────────────────────────────────────

@app.route('/health')
@limiter.exempt
def health():
    return jsonify({'status': 'ok'})


# ─── Auth routes ──────────────────────────────────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit('20 per minute')
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.scalar(
            sa.select(User).where(User.username == form.username.data)
        )
        if user is None or not user.check_password(form.password.data):
            log_action(f'failed_login:{form.username.data}')
            flash('Invalid username or password')
            return redirect(url_for('login'))
        if not user.is_email_verified:
            flash('Please verify your email before logging in. Check your inbox or console.')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        log_action('login', user)
        next_page = request.args.get('next')
        next_page = next_page or url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form, github_bp=github_bp)


@app.route('/logout')
@login_required
def logout():
    log_action('logout', current_user)
    logout_user()
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit('10 per hour')
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = Registration()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            is_email_verified=False,
        )
        user.set_password(form.password.data)
        token = user.generate_verification_token()
        db.session.add(user)
        db.session.commit()
        verify_url = url_for('verify_email', token=token, _external=True)
        # Print to console (swap for Flask-Mail send in production)
        print(f'\n[M-Blog] VERIFY EMAIL LINK for {user.email}:\n  {verify_url}\n')
        flash('Account created! Check your email (or console) for the verification link.')
        log_action('register', user)
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route('/verify/<token>')
def verify_email(token):
    user = db.session.scalar(sa.select(User).where(User.verification_token == token))
    if not user:
        flash('Invalid or expired verification link.')
        return redirect(url_for('login'))
    user.is_email_verified = True
    user.verification_token = None
    db.session.commit()
    flash('Email verified! You can now sign in.')
    log_action('email_verified', user)
    return redirect(url_for('login'))


# ─── GitHub OAuth ─────────────────────────────────────────────────────────────

@app.route('/github-login')
def github_login():
    """Redirect to GitHub OAuth. Handled by Flask-Dance blueprint."""
    if not github_bp:
        flash('GitHub OAuth is not configured on this server.')
        return redirect(url_for('login'))
    from flask_dance.contrib.github import github as github_oauth
    if not github_oauth.authorized:
        return redirect(url_for('github.login'))
    return redirect(url_for('github_login'))


@app.route('/login/github/authorized')
def github_login_callback():
    """Called by Flask-Dance after GitHub authorization."""
    return redirect(url_for('index'))


# Connect Flask-Dance authorized signal
if github_bp:
    from flask_dance.consumer import oauth_authorized
    from flask_dance.contrib.github import github as _github_oauth

    @oauth_authorized.connect_via(github_bp)
    def github_logged_in(blueprint, token):
        if not token:
            flash('GitHub login failed.')
            return False
        resp = blueprint.session.get('/user')
        if not resp.ok:
            flash('Could not fetch GitHub user info.')
            return False
        github_info = resp.json()
        github_id = str(github_info['id'])
        github_login_name = github_info.get('login', '')
        github_email = github_info.get('email') or f'{github_login_name}@github.invalid'

        # Find existing user by github_id or email
        user = db.session.scalar(
            sa.select(User).where(User.github_id == github_id)
        ) or db.session.scalar(
            sa.select(User).where(User.email == github_email)
        )

        if not user:
            # Auto-register via GitHub
            username = github_login_name
            # Ensure unique username
            suffix = 1
            base = username
            while db.session.scalar(sa.select(User).where(User.username == username)):
                username = f'{base}{suffix}'
                suffix += 1
            user = User(
                username=username,
                email=github_email,
                github_id=github_id,
                is_email_verified=True,
            )
            db.session.add(user)
            db.session.commit()
            flash(f'Welcome, {user.username}! Account created via GitHub.')

        user.github_id = github_id
        db.session.commit()
        login_user(user)
        log_action('github_login', user)
        flash(f'Signed in as {user.username} via GitHub.')
        return False  # Prevent Flask-Dance from saving the token


# ─── Password reset ───────────────────────────────────────────────────────────

@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = db.session.scalar(
            sa.select(User).where(User.email == form.email.data))
        if user:
            token = user.get_reset_password_token()
            reset_url = url_for('reset_password', token=token, _external=True)
            print(f'\n[M-Blog] RESET PASSWORD LINK for {user.email}:\n  {reset_url}\n')
        flash('Check your email for the instructions to reset your password')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html',
                           title='Reset Password', form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been reset.')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)


# ─── Index / Feed ─────────────────────────────────────────────────────────────

@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
def index():
    form = PostForm()
    if current_user.is_authenticated and form.validate_on_submit():
        post = Post(
            title=form.title.data,
            body=form.body.data,
            author=current_user
        )
        # Handle tags
        if form.tags.data:
            post.tags = get_or_create_tags(form.tags.data)
        db.session.add(post)
        db.session.commit()
        flash('Your post is now live!')
        return redirect(url_for('index'))

    tag_filter = request.args.get('tag', '')
    page = request.args.get('page', 1, type=int)

    if tag_filter:
        tag = db.session.scalar(sa.select(Tag).where(Tag.name == tag_filter))
        if tag:
            query = (
                sa.select(Post)
                .join(Post.tags)
                .where(Tag.name == tag_filter)
                .order_by(Post.timestamp.desc())
            )
        else:
            query = sa.select(Post).where(sa.false())
    else:
        query = sa.select(Post).order_by(Post.timestamp.desc())

    posts = db.paginate(
        query, page=page,
        per_page=app.config.get('POSTS_PER_PAGE', 10),
        error_out=False
    )

    # Tag cloud
    all_tags = db.session.scalars(sa.select(Tag)).all()

    next_url = url_for('index', page=posts.next_num, tag=tag_filter) \
        if posts.has_next else None
    prev_url = url_for('index', page=posts.prev_num, tag=tag_filter) \
        if posts.has_prev else None

    # For AJAX (infinite scroll)
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'posts': [p.to_dict() for p in posts.items],
            'has_next': posts.has_next,
            'next_page': posts.next_num,
        })

    return render_template(
        'index.html', title='Home', form=form,
        posts=posts.items, next_url=next_url, prev_url=prev_url,
        all_tags=all_tags, tag_filter=tag_filter,
    )


# ─── Single post ──────────────────────────────────────────────────────────────

@app.route('/post/<int:post_id>', methods=['GET'])
def post_detail(post_id):
    post = db.get_or_404(Post, post_id)
    increment_view(post)
    comment_form = CommentForm()
    comments = db.session.scalars(
        post.comments.select().order_by(Comment.timestamp.asc())
    ).all()
    return render_template(
        'post.html', title=post.title or 'Post',
        post=post, comment_form=comment_form, comments=comments,
    )


@app.route('/post/<int:post_id>/comment', methods=['POST'])
@login_required
@limiter.limit('20 per minute')
def add_comment(post_id):
    post = db.get_or_404(Post, post_id)
    form = CommentForm()
    if form.validate_on_submit():
        comment = Comment(
            body=form.body.data,
            author=current_user,
            post=post,
        )
        db.session.add(comment)
        # Notify the post author (unless commenting on own post)
        if post.author != current_user:
            db.session.add(Notification(
                user_id=post.author.id,
                message=f'{current_user.username} commented on your post "{post.title or "Untitled"}"',
                notif_type='comment',
            ))
        db.session.commit()
        flash('Comment posted!')
    return redirect(url_for('post_detail', post_id=post_id))


@app.route('/post/<int:post_id>/delete_comment/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(post_id, comment_id):
    comment = db.get_or_404(Comment, comment_id)
    if comment.author != current_user and not current_user.is_admin:
        abort(403)
    db.session.delete(comment)
    db.session.commit()
    flash('Comment deleted.')
    return redirect(url_for('post_detail', post_id=post_id))


# ─── Search ───────────────────────────────────────────────────────────────────

@app.route('/search')
@limiter.limit('30 per minute')
def search():
    q = request.args.get('q', '').strip()
    page = request.args.get('page', 1, type=int)
    posts_pagination = None
    if q:
        term = f'%{q}%'
        query = (
            sa.select(Post)
            .where(sa.or_(Post.title.ilike(term), Post.body.ilike(term)))
            .order_by(Post.timestamp.desc())
        )
        posts_pagination = db.paginate(
            query, page=page,
            per_page=app.config.get('POSTS_PER_PAGE', 10),
            error_out=False
        )
    return render_template(
        'search.html', title='Search', q=q,
        posts=posts_pagination.items if posts_pagination else [],
        total=posts_pagination.total if posts_pagination else 0,
        next_url=url_for('search', q=q, page=posts_pagination.next_num)
            if posts_pagination and posts_pagination.has_next else None,
        prev_url=url_for('search', q=q, page=posts_pagination.prev_num)
            if posts_pagination and posts_pagination.has_prev else None,
    )


# ─── Tags ─────────────────────────────────────────────────────────────────────

@app.route('/tag/<name>')
def tag(name):
    tag_obj = db.session.scalar(sa.select(Tag).where(Tag.name == name))
    if not tag_obj:
        abort(404)
    page = request.args.get('page', 1, type=int)
    query = (
        sa.select(Post)
        .join(Post.tags)
        .where(Tag.name == name)
        .order_by(Post.timestamp.desc())
    )
    posts = db.paginate(
        query, page=page,
        per_page=app.config.get('POSTS_PER_PAGE', 10),
        error_out=False
    )
    next_url = url_for('tag', name=name, page=posts.next_num) \
        if posts.has_next else None
    prev_url = url_for('tag', name=name, page=posts.prev_num) \
        if posts.has_prev else None
    return render_template(
        'tag.html', title=f'#{name}', tag=tag_obj,
        posts=posts.items, next_url=next_url, prev_url=prev_url,
    )


# ─── User profile ─────────────────────────────────────────────────────────────

@app.route('/user/<username>')
@login_required
def user(username):
    user_obj = db.session.scalar(sa.select(User).where(User.username == username))
    if not user_obj:
        abort(404)
    page = request.args.get('page', 1, type=int)
    query = user_obj.posts.select().order_by(Post.timestamp.desc())
    posts = db.paginate(
        query, page=page,
        per_page=app.config.get('POSTS_PER_PAGE', 10), error_out=False
    )
    next_url = url_for('user', username=user_obj.username, page=posts.next_num) \
        if posts.has_next else None
    prev_url = url_for('user', username=user_obj.username, page=posts.prev_num) \
        if posts.has_prev else None
    form = EmptyForm()

    # Activity heatmap data (last 52 weeks)
    today = datetime.now(timezone.utc).date()
    start_date = today - timedelta(weeks=52)
    activity_rows = db.session.execute(
        sa.text(
            "SELECT strftime('%Y-%m-%d', timestamp) as day, COUNT(*) as cnt "
            "FROM post WHERE user_id = :uid AND date(timestamp) >= :start "
            "GROUP BY day"
        ),
        {'uid': user_obj.id, 'start': start_date.isoformat()}
    ).fetchall()
    activity_data = {row[0]: row[1] for row in activity_rows}

    return render_template(
        'user.html', user=user_obj,
        posts=posts.items, next_url=next_url, prev_url=prev_url,
        form=form, activity_data=json.dumps(activity_data),
    )


@app.route('/edit/profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm(current_user.username)
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.about_me = form.about_me.data
        db.session.commit()
        flash('Your profile has been updated!')
        return redirect(url_for('edit_profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', title='Edit Profile', form=form)


# ─── Follow / Unfollow ────────────────────────────────────────────────────────

@app.route('/follow/<username>', methods=['POST'])
@login_required
def follow(username):
    form = EmptyForm()
    if form.validate_on_submit():
        user_obj = db.session.scalar(sa.select(User).where(User.username == username))
        if user_obj is None:
            flash(f'User {username} not found.')
            return redirect(url_for('index'))
        if user_obj == current_user:
            flash('You cannot follow yourself!')
            return redirect(url_for('user', username=username))
        current_user.follow(user_obj)
        db.session.commit()
        flash(f'You are following {username}!')
        return redirect(url_for('user', username=username))
    return redirect(url_for('index'))


@app.route('/unfollow/<username>', methods=['POST'])
@login_required
def unfollow(username):
    form = EmptyForm()
    if form.validate_on_submit():
        user_obj = db.session.scalar(sa.select(User).where(User.username == username))
        if user_obj is None:
            flash(f'User {username} not found.')
            return redirect(url_for('index'))
        if user_obj == current_user:
            flash('You cannot unfollow yourself!')
            return redirect(url_for('user', username=username))
        current_user.unfollow(user_obj)
        db.session.commit()
        flash(f'You unfollowed {username}.')
        return redirect(url_for('user', username=username))
    return redirect(url_for('index'))


# ─── API key management ───────────────────────────────────────────────────────

@app.route('/settings/api-key', methods=['POST'])
@login_required
def generate_api_key():
    key = current_user.generate_api_key()
    db.session.commit()
    flash(f'Your new API key: {key}')
    return redirect(url_for('user', username=current_user.username))


# ─── Notifications ────────────────────────────────────────────────────────────

@app.route('/notifications/mark-read', methods=['POST'])
@login_required
def mark_notifications_read():
    notifications = db.session.scalars(
        current_user.notifications.select()
        .where(Notification.is_read == False)  # noqa: E712
    ).all()
    for n in notifications:
        n.is_read = True
    db.session.commit()
    return jsonify({'marked': len(notifications)})


# ─── SSE stream ───────────────────────────────────────────────────────────────

@app.route('/stream')
@login_required
def stream():
    """
    Server-Sent Events endpoint.
    Sends notification updates every 5 seconds for up to 60 seconds,
    then the client auto-reconnects (standard SSE behaviour).
    Requires gunicorn --threads or dev server for concurrent connections.
    """
    user_id = current_user.id

    def event_stream():
        last_id = request.args.get('lastEventId', 0, type=int)
        max_cycles = 12  # 12 × 5 s = 60 s, then client reconnects
        for _ in range(max_cycles):
            new_notifs = db.session.scalars(
                sa.select(Notification)
                .where(
                    Notification.user_id == user_id,
                    Notification.id > last_id,
                    Notification.is_read == False,  # noqa: E712
                )
                .order_by(Notification.id.desc())
                .limit(10)
            ).all()
            if new_notifs:
                last_id = new_notifs[0].id
                payload = json.dumps({
                    'count': len(new_notifs),
                    'notifications': [n.to_dict() for n in new_notifs],
                })
                yield f'id: {last_id}\ndata: {payload}\n\n'
            else:
                yield 'data: {}\n\n'
            _time.sleep(5)

    response = Response(event_stream(), mimetype='text/event-stream')
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['X-Accel-Buffering'] = 'no'
    return response


# ─── Admin dashboard ──────────────────────────────────────────────────────────

@app.route('/admin')
@login_required
@admin_required
def admin():
    stats = {
        'users': db.session.scalar(sa.select(sa.func.count()).select_from(User)),
        'posts': db.session.scalar(sa.select(sa.func.count()).select_from(Post)),
        'comments': db.session.scalar(sa.select(sa.func.count()).select_from(Comment)),
        'tags': db.session.scalar(sa.select(sa.func.count()).select_from(Tag)),
    }
    recent_logs = db.session.scalars(
        sa.select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(20)
    ).all()
    top_posts = db.session.scalars(
        sa.select(Post).order_by(Post.view_count.desc()).limit(5)
    ).all()
    return render_template(
        'admin.html', title='Admin', stats=stats,
        recent_logs=recent_logs, top_posts=top_posts,
        now=datetime.now(timezone.utc),
    )
