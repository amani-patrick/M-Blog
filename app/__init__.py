import logging
import os
from logging.handlers import SMTPHandler, RotatingFileHandler
from flask import Flask
from config import Config
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail

app = Flask(__name__)
app.config.from_object(Config)

# Allow HTTP for OAuth in development
os.environ.setdefault('OAUTHLIB_INSECURE_TRANSPORT',
                      app.config.get('OAUTHLIB_INSECURE_TRANSPORT', '1'))

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login = LoginManager(app)
login.login_view = 'login'
mail = Mail(app)

# ─── Flask-Limiter ────────────────────────────────────────────────────────────
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri=app.config['RATELIMIT_STORAGE_URI'],
    default_limits=[app.config['RATELIMIT_DEFAULT']],
)

# ─── Redis (optional — view counter caching) ─────────────────────────────────
redis_client = None
try:
    import redis as _redis
    _rc = _redis.from_url(app.config['REDIS_URL'], socket_connect_timeout=1)
    _rc.ping()
    redis_client = _rc
    app.logger.info('Redis connected at %s', app.config['REDIS_URL'])
except Exception:
    app.logger.info('Redis unavailable — using DB-based view counter fallback.')

# ─── GitHub OAuth Blueprint ───────────────────────────────────────────────────
github_bp = None
try:
    from flask_dance.contrib.github import make_github_blueprint
    github_bp = make_github_blueprint(
        client_id=app.config.get('GITHUB_OAUTH_CLIENT_ID', ''),
        client_secret=app.config.get('GITHUB_OAUTH_CLIENT_SECRET', ''),
        redirect_to='github_login',
    )
    app.register_blueprint(github_bp, url_prefix='/login')
except Exception as e:
    app.logger.warning('GitHub OAuth blueprint not registered: %s', e)

# ─── Logging ─────────────────────────────────────────────────────────────────
if not app.debug:
    if app.config['MAIL_SERVER']:
        auth = None
        if app.config['MAIL_USERNAME'] or app.config['MAIL_PASSWORD']:
            auth = (app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        secure = None
        if app.config['MAIL_USE_TLS']:
            secure = ()
        mail_handler = SMTPHandler(
            mailhost=(app.config['MAIL_SERVER'], app.config['MAIL_PORT']),
            fromaddr='no-reply@' + app.config['MAIL_SERVER'],
            toaddrs=app.config['ADMINS'], subject='Microblog Failure',
            credentials=auth, secure=secure
        )
        mail_handler.setLevel(logging.ERROR)
        app.logger.addHandler(mail_handler)

    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler(
        'logs/microblog.log', maxBytes=10240, backupCount=10
    )
    formatter = logging.Formatter(
        '%(asctime)s %(levelname)s [in %(pathname)s:%(lineno)d]'
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Microblog startup')

from app import routes, models, errors  # noqa: E402, F401
from app import api as api_module  # noqa: E402, F401
app.register_blueprint(api_module.api_bp)
