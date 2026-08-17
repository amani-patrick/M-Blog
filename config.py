import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'app.db')
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 25)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS') is not None
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    ADMINS = ['pazzoamani@gmail.com']
    POSTS_PER_PAGE = int(os.environ.get('POSTS_PER_PAGE') or 10)

    # Redis (view counter caching; graceful fallback if unavailable)
    REDIS_URL = os.environ.get('REDIS_URL') or 'redis://localhost:6379/0'

    # GitHub OAuth (register at github.com/settings/developers)
    GITHUB_OAUTH_CLIENT_ID = os.environ.get('GITHUB_CLIENT_ID') or ''
    GITHUB_OAUTH_CLIENT_SECRET = os.environ.get('GITHUB_CLIENT_SECRET') or ''

    # Flask-Limiter (in-memory for single-process; swap to Redis URI in prod)
    RATELIMIT_STORAGE_URI = os.environ.get('RATELIMIT_STORAGE_URI') or 'memory://'
    RATELIMIT_DEFAULT = '300 per day;60 per hour'

    # Allow HTTP for OAuth in development
    OAUTHLIB_INSECURE_TRANSPORT = os.environ.get('OAUTHLIB_INSECURE_TRANSPORT') or '1'