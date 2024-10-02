from app import app, db
from app.models import User, Post
from flask_migrate import Migrate
import sqlalchemy as sa
import sqlalchemy.orm as so

migrate = Migrate(app, db)

@app.shell_context_processor
def make_shell_context():
    return {'sa': sa, 'so': so, 'db': db, 'User': User, 'Post': Post}
