from flask import render_template
from app import app,db 

@app.error_handler(404)
def not_found_errors(error):
    return render_template('404.html'),404
@app.error_handler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'),500