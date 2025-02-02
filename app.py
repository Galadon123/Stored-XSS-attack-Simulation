from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from routes.routes import init_routes
from models.models import db

def create_app():
    app = Flask(__name__)
    app.config.from_object('config')
    
    # Initialize database
    db.init_app(app)
    
    # Initialize routes
    init_routes(app)
    
    return app

if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=8000)