from flask_sqlalchemy import SQLAlchemy

# Cria a instância do SQLAlchemy
db = SQLAlchemy()

# Adicione esta função
def init_app(app):
    db.init_app(app)
    with app.app_context():
        db.create_all()  # Isso criará todas as tabelas definidas nos modelos