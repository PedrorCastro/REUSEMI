from flask import Flask, request, jsonify, g, session, render_template, url_for, redirect, send_file, flash, send_from_directory
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import pandas as pd
from io import BytesIO
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os
from dotenv import load_dotenv
from flask_login import LoginManager, login_user, logout_user, login_required, current_user

# Inicializações
load_dotenv()
app = Flask(__name__)
CORS(app)

# Configurações
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DB_URI', 'sqlite:///reusemi.db')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'Jopepa123')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SECURE'] = True
app.config['REMEMBER_COOKIE_SECURE'] = True

# Inicialização do banco de dados
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Configuração do Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Modelos (movidos para o mesmo arquivo para evitar imports circulares)
class Usuario(db.Model):
    __tablename__ = 'usuarios'
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    senha = db.Column(db.String(200), nullable=False)
    nivel = db.Column(db.String(20), default='user')
    itens = db.relationship('Item', backref='dono', lazy=True)

    def set_senha(self, senha):
        self.senha = generate_password_hash(senha)

    def check_senha(self, senha):
        return check_password_hash(self.senha, senha)

class Item(db.Model):
    __tablename__ = 'itens'
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    descricao = db.Column(db.Text)
    categoria = db.Column(db.String(50))
    cidade = db.Column(db.String(50))
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=False)

@login_manager.user_loader
def load_user(id):
    return Usuario.query.get(int(id))

# Decoradores
def nivel_minimo(nivel_necessario):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            niveis = {'user': 1, 'admin': 2}
            user_nivel = current_user.nivel if current_user.is_authenticated else 'user'
            if niveis.get(user_nivel, 0) < niveis.get(nivel_necessario, 0):
                return render_template('error.html', error_message='Permissão negada'), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator


    
# Rotas

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, 'static', 'img', 'web'),
        'icons8-sinal-de-reciclagem-color-16.png',
        mimetype='image/vnd.microsoft.icon'
    )

@app.route('/trocas_sustentaveis.png')
def img_index():
    return send_from_directory(
        os.path.join(app.root_path, 'static', 'img',),
        '20250519_2027_Design de Troca Sustentável_simple_compose_01jvndvxqxefb955m2d0ydbjcj.png',
        mimetype='image/vnd.microsoft.icon'
    )
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = Usuario.query.filter_by(email=request.form['email']).first()
        if usuario and usuario.check_senha(request.form['senha']):
            login_user(usuario)
            return redirect(url_for('perfil'))
        flash('Email ou senha incorretos')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        usuario = Usuario(
            nome=request.form['nome'],
            email=request.form['email'],
            nivel='user'
        )
        usuario.set_senha(request.form['senha'])
        db.session.add(usuario)
        db.session.commit()
        flash('Cadastro realizado com sucesso!')
        return redirect(url_for('login'))
    return render_template('cadastro.html')

@app.route('/perfil')
@login_required
def perfil():
    return render_template('perfil.html', usuario=current_user)

@app.route('/categorias')
def categorias():
    categorias = db.session.query(Item.categoria).distinct().all()
    return render_template('categorias.html', categorias=[c[0] for c in categorias])

@app.route('/anunciar', methods=['GET', 'POST'])
@login_required
def anunciar():
    if request.method == 'POST':
        item = Item(
            nome=request.form['nome'],
            descricao=request.form['descricao'],
            categoria=request.form['categoria'],
            cidade=request.form['cidade'],
            usuario_id=current_user.id
        )
        db.session.add(item)
        db.session.commit()
        flash('Item anunciado com sucesso!')
        return redirect(url_for('perfil'))
    return render_template('anunciar.html')


@app.route('/admin')
@login_required
@nivel_minimo('admin')
def admin():
    return render_template('admin.html')

@app.route('/exportar-usuarios')
@login_required
@nivel_minimo('admin')
def exportar_usuarios():
    try:
        usuarios = Usuario.query.all()
        if not usuarios:
            return "Nenhum usuário encontrado", 404

        data = [{
            "ID": u.id,
            "Nome": u.nome,
            "Email": u.email,
            "Nível de Acesso": u.nivel
        } for u in usuarios]

        df = pd.DataFrame(data)
        output = BytesIO()
        df.to_excel(output, index=False)
        output.seek(0)

        return send_file(
            output,
            as_attachment=True,
            download_name="usuarios_REUSEMI.xlsx",
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
    except Exception as e:
        return f"Erro ao exportar usuários: {str(e)}", 500

@app.route('/foster')
def foster():
    return render_template('foster.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=8080, debug=True)