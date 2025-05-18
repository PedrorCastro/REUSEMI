from flask import Flask, request, jsonify, g, session, render_template, url_for, redirect, send_file, flash
from flask_cors import CORS
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import pandas as pd
from io import BytesIO
from flask_httpauth import HTTPBasicAuth
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os
from dotenv import load_dotenv
from models import Usuario, Item
from extensions import db
from flask_login import login_user, logout_user, login_required

@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        usuario = Usuario(
            nome=request.form['nome'],
            email=request.form['email']
        )
        usuario.set_senha(request.form['senha'])
        db.session.add(usuario)
        db.session.commit()
        flash('Cadastro realizado com sucesso!')
        return redirect(url_for('login'))
    return render_template('cadastro.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = Usuario.query.filter_by(email=request.form['email']).first()
        if usuario and usuario.check_senha(request.form['senha']):
            login_user(usuario)
            return redirect(url_for('home'))
        flash('Email ou senha incorretos')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'Jopepa123'  # Altere para uma chave segura
app.config.update(...)


# Decoradores
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'usuario_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def nivel_minimo(nivel_necessario):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            niveis = {'user': 1, 'admin': 2}
            user_nivel = session.get('user_nivel', 'user')
            if niveis.get(user_nivel, 0) < niveis.get(nivel_necessario, 0):
                return render_template('error.html', error_message='Permissão negada'), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Banco de dados
DATABASE = 'reusemi.db'



def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        c = db.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                senha TEXT NOT NULL,
                nivel TEXT NOT NULL DEFAULT 'user'
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS itens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL,
                descricao TEXT,
                categoria TEXT,
                cidade TEXT,
                usuario_id INTEGER,
                FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
            )
        ''')
        db.commit()

# Rotas
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        senha = request.form.get('senha')
        
        # Verifique se os campos foram preenchidos
        if not email or not senha:
            return render_template('login.html', error='Por favor, preencha todos os campos')
        
        # Aqui você deve verificar as credenciais no seu banco de dados
        # Exemplo básico (substitua pela sua lógica real):
        if email == 'usuario@exemplo.com' and senha == 'senha123':
            session['usuario_id'] = 1  # Armazena o ID do usuário na sessão
            session['user_email'] = email
            return redirect(url_for('perfil'))  # Redireciona para a página de perfil
        else:
            return render_template('login.html', error='Credenciais inválidas')
    
    # Se for GET, apenas mostra o formulário
    return render_template('login.html')
    
    
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        nome = request.form.get('nome')
        email = request.form.get('email')
        senha = request.form.get('senha')
        confirmar_senha = request.form.get('confirmar_senha')

        if not nome or not email or not senha:
            return render_template('cadastro.html', error='Todos os campos são obrigatórios')

        if senha != confirmar_senha:
            return render_template('cadastro.html', error='As senhas não coincidem')

        if len(senha) < 6:
            return render_template('cadastro.html', error='Senha deve ter pelo menos 6 caracteres')

        hashed_senha = generate_password_hash(senha)

        try:
            db = get_db()
            c = db.cursor()
            c.execute("INSERT INTO usuarios (nome, email, senha, nivel) VALUES (?, ?, ?, ?)",
                      (nome, email, hashed_senha, 'user'))
            db.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return render_template('cadastro.html', error='Email já cadastrado')
        except sqlite3.Error as e:
            return render_template('cadastro.html', error=f'Erro no banco de dados: {str(e)}')

    return render_template('cadastro.html')

@app.route('/categorias')
def categorias():
    try:
        db = get_db()
        c = db.cursor()
        c.execute("SELECT DISTINCT categoria FROM itens")
        categorias = [row['categoria'] for row in c.fetchall()]
        return render_template('categorias.html', categorias=categorias)
    except sqlite3.Error as e:
        return render_template('error.html', error_message=f'Erro no banco de dados: {str(e)}')


@app.route('/perfil')
@login_required
def perfil():
    db = get_db()
    c = db.cursor()
    c.execute("SELECT id, nome, email, nivel FROM usuarios WHERE id = ?", (session['usuario_id'],))
    usuario = c.fetchone()

    if not usuario:
        session.clear()
        return redirect(url_for('login'))

    return render_template('perfil.html', usuario=usuario)


app.config['SESSION_COOKIE_SECURE'] = True
app.config['REMEMBER_COOKIE_SECURE'] = True
@app.route('/anunciar', methods=['GET', 'POST'])
@login_required
def anunciar():
    if request.method == 'POST':
        nome = request.form.get('nome')
        descricao = request.form.get('descricao')
        categoria = request.form.get('categoria')
        cidade = request.form.get('cidade')

        if not nome or not categoria or not cidade:
            return render_template('anunciar.html', error='Nome, categoria e cidade são obrigatórios')

        try:
            db = get_db()
            c = db.cursor()
            c.execute("INSERT INTO itens (nome, descricao, categoria, cidade, usuario_id) VALUES (?, ?, ?, ?, ?)",
                      (nome, descricao, categoria, cidade, session['usuario_id']))
            db.commit()
            return redirect(url_for('perfil'))
        except sqlite3.Error as e:
            return render_template('anunciar.html', error=f'Erro no banco de dados: {str(e)}')

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
        db = get_db()
        c = db.cursor()
        c.execute("SELECT id, nome, email, nivel FROM usuarios")
        rows = c.fetchall()

        if not rows:
            return "Nenhum usuário encontrado", 404

        df = pd.DataFrame(rows, columns=["ID", "Nome", "Email", "Nível de Acesso"])

        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name="Usuários")
            writer.save()
        output.seek(0)

        return send_file(output,
                         as_attachment=True,
                         download_name="usuarios_REUSEMI.xlsx",
                         mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

    except Exception as e:
        return f"Erro ao exportar usuários: {str(e)}", 500

@app.route('/foster')  # Verifique se esta rota existe
def foster():
    return render_template('foster.html')  # Este arquivo precisa existir



auth = HTTPBasicAuth()

users = {
    "Pedro": "Jopepa123"
}

@auth.verify_password
def verify_password(username, password):
    return users.get(username) == password

@app.route('/')
@auth.login_required
def home():
    return "Conteúdo protegido"



load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DB_URI')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicialização do db deve vir DEPOIS de criar o app
db.init_app(app)  # Agora db está definido
migrate = Migrate(app, db)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=8080, debug=True)



