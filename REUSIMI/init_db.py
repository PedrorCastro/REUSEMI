import sqlite3
from werkzeug.security import generate_password_hash

def init_db():
    conn = sqlite3.connect('reusemi.db')
    cursor = conn.cursor()
    
    # Criar tabela de usuários
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        full_name TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Criar um usuário admin inicial (opcional)
    admin_password = generate_password_hash('admin123')
    cursor.execute('''
    INSERT OR IGNORE INTO users (username, password_hash, email, full_name)
    VALUES (?, ?, ?, ?)
    ''', ('admin', admin_password, 'admin@reusemi.com', 'Administrador'))
    
    conn.commit()
    conn.close()
    print("Banco de dados inicializado com sucesso!")

if __name__ == '__main__':
    init_db()