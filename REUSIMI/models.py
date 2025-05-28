from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

class User:
    def __init__(self, username, password_hash=None, email=None, full_name=None, id=None):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.email = email
        self.full_name = full_name
    
    @classmethod
    def find_by_username(cls, username):
        conn = sqlite3.connect('reusemi.db')
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user_data = cursor.fetchone()
        conn.close()
        
        if user_data:
            return cls(
                id=user_data[0],
                username=user_data[1],
                password_hash=user_data[2],
                email=user_data[3],
                full_name=user_data[4]
            )
        return None
    
    @classmethod
    def create_user(cls, username, password, email=None, full_name=None):
        password_hash = generate_password_hash(password)
        
        conn = sqlite3.connect('reusemi.db')
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
            INSERT INTO users (username, password_hash, email, full_name)
            VALUES (?, ?, ?, ?)
            ''', (username, password_hash, email, full_name))
            conn.commit()
            user_id = cursor.lastrowid
            conn.close()
            return cls(username, password_hash, email, full_name, user_id)
        except sqlite3.IntegrityError:
            conn.close()
            return None
    
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)