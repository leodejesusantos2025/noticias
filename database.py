import os
import logging
import psycopg2
from psycopg2 import extras
import sqlite3
from flask_login import UserMixin
from werkzeug.security import generate_password_hash
from datetime import datetime

DATABASE_URL = os.environ.get('DATABASE_URL')
POSTGRES_HOST = os.environ.get('POSTGRES_HOST')
POSTGRES_PORT = os.environ.get('POSTGRES_PORT', '5432')
POSTGRES_DB = os.environ.get('POSTGRES_DB', 'postgres')
POSTGRES_USER = os.environ.get('POSTGRES_USER')
POSTGRES_PASSWORD = os.environ.get('POSTGRES_PASSWORD')
APP_ENV = os.environ.get('APP_ENV', os.environ.get('FLASK_ENV', 'production')).lower()
ALLOW_SQLITE = os.environ.get('ALLOW_SQLITE', 'false').lower() == 'true'
SQLITE_PATH = os.environ.get('SQLITE_PATH', 'clicks.db')
logger = logging.getLogger(__name__)

if DATABASE_URL:
    print(f"✅ DATABASE_URL encontrada: {DATABASE_URL[:50]}...")
    conn_string = DATABASE_URL
    db_type = 'postgresql'
elif POSTGRES_HOST and POSTGRES_USER and POSTGRES_PASSWORD:
    print(f"✅ Configuração PostgreSQL encontrada: {POSTGRES_USER}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}")
    conn_string = {
        'host': POSTGRES_HOST,
        'port': POSTGRES_PORT,
        'dbname': POSTGRES_DB,
        'user': POSTGRES_USER,
        'password': POSTGRES_PASSWORD,
    }
    db_type = 'postgresql'
else:
    if APP_ENV not in {'development', 'dev', 'local'} and not ALLOW_SQLITE:
        raise RuntimeError(
            "DATABASE_URL ou POSTGRES_HOST/POSTGRES_USER/POSTGRES_PASSWORD são obrigatórias fora de desenvolvimento. "
            "Defina APP_ENV=development para uso local ou ALLOW_SQLITE=true conscientemente."
        )
    print("AVISO: DATABASE_URL não definida. Usando SQLite para desenvolvimento local.")
    DATABASE = 'clicks.db'
    conn_string = SQLITE_PATH
    db_type = 'sqlite'

def get_db_connection():
    if db_type == 'sqlite':
        conn = sqlite3.connect(conn_string, timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
    else:
        if isinstance(conn_string, dict):
            conn = psycopg2.connect(**conn_string, cursor_factory=psycopg2.extras.DictCursor)
        else:
            conn = psycopg2.connect(conn_string, cursor_factory=psycopg2.extras.DictCursor)
    return conn

class User(UserMixin):
    def __init__(self, id, username, password_hash, expo_push_token=None, is_admin=False, created_at=None, last_login=None):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.expo_push_token = expo_push_token
        self.is_admin = is_admin
        self.created_at = created_at
        self.last_login = last_login
        print(f"🔍 DEBUG: Usuário criado/carregado - ID: {id}, Username: {username}, Is_Admin: {is_admin}")

    @staticmethod
    def get(user_id):
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            if db_type == 'sqlite':
                cursor.execute("SELECT id, username, password_hash, expo_push_token, is_admin, created_at, last_login FROM users WHERE id = ?", (user_id,))
            else:
                cursor.execute("SELECT id, username, password_hash, expo_push_token, is_admin, created_at, last_login FROM users WHERE id = %s", (user_id,))
            user_data = cursor.fetchone()
            conn.close()
            if user_data:
                user = User(
                    id=user_data['id'],
                    username=user_data['username'],
                    password_hash=user_data['password_hash'],
                    expo_push_token=user_data['expo_push_token'],
                    is_admin=user_data['is_admin'],
                    created_at=user_data['created_at'],
                    last_login=user_data['last_login']
                )
                print(f"🔍 DEBUG: User.get({user_id}) encontrado - Admin: {user.is_admin}")
                return user
            else:
                print(f"❌ DEBUG: User.get({user_id}) não encontrado")
            return None
        except Exception as e:
            print(f"❌ DEBUG: Erro em User.get({user_id}): {e}")
            conn.close()
            return None

    @staticmethod
    def get_by_username(username):
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            if db_type == 'sqlite':
                cursor.execute("SELECT id, username, password_hash, expo_push_token, is_admin, created_at, last_login FROM users WHERE username = ?", (username,))
            else:
                cursor.execute("SELECT id, username, password_hash, expo_push_token, is_admin, created_at, last_login FROM users WHERE username = %s", (username,))
            user_data = cursor.fetchone()
            conn.close()
            if user_data:
                user = User(
                    id=user_data['id'],
                    username=user_data['username'],
                    password_hash=user_data['password_hash'],
                    expo_push_token=user_data['expo_push_token'],
                    is_admin=user_data['is_admin'],
                    created_at=user_data['created_at'],
                    last_login=user_data['last_login']
                )
                print(f"🔍 DEBUG: User.get_by_username({username}) encontrado - Admin: {user.is_admin}")
                return user
            else:
                print(f"❌ DEBUG: User.get_by_username({username}) não encontrado")
            return None
        except Exception as e:
            print(f"❌ DEBUG: Erro em User.get_by_username({username}): {e}")
            try:
                if db_type == 'sqlite':
                    cursor.execute("SELECT id, username, password_hash, expo_push_token FROM users WHERE username = ?", (username,))
                else:
                    cursor.execute("SELECT id, username, password_hash, expo_push_token FROM users WHERE username = %s", (username,))
                user_data = cursor.fetchone()
                conn.close()
                if user_data:
                    print(f"🔍 DEBUG: User.get_by_username({username}) encontrado (sem is_admin, fallback)")
                    return User(id=user_data['id'], username=user_data['username'],
                                password_hash=user_data['password_hash'],
                                expo_push_token=user_data['expo_push_token'],
                                is_admin=False, created_at=None, last_login=None)
                return None
            except Exception as e2:
                print(f"❌ DEBUG: Erro em fallback User.get_by_username({username}): {e2}")
                conn.close()
                return None


def get_admin_bootstrap_credentials():
    username = os.environ.get('DEFAULT_ADMIN_USERNAME')
    password = os.environ.get('DEFAULT_ADMIN_PASSWORD')
    if username and password:
        return username, password
    return None, None


def init_db():
    print("🚀 Iniciando inicialização do banco de dados...")
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        if db_type == 'sqlite':
            print("📊 Usando SQLite - Criando tabelas...")
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    expo_push_token TEXT UNIQUE,
                    is_admin BOOLEAN DEFAULT FALSE,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_login DATETIME
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS generated_links (
                    link_id TEXT PRIMARY KEY,
                    original_url TEXT NOT NULL,
                    user_id INTEGER NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS clicks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    link_id TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    referer TEXT,
                    accept_language TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    browser_fingerprint TEXT,
                    geolocation_info TEXT,
                    notes TEXT,
                    client_port TEXT,
                    port_detection_method TEXT,
                    network_info TEXT,
                    destination_port TEXT,
                    destination_port_method TEXT,
                    FOREIGN KEY (link_id) REFERENCES generated_links (link_id) ON DELETE CASCADE
                )
            ''')
            cursor.execute("PRAGMA table_info(clicks)")
            clicks_columns = [c[1] for c in cursor.fetchall()]
            if 'client_port' not in clicks_columns:
                cursor.execute('ALTER TABLE clicks ADD COLUMN client_port TEXT')
                print("✅ Coluna client_port adicionada à tabela clicks")
            if 'port_detection_method' not in clicks_columns:
                cursor.execute('ALTER TABLE clicks ADD COLUMN port_detection_method TEXT')
                print("✅ Coluna port_detection_method adicionada à tabela clicks")
            if 'network_info' not in clicks_columns:
                cursor.execute('ALTER TABLE clicks ADD COLUMN network_info TEXT')
                print("✅ Coluna network_info adicionada à tabela clicks")
            if 'destination_port' not in clicks_columns:
                cursor.execute('ALTER TABLE clicks ADD COLUMN destination_port TEXT')
                print("✅ Coluna destination_port adicionada à tabela clicks")
            if 'destination_port_method' not in clicks_columns:
                cursor.execute('ALTER TABLE clicks ADD COLUMN destination_port_method TEXT')
                print("✅ Coluna destination_port_method adicionada à tabela clicks")
            cursor.execute("PRAGMA table_info(users)")
            user_columns = [c[1] for c in cursor.fetchall()]
            if 'is_admin' not in user_columns:
                cursor.execute('ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT FALSE')
                print("✅ Coluna is_admin adicionada à tabela users")
            if 'created_at' not in user_columns:
                cursor.execute('ALTER TABLE users ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP')
                print("✅ Coluna created_at adicionada à tabela users")
            if 'last_login' not in user_columns:
                cursor.execute('ALTER TABLE users ADD COLUMN last_login DATETIME')
                print("✅ Coluna last_login adicionada à tabela users")
        else:
            print("🐘 Usando PostgreSQL - Criando tabelas...")
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    expo_push_token VARCHAR(255) UNIQUE,
                    is_admin BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP
                );
            ''')
            print("✅ Tabela users criada/verificada")
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS generated_links (
                    link_id VARCHAR(255) PRIMARY KEY,
                    original_url TEXT NOT NULL,
                    user_id INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                );
            ''')
            print("✅ Tabela generated_links criada/verificada")
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS clicks (
                    id SERIAL PRIMARY KEY,
                    link_id VARCHAR(255) NOT NULL,
                    ip_address VARCHAR(255),
                    user_agent TEXT,
                    referer TEXT,
                    accept_language VARCHAR(255),
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    browser_fingerprint TEXT,
                    geolocation_info TEXT,
                    notes TEXT,
                    client_port VARCHAR(10),
                    port_detection_method VARCHAR(50),
                    network_info TEXT,
                    destination_port VARCHAR(10),
                    destination_port_method VARCHAR(50),
                    FOREIGN KEY (link_id) REFERENCES generated_links (link_id) ON DELETE CASCADE
                );
            ''')
            print("✅ Tabela clicks criada/verificada")
            cursor.execute('ALTER TABLE clicks ADD COLUMN IF NOT EXISTS client_port VARCHAR(10)')
            cursor.execute('ALTER TABLE clicks ADD COLUMN IF NOT EXISTS port_detection_method VARCHAR(50)')
            cursor.execute('ALTER TABLE clicks ADD COLUMN IF NOT EXISTS network_info TEXT')
            cursor.execute('ALTER TABLE clicks ADD COLUMN IF NOT EXISTS destination_port VARCHAR(10)')
            cursor.execute('ALTER TABLE clicks ADD COLUMN IF NOT EXISTS destination_port_method VARCHAR(50)')
            cursor.execute('ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE')
            cursor.execute('ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP')
            cursor.execute('ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMP')
            print("✅ Colunas adicionais verificadas/adicionadas")
            cursor.execute("SELECT COUNT(*) FROM users;")
            user_count = cursor.fetchone()[0]
            print(f"📊 Total de usuários no banco: {user_count}")
            if user_count == 0:
                print("👤 Criando usuário administrador padrão...")
                default_username = os.environ.get('DEFAULT_ADMIN_USERNAME')
                default_password = os.environ.get('DEFAULT_ADMIN_PASSWORD')
                if not default_username or not default_password:
                    raise RuntimeError(
                        "Banco vazio sem bootstrap seguro. Defina DEFAULT_ADMIN_USERNAME e DEFAULT_ADMIN_PASSWORD."
                    )
                default_password_hash = generate_password_hash(default_password)
                cursor.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (%s, %s, %s);", (default_username, default_password_hash, True))
                print(f"✅ Usuário administrador '{default_username}' criado com sucesso!")
            else:
                cursor.execute("SELECT COUNT(*) FROM users WHERE is_admin = TRUE;")
                admin_count = cursor.fetchone()[0]
                print(f"👑 Total de administradores: {admin_count}")
                if admin_count == 0:
                    print("⚠️ Nenhum administrador encontrado. Promovendo usuário 'admin' se existir...")
                    bootstrap_username = os.environ.get('DEFAULT_ADMIN_USERNAME')
                    if not bootstrap_username:
                        raise RuntimeError(
                            "Nenhum administrador encontrado. Defina DEFAULT_ADMIN_USERNAME para bootstrap seguro."
                        )
                    cursor.execute("UPDATE users SET is_admin = TRUE WHERE username = %s;", (bootstrap_username,))
                    affected_rows = cursor.rowcount
                    if affected_rows > 0:
                        print("✅ Usuário 'admin' promovido a administrador!")
                    else:
                        print("❌ Usuário 'admin' não encontrado para promoção, criando um novo...")
                        default_username = os.environ.get('DEFAULT_ADMIN_USERNAME')
                        default_password = os.environ.get('DEFAULT_ADMIN_PASSWORD')
                        if not default_username or not default_password:
                            raise RuntimeError(
                                "Nenhum administrador encontrado. Defina credenciais de bootstrap seguras."
                            )
                        default_password_hash = generate_password_hash(default_password)
                        try:
                            cursor.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (%s, %s, %s);", (default_username, default_password_hash, True))
                            print(f"✅ Usuário administrador '{default_username}' criado!")
                        except psycopg2.IntegrityError:
                            print("ℹ️ Usuário 'admin' já existe (erro de concorrência?), garantindo que seja admin...")
                            cursor.execute("UPDATE users SET is_admin = TRUE WHERE username = %s;", (default_username,))
            conn.commit()
        conn.close()
        print("🎉 Banco de dados inicializado com sucesso!")
        bootstrap_username = os.environ.get('DEFAULT_ADMIN_USERNAME')
        test_admin = User.get_by_username(bootstrap_username) if bootstrap_username else None
        if test_admin:
            print(f"🔍 Teste: Usuário admin encontrado - Is_Admin: {test_admin.is_admin}")
        else:
            print("❌ Teste: Usuário admin não encontrado após inicialização!")
    except Exception as e:
        print(f"❌ ERRO CRÍTICO na inicialização do banco: {e}")
        conn.rollback()
        conn.close()
        raise e

def update_user_push_token(user_id, token):
    conn = get_db_connection()
    cursor = conn.cursor()
    if db_type == 'sqlite':
        cursor.execute("UPDATE users SET expo_push_token = ? WHERE id = ?", (token, user_id))
    else:
        cursor.execute("UPDATE users SET expo_push_token = %s WHERE id = %s", (token, user_id))
    conn.commit()
    conn.close()

def get_user_push_token(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    if db_type == 'sqlite':
        cursor.execute("SELECT expo_push_token FROM users WHERE id = ?", (user_id,))
    else:
        cursor.execute("SELECT expo_push_token FROM users WHERE id = %s", (user_id,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

def add_user(username, password_hash, is_admin=False):
    print(f"🔍 DEBUG: Tentando criar usuário - Username: {username}, Is_Admin: {is_admin}")
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        if db_type == 'sqlite':
            cursor.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)", (username, password_hash, is_admin))
            user_id = cursor.lastrowid
        else:
            cursor.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (%s, %s, %s) RETURNING id", (username, password_hash, is_admin))
            user_id = cursor.fetchone()[0]
        conn.commit()
        conn.close()
        print(f"✅ DEBUG: Usuário criado com sucesso - ID: {user_id}")
        return user_id
    except (sqlite3.IntegrityError, psycopg2.IntegrityError) as e:
        print(f"❌ DEBUG: Erro de integridade ao criar usuário: {e}")
        conn.rollback()
        conn.close()
        return None
    except Exception as e:
        print(f"❌ DEBUG: Erro geral ao criar usuário: {e}")
        conn.rollback()
        conn.close()
        return None

def add_generated_link(link_id, original_url, user_id):
    print(f"🔍 DEBUG: Criando link - ID: {link_id}, URL: {original_url[:50]}..., User: {user_id}")
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        if db_type == 'sqlite':
            cursor.execute('''
                INSERT OR IGNORE INTO generated_links (link_id, original_url, user_id)
                VALUES (?, ?, ?)
            ''', (link_id, original_url, user_id))
        else:
            cursor.execute('''
                INSERT INTO generated_links (link_id, original_url, user_id)
                VALUES (%s, %s, %s) ON CONFLICT (link_id) DO NOTHING
            ''', (link_id, original_url, user_id))
        conn.commit()
        conn.close()
        print(f"✅ DEBUG: Link criado com sucesso - ID: {link_id}")
    except Exception as e:
        print(f"❌ DEBUG: Erro ao criar link: {e}")
        conn.rollback()
        conn.close()

def get_original_url_from_generated_link(link_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    if db_type == 'sqlite':
        cursor.execute('SELECT original_url FROM generated_links WHERE link_id = ?', (link_id,))
    else:
        cursor.execute('SELECT original_url FROM generated_links WHERE link_id = %s', (link_id,))
    result = cursor.fetchone()
    conn.close()
    if result:
        print(f"🔍 DEBUG: Link encontrado - ID: {link_id}, URL: {result['original_url'][:50]}...")
    else:
        print(f"❌ DEBUG: Link não encontrado - ID: {link_id}")
    return result['original_url'] if result else None

def get_generated_link_details(link_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    if db_type == 'sqlite':
        cursor.execute('SELECT link_id, original_url, user_id, created_at FROM generated_links WHERE link_id = ?', (link_id,))
    else:
        cursor.execute('SELECT link_id, original_url, user_id, created_at FROM generated_links WHERE link_id = %s', (link_id,))
    result = cursor.fetchone()
    conn.close()
    return result if result else None

def add_click(
    link_id,
    ip,
    user_agent,
    referer,
    accept_language,
    browser_fingerprint=None,
    geolocation_info=None,
    notes="",
    client_port=None,
    port_detection_method=None,
    network_info=None,
    destination_port=None,
    destination_port_method=None
):
    conn = get_db_connection()
    cursor = conn.cursor()
    print(f"🔍 DEBUG: Salvando click - Link: {link_id}, IP: {ip}, Porta: {client_port}")
    try:
        if db_type == 'sqlite':
            cursor.execute('''
                INSERT INTO clicks (link_id, ip_address, user_agent, referer, accept_language, browser_fingerprint, geolocation_info, notes, client_port, port_detection_method, network_info, destination_port, destination_port_method)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (link_id, ip, user_agent, referer, accept_language, browser_fingerprint, geolocation_info, notes, client_port, port_detection_method, network_info, destination_port, destination_port_method))
        else:
            cursor.execute('''
                INSERT INTO clicks (link_id, ip_address, user_agent, referer, accept_language, browser_fingerprint, geolocation_info, notes, client_port, port_detection_method, network_info, destination_port, destination_port_method)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (link_id, ip, user_agent, referer, accept_language, browser_fingerprint, geolocation_info, notes, client_port, port_detection_method, network_info, destination_port, destination_port_method))
        conn.commit()
        print(f"✅ DEBUG: Commit do click realizado com sucesso") # Novo log de diagnóstico
        conn.close()
        print(f"✅ DEBUG: Click salvo e conexão fechada com sucesso") # Novo log de diagnóstico
    except Exception as e:
        print(f"❌ ERRO CRÍTICO ao salvar click: {e}")
        conn.rollback()
        conn.close()
        raise e

def get_all_clicks_for_user(user_id, ip_filter=None, start_date=None, end_date=None, link_id_filter=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if db_type == 'sqlite':
        query = '''
            SELECT
                c.id, c.ip_address, c.user_agent, c.referer, c.accept_language,
                c.timestamp, c.link_id, c.browser_fingerprint, c.geolocation_info, c.notes,
                c.client_port, c.port_detection_method, c.network_info,
                c.destination_port, c.destination_port_method, gl.original_url
            FROM clicks c
            JOIN generated_links gl ON c.link_id = gl.link_id
            WHERE gl.user_id = ?
        '''
        params = [user_id]
        if ip_filter:
            query += ' AND c.ip_address LIKE ?'
            params.append(f'%{ip_filter}%')
        if link_id_filter:
            query += ' AND c.link_id LIKE ?'
            params.append(f'%{link_id_filter}%')
        if start_date:
            query += ' AND c.timestamp >= ?'
            params.append(start_date)
        if end_date:
            query += ' AND c.timestamp <= ?'
            params.append(end_date)
    else: # PostgreSQL
        query = '''
            SELECT
                c.id, c.ip_address, c.user_agent, c.referer, c.accept_language,
                c.timestamp, c.link_id, c.browser_fingerprint, c.geolocation_info, c.notes,
                c.client_port, c.port_detection_method, c.network_info,
                c.destination_port, c.destination_port_method, gl.original_url
            FROM clicks c
            JOIN generated_links gl ON c.link_id = gl.link_id
            WHERE gl.user_id = %s
        '''
        params = [user_id]
        if ip_filter:
            query += ' AND c.ip_address ILIKE %s'
            params.append(f'%{ip_filter}%')
        if link_id_filter:
            query += ' AND c.link_id ILIKE %s'
            params.append(f'%{link_id_filter}%')
        if start_date:
            query += ' AND c.timestamp >= %s'
            params.append(start_date)
        if end_date:
            query += ' AND c.timestamp <= %s'
            params.append(end_date)
    query += ' ORDER BY c.timestamp DESC'
    cursor.execute(query, params)
    clicks = cursor.fetchall()
    conn.close()
    return clicks

def get_all_users():
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        query = "SELECT id, username, is_admin, created_at, last_login FROM users ORDER BY created_at DESC"
        cursor.execute(query)
        users_raw = cursor.fetchall()
        users = [dict(u) for u in users_raw]
        conn.close()
        return users
    except Exception as e:
        print(f"❌ DEBUG: Erro em get_all_users: {e}")
        conn.close()
        return []

def reset_user_password(user_id, new_password_hash):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        if db_type == 'sqlite':
            cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_password_hash, user_id))
        else:
            cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s", (new_password_hash, user_id))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"❌ DEBUG: Erro ao resetar senha: {e}")
        conn.rollback()
        conn.close()

def get_all_links_audit():
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        query = '''
            SELECT gl.link_id, gl.original_url, gl.created_at, u.username,
                    COUNT(c.id) AS click_count
            FROM generated_links gl
            JOIN users u ON gl.user_id = u.id
            LEFT JOIN clicks c ON gl.link_id = c.link_id
            GROUP BY gl.link_id, gl.original_url, gl.created_at, u.username
            ORDER BY gl.created_at DESC
        '''
        cursor.execute(query)
        links_raw = cursor.fetchall()
        links = [dict(l) for l in links_raw]
        conn.close()
        return links
    except Exception as e:
        print(f"❌ DEBUG: Erro em get_all_links_audit: {e}")
        conn.close()
        return []

def update_last_login(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        if db_type == 'sqlite':
            cursor.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user_id,))
        else:
            cursor.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s", (user_id,))
        conn.commit()
        conn.close()
        print(f"✅ DEBUG: Last login atualizado para usuário ID: {user_id}")
    except Exception as e:
        print(f"❌ DEBUG: Erro ao atualizar last login: {e}")
        conn.rollback()
        conn.close()

if __name__ == '__main__':
    init_db()
