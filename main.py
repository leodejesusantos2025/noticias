from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from urllib.parse import urlparse, urljoin
import secrets
import string
import requests
import json
from datetime import datetime
import os
import io
import logging
from bs4 import BeautifulSoup
from reportlab.lib.pagesizes import letter, A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from user_agents import parse
import re

from database import (
    init_db, User, add_user, add_generated_link, get_original_url_from_generated_link,
    add_click, get_all_clicks_for_user, get_generated_link_details, get_user_push_token,
    update_user_push_token, get_all_users, reset_user_password, get_all_links_audit, update_last_login,
    db_type
)
from config import get_config

app = Flask(__name__)
app.config.from_object(get_config())
app.secret_key = app.config['SECRET_KEY']

logging.basicConfig(
    level=getattr(logging, app.config['LOG_LEVEL'].upper(), logging.INFO),
    format='%(asctime)s %(levelname)s %(name)s %(message)s'
)
logger = logging.getLogger(__name__)

print("🚀 INICIANDO APLICAÇÃO FLASK...")

try:
    print("🔧 Executando init_db()...")
    init_db()
    print("✅ Banco de dados inicializado com sucesso!")
except Exception as e:
    print(f"❌ Erro ao inicializar banco de dados: {e}")
    raise e

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


def is_safe_redirect_target(target):
    if not target:
        return False
    host_url = urlparse(request.host_url)
    redirect_url = urlparse(urljoin(request.host_url, target))
    return redirect_url.scheme in ('http', 'https') and host_url.netloc == redirect_url.netloc

@login_manager.user_loader
def load_user(user_id):
    print(f"🔍 DEBUG: load_user chamado para ID: {user_id}")
    user = User.get(int(user_id))
    if user:
        print(f"🔍 DEBUG: load_user encontrou usuário: {user.username}, is_admin: {user.is_admin}")
    else:
        print(f"❌ DEBUG: load_user não encontrou usuário para ID: {user_id}")
    return user

def get_client_ip():
    ip_headers = [
        'CF-Connecting-IP',
        'X-Forwarded-For',
        'X-Real-IP',
        'X-Client-IP',
        'True-Client-IP',
        'X-Cluster-Client-IP'
    ]
    for header in ip_headers:
        ip = request.headers.get(header)
        if ip:
            if ',' in ip:
                ip = ip.split(',')[0].strip()
            if ip and ip != 'unknown':
                print(f"DEBUG: IP capturado via {header}: {ip}")
                return ip
    remote_ip = request.remote_addr
    print(f"DEBUG: IP fallback (remote_addr): {remote_ip}")
    return remote_ip

def get_client_port():
    port_headers = [
        'X-Forwarded-Port',
        'X-Real-Port',
        'X-Client-Port',
        'CF-Connecting-Port'
    ]
    for header in port_headers:
        port = request.headers.get(header)
        if port:
            print(f"DEBUG: Porta capturada via {header}: {port}")
            return port, f"header_{header.lower().replace('-', '_')}"
    host = request.headers.get('Host', '')
    if ':' in host:
        port = host.split(':')[1]
        print(f"DEBUG: Porta capturada via Host: {port}")
        return port, "host_header"
    if request.is_secure:
        print("DEBUG: Porta padrão HTTPS: 443")
        return '443', 'default_https'
    else:
        print("DEBUG: Porta padrão HTTP: 80")
        return '80', 'default_http'

def parse_user_agent_robust(user_agent_string):
    try:
        parsed = parse(user_agent_string)
        os_name = parsed.os.family if parsed.os.family else "Unknown"
        browser_name = f"{parsed.browser.family} {parsed.browser.version_string}" if parsed.browser.family else "Unknown"
        device_type = "Mobile" if parsed.is_mobile else ("Tablet" if parsed.is_tablet else ("PC" if parsed.is_pc else "Outro Dispositivo"))
        return {
            'os': os_name,
            'browser': browser_name,
            'device': device_type,
            'method': 'user_agents_lib'
        }
    except Exception as e:
        print(f"Erro no parsing com user-agents lib: {e}")
        try:
            ua_lower = user_agent_string.lower()
            if 'windows' in ua_lower:
                os_name = "Windows"
            elif 'mac' in ua_lower or 'darwin' in ua_lower:
                os_name = "macOS"
            elif 'linux' in ua_lower:
                os_name = "Linux"
            elif 'android' in ua_lower:
                os_name = "Android"
            elif 'ios' in ua_lower or 'iphone' in ua_lower or 'ipad' in ua_lower:
                os_name = "iOS"
            else:
                os_name = "Unknown"
            if 'chrome' in ua_lower and 'edg' not in ua_lower:
                browser_name = "Chrome"
            elif 'firefox' in ua_lower:
                browser_name = "Firefox"
            elif 'safari' in ua_lower and 'chrome' not in ua_lower:
                browser_name = "Safari"
            elif 'edg' in ua_lower:
                browser_name = "Edge"
            elif 'opera' in ua_lower:
                browser_name = "Opera"
            else:
                browser_name = "Other"
            if 'mobile' in ua_lower or 'android' in ua_lower:
                device_type = "Mobile"
            elif 'tablet' in ua_lower or 'ipad' in ua_lower:
                device_type = "Tablet"
            else:
                device_type = "Desktop PC"
            return {
                'os': os_name,
                'browser': browser_name,
                'device': device_type,
                'method': 'manual_parsing'
            }
        except Exception as e2:
            print(f"Erro no parsing manual: {e2}")
            return {
                'os': "Unknown",
                'browser': "Unknown",
                'device': "Unknown",
                'method': 'fallback'
            }

def is_bot_request(user_agent):
    bot_patterns = [
        r'bot', r'crawler', r'spider', r'scraper', r'curl', r'wget', r'python',
        r'java', r'go-http', r'okhttp', r'apache-httpclient', r'facebookexternalhit',
        r'twitterbot', r'linkedinbot', r'whatsapp', r'telegram', r'slack'
    ]
    user_agent_lower = user_agent.lower()
    for pattern in bot_patterns:
        if re.search(pattern, user_agent_lower):
            return True
    return False

def get_geolocation_info(ip):
    if ip.startswith(('192.168.', '10.', '127.')) or ':' in ip:
        print(f"DEBUG: IP {ip} é local/privado ou IPv6. Pulando geolocalização.")
        return "IP Local/Privado"
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"DEBUG Geolocalização bruta para {ip}: {data}")
            if data.get('status') == 'success':
                city = data.get('city', 'N/A')
                region = data.get('regionName', 'N/A')
                country = data.get('country', 'N/A')
                isp = data.get('isp', 'N/A')
                result_str = f"{city}, {region}, {country} - ISP: {isp}"
                print(f"DEBUG: get_geolocation_info retornou: {result_str}")
                return result_str
            else:
                error_msg = f"Falha na geolocalização: {data.get('message', 'Erro desconhecido da API')}"
                print(f"DEBUG: get_geolocation_info ERRO: {error_msg}")
                return error_msg
        else:
            error_msg = f"Erro HTTP {response.status_code} ao obter geolocalização"
            print(f"DEBUG: get_geolocation_info ERRO HTTP: {error_msg}")
            return error_msg
    except requests.exceptions.RequestException as e:
        error_msg = f"Erro de rede na geolocalização: {str(e)}"
        print(f"DEBUG: get_geolocation_info ERRO DE REDE: {error_msg}")
        return error_msg
    except Exception as e:
        error_msg = f"Erro inesperado na geolocalização: {str(e)}"
        print(f"DEBUG: get_geolocation_info ERRO INESPERADO: {error_msg}")
        return error_msg

@app.route('/')
def index():
    print(f"🔍 DEBUG: Rota / acessada. Usuário autenticado: {current_user.is_authenticated}")
    if current_user.is_authenticated:
        print(f"🔍 DEBUG: Usuário atual: {current_user.username}, is_admin: {getattr(current_user, 'is_admin', 'N/A')}")
        return redirect(url_for('home'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    print(f"🔍 DEBUG: Rota /login acessada. Método: {request.method}")
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        print(f"🔍 DEBUG: Tentativa de login - Username: {username}")
        
        user = User.get_by_username(username)
        
        if user:
            print(f"🔍 DEBUG: Usuário encontrado - ID: {user.id}, Username: {user.username}, is_admin: {user.is_admin}")
            if check_password_hash(user.password_hash, password):
                login_user(user)
                update_last_login(user.id)
                print(f"✅ DEBUG: Login bem-sucedido para {username}")
                flash('Login realizado com sucesso!', 'success')
                
                if hasattr(user, 'is_admin') and user.is_admin:
                    print(f"🔍 DEBUG: Usuário é admin, redirecionando para painel administrativo")
                    return redirect(url_for('admin_panel'))
                
                next_page = request.args.get('next')
                if next_page and not is_safe_redirect_target(next_page):
                    logger.warning("Tentativa de redirecionamento externo bloqueada: %s", next_page)
                    next_page = None
                if next_page:
                    print(f"🔍 DEBUG: Redirecionando para página solicitada: {next_page}")
                    return redirect(next_page)
                else:
                    print(f"🔍 DEBUG: Redirecionando para home (padrão)")
                    return redirect(url_for('home'))
            else:
                print(f"❌ DEBUG: Senha incorreta para {username}")
                flash('Nome de usuário ou senha incorretos.', 'error')
        else:
            print(f"❌ DEBUG: Usuário {username} não encontrado")
            flash('Nome de usuário ou senha incorretos.', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    print(f"🔍 DEBUG: Rota /register acessada. Método: {request.method}")
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        print(f"🔍 DEBUG: Tentativa de registro - Username: {username}")
        
        if User.get_by_username(username):
            print(f"❌ DEBUG: Usuário {username} já existe")
            flash('Nome de usuário já existe.', 'error')
            return render_template('register.html')
        
        password_hash = generate_password_hash(password)
        user_id = add_user(username, password_hash)
        
        if user_id:
            print(f"✅ DEBUG: Usuário {username} criado com sucesso - ID: {user_id}")
            flash('Usuário criado com sucesso! Faça login.', 'success')
            return redirect(url_for('login'))
        else:
            print(f"❌ DEBUG: Erro ao criar usuário {username}")
            flash('Erro ao criar usuário.', 'error')
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    print(f"🔍 DEBUG: Logout do usuário: {current_user.username}")
    logout_user()
    flash('Logout realizado com sucesso!', 'success')
    return redirect(url_for('login'))

@app.route('/home', methods=['GET', 'POST'])
@login_required
def home():
    print(f"🔍 DEBUG: Rota /home acessada por {current_user.username}. Método: {request.method}")
    if request.method == 'POST':
        original_url = request.form['original_url']
        
        print(f"🔍 DEBUG: Gerando link para URL: {original_url}")
        
        link_id = ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(6))
        
        print(f"🔍 DEBUG: Link ID gerado: {link_id}")
        
        try:
            add_generated_link(link_id, original_url, current_user.id)
            print(f"✅ DEBUG: Link salvo no banco com sucesso")
        except Exception as e:
            print(f"❌ DEBUG: Erro ao salvar link no banco: {e}")
            flash('Erro ao gerar link. Tente novamente.', 'error')
            return render_template('index.html')
        
        base_url = request.host_url.rstrip('/')
        camouflaged_link = f"{base_url}/{link_id}"
        
        print(f"🔍 DEBUG: Link camuflado gerado: {camouflaged_link}")
        
        return render_template('index.html', camouflaged_link=camouflaged_link)
    
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    print(f"🔍 DEBUG: Dashboard acessado por {current_user.username}")
    ip_filter = request.args.get('ip_filter', '')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    link_id_filter = request.args.get('link_id_filter', '')
    
    start_date_obj = datetime.strptime(start_date, '%Y-%m-%d') if start_date else None
    end_date_obj = datetime.strptime(end_date, '%Y-%m-%d') if end_date else None
    
    clicks = get_all_clicks_for_user(
        current_user.id,
        ip_filter=ip_filter if ip_filter else None,
        start_date=start_date_obj,
        end_date=end_date_obj,
        link_id_filter=link_id_filter if link_id_filter else None
    )
    
    print(f"🔍 DEBUG: Dashboard retornou {len(clicks)} cliques")
    
    return render_template('dashboard.html', clicks=clicks,
                         ip_filter=ip_filter, start_date=start_date,
                         end_date=end_date, link_id_filter=link_id_filter)

def json_serial(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError ("Type %s not serializable" % type(obj))

@app.route('/admin')
@login_required
def admin_panel():
    print("--- INICIANDO ROTA /admin ---")
    if not hasattr(current_user, 'is_admin') or not current_user.is_admin:
        flash('Acesso negado. Apenas administradores podem acessar esta página.', 'error')
        return redirect(url_for('home'))
    
    try:
        print("Executando consultas...")
        all_users = get_all_users()
        print(f"Consulta de usuários retornou {len(all_users)} registros.")
        
        all_links_audit = get_all_links_audit()
        print(f"Consulta de links retornou {len(all_links_audit)} registros.")
        
        users_json = json.dumps(all_users, default=json_serial)
        links_json = json.dumps(all_links_audit, default=json_serial)
        
        print("Dados convertidos para JSON. Renderizando template...")
        return render_template('admin.html',
                               users_json=users_json,
                               links_json=links_json)

    except Exception as e:
        app.logger.error(f"❌ ERRO CRÍTICO na rota /admin: {e}", exc_info=True)
        error_message = "Ocorreu um erro inesperado ao executar as consultas do painel. Verifique os logs."
        return render_template('admin.html', error_message=error_message)

@app.route('/admin/reset_password/<int:user_id>', methods=['POST'])
@login_required
def admin_reset_password(user_id):
    print(f"🔍 DEBUG: Reset de senha solicitado para user_id {user_id} por {current_user.username}")
    
    if not hasattr(current_user, 'is_admin') or not current_user.is_admin:
        print(f"❌ DEBUG: Acesso negado para reset de senha")
        flash('Acesso negado.', 'error')
        return redirect(url_for('home'))
    
    new_password = request.form['new_password']
    password_hash = generate_password_hash(new_password)
    
    try:
        reset_user_password(user_id, password_hash)
        print(f"✅ DEBUG: Senha resetada com sucesso para user_id {user_id}")
        flash('Senha resetada com sucesso!', 'success')
    except Exception as e:
        print(f"❌ DEBUG: Erro ao resetar senha: {e}")
        flash('Erro ao resetar senha.', 'error')
    
    return redirect(url_for('admin_panel'))

@app.route('/admin/create_user', methods=['POST'])
@login_required
def admin_create_user():
    print(f"🔍 DEBUG: Criação de usuário solicitada por {current_user.username}")
    
    if not hasattr(current_user, 'is_admin') or not current_user.is_admin:
        print(f"❌ DEBUG: Acesso negado para criação de usuário")
        flash('Acesso negado.', 'error')
        return redirect(url_for('home'))
    
    username = request.form['username']
    password = request.form['password']
    is_admin = 'is_admin' in request.form
    
    print(f"🔍 DEBUG: Criando usuário - Username: {username}, is_admin: {is_admin}")
    
    if User.get_by_username(username):
        print(f"❌ DEBUG: Usuário {username} já existe")
        flash('Nome de usuário já existe.', 'error')
        return redirect(url_for('admin_panel'))
    
    password_hash = generate_password_hash(password)
    user_id = add_user(username, password_hash, is_admin)
    
    if user_id:
        print(f"✅ DEBUG: Usuário {username} criado com sucesso - ID: {user_id}")
        flash('Usuário criado com sucesso!', 'success')
    else:
        print(f"❌ DEBUG: Erro ao criar usuário {username}")
        flash('Erro ao criar usuário.', 'error')
    
    return redirect(url_for('admin_panel'))

@app.route('/generate_report/<link_id>')
@login_required
def generate_report(link_id):
    print(f"🔍 DEBUG: Relatório solicitado para link {link_id} por {current_user.username}")

    link_details = get_generated_link_details(link_id)
    if not link_details:
        print(f"❌ DEBUG: Link {link_id} não encontrado")
        flash('Link não encontrado.', 'error')
        return redirect(url_for('dashboard'))

    is_admin = hasattr(current_user, 'is_admin') and current_user.is_admin
    
    print(f"🔍 DEBUG: is_admin = {is_admin}, link owner = {link_details['user_id']}, current_user.id = {current_user.id}")
    
    if link_details['user_id'] != current_user.id and not is_admin:
        print(f"❌ DEBUG: Acesso negado ao link {link_id}")
        flash('Acesso negado a este link.', 'error')
        return redirect(url_for('dashboard'))
    
    if is_admin:
        clicks = get_all_clicks_for_user(link_details['user_id'], link_id_filter=link_id)
    else:
        clicks = get_all_clicks_for_user(current_user.id, link_id_filter=link_id)
    
    print(f"🔍 DEBUG: Relatório para link {link_id} com {len(clicks)} cliques")
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(A4), rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
    
    styles = getSampleStyleSheet()
    normal_paragraph_style = ParagraphStyle(
        'NormalPara',
        parent=styles['Normal'],
        fontSize=7,
        leading=8,
        wordWrap='CJK',
    )
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=18,
        spaceAfter=30,
        alignment=TA_CENTER
    )
    
    story = []
    
    story.append(Paragraph("Relatório de Investigação de Link", title_style))
    story.append(Spacer(1, 12))
    
    story.append(Paragraph(f"<b>URL Original da Isca:</b> {link_details['original_url']}", styles['Normal']))
    story.append(Paragraph(f"<b>Link Camuflado Gerado:</b> {request.host_url.rstrip('/')}/{link_id}", styles['Normal']))
    
    user = User.get(link_details['user_id'])
    story.append(Paragraph(f"<b>Gerado por:</b> {user.username if user else 'Usuário desconhecido'}", styles['Normal']))
    story.append(Spacer(1, 20))
    
    story.append(Paragraph("<b>Detalhes dos Cliques:</b>", styles['Heading2']))
    story.append(Spacer(1, 12))
    
    if clicks:
        has_port_info = any(click.get('client_port') for click in clicks)
        
        if has_port_info:
            data = [['Data/Hora', 'IP', 'Porta', 'Localização', 'Navegador/OS/Disp.', 'Fingerprint', 'Notas']]
        else:
            data = [['Data/Hora', 'IP', 'Localização', 'Navegador/OS/Disp.', 'Fingerprint', 'Notas']]
        
        for click in clicks:
            ua_info = parse_user_agent_robust(click.get('user_agent', '') or "")
            ua_text = f"OS: {ua_info['os']} | Navegador: {ua_info['browser']} | Dispositivo: {ua_info['device']}"
            
            timestamp_obj = click.get('timestamp')
            if isinstance(timestamp_obj, datetime):
                timestamp = timestamp_obj.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            else:
                timestamp = 'N/A'
            
            geo_info = click.get('geolocation_info', 'N/A')
            
            port_val = click.get('client_port', 'N/A')
            port_method_val = click.get('port_detection_method', '')
            port_info = f"Porta: {port_val}"
            if port_method_val and port_method_val != 'N/A':
                port_info += f" (via {port_method_val})"
            
            row_data = [
                Paragraph(timestamp, normal_paragraph_style),
                Paragraph(click.get('ip_address', 'N/A'), normal_paragraph_style),
                Paragraph(geo_info, normal_paragraph_style),
                Paragraph(ua_text, normal_paragraph_style),
                Paragraph(click.get('browser_fingerprint', 'N/A'), normal_paragraph_style),
                Paragraph(click.get('notes', ''), normal_paragraph_style)
            ]

            if has_port_info:
                row_data.insert(2, Paragraph(port_info, normal_paragraph_style))
            
            data.append(row_data)
        
        if has_port_info:
            col_widths = [1.2*inch, 0.9*inch, 0.9*inch, 1.9*inch, 1.9*inch, 1.4*inch, 1.0*inch]
        else:
            col_widths = [1.2*inch, 0.9*inch, 2.4*inch, 2.4*inch, 1.4*inch, 1.0*inch]
            
        table = Table(data, colWidths=col_widths)
            
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 8),
            ('FONTSIZE', (0, 1), (-1, -1), 7),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f0f0f0')),
            ('BACKGROUND', (0, 2), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0,0), (-1,-1), 2),
            ('RIGHTPADDING', (0,0), (-1,-1), 2),
        ]))
        
        story.append(table)
    else:
        story.append(Paragraph("Nenhum clique registrado para este link.", styles['Normal']))
    
    doc.build(story)
    buffer.seek(0)
    
    print(f"✅ DEBUG: Relatório PDF gerado com sucesso para link {link_id}")
    
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f'relatorio_link_{link_id}.pdf',
        mimetype='application/pdf'
    )

@app.route('/<link_id>')
def collect_data_and_redirect(link_id):
    print(f"🔍 DEBUG: Link {link_id} acessado")
    
    original_url = get_original_url_from_generated_link(link_id)
    if not original_url:
        print(f"❌ DEBUG: Link {link_id} não encontrado")
        return "Link não encontrado", 404
    
    print(f"🔍 DEBUG: Link {link_id} redirecionará para {original_url}")
    
    user_agent = request.headers.get('User-Agent', '')
    referer = request.headers.get('Referer', '')
    accept_language = request.headers.get('Accept-Language', '')

    print(f"🔍 DEBUG: Todos os cabeçalhos recebidos para {link_id}: {request.headers}")
    
    client_ip = get_client_ip()
    
    client_port, port_method = get_client_port()
    
    is_bot = is_bot_request(user_agent)
    
    print(f"Requisição para link {link_id} | User-Agent: {user_agent} | É bot? {is_bot}")
    print(f"IP capturado: {client_ip} (remote_addr: {request.remote_addr})")
    print(f"Porta capturada: {client_port} via {port_method}")
    
    ua_parsed = parse_user_agent_robust(user_agent)
    print(f"User-Agent Parseado (Robusto) para {user_agent}: OS: {ua_parsed['os']} | Navegador: {ua_parsed['browser']} | Dispositivo: {ua_parsed['device']}")
    
    geolocation_info = get_geolocation_info(client_ip)
    
    link_details = get_generated_link_details(link_id)
    owner_user_id = link_details['user_id'] if link_details else None
    
    expo_token = get_user_push_token(owner_user_id) if owner_user_id else None
    
    if not is_bot:
        print(f"🔍 DEBUG: Renderizando página de coleta para link {link_id}")
        return render_template('collect.html', 
                             original_url=original_url, 
                             link_id=link_id,
                             client_ip=client_ip,
                             client_port=client_port,
                             port_method=port_method,
                             geolocation_info=geolocation_info,
                             user_agent=user_agent,
                             referer=referer,
                             accept_language=accept_language,
                             expo_token=expo_token)
    else:
        print(f"🔍 DEBUG: Bot detectado, redirecionando diretamente para {original_url}")
        return redirect(url_for('preview_bot', original_url=original_url))

@app.route('/preview_bot')
def preview_bot():
    original_url = request.args.get('original_url')
    # Use requests para obter as meta tags Open Graph da URL original
    og_title = "Conteúdo de Notícia"
    og_description = "Clique para ver o conteúdo completo da notícia."
    og_image = "" # URL da imagem padrão
    try:
        response = requests.get(original_url, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            og_title_tag = soup.find('meta', property='og:title')
            if og_title_tag and og_title_tag.get('content'):
                og_title = og_title_tag['content']
            og_description_tag = soup.find('meta', property='og:description')
            if og_description_tag and og_description_tag.get('content'):
                og_description = og_description_tag['content']
            og_image_tag = soup.find('meta', property='og:image')
            if og_image_tag and og_image_tag.get('content'):
                og_image = og_image_tag['content']
    except Exception as e:
        print(f"❌ Erro ao obter meta tags para {original_url}: {e}")

    return render_template('preview_bot.html',
                           og_title=og_title,
                           og_description=og_description,
                           og_image=og_image,
                           og_url=original_url)

@app.route('/submit_fingerprint', methods=['POST'])
def submit_fingerprint():
    data = request.get_json(silent=True) or {}
    link_id = data.get('link_id')
    fingerprint = data.get('fingerprint')
    client_ip = data.get('client_ip')
    client_port = data.get('client_port')
    port_method = data.get('port_method')
    network_info = data.get('network_info', '')
    geolocation_info = data.get('geolocation_info')
    user_agent = data.get('user_agent')
    referer = data.get('referer')
    accept_language = data.get('accept_language')
    original_url = data.get('original_url')
    expo_token = data.get('expo_token')
    
    print(f"🔍 DEBUG: Fingerprint recebido para link {link_id}")
    print(f"🔍 DEBUG: Fingerprint: {fingerprint}")
    print(f"🔍 DEBUG: IP: {client_ip}, Porta: {client_port} (método: {port_method})")
    
    fp_method = "Unknown"
    if fingerprint:
        if fingerprint.startswith('fpjs_'):
            fp_method = "FingerprintJS Enhanced"
        elif fingerprint.startswith('basic_'):
            fp_method = "Basic Fallback"
        elif fingerprint.startswith('emergency_'):
            fp_method = "Emergency Fallback"
    
    notes = f"Fingerprint capturado via: {fp_method}"
    if user_agent:
        ua_parsed = parse_user_agent_robust(user_agent)
        notes += f" | UA: {user_agent[:50]}..."
    
    print(f"DEBUG: Recebido fingerprint: {fingerprint}")
    print(f"DEBUG: IP: {client_ip}, Porta: {client_port} (método: {port_method})")
    print(f"DEBUG: Geolocalização: {geolocation_info}")
    print(f"DEBUG: Network Info: {network_info}")
    
    try:
        add_click(
            link_id=link_id,
            ip=client_ip,
            user_agent=user_agent,
            referer=referer,
            accept_language=accept_language,
            browser_fingerprint=fingerprint,
            geolocation_info=geolocation_info,
            notes=notes,
            client_port=client_port,
            port_detection_method=port_method,
            network_info=network_info
        )
        print(f"✅ DEBUG: Click salvo com sucesso no banco")
    except Exception as e:
        print(f"❌ DEBUG: Erro ao salvar click no banco: {e}")
        print(f"❌ DEBUG: Erro ao salvar click (sem fallback): {e}")
    
    if expo_token:
        try:
            push_data = {
                "to": expo_token,
                "title": "Novo Clique Detectado!",
                "body": f"IP: {client_ip} | Porta: {client_port} | Fingerprint: {fingerprint[:20]}...",
                "data": {
                    "link_id": link_id,
                    "ip": client_ip,
                    "port": client_port,
                    "fingerprint": fingerprint
                }
            }
            
            response = requests.post(
                'https://exp.host/--/api/v2/push/send',
                json=push_data,
                headers={'Content-Type': 'application/json'}
            )
            print(f"Push notification sent: {response.status_code}")
        except Exception as e:
            print(f"Erro ao enviar notificação push: {e}")
    
    return jsonify({
        'status': 'success',
        'redirect_url': original_url,
        'fingerprint_received': fingerprint,
        'port_info': f"{client_port} (via {port_method})"
    })
if __name__ == '__main__':
    print("🔧 Executando init_db() no __main__...")
    init_db()
    port = int(os.environ.get('PORT', 5000))
    print(f"🚀 Iniciando Flask na porta {port}")
    app.run(host='0.0.0.0', port=port, debug=app.config['DEBUG'])
