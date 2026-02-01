"""
Globalled SST - Plataforma de Saúde e Segurança no Trabalho
Backend API Flask
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import psycopg2
import psycopg2.extras
from datetime import datetime, timedelta
import os

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'change-in-production')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=8)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

CORS(app)
jwt = JWTManager(app)

DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'database': os.getenv('DB_NAME', 'globalled_sst'),
    'user': os.getenv('DB_USER', 'postgres'),
    'password': os.getenv('DB_PASSWORD', 'postgres'),
    'port': os.getenv('DB_PORT', '5432')
}

def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)

# AUTENTICAÇÃO
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM usuarios WHERE email = %s AND ativo = TRUE", (data.get('email'),))
    usuario = cur.fetchone()
    cur.close()
    conn.close()
    
    if usuario and check_password_hash(usuario['senha_hash'], data.get('senha')):
        access_token = create_access_token(identity=usuario['id'])
        return jsonify({'success': True, 'token': access_token, 'usuario': usuario})
    return jsonify({'success': False, 'message': 'Credenciais inválidas'}), 401

@app.route('/api/auth/me', methods=['GET'])
@jwt_required()
def get_current_user():
    user_id = get_jwt_identity()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT id, nome, email, perfil FROM usuarios WHERE id = %s", (user_id,))
    usuario = cur.fetchone()
    cur.close()
    conn.close()
    return jsonify({'success': True, 'usuario': usuario})

# EMPRESAS
@app.route('/api/empresas', methods=['GET'])
@jwt_required()
def listar_empresas():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM empresas WHERE ativo = TRUE ORDER BY razao_social")
    empresas = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify({'success': True, 'data': empresas})

@app.route('/api/empresas', methods=['POST'])
@jwt_required()
def criar_empresa():
    data = request.get_json()
    user_id = get_jwt_identity()
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO empresas (razao_social, nome_fantasia, cnpj, cidade, estado, usuario_id)
            VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
        """, (data['razao_social'], data.get('nome_fantasia'), data['cnpj'], 
              data.get('cidade'), data.get('estado'), user_id))
        empresa_id = cur.fetchone()[0]
        conn.commit()
        return jsonify({'success': True, 'id': empresa_id})
    except psycopg2.IntegrityError:
        conn.rollback()
        return jsonify({'success': False, 'message': 'CNPJ já cadastrado'}), 400
    finally:
        cur.close()
        conn.close()

# FUNCIONÁRIOS
@app.route('/api/funcionarios', methods=['GET'])
@jwt_required()
def listar_funcionarios():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT f.*, e.razao_social as nome_empresa 
        FROM funcionarios f
        JOIN empresas e ON f.empresa_id = e.id
        WHERE f.ativo = TRUE ORDER BY f.nome
    """)
    funcionarios = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify({'success': True, 'data': funcionarios})

@app.route('/api/funcionarios', methods=['POST'])
@jwt_required()
def criar_funcionario():
    data = request.get_json()
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO funcionarios (empresa_id, nome, cpf, matricula, funcao, dt_adm)
            VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
        """, (data['empresa_id'], data['nome'], data['cpf'], 
              data['matricula'], data.get('funcao'), data.get('dt_adm')))
        funcionario_id = cur.fetchone()[0]
        conn.commit()
        return jsonify({'success': True, 'id': funcionario_id})
    except psycopg2.IntegrityError:
        conn.rollback()
        return jsonify({'success': False, 'message': 'CPF ou matrícula já existe'}), 400
    finally:
        cur.close()
        conn.close()

# EXAMES
@app.route('/api/exames', methods=['POST'])
@jwt_required()
def criar_exame():
    data = request.get_json()
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO exames (funcionario_id, tipo_exame, dt_exame, nm_med, ind_result)
        VALUES (%s, %s, %s, %s, %s) RETURNING id
    """, (data['funcionario_id'], data['tipo_exame'], data['dt_exame'],
          data.get('nm_med'), data.get('ind_result')))
    exame_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'success': True, 'id': exame_id})

@app.route('/api/exames/pendentes', methods=['GET'])
@jwt_required()
def exames_pendentes():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT e.*, f.nome as nome_funcionario, f.cpf, f.matricula
        FROM exames e
        JOIN funcionarios f ON e.funcionario_id = f.id
        WHERE e.enviado_esocial = FALSE
        ORDER BY e.dt_exame DESC
    """)
    exames = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify({'success': True, 'data': exames})

# ACIDENTES
@app.route('/api/acidentes', methods=['POST'])
@jwt_required()
def criar_acidente():
    data = request.get_json()
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO acidentes (funcionario_id, dt_acid, tp_acid, dsc_acidente)
        VALUES (%s, %s, %s, %s) RETURNING id
    """, (data['funcionario_id'], data['dt_acid'], data['tp_acid'], data['dsc_acidente']))
    acidente_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'success': True, 'id': acidente_id})

# DASHBOARD
@app.route('/api/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    cur.execute("SELECT COUNT(*) as total FROM empresas WHERE ativo = TRUE")
    total_empresas = cur.fetchone()['total']
    
    cur.execute("SELECT COUNT(*) as total FROM funcionarios WHERE ativo = TRUE")
    total_funcionarios = cur.fetchone()['total']
    
    cur.execute("SELECT COUNT(*) as total FROM exames WHERE enviado_esocial = FALSE")
    exames_pendentes = cur.fetchone()['total']
    
    cur.execute("SELECT COUNT(*) as total FROM acidentes WHERE enviado_esocial = FALSE")
    acidentes_pendentes = cur.fetchone()['total']
    
    cur.close()
    conn.close()
    
    return jsonify({
        'success': True,
        'data': {
            'total_empresas': total_empresas,
            'total_funcionarios': total_funcionarios,
            'exames_pendentes': exames_pendentes,
            'acidentes_pendentes': acidentes_pendentes
        }
    })

# SERVIR FRONTEND
@app.route('/')
def serve_index():
    return send_from_directory('../frontend', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('../frontend', path)

if __name__ == '__main__':
    print("🚀 Globalled SST API iniciada!")
    print("📡 http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
