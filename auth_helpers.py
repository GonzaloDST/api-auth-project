# auth_helpers.py
import jwt
import os
import json
from datetime import datetime

def verify_jwt_token(token):
    """
    Verifica si un token JWT es válido
    """
    try:
        JWT_SECRET = os.environ.get('JWT_SECRET', 'tu-clave-secreta-muy-segura-aqui')
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload
        
    except jwt.ExpiredSignatureError:
        print("Token JWT expirado")
        return None
    except jwt.InvalidTokenError as e:
        print(f"Token JWT inválido: {str(e)}")
        return None
    except Exception as e:
        print(f"Error verificando token JWT: {str(e)}")
        return None

def extract_token_from_cookies(cookie_header):
    """
    Extrae el token de las cookies del header
    """
    if not cookie_header:
        return None
        
    cookies = cookie_header.split(';')
    for cookie in cookies:
        cookie = cookie.strip()
        if cookie.startswith('auth_token='):
            return cookie.split('=')[1]
    return None

def require_auth(event):
    """
    Función helper que verifica autenticación y retorna payload o error
    """
    cookies = event.get('headers', {}).get('Cookie', '') or event.get('headers', {}).get('cookie', '')
    token = extract_token_from_cookies(cookies)
    
    if not token:
        return None, {'statusCode': 401, 'body': json.dumps({'error': 'No autenticado'})}
    
    payload = verify_jwt_token(token)
    if not payload:
        return None, {'statusCode': 401, 'body': json.dumps({'error': 'Token inválido o expirado'})}
    
    return payload, None

def require_staff_auth(event, required_permission=None):
    """
    Función helper que verifica autenticación Y que sea staff
    """
    payload, error = require_auth(event)
    if error:
        return None, error
    
    if payload.get('user_type') != 'staff':
        return None, {
            'statusCode': 403, 
            'body': json.dumps({'error': 'Acceso denegado. Solo para staff.'})
        }
    
    if required_permission and required_permission not in payload.get('permissions', []):
        return None, {
            'statusCode': 403,
            'body': json.dumps({'error': 'Permisos insuficientes'})
        }
    
    return payload, None