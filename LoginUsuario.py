import boto3
import hashlib
import json
import jwt
import os
from datetime import datetime, timedelta

# Hashear contraseña
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Generar token JWT
def generate_jwt_token(user_data):
    try:
        JWT_SECRET = os.environ.get('JWT_SECRET', 'utec')
        
        # Payload del token
        payload = {
            'user_id': user_data.get('user_id'),
            'email': user_data.get('email'),
            'user_type': user_data.get('user_type'),
            'staff_tier': user_data.get('staff_tier'),
            'permissions': user_data.get('permissions', []),
            'exp': datetime.utcnow() + timedelta(hours=24),
            'iat': datetime.utcnow(),
            'frontend_type': user_data.get('frontend_type', 'client')
        }
        
        # Generar token JWT
        token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
        
        return token, payload['exp']
        
    except Exception as e:
        print(f"Error generating JWT: {str(e)}")
        raise e

# Headers CORS para todas las respuestas
CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS, GET',
    'Access-Control-Allow-Headers': 'Content-Type, X-Amz-Date, Authorization, X-Api-Key, X-Amz-Security-Token, Accept',
    'Content-Type': 'application/json'
}

# Función para determinar redirección después del login
## Creo que no es necesario si se maneja desde el front
def get_redirect_path(user_type, staff_tier, frontend_type):
    if user_type == 'staff':
        if staff_tier == 'admin':
            return '/admin/dashboard'
        else:  # trabajador
            return '/trabajador/pedidos'
    else:  # cliente
        return '/dashboard'

# Función principal del Lambda de Login
def lambda_handler(event, context):
    try:
        print("Login event received:", json.dumps(event, indent=2))
        
        if 'body' in event:
            if isinstance(event['body'], str):
                body = json.loads(event['body'])
            else:
                body = event['body']
        else:
            body = event

        # ✅ Obtener datos del body correctamente
        email = body.get('email', '').lower().strip()
        password = body.get('password')
        frontend_type = body.get('frontend_type', 'client')
        tenant_id_sede = body.get('tenant_id_sede')

        # Validación 1: Campos obligatorios
        if not email or not password:
            return {
                'statusCode': 400,
                'headers': CORS_HEADERS,
                'body': json.dumps({
                    'error': 'Campos obligatorios faltantes: email y password son requeridos'
                })
            }

        dynamodb = boto3.resource('dynamodb')
        clientes_table_name = os.environ.get('USUARIOS_TABLE', 'dev-t_clientes')
        staff_table_name = os.environ.get('STAFF_TABLE', 'dev-t_staff')
        t_clientes = dynamodb.Table(clientes_table_name)
        t_staff = dynamodb.Table(staff_table_name)
        
        # Buscar usuario por email
        if frontend_type == 'client':
            try:
                response = t_clientes.get_item(Key={'email': email})
                if 'Item' not in response:
                    return {
                        'statusCode': 401,
                        'headers': CORS_HEADERS,
                        'body': json.dumps({
                            'error': 'Credenciales inválidas'
                        })
                    }
                
                user = response['Item']
                
            except Exception as e:
                print(f"Error fetching user: {str(e)}")
                return {
                    'statusCode': 500,
                    'headers': CORS_HEADERS,
                    'body': json.dumps({
                        'error': 'Error interno del servidor'
                    })
                }
        elif frontend_type == 'staff':
            try:
                response = t_staff.get_item(Key={
                            'tenant_id_sede': tenant_id_sede,
                            'email': email
                            })
                if 'Item' not in response:
                    return {
                        'statusCode': 401,
                        'headers': CORS_HEADERS,
                        'body': json.dumps({
                            'error': 'Credenciales inválidas'
                        })
                    }
                
                user = response['Item']
                
            except Exception as e:
                print(f"Error fetching user: {str(e)}")
                return {
                    'statusCode': 500,
                    'headers': CORS_HEADERS,
                    'body': json.dumps({
                        'error': 'Error interno del servidor'
                    })
                }
        
        # Verificar contraseña
        hashed_input = hash_password(password)
        if hashed_input != user.get('password'):
            return {
                'statusCode': 401,
                'headers': CORS_HEADERS,
                'body': json.dumps({
                    'error': 'Credenciales inválidas'
                })
            }
        
        # Verificar que el usuario esté activo
        if not user.get('is_active', True):
            return {
                'statusCode': 403,
                'headers': CORS_HEADERS,
                'body': json.dumps({
                    'error': 'Cuenta desactivada. Contacta al administrador.'
                })
            }
        
        user_type = user.get('user_type', 'cliente')
        staff_tier = user.get('staff_tier')
        
        # Validaciones de frontend
        if frontend_type == 'staff' and user_type != 'staff':
            return {
                'statusCode': 403,
                'headers': CORS_HEADERS,
                'body': json.dumps({
                    'error': 'Acceso denegado. El portal staff es solo para personal autorizado.'
                })
            }
        elif frontend_type == 'client' and user_type == 'staff':
            return {
                'statusCode': 403,
                'headers': CORS_HEADERS,
                'body': json.dumps({
                    'error': 'Acceso denegado. El personal debe usar el portal staff.'
                })
            }

        # Actualizar último login
        current_time = datetime.utcnow().isoformat()
        if frontend_type == 'client':
            try:
                t_clientes.update_item(
                    Key={'email': email},
                    UpdateExpression='SET last_login = :login_time, updated_at = :update_time',
                    ExpressionAttributeValues={
                        ':login_time': current_time,
                        ':update_time': current_time
                    }
                )
            except Exception as e:
                print(f"Error updating last login: {str(e)}")
        elif frontend_type == 'staff':
            try:
                t_staff.update_item(
                    Key={
                            'tenant_id_sede': tenant_id_sede,
                            'email': email
                        },
                    UpdateExpression='SET last_login = :login_time, updated_at = :update_time',
                    ExpressionAttributeValues={
                        ':login_time': current_time,
                        ':update_time': current_time
                    }
                )
            except Exception as e:
                print(f"Error updating last login: {str(e)}")
        
        # Generar token JWT
        user_token_data = {
            'user_id': user.get('user_id'),
            'email': user.get('email'),
            'user_type': user_type,
            'staff_tier': staff_tier,
            'permissions': user.get('permissions', []),
            'frontend_type': frontend_type
        }
        
        token, expires_at = generate_jwt_token(user_token_data)

        # Preparar respuesta
        user_data = {
            'user_id': user.get('user_id'),
            'email': user.get('email'),
            'name': user.get('name'),
            'user_type': user_type,
            'is_active': user.get('is_active', True),
            'last_login': current_time,
            'redirect_to': get_redirect_path(user_type, staff_tier, frontend_type)  
        }
        
        if user_type == 'staff':
            user_data['staff_tier'] = staff_tier
            user_data['permissions'] = user.get('permissions', [])
            user_data['is_verified'] = user.get('is_verified', True)
        else:
            user_data['is_verified'] = user.get('is_verified', False)
        
        response_data = {
            'message': 'Login exitoso',
            'user': user_data,
            'token': token,
            'token_expires': expires_at.isoformat() if hasattr(expires_at, 'isoformat') else expires_at,
            'session': {
                'logged_in_at': current_time,
                'frontend_type': frontend_type
            }
        }
        
        return {
            'statusCode': 200,
            'headers': CORS_HEADERS,
            'body': json.dumps(response_data)
        }

    except Exception as e:
        print("Exception in login:", str(e))
        import traceback
        print("Traceback:", traceback.format_exc())
        
        return {
            'statusCode': 500,
            'headers': CORS_HEADERS,
            'body': json.dumps({
                'error': 'Internal server error',
                'details': str(e)
            })
        }