import boto3
import hashlib
import uuid
from datetime import datetime
import json
import os
import traceback

# Hashear contraseña
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Validar y asignar tier de staff (MODIFICADO)
def validate_staff_tier(tier):
    valid_tiers = ['admin', 'trabajador']  # CAMBIADO: 'basic', 'gerente' -> 'admin', 'trabajador'
    if tier not in valid_tiers:
        raise ValueError(f"Tier inválido. Debe ser uno de: {valid_tiers}")
    return tier

# Validar código de invitación para staff
def validate_invitation_code(code):
    if not code:
        return False
        
    dynamodb = boto3.resource('dynamodb')
    # Usar variable de entorno para el nombre de la tabla
    invitation_table_name = os.environ.get('INVITATION_CODES_TABLE', 'dev-t_invitation_codes')
    table = dynamodb.Table(invitation_table_name)
    
    try:
        response = table.get_item(Key={'code': code})
        if 'Item' in response:
            item = response['Item']
            
            # Verificar que esté activo y no haya expirado
            # Parsear expires_at de manera segura
            try:
                expires_at_str = item.get('expires_at')
                if not expires_at_str:
                    return False
                expires_at = datetime.fromisoformat(expires_at_str)
            except Exception as e:
                print(f"Error parsing expires_at for code {code}: {e}")
                return False

            try:
                used_count = int(item.get('used_count', 0))
                max_uses = int(item.get('max_uses', 1))
            except Exception:
                used_count = 0
                max_uses = 1

            if (item.get('is_active', False) and 
                expires_at > datetime.utcnow() and
                used_count < max_uses):

                # Incrementar contador de usos de forma segura (si no existe, asumir 0)
                try:
                    table.update_item(
                        Key={'code': code},
                        UpdateExpression='SET used_count = if_not_exists(used_count, :zero) + :inc',
                        ExpressionAttributeValues={':inc': 1, ':zero': 0}
                    )
                except Exception as e:
                    print(f"Error updating used_count for code {code}: {str(e)}")
                    return False

                return True
        return False
    except Exception as e:
        print(f"Error validating invitation code: {str(e)}")
        return False

# Asignar permisos basados en el tier de staff (MODIFICADO)
def get_staff_permissions(tier):
    permissions = {
        'trabajador': [  # CAMBIADO: 'basic' -> 'trabajador'
            'view_products',
            'view_orders', 
            'update_order_status',
            'view_customers',
            'manage_own_profile'
        ],
        'admin': [  # CAMBIADO: 'gerente' -> 'admin'
            'view_products',
            'view_orders',
            'update_order_status', 
            'view_customers',
            'manage_products',
            'manage_orders',
            'manage_staff_trabajador',  # CAMBIADO: 'manage_staff_basic' -> 'manage_staff_trabajador'
            'view_reports',
            'manage_inventory',
            'generate_invitation_codes',
            'manage_all_profiles'
        ]
    }
    return permissions.get(tier, [])

# Headers CORS para todas las respuestas
CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS, GET',
    'Access-Control-Allow-Headers': 'Content-Type, X-Amz-Date, Authorization, X-Api-Key, X-Amz-Security-Token, Accept',
    'Content-Type': 'application/json'
}

# Función principal del Lambda
def lambda_handler(event, context):
    """
    Maneja el registro de usuarios para ambos frontends
    """
    try:
        print("Event received:", json.dumps(event, indent=2))
        
        if 'body' in event:
            if isinstance(event['body'], str):
                body = json.loads(event['body'])
            else:
                body = event['body']
        else:
            body = event

        # ✅ Obtener datos del body correctamente
        password = body.get('password')
        name = body.get('name')
        email = body.get('email', '').lower().strip() 
        phone = body.get('phone')
        gender = body.get('gender')
        user_type = body.get('user_type', 'cliente')
        staff_tier = body.get('staff_tier')
        invitation_code = body.get('invitation_code')
        frontend_type = body.get('frontend_type', 'client')

        # Validación 1: Campos obligatorios
        if not email or not password:
            return {
                'statusCode': 400,
                'headers': CORS_HEADERS,
                'body': json.dumps({
                    'error': 'Campos obligatorios faltantes: email y password son requeridos'
                })
            }
        
        # Validación 2: Restricciones por tipo de frontend
        if frontend_type == 'staff':
            # Desde staff frontend, solo permitir registro de staff
            if user_type != 'staff':
                return {
                    'statusCode': 403,
                    'headers': CORS_HEADERS,
                    'body': json.dumps({
                        'error': 'Acceso denegado. El portal staff es solo para registro de personal'
                    })
                }
            
            # Validar código de invitación para staff
            if not validate_invitation_code(invitation_code):
                return {
                    'statusCode': 403,
                    'headers': CORS_HEADERS,
                    'body': json.dumps({
                        'error': 'Código de invitación inválido o expirado. Contacta al administrador.'
                    })
                }
                
        elif frontend_type == 'client':
            # Desde cliente frontend, solo permitir clientes
            if user_type != 'cliente':
                return {
                    'statusCode': 403,
                    'headers': CORS_HEADERS,
                    'body': json.dumps({
                        'error': 'Acceso denegado. El portal cliente es solo para usuarios clientes'
                    })
                }
        else:
            # Si no se especifica frontend_type, asumimos cliente por defecto
            frontend_type = 'client'
            if user_type == 'staff':
                return {
                    'statusCode': 403,
                    'headers': CORS_HEADERS,
                    'body': json.dumps({
                        'error': 'Registro de staff requiere especificar frontend_type: staff'
                    })
                }
        
        # Validación 3: Tipo de usuario válido
        if user_type not in ['cliente', 'staff']:
            return {
                'statusCode': 400,
                'headers': CORS_HEADERS,
                'body': json.dumps({
                    'error': 'Tipo de usuario inválido. Debe ser "cliente" o "staff"'
                })
            }
        
        # Validación 4: Staff tier requerido para staff
        if user_type == 'staff':
            if not staff_tier:
                return {
                    'statusCode': 400,
                    'headers': CORS_HEADERS,
                    'body': json.dumps({
                        'error': 'Usuarios staff requieren el campo staff_tier'
                    })
                }
            try:
                staff_tier = validate_staff_tier(staff_tier)
            except ValueError as e:
                return {
                    'statusCode': 400,
                    'headers': CORS_HEADERS,
                    'body': json.dumps({'error': str(e)})
                }
        else:
            # Clientes no deben tener staff_tier
            staff_tier = None
        
        dynamodb = boto3.resource('dynamodb')
        usuarios_table_name = os.environ.get('USUARIOS_TABLE', 'dev-t_usuarios')
        t_usuarios = dynamodb.Table(usuarios_table_name)
        
        # Verificar si el email ya está registrado
        try:
            existing_user = t_usuarios.get_item(Key={'email': email})
            if 'Item' in existing_user:
                return {
                    'statusCode': 409,
                    'headers': CORS_HEADERS,
                    'body': json.dumps({
                        'error': 'El email ya está registrado en el sistema'
                    })
                }
        except Exception as e:
            print(f"Error checking existing user: {str(e)}")
        
        ## REGISTRO
        hashed_password = hash_password(password)
        current_time = datetime.utcnow().isoformat()
        
        # Crear el item completo 
        user_item = {
            'user_id': str(uuid.uuid4()),
            'email': email,
            'password': hashed_password,  
            'name': name,
            'phone': phone,
            'gender': gender,
            'user_type': user_type,
            'created_at': current_time,    
            'updated_at': current_time,    
            'is_active': True,             
            'last_login': None,            
            'registration_source': frontend_type
        }
        
        # Agregar campos específicos de staff
        if user_type == 'staff':
            user_item['staff_tier'] = staff_tier
            user_item['permissions'] = get_staff_permissions(staff_tier)
            user_item['is_verified'] = True
        else:
            user_item['is_verified'] = True
           
        # Guardar usuario en DynamoDB
        t_usuarios.put_item(Item=user_item)
        
        print(f"Usuario registrado exitosamente: {email}, tipo: {user_type}, frontend: {frontend_type}")

        ## RESPONSE
        response_data = {
            'message': 'Usuario registrado exitosamente',
            'user_id': user_item['user_id'],
            'email': email,
            'name': name,
            'user_type': user_type,
            'is_active': True,
            'registration_source': frontend_type,
            'requires_verification': not user_item['is_verified']
        }
        
        # Agregar información específica de staff a la respuesta
        if user_type == 'staff':
            response_data['staff_tier'] = staff_tier
            response_data['permissions'] = user_item['permissions']
            response_data['is_verified'] = True
        
        return {
            'statusCode': 201,
            'headers': CORS_HEADERS,
            'body': json.dumps(response_data)
        }

    except Exception as e:
        print("Exception:", str(e))
        error_response = {
            'error': 'Error interno del servidor',
            'code': 'INTERNAL_ERROR'
        }
        
        return {
            'statusCode': 500,
            'headers': CORS_HEADERS,
            'body': json.dumps(error_response)
        }