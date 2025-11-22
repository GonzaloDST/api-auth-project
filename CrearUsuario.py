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

# Validar y asignar tier de staff
def validate_staff_tier(tier):
    valid_tiers = ['admin', 'trabajador']
    if tier not in valid_tiers:
        raise ValueError(f"Tier inválido. Debe ser uno de: {valid_tiers}")
    return tier

# Validar código de invitación
def validate_invitation_code(code):
    if not code:
        return False
        
    dynamodb = boto3.resource('dynamodb')
    invitation_table_name = os.environ.get('INVITATION_CODES_TABLE', 'dev-t_invitation_codes')
    table = dynamodb.Table(invitation_table_name)
    
    try:
        response = table.get_item(Key={'code': code})
        if 'Item' not in response:
            return False
            
        item = response['Item']
        
        # Validar fecha de expiración
        try:
            expires_at_str = item.get('expires_at')
            if not expires_at_str:
                return False
            expires_at = datetime.fromisoformat(expires_at_str)
        except Exception:
            return False
        
        used_count = int(item.get('used_count', 0))
        max_uses = int(item.get('max_uses', 1))
        
        if (
            item.get('is_active', False) and
            expires_at > datetime.utcnow() and
            used_count < max_uses
        ):
            # Incrementar contador de uso
            table.update_item(
                Key={'code': code},
                UpdateExpression='SET used_count = if_not_exists(used_count, :zero) + :inc',
                ExpressionAttributeValues={':inc': 1, ':zero': 0}
            )
            return True

        return False

    except Exception as e:
        print(f"Error validating invitation code: {str(e)}")
        return False

# Permisos por tier
def get_staff_permissions(tier):
    permissions = {
        'trabajador': [
            'view_products',
            'view_orders',
            'update_order_status',
            'view_customers',
            'manage_own_profile'
        ],
        'admin': [
            'view_products',
            'view_orders',
            'update_order_status',
            'view_customers',
            'manage_products',
            'manage_orders',
            'manage_staff_trabajador',
            'view_reports',
            'manage_inventory',
            'generate_invitation_codes',
            'manage_all_profiles'
        ]
    }
    return permissions.get(tier, [])

# Headers CORS
CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS, GET',
    'Access-Control-Allow-Headers': 'Content-Type, X-Amz-Date, Authorization, X-Api-Key, X-Amz-Security-Token, Accept',
    'Content-Type': 'application/json'
}

# LAMBDA
def lambda_handler(event, context):
    try:
        print("Event received:", json.dumps(event, indent=2))
        
        # Obtener body
        body = json.loads(event['body']) if 'body' in event and isinstance(event['body'], str) else event.get('body', event)

        # Inputs
        password = body.get('password')
        name = body.get('name')
        email = body.get('email', '').lower().strip()
        phone = body.get('phone')
        gender = body.get('gender')
        user_type = body.get('user_type', 'cliente')
        staff_tier = body.get('staff_tier')
        invitation_code = body.get('invitation_code')
        frontend_type = body.get('frontend_type', 'client')
        tenant_id_sede = body.get('tenant_id_sede')

        # Validación 1
        if not email or not password:
            return {
                'statusCode': 400,
                'headers': CORS_HEADERS,
                'body': json.dumps({'error': 'Email y password son requeridos'})
            }

        # Validación 2: frontend
        if frontend_type == 'staff':
            if user_type != 'staff':
                return {
                    'statusCode': 403,
                    'headers': CORS_HEADERS,
                    'body': json.dumps({'error': 'El portal staff es solo para personal'})
                }
            if not validate_invitation_code(invitation_code):
                return {
                    'statusCode': 403,
                    'headers': CORS_HEADERS,
                    'body': json.dumps({'error': 'Código de invitación inválido'})
                }

        if frontend_type == 'client' and user_type != 'cliente':
            return {
                'statusCode': 403,
                'headers': CORS_HEADERS,
                'body': json.dumps({'error': 'El portal cliente es solo para usuarios clientes'})
            }

        # Validación user_type
        if user_type not in ['cliente', 'staff']:
            return {
                'statusCode': 400,
                'headers': CORS_HEADERS,
                'body': json.dumps({'error': 'Tipo de usuario inválido'})
            }

        # Staff debe tener tier
        if user_type == 'staff':
            if not staff_tier:
                return {
                    'statusCode': 400,
                    'headers': CORS_HEADERS,
                    'body': json.dumps({'error': 'staff_tier es requerido para registro staff'})
                }
            staff_tier = validate_staff_tier(staff_tier)

        dynamodb = boto3.resource('dynamodb')
        clientes_table = dynamodb.Table(os.environ.get('USUARIOS_TABLE', 'dev-t_clientes'))
        staff_table = dynamodb.Table(os.environ.get('STAFF_TABLE', 'dev-t_staff'))

        # Verificar email duplicado
        if frontend_type == 'staff':
            existing = staff_table.get_item(Key={'tenant_id_sede': tenant_id_sede, 'email': email})
            if 'Item' in existing:
                return {
                    'statusCode': 409,
                    'headers': CORS_HEADERS,
                    'body': json.dumps({'error': 'Email ya registrado en esta sede'})
                }
        else:
            existing = clientes_table.get_item(Key={'email': email})
            if 'Item' in existing:
                return {
                    'statusCode': 409,
                    'headers': CORS_HEADERS,
                    'body': json.dumps({'error': 'Email ya registrado'})
                }

        # Crear usuario general
        hashed_password = hash_password(password)
        current_time = datetime.utcnow().isoformat()

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
            'registration_source': frontend_type,
            'is_verified': True
        }

        # Campos staff
        if user_type == 'staff':
            user_item['tenant_id_sede'] = tenant_id_sede
            user_item['staff_tier'] = staff_tier
            user_item['permissions'] = get_staff_permissions(staff_tier)

        # Guardar
        if frontend_type == 'staff':
            staff_table.put_item(Item=user_item)
        else:
            clientes_table.put_item(Item=user_item)

        print(f"Usuario registrado: {email}")

        # Respuesta
        response_data = {
            'message': 'Usuario registrado exitosamente',
            'user_id': user_item['user_id'],
            'email': user_item['email'],
            'name': user_item['name'],
            'user_type': user_item['user_type'],
            'registration_source': frontend_type,
            'is_verified': user_item['is_verified']
        }

        if user_type == 'staff':
            response_data['staff_tier'] = user_item['staff_tier']
            response_data['permissions'] = user_item['permissions']

        return {
            'statusCode': 201,
            'headers': CORS_HEADERS,
            'body': json.dumps(response_data)
        }

    except Exception as e:
        print("Exception:", str(e))
        return {
            'statusCode': 500,
            'headers': CORS_HEADERS,
            'body': json.dumps({'error': 'Error interno', 'details': str(e)})
        }
    