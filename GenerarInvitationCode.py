import boto3
import json
import uuid
import os
from datetime import datetime, timedelta

# Headers CORS para todas las respuestas
CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS, GET',
    'Access-Control-Allow-Headers': 'Content-Type, X-Amz-Date, Authorization, X-Api-Key, X-Amz-Security-Token, Accept',
    'Content-Type': 'application/json'
}

def generate_invitation_code():
    """Generar un código de invitación único"""
    # Generar un código alfanumérico de 8 caracteres
    return str(uuid.uuid4())[:8].upper()

def lambda_handler(event, context):
    """
    Genera un nuevo código de invitación para registro de staff
    """
    try:
        print("Generate invitation code event:", json.dumps(event, indent=2))
        
        # Parsear el body
        if 'body' in event:
            if isinstance(event['body'], str):
                body = json.loads(event['body'])
            else:
                body = event['body']
        else:
            body = {}
        
        # Parámetros configurables desde el request
        max_uses = body.get('max_uses', 10)  # Número máximo de usos
        expires_in_days = body.get('expires_in_days', 30)  # Días hasta expiración
        created_by = body.get('created_by', 'system')  # Quién crea el código
        
        # Generar código único
        code = generate_invitation_code()
        
        # Configurar fechas
        current_time = datetime.utcnow()
        expires_at = current_time + timedelta(days=expires_in_days)
        
        # Calcular TTL para DynamoDB (48 horas después de la expiración para limpieza)
        ttl_timestamp = int((expires_at + timedelta(days=2)).timestamp())
        
        # Conectar a DynamoDB
        dynamodb = boto3.resource('dynamodb')
        invitation_table_name = os.environ.get('INVITATION_CODES_TABLE', 'dev-t_invitation_codes')
        table = dynamodb.Table(invitation_table_name)
        
        # Crear item del código de invitación
        invitation_item = {
            'code': code,
            'is_active': True,
            'expires_at': expires_at.isoformat(),
            'max_uses': max_uses,
            'used_count': 0,
            'created_by': created_by,
            'created_at': current_time.isoformat(),
            'ttl': ttl_timestamp  # Para auto-eliminación en DynamoDB
        }
        
        # Guardar en DynamoDB
        table.put_item(Item=invitation_item)
        
        print(f"Código de invitación generado: {code}")
        
        # Preparar respuesta
        response_data = {
            'message': 'Código de invitación generado exitosamente',
            'invitation_code': code,
            'details': {
                'max_uses': max_uses,
                'expires_at': expires_at.isoformat(),
                'expires_in_days': expires_in_days,
                'created_by': created_by,
                'created_at': current_time.isoformat()
            },
            'usage_instructions': {
                'para_staff': 'Use este código para registrar nuevo personal staff',
                'endpoint': '/auth/registro',
                'campo': 'invitation_code'
            }
        }
        
        return {
            'statusCode': 201,
            'headers': CORS_HEADERS,
            'body': json.dumps(response_data)
        }

    except Exception as e:
        print("Exception generating invitation code:", str(e))
        import traceback
        print("Traceback:", traceback.format_exc())
        
        return {
            'statusCode': 500,
            'headers': CORS_HEADERS,
            'body': json.dumps({
                'error': 'Error interno del servidor al generar código de invitación',
                'details': str(e)
            })
        }