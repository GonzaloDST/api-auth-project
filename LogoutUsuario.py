import json
from datetime import datetime

CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS, GET',
    'Access-Control-Allow-Headers': 'Content-Type, X-Amz-Date, Authorization, X-Api-Key, X-Amz-Security-Token, Accept',
    'Content-Type': 'application/json'
}

def lambda_handler(event, context):
    try:
        print("Logout event received:", json.dumps(event, indent=2))
        
        response_data = {
            'message': 'Sesión cerrada exitosamente',
            'timestamp': datetime.utcnow().isoformat(),
            'note': 'Token eliminado del cliente. El token JWT seguirá siendo válido hasta su expiración natural.'
        }
        
        return {
            'statusCode': 200,
            'headers': CORS_HEADERS,
            'body': json.dumps(response_data)
        }

    except Exception as e:
        print("Exception in logout:", str(e))
        import traceback
        print("Traceback:", traceback.format_exc())
        
        return {
            'statusCode': 500,
            'headers': CORS_HEADERS,
            'body': json.dumps({
                'error': 'Error interno del servidor',
                'details': str(e)
            })
        }