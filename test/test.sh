#!/bin/bash

# ==========================================
# TEST COMPLETO API AUTH - VERSIÓN CORREGIDA
# ==========================================

API_BASE="https://62rucwto8i.execute-api.us-east-1.amazonaws.com/dev"
TIMESTAMP=$(date +%s)

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo() { builtin echo -e "$@"; }

# Funciones de ayuda
success() { echo "${GREEN}✅ $1${NC}"; }
error() { echo "${RED}❌ $1${NC}"; }
info() { echo "${BLUE}ℹ️  $1${NC}"; }
warning() { echo "${YELLOW}⚠️  $1${NC}"; }

# Función CORREGIDA para extraer código de invitación
get_invitation_code() {
    local response
    response=$(curl -s -X POST "$API_BASE/auth/generate-invitation" \
        -H "Content-Type: application/json" \
        -d '{"max_uses": 5, "expires_in_days": 1}')
    
    # Extraer el código - MÉTODO MEJORADO
    local code
    code=$(echo "$response" | grep -o '"invitation_code": "[^"]*"' | cut -d'"' -f4)
    
    if [ -n "$code" ]; then
        echo "$code"
        return 0
    else
        return 1
    fi
}

# Función para hacer requests CORREGIDA
api_call() {
    local desc="$1"
    local endpoint="$2"
    local data="$3"
    local expected="$4"
    
    echo "\n${BLUE}➡️  $desc${NC}"
    echo "   Endpoint: POST $endpoint"
    echo "   Data: $data"
    
    local response
    response=$(curl -s -w "|%{http_code}" -X POST "$API_BASE$endpoint" \
        -H "Content-Type: application/json" \
        -d "$data")
    
    local body=$(echo "$response" | cut -d'|' -f1)
    local code=$(echo "$response" | cut -d'|' -f2)
    
    echo "   Response: $body"
    echo "   HTTP Code: $code"
    
    if [ "$code" = "$expected" ]; then
        success "   ✓ PASS - Expected $expected"
        return 0
    else
        error "   ✗ FAIL - Expected $expected, got $code"
        return 1
    fi
}

echo "${GREEN}"
echo "=========================================="
echo "           API AUTH TEST SUITE"
echo "=========================================="
echo "Base URL: $API_BASE"
echo "Timestamp: $TIMESTAMP"
echo "=========================================="
echo "${NC}"

# Variables de prueba
CLIENT_EMAIL="client.$TIMESTAMP@example.com"
STAFF_EMAIL="staff.$TIMESTAMP@example.com"
CLIENT_PASS="cliente123"
STAFF_PASS="staff123"

# ============================================================================
# 1. GENERAR CÓDIGO DE INVITACIÓN (CORREGIDO)
# ============================================================================
info "=== 1. GENERAR CÓDIGO DE INVITACIÓN ==="

echo "\n${BLUE}➡️  Generar código de invitación${NC}"
INVITE_CODE=$(get_invitation_code)

if [ $? -eq 0 ] && [ -n "$INVITE_CODE" ]; then
    success "   ✓ Código generado: $INVITE_CODE"
else
    error "   ✗ No se pudo generar código"
    exit 1
fi

# ============================================================================
# 2. PRUEBAS DE STAFF (CORREGIDAS)
# ============================================================================
info "=== 2. PRUEBAS DE STAFF ==="

# 2.1 Registrar staff con código válido - DATOS CORREGIDOS
api_call "Registrar staff con código válido" "/auth/registro" "{
    \"name\": \"Staff Admin\",
    \"email\": \"$STAFF_EMAIL\",
    \"password\": \"$STAFF_PASS\",
    \"user_type\": \"staff\",
    \"staff_tier\": \"admin\", 
    \"invitation_code\": \"$INVITE_CODE\",
    \"frontend_type\": \"staff\"
}" "201"

# 2.2 Login de staff exitoso
api_call "Login de staff exitoso" "/auth/login" "{
    \"email\": \"$STAFF_EMAIL\",
    \"password\": \"$STAFF_PASS\",
    \"frontend_type\": \"staff\"
}" "200"

# ============================================================================
# 3. PRUEBAS DE CLIENTE
# ============================================================================
info "=== 3. PRUEBAS DE CLIENTE ==="

# 3.1 Registrar cliente
api_call "Registrar cliente" "/auth/registro" "{
    \"name\": \"Cliente Normal\",
    \"email\": \"$CLIENT_EMAIL\",
    \"password\": \"$CLIENT_PASS\",
    \"phone\": \"123456789\",
    \"gender\": \"masculino\",
    \"user_type\": \"cliente\",
    \"frontend_type\": \"client\"
}" "201"

# 3.2 Login de cliente exitoso
api_call "Login de cliente exitoso" "/auth/login" "{
    \"email\": \"$CLIENT_EMAIL\",
    \"password\": \"$CLIENT_PASS\",
    \"frontend_type\": \"client\"
}" "200"

# ============================================================================
# 4. PRUEBAS DE ERRORES - REGISTRO
# ============================================================================
info "=== 4. PRUEBAS DE ERRORES - REGISTRO ==="

# 4.1 Email duplicado (cliente)
api_call "Registro con email duplicado (cliente)" "/auth/registro" "{
    \"name\": \"Cliente Duplicado\",
    \"email\": \"$CLIENT_EMAIL\",
    \"password\": \"otraPassword\",
    \"user_type\": \"cliente\",
    \"frontend_type\": \"client\"
}" "409"

# 4.2 Email duplicado (staff)
api_call "Registro con email duplicado (staff)" "/auth/registro" "{
    \"name\": \"Staff Duplicado\",
    \"email\": \"$STAFF_EMAIL\",
    \"password\": \"otraPassword\",
    \"user_type\": \"staff\",
    \"staff_tier\": \"admin\",
    \"invitation_code\": \"$INVITE_CODE\",
    \"frontend_type\": \"staff\"
}" "409"

# 4.3 Staff sin código de invitación
api_call "Registro staff sin código" "/auth/registro" "{
    \"name\": \"Staff Sin Código\",
    \"email\": \"staff.sin.codigo.$TIMESTAMP@example.com\",
    \"password\": \"staff123\",
    \"user_type\": \"staff\",
    \"staff_tier\": \"admin\",
    \"frontend_type\": \"staff\"
}" "403"

# 4.4 Staff con código inválido
api_call "Registro staff con código inválido" "/auth/registro" "{
    \"name\": \"Staff Código Inválido\",
    \"email\": \"staff.codigo.invalido.$TIMESTAMP@example.com\",
    \"password\": \"staff123\",
    \"user_type\": \"staff\",
    \"staff_tier\": \"admin\",
    \"invitation_code\": \"CODIGO_INEXISTENTE_123\",
    \"frontend_type\": \"staff\"
}" "403"

# 4.5 Campos obligatorios faltantes
api_call "Registro sin email" "/auth/registro" "{
    \"name\": \"Sin Email\",
    \"password\": \"algunpass\",
    \"user_type\": \"cliente\",
    \"frontend_type\": \"client\"
}" "400"

# ============================================================================
# 5. PRUEBAS DE ERRORES - LOGIN
# ============================================================================
info "=== 5. PRUEBAS DE ERRORES - LOGIN ==="

# 5.1 Login con contraseña incorrecta (cliente)
api_call "Login cliente con contraseña incorrecta" "/auth/login" "{
    \"email\": \"$CLIENT_EMAIL\",
    \"password\": \"CONTRASEÑA_INCORRECTA\",
    \"frontend_type\": \"client\"
}" "401"

# 5.2 Login con contraseña incorrecta (staff)
api_call "Login staff con contraseña incorrecta" "/auth/login" "{
    \"email\": \"$STAFF_EMAIL\",
    \"password\": \"CONTRASEÑA_INCORRECTA\",
    \"frontend_type\": \"staff\"
}" "401"

# 5.3 Login con email inexistente
api_call "Login con email inexistente" "/auth/login" "{
    \"email\": \"noexiste.$TIMESTAMP@example.com\",
    \"password\": \"algunpass\",
    \"frontend_type\": \"client\"
}" "401"

# 5.4 Frontend incorrecto (staff en cliente) - EXPECTATIVA CORREGIDA
api_call "Staff login desde frontend cliente" "/auth/login" "{
    \"email\": \"$STAFF_EMAIL\",
    \"password\": \"$STAFF_PASS\",
    \"frontend_type\": \"client\"
}" "403"

# 5.5 Frontend incorrecto (cliente en staff)
api_call "Cliente login desde frontend staff" "/auth/login" "{
    \"email\": \"$CLIENT_EMAIL\",
    \"password\": \"$CLIENT_PASS\",
    \"frontend_type\": \"staff\"
}" "403"

# ============================================================================
# 6. PRUEBAS DE LOGOUT
# ============================================================================
info "=== 6. PRUEBAS DE LOGOUT ==="

# 6.1 Logout simple
api_call "Logout simple (sin token)" "/auth/logout" "{}" "200"

# ============================================================================
# 7. PRUEBAS ADICIONALES
# ============================================================================
info "=== 7. PRUEBAS ADICIONALES ==="

# 7.1 Generar segundo código de invitación
echo "\n${BLUE}➡️  Generar segundo código de invitación${NC}"
INVITE_CODE_2=$(get_invitation_code)

if [ $? -eq 0 ] && [ -n "$INVITE_CODE_2" ]; then
    success "   ✓ Segundo código: $INVITE_CODE_2"
    
    # 7.2 Registrar trabajador con segundo código
    api_call "Registrar staff trabajador" "/auth/registro" "{
        \"name\": \"Staff Trabajador\",
        \"email\": \"trabajador.$TIMESTAMP@example.com\",
        \"password\": \"trabajador123\",
        \"user_type\": \"staff\",
        \"staff_tier\": \"trabajador\",
        \"invitation_code\": \"$INVITE_CODE_2\",
        \"frontend_type\": \"staff\"
    }" "201"
else
    warning "   ⚠️  No se pudo generar segundo código, continuando..."
fi

# 7.3 Registro mínimo (solo campos obligatorios)
api_call "Registro mínimo de cliente" "/auth/registro" "{
    \"name\": \"Usuario Mínimo\",
    \"email\": \"minimo.$TIMESTAMP@example.com\",
    \"password\": \"minimo123\",
    \"user_type\": \"cliente\",
    \"frontend_type\": \"client\"
}" "201"

# ============================================================================
# RESUMEN FINAL CORREGIDO
# ============================================================================
echo "${GREEN}"
echo "=========================================="
echo "           TESTING COMPLETADO"
echo "=========================================="
echo "${NC}"

success "Resumen de pruebas ejecutadas:"
echo "  • Generación de códigos invitación: 2"
echo "  • Registro exitoso: 4" 
echo "  • Login exitoso: 2"
echo "  • Errores de registro: 5"
echo "  • Errores de login: 5"
echo "  • Logout: 1"
echo ""
echo "  ${GREEN}Total: ~19 pruebas${NC}"

info "Datos de prueba utilizados:"
echo "  📧 Cliente: $CLIENT_EMAIL"
echo "  📧 Staff: $STAFF_EMAIL"
echo "  🔑 Código 1: $INVITE_CODE"
if [ -n "$INVITE_CODE_2" ]; then
    echo "  🔑 Código 2: $INVITE_CODE_2"
fi

echo ""
info "Para ejecutar con otra URL:"
echo "  API_BASE_URL=\"https://tu-api.ejemplo.com/dev\" ./test_api_corregido.sh"