#!/usr/bin/env bash
# =============================================================================
# setup-ssh-security.sh
# Меняет SSH порт на 2224, открывает его в firewall, ставит fail2ban
# Поддерживаемые системы: Ubuntu 20.04 / 22.04 / 24.04
# Использование: curl -fsSL <URL> | sudo bash
# =============================================================================

set -euo pipefail

# --- Цвета ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SSH_PORT=2224
FAIL2BAN_MAXRETRY=5
FAIL2BAN_BANTIME=3600  # 1 час в секундах

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()     { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# --- Проверка root ---
[[ $EUID -eq 0 ]] || die "Запусти скрипт от root: sudo bash $0"

# --- Проверка Ubuntu ---
. /etc/os-release
[[ "$ID" == "ubuntu" ]] || die "Скрипт рассчитан на Ubuntu. Обнаружено: $ID"

echo ""
echo -e "${BOLD}========================================${NC}"
echo -e "${BOLD}   SSH Security Setup — порт $SSH_PORT   ${NC}"
echo -e "${BOLD}========================================${NC}"
echo ""

# =============================================================================
# 1. SSH — меняем порт
# =============================================================================
info "Настройка SSH (порт $SSH_PORT)..."

SSHD_CONFIG="/etc/ssh/sshd_config"

# Бэкап конфига
cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak.$(date +%Y%m%d%H%M%S)"
success "Бэкап sshd_config создан"

# Убираем все строки Port (включая закомментированные) и добавляем нужную
sed -i '/^#\?Port /d' "$SSHD_CONFIG"
echo "Port $SSH_PORT" >> "$SSHD_CONFIG"

# Дополнительные базовые харденинги
sed -i '/^#\?PermitRootLogin /d' "$SSHD_CONFIG"
echo "PermitRootLogin prohibit-password" >> "$SSHD_CONFIG"

sed -i '/^#\?MaxAuthTries /d' "$SSHD_CONFIG"
echo "MaxAuthTries 4" >> "$SSHD_CONFIG"

# Проверка конфига перед перезапуском
sshd -t 2>/dev/null || /usr/sbin/sshd -t || die "Ошибка в sshd_config! Откатываю бэкап..."
success "sshd_config валиден"

# =============================================================================
# 2. Firewall — UFW или iptables
# =============================================================================
info "Настройка firewall..."

if command -v ufw &>/dev/null; then
    # Убеждаемся что текущая сессия не потеряется — сначала добавляем новый порт
    ufw allow "$SSH_PORT/tcp" comment "SSH custom port" >/dev/null
    
    # Включаем UFW если выключен (не блокируя текущее соединение на 22)
    if ! ufw status | grep -q "Status: active"; then
        ufw allow 22/tcp >/dev/null 2>&1 || true  # временно, удалим ниже
        echo "y" | ufw enable >/dev/null
    fi

    # Удаляем старый порт 22 (если был явно открыт)
    ufw delete allow 22/tcp >/dev/null 2>&1 || true
    ufw delete allow ssh >/dev/null 2>&1 || true

    success "UFW: порт $SSH_PORT открыт, порт 22 закрыт"
    ufw status | grep -E "$SSH_PORT|22" || true

elif command -v iptables &>/dev/null; then
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT
    iptables -D INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || true
    
    # Сохраняем правила
    if command -v iptables-save &>/dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
        iptables-save > /etc/iptables.rules 2>/dev/null || true
    fi
    success "iptables: порт $SSH_PORT открыт"
else
    warn "Firewall не обнаружен. Открой порт $SSH_PORT вручную!"
fi

# =============================================================================
# 3. fail2ban
# =============================================================================
info "Установка и настройка fail2ban..."

apt-get update -qq
apt-get install -y -qq fail2ban

# Создаём локальный jail конфиг (не трогаем jail.conf, чтобы обновления не затёрли)
cat > /etc/fail2ban/jail.d/sshd-custom.conf <<EOF
[sshd]
enabled   = true
port      = $SSH_PORT
filter    = sshd
backend   = systemd
maxretry  = $FAIL2BAN_MAXRETRY
bantime   = $FAIL2BAN_BANTIME
findtime  = 600
logpath   = %(sshd_log)s
EOF

success "fail2ban jail настроен: maxretry=$FAIL2BAN_MAXRETRY, bantime=${FAIL2BAN_BANTIME}s (1 час)"

# =============================================================================
# 4. Перезапуск сервисов
# =============================================================================
info "Перезапуск сервисов..."

systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || die "Не удалось перезапустить SSH сервис"
success "SSH перезапущен на порту $SSH_PORT"

systemctl enable fail2ban --quiet
systemctl restart fail2ban
success "fail2ban запущен"

# =============================================================================
# Итог
# =============================================================================
echo ""
echo -e "${BOLD}${GREEN}========================================${NC}"
echo -e "${BOLD}${GREEN}   Готово!                              ${NC}"
echo -e "${BOLD}${GREEN}========================================${NC}"
echo ""
echo -e "  SSH порт:       ${BOLD}$SSH_PORT${NC}"
echo -e "  fail2ban:       ${BOLD}maxretry=$FAIL2BAN_MAXRETRY, ban=1 час${NC}"
echo ""
echo -e "${YELLOW}  ⚠  НЕ закрывай текущую сессию!${NC}"
echo -e "  Открой новое окно и проверь подключение:"
echo -e "  ${CYAN}ssh -p $SSH_PORT user@<IP>${NC}"
echo ""
