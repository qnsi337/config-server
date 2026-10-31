#!/usr/bin/env bash
# =============================================================================
# setup-ssh-security.sh
# Меняет SSH порт на 2224, открывает его в firewall, ставит fail2ban
# Поддерживаемые системы: Debian 10/11/12/13, Ubuntu 20.04/22.04/24.04,
#                          RHEL/CentOS/Rocky/AlmaLinux 8/9, Fedora
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

# =============================================================================
# 0. Определение дистрибутива и пакетного менеджера
# =============================================================================
[[ -f /etc/os-release ]] || die "Не найден /etc/os-release — не удалось определить ОС"
. /etc/os-release

OS_ID="$ID"
OS_ID_LIKE="${ID_LIKE:-}"
OS_VERSION="${VERSION_ID:-unknown}"

PKG_FAMILY=""   # debian | rhel
PM=""           # apt | dnf | yum
SSH_SERVICE=""  # ssh | sshd

case "$OS_ID $OS_ID_LIKE" in
    *debian*|*ubuntu*)
        PKG_FAMILY="debian"
        PM="apt"
        SSH_SERVICE="ssh"
        ;;
    *rhel*|*fedora*|*centos*|*rocky*|*almalinux*)
        PKG_FAMILY="rhel"
        SSH_SERVICE="sshd"
        if command -v dnf &>/dev/null; then
            PM="dnf"
        elif command -v yum &>/dev/null; then
            PM="yum"
        else
            die "Не найден dnf/yum на системе семейства RHEL"
        fi
        ;;
    *)
        # Фоллбэк по наличию пакетного менеджера, если ID/ID_LIKE не распознаны
        if command -v apt-get &>/dev/null; then
            PKG_FAMILY="debian"; PM="apt"; SSH_SERVICE="ssh"
        elif command -v dnf &>/dev/null; then
            PKG_FAMILY="rhel"; PM="dnf"; SSH_SERVICE="sshd"
        elif command -v yum &>/dev/null; then
            PKG_FAMILY="rhel"; PM="yum"; SSH_SERVICE="sshd"
        else
            die "Неподдерживаемая ОС: $OS_ID (ID_LIKE=$OS_ID_LIKE). Нужен apt, dnf или yum."
        fi
        ;;
esac

info "Обнаружена ОС: $OS_ID $OS_VERSION (семейство: $PKG_FAMILY, пакетный менеджер: $PM)"

# Универсальная установка пакетов
install_pkg() {
    case "$PM" in
        apt)
            apt-get update -qq
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
            ;;
        dnf)
            dnf install -y -q "$@"
            ;;
        yum)
            yum install -y -q "$@"
            ;;
    esac
}

echo ""
echo -e "${BOLD}========================================${NC}"
echo -e "${BOLD}   SSH Security Setup — порт $SSH_PORT   ${NC}"
echo -e "${BOLD}========================================${NC}"
echo ""

# =============================================================================
# 0.5. Локали (убирает "locale: Cannot set LC_CTYPE/LC_ALL to default locale")
# =============================================================================
info "Проверка локалей..."

if ! locale -a 2>/dev/null | grep -qi '^en_US\.utf8$'; then
    case "$PKG_FAMILY" in
        debian)
            install_pkg locales >/dev/null 2>&1 || true
            if [[ -f /etc/locale.gen ]]; then
                sed -i 's/^# *\(en_US\.UTF-8 UTF-8\)/\1/' /etc/locale.gen
                grep -q '^en_US\.UTF-8 UTF-8' /etc/locale.gen || echo 'en_US.UTF-8 UTF-8' >> /etc/locale.gen
            fi
            locale-gen en_US.UTF-8 >/dev/null 2>&1 || true
            update-locale LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8 >/dev/null 2>&1 || true
            ;;
        rhel)
            install_pkg glibc-langpack-en >/dev/null 2>&1 || true
            localectl set-locale LANG=en_US.UTF-8 >/dev/null 2>&1 || true
            ;;
    esac

    if locale -a 2>/dev/null | grep -qi '^en_US\.utf8$'; then
        success "Локаль en_US.UTF-8 сгенерирована"
    else
        warn "Не удалось сгенерировать локаль автоматически — предупреждения perl/locale могут остаться (не влияет на работу SSH/fail2ban)"
    fi
else
    success "Локаль en_US.UTF-8 уже есть"
fi

# Подхватываем для остального скрипта (не обязательно, но убирает warning прямо сейчас)
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

# =============================================================================
# 1. SSH — меняем порт
# =============================================================================
info "Настройка SSH (порт $SSH_PORT)..."

SSHD_CONFIG="/etc/ssh/sshd_config"
[[ -f "$SSHD_CONFIG" ]] || die "Не найден $SSHD_CONFIG"

# Бэкап конфига
cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak.$(date +%Y%m%d%H%M%S)"
success "Бэкап sshd_config создан"

# Убираем все строки Port (включая закомментированные) и добавляем нужную
sed -i '/^#\?Port /d' "$SSHD_CONFIG"
echo "Port $SSH_PORT" >> "$SSHD_CONFIG"

# Дополнительные базовые харденинги
sed -i '/^#\?MaxAuthTries /d' "$SSHD_CONFIG"
echo "MaxAuthTries 4" >> "$SSHD_CONFIG"

# RHEL-семейство с SELinux: порт нужно явно разрешить в политике,
# иначе sshd не сможет забиндиться на нестандартный порт
if [[ "$PKG_FAMILY" == "rhel" ]] && command -v semanage &>/dev/null; then
    semanage port -a -t ssh_port_t -p tcp "$SSH_PORT" 2>/dev/null || \
    semanage port -m -t ssh_port_t -p tcp "$SSH_PORT" 2>/dev/null || true
    success "SELinux: порт $SSH_PORT добавлен в ssh_port_t"
elif [[ "$PKG_FAMILY" == "rhel" ]] && command -v getenforce &>/dev/null && [[ "$(getenforce)" != "Disabled" ]]; then
    warn "SELinux активен, но semanage недоступен (пакет policycoreutils-python-utils). Порт $SSH_PORT может быть заблокирован политикой."
fi

# Проверка конфига перед перезапуском
sshd -t 2>/dev/null || /usr/sbin/sshd -t || die "Ошибка в sshd_config! Проверь бэкап: ${SSHD_CONFIG}.bak.*"
success "sshd_config валиден"

# =============================================================================
# 2. Обновление ядра (CVE-2026-98432 — use-after-free в обработке IP-опций
#    TCP SYN/SYNACK, tcp_v4_syn_recv_sock/ireq_opt). Чинится только апдейтом
#    ядра, никакой sysctl/runtime-митигации для этой уязвимости нет.
# =============================================================================
info "Обновление пакета ядра (CVE-2026-98432)..."

KERNEL_BEFORE="$(uname -r)"
KERNEL_UPDATED=0

case "$PKG_FAMILY" in
    debian)
        apt-get update -qq
        # Метапакет ядра отличается между Debian (linux-image-<arch>) и Ubuntu (linux-image-generic)
        if apt-cache policy linux-image-amd64 2>/dev/null | grep -q Candidate; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --only-upgrade linux-image-amd64 && KERNEL_UPDATED=1
        elif apt-cache policy linux-image-generic 2>/dev/null | grep -q Candidate; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --only-upgrade linux-image-generic && KERNEL_UPDATED=1
        else
            # Фоллбэк — обновляем все установленные linux-image-* пакеты, какие найдутся
            INSTALLED_KERNELS="$(dpkg-query -W -f='${Package}\n' 'linux-image-*' 2>/dev/null | grep -v '^linux-image-amd64$\|^linux-image-generic$' || true)"
            if [[ -n "$INSTALLED_KERNELS" ]]; then
                DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --only-upgrade $INSTALLED_KERNELS && KERNEL_UPDATED=1
            fi
        fi
        ;;
    rhel)
        install_pkg kernel kernel-core kernel-modules 2>/dev/null && KERNEL_UPDATED=1
        ;;
esac

if [[ "$KERNEL_UPDATED" -eq 1 ]]; then
    success "Пакет ядра обновлён (текущее загруженное ядро: $KERNEL_BEFORE)"
    warn "Патч для CVE-2026-98432 вступит в силу только после перезагрузки (reboot). Без перезагрузки ядро по-прежнему уязвимо!"
else
    warn "Не удалось автоматически обновить ядро (возможно, уже последняя версия, либо сетевой репозиторий недоступен). Проверь вручную: uname -r и сверь с fixed-версией для твоего дистрибутива (CVE-2026-98432)."
fi

# =============================================================================
# 3. Firewall — UFW / firewalld / iptables
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

elif command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld 2>/dev/null; then
    firewall-cmd --permanent --add-port="$SSH_PORT/tcp" >/dev/null
    firewall-cmd --permanent --remove-service=ssh >/dev/null 2>&1 || true
    firewall-cmd --permanent --remove-port=22/tcp >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null

    success "firewalld: порт $SSH_PORT открыт, порт 22 закрыт"
    firewall-cmd --list-ports

elif command -v iptables &>/dev/null; then
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT
    iptables -D INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || true

    # Сохраняем правила (путь отличается между Debian- и RHEL-семейством)
    if command -v iptables-save &>/dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
        iptables-save > /etc/sysconfig/iptables 2>/dev/null || \
        iptables-save > /etc/iptables.rules 2>/dev/null || true
    fi
    success "iptables: порт $SSH_PORT открыт"

elif command -v nft &>/dev/null; then
    # Современный Debian/Ubuntu без ufw/iptables управляет firewall через nftables напрямую
    RULESET="$(nft list ruleset 2>/dev/null || true)"

    if [[ -z "$RULESET" ]]; then
        info "nftables установлен, но набор правил пуст — соединения не ограничены, порт $SSH_PORT уже доступен"
    else
        # Ищем базовую input-цепочку с политикой drop/reject — только такая цепочка
        # реально что-то блокирует. Таблицы с policy accept (например, служебная
        # таблица fail2ban f2b-table, которая только банит отдельные IP) не считаются.
        DROP_CHAIN_INFO="$(echo "$RULESET" | awk '
            $1=="table" { fam=$2; tbl=$3 }
            $1=="chain" { chain=$2 }
            /hook input/ && /policy (drop|reject)/ { print fam, tbl, chain; exit }
        ')"

        if [[ -z "$DROP_CHAIN_INFO" ]]; then
            info "nftables активен, но входящий трафик не блокируется политикой (policy accept) — порт $SSH_PORT уже доступен. Правила fail2ban (если есть) только банят отдельные IP и не ограничивают порт в целом."
        else
            NFT_FAMILY="$(echo "$DROP_CHAIN_INFO" | awk '{print $1}')"
            NFT_TABLE="$(echo "$DROP_CHAIN_INFO" | awk '{print $2}')"
            NFT_CHAIN="$(echo "$DROP_CHAIN_INFO" | awk '{print $3}')"

            if nft insert rule "$NFT_FAMILY" "$NFT_TABLE" "$NFT_CHAIN" tcp dport "$SSH_PORT" accept 2>/dev/null; then
                nft delete rule "$NFT_FAMILY" "$NFT_TABLE" "$NFT_CHAIN" tcp dport 22 accept 2>/dev/null || true
                success "nftables: правило для порта $SSH_PORT добавлено в начало цепочки $NFT_CHAIN ($NFT_FAMILY $NFT_TABLE, policy drop/reject)"
                warn "Правило не сохранено на диск — сохрани вручную (nft list ruleset > /etc/nftables.conf) или через твой менеджер nftables"
            else
                warn "Не удалось автоматически добавить правило в nftables ($NFT_FAMILY $NFT_TABLE $NFT_CHAIN). Открой порт $SSH_PORT вручную!"
            fi
        fi
    fi
else
    warn "Firewall не обнаружен. Открой порт $SSH_PORT вручную!"
fi

# =============================================================================
# 4. fail2ban
# =============================================================================
info "Установка и настройка fail2ban..."

if [[ "$PKG_FAMILY" == "rhel" ]] && ! rpm -q epel-release &>/dev/null && [[ "$OS_ID" != "fedora" ]]; then
    # fail2ban на RHEL/CentOS/Rocky/Alma лежит в EPEL, в Fedora он уже в базовых репах
    install_pkg epel-release || warn "Не удалось установить epel-release — fail2ban может не найтись"
fi

install_pkg fail2ban

mkdir -p /etc/fail2ban/jail.d

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
# 5. Перезапуск сервисов
# =============================================================================
info "Перезапуск сервисов..."

systemctl restart "$SSH_SERVICE" 2>/dev/null || \
systemctl restart ssh 2>/dev/null || \
systemctl restart sshd 2>/dev/null || \
die "Не удалось перезапустить SSH сервис"
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
echo -e "  ОС:             ${BOLD}$OS_ID $OS_VERSION${NC}"
echo -e "  SSH порт:       ${BOLD}$SSH_PORT${NC}"
echo -e "  Ядро:           ${BOLD}$(uname -r)${NC} $([[ "$KERNEL_UPDATED" -eq 1 ]] && echo "(обновлено, нужен reboot для применения патча CVE-2026-98432)" || echo "(обновление не выполнено — проверь вручную)")"
echo -e "  fail2ban:       ${BOLD}maxretry=$FAIL2BAN_MAXRETRY, ban=1 час${NC}"
echo ""
echo -e "${YELLOW}  ⚠  НЕ закрывай текущую сессию!${NC}"
echo -e "  Открой новое окно и проверь подключение:"
echo -e "  ${CYAN}ssh -p $SSH_PORT user@<IP>${NC}"
echo ""
if [[ "$KERNEL_UPDATED" -eq 1 ]]; then
    echo -e "${YELLOW}  ⚠  Ядро обновлено — патч CVE-2026-98432 применится только после перезагрузки (sudo reboot).${NC}"
    echo -e "  Сначала убедись, что подключение по новому SSH-порту работает, и только потом перезагружай сервер."
    echo ""
fi