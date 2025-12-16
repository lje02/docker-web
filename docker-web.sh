#!/bin/bash

# ================= 1. 配置区域 =================
# 脚本版本号
VERSION="V72 (GitHub-Source-Enhanced)"

# 数据存储路径
BASE_DIR="/root/wp-cluster"
SITES_DIR="$BASE_DIR/sites"
GATEWAY_DIR="$BASE_DIR/gateway"
FW_DIR="$BASE_DIR/firewall"
TG_CONF="$BASE_DIR/telegram.conf"
LOG_FILE="$BASE_DIR/operation.log"
MONITOR_PID="$BASE_DIR/monitor.pid"
MONITOR_SCRIPT="$BASE_DIR/monitor_daemon.sh"
LISTENER_PID="$BASE_DIR/tg_listener.pid"
LISTENER_SCRIPT="$BASE_DIR/tg_listener.sh"
BACKUP_KEY_FILE="$BASE_DIR/backup.key"
ENCRYPT_KEY=""

# [V72 更新] 自动更新源 (GitHub Raw 链接)
UPDATE_URL="https://raw.githubusercontent.com/lje02/wp-manager/main/wp-manager.sh"

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# 初始化目录
mkdir -p "$SITES_DIR" "$GATEWAY_DIR" "$FW_DIR"
touch "$FW_DIR/access.conf" "$FW_DIR/geo.conf"
[ ! -f "$LOG_FILE" ] && touch "$LOG_FILE"
[ ! -f "$BACKUP_KEY_FILE" ] && openssl rand -base64 32 > "$BACKUP_KEY_FILE"
ENCRYPT_KEY=$(cat "$BACKUP_KEY_FILE")

# ================= 2. 基础工具函数 =================

function write_log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

function pause_prompt() {
    echo -e "\n${YELLOW}>>> 操作完成，按回车键返回...${NC}"
    read -r
}

function install_shortcut() {
    local script_path=$(readlink -f "$0")
    if [ ! -L "/usr/bin/wp" ] || [ "$(readlink -f "/usr/bin/wp")" != "$script_path" ]; then
        ln -sf "$script_path" /usr/bin/wp && chmod +x "$script_path"
        echo -e "${GREEN}✔ 已创建快捷命令: wp${NC}"
    fi
}

function check_dependencies() {
    local missing_deps=()
    
    # 检查必需工具
    if ! command -v jq >/dev/null 2>&1; then
        missing_deps+=("jq")
    fi
    if ! command -v openssl >/dev/null 2>&1; then
        missing_deps+=("openssl")
    fi
    if ! command -v curl >/dev/null 2>&1; then
        missing_deps+=("curl")
    fi
    if ! command -v gpg >/dev/null 2>&1; then
        missing_deps+=("gnupg")
    fi
    
    # 安装缺失的依赖
    if [ ${#missing_deps[@]} -gt 0 ]; then
        echo -e "${YELLOW}>>> 正在安装依赖组件 (${missing_deps[*]})...${NC}"
        if [ -f /etc/debian_version ]; then
            apt-get update && apt-get install -y "${missing_deps[@]}"
        else
            yum install -y epel-release && yum install -y "${missing_deps[@]}"
        fi
    fi
    
    # 检查Docker
    if ! command -v docker >/dev/null 2>&1; then
        echo -e "${YELLOW}>>> 正在安装 Docker...${NC}"
        curl -fsSL https://get.docker.com | bash -s docker --mirror Aliyun
        systemctl enable docker && systemctl start docker
        write_log "Installed Docker"
        
        # 安装docker-compose
        if ! command -v docker-compose >/dev/null 2>&1; then
            curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
            chmod +x /usr/local/bin/docker-compose
        fi
    fi
}

function ensure_firewall_installed() {
    if command -v ufw >/dev/null || command -v firewall-cmd >/dev/null; then return 0; fi
    echo -e "${YELLOW}>>> 正在安装防火墙...${NC}"
    if [ -f /etc/debian_version ]; then 
        apt-get update && apt-get install -y ufw
        ufw allow 22/tcp
        ufw allow 80/tcp
        ufw allow 443/tcp
        echo "y" | ufw enable
    elif [ -f /etc/redhat-release ]; then 
        yum install -y firewalld
        systemctl enable firewalld --now
        firewall-cmd --permanent --add-service={ssh,http,https}
        firewall-cmd --reload
    else 
        echo -e "${RED}❌ 系统不支持自动安装防火墙${NC}"
        pause_prompt
        return 1
    fi
    echo -e "${GREEN}✔ 防火墙就绪${NC}"
    sleep 1
}

function check_ssl_status() {
    local domain=$1
    echo -e "${CYAN}>>> [SSL] 正在申请证书...${NC}"
    for ((i=1; i<=20; i++)); do
        if docker exec gateway_acme test -f "/etc/nginx/certs/$domain.crt" 2>/dev/null; then
            echo -e "${GREEN}✔ SSL证书申请成功: https://$domain${NC}"
            
            # 验证证书有效性
            if curl -s -o /dev/null --connect-timeout 10 -w "%{http_code}" "https://$domain" | grep -q "200\|301\|302"; then
                echo -e "${GREEN}✔ 站点 HTTPS 访问正常${NC}"
            else
                echo -e "${YELLOW}⚠️ 站点暂时无法访问，可能是DNS延迟${NC}"
            fi
            
            pause_prompt
            return 0
        fi
        echo -n "."
        sleep 5
    done
    echo -e "\n${YELLOW}⚠️ 证书暂未生成 (可能是DNS延迟或网络问题)${NC}"
    echo -e "${CYAN}>>> 尝试手动验证:${NC}"
    echo "1. 检查域名解析: dig +short $domain"
    echo "2. 查看网关日志: docker logs gateway_acme"
    echo "3. 稍后手动重启: docker restart gateway_acme"
    pause_prompt
}

function normalize_url() {
    local url=$1
    url=${url%/}
    if [[ "$url" != http* ]]; then
        echo "https://$url"
    else
        echo "$url"
    fi
}

function update_script() {
    clear
    echo -e "${GREEN}=== 脚本自动更新 ===${NC}"
    echo -e "版本: $VERSION"
    echo -e "源: GitHub (lje02/wp-manager)"
    
    # 检查当前用户是否有写入权限
    if [ ! -w "$0" ]; then
        echo -e "${RED}❌ 当前用户没有写入权限，请使用sudo运行${NC}"
        pause_prompt
        return 1
    fi
    
    temp_file="/tmp/wp_manager_new.sh"
    # GitHub Raw 通常需要 -L 参数跟随跳转
    echo -e "${CYAN}>>> 正在从 GitHub 下载更新...${NC}"
    
    if curl -f -L -s -o "$temp_file" "$UPDATE_URL" && head -n 1 "$temp_file" | grep -q "/bin/bash"; then
        # 备份旧版本
        cp "$0" "$0.backup.$(date +%Y%m%d%H%M%S)"
        
        # 替换新版本
        mv "$temp_file" "$0"
        chmod +x "$0"
        
        echo -e "${GREEN}✔ 更新成功，正在重启...${NC}"
        write_log "Updated script from GitHub"
        sleep 2
        exec "$0"
    else 
        echo -e "${RED}❌ 更新失败!${NC}"
        echo "可能的原因:"
        echo "1. GitHub 网络连接问题"
        echo "2. 原始地址变更"
        echo "3. 服务器防火墙限制"
        rm -f "$temp_file"
    fi
    pause_prompt
}

function send_tg_msg() {
    local msg=$1
    if [ -f "$TG_CONF" ]; then
        source "$TG_CONF"
        if [ ! -z "$TG_BOT_TOKEN" ] && [ ! -z "$TG_CHAT_ID" ]; then
            curl -s -X POST "https://api.telegram.org/bot$TG_BOT_TOKEN/sendMessage" \
                -d chat_id="$TG_CHAT_ID" \
                -d text="$msg" \
                -d parse_mode="Markdown" >/dev/null 2>&1
        fi
    fi
}

# --- 错误处理函数 ---
function handle_error() {
    local err_msg=$1
    local exit_code=${2:-1}
    
    echo -e "\n${RED}❌ 错误: $err_msg${NC}"
    write_log "ERROR: $err_msg"
    
    # 发送Telegram通知
    if [ -f "$TG_CONF" ]; then
        source "$TG_CONF"
        if [ ! -z "$TG_BOT_TOKEN" ] && [ ! -z "$TG_CHAT_ID" ]; then
            local hostname=$(hostname)
            local ip=$(curl -s4 ifconfig.me 2>/dev/null || echo "未知")
            curl -s -X POST "https://api.telegram.org/bot$TG_BOT_TOKEN/sendMessage" \
                -d chat_id="$TG_CHAT_ID" \
                -d text="❌ *脚本错误报警*
主机: $hostname ($ip)
错误: $err_msg
时间: $(date '+%Y-%m-%d %H:%M:%S')" \
                -d parse_mode="Markdown" >/dev/null 2>&1
        fi
    fi
    
    # 如果不是致命错误，不退出
    if [ $exit_code -ne 0 ]; then
        echo -e "${YELLOW}>>> 按回车键继续...${NC}"
        read -r
    fi
}

# --- 验证函数 ---
function validate_password() {
    local pass=$1
    local min_length=8
    
    if [ ${#pass} -lt $min_length ]; then
        echo -e "${RED}❌ 密码至少需要 $min_length 位${NC}"
        return 1
    fi
    
    # 检查是否包含数字和字母
    if ! [[ "$pass" =~ [0-9] ]] || ! [[ "$pass" =~ [a-zA-Z] ]]; then
        echo -e "${YELLOW}⚠️ 建议: 密码应包含数字和字母${NC}"
        # 不强求，只警告
    fi
    
    return 0
}

function validate_compose() {
    local dir=$1
    local compose_file="$dir/docker-compose.yml"
    
    if [ ! -f "$compose_file" ]; then
        handle_error "配置文件不存在: $compose_file"
        return 1
    fi
    
    # 检查语法
    if docker compose -f "$compose_file" config --quiet 2>/dev/null; then
        echo -e "${GREEN}✔ 配置文件语法正确${NC}"
        return 0
    else
        handle_error "docker-compose.yml 语法错误"
        return 1
    fi
}

function check_site_health() {
    local domain=$1
    local timeout=10
    
    echo -e "${CYAN}>>> 检查站点健康状态...${NC}"
    
    # 检查HTTP响应
    local http_code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout $timeout "https://$domain" 2>/dev/null)
    
    case $http_code in
        200|301|302)
            echo -e "${GREEN}✔ 站点访问正常 (HTTP $http_code)${NC}"
            return 0
            ;;
        000)
            echo -e "${YELLOW}⚠️ 站点无法访问 (连接超时)${NC}"
            return 1
            ;;
        4*)
            echo -e "${YELLOW}⚠️ 客户端错误 (HTTP $http_code)${NC}"
            return 1
            ;;
        5*)
            echo -e "${RED}❌ 服务器错误 (HTTP $http_code)${NC}"
            return 1
            ;;
        *)
            echo -e "${YELLOW}⚠️ 未知响应 (HTTP $http_code)${NC}"
            return 1
            ;;
    esac
}

# --- 性能监控函数 ---
function monitor_container_resources() {
    clear
    echo -e "${GREEN}=== 容器资源使用监控 ===${NC}"
    
    # 获取所有容器资源使用情况
    docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}" \
        | head -20
    
    echo -e "\n${CYAN}资源使用统计:${NC}"
    
    # 统计容器数量
    local total_containers=$(docker ps -q | wc -l)
    local running_containers=$(docker ps -q --filter "status=running" | wc -l)
    
    echo "总容器数: $total_containers"
    echo "运行中: $running_containers"
    echo "停止状态: $((total_containers - running_containers))"
    
    # 检查资源异常
    local high_cpu=$(docker stats --no-stream --format "{{.CPUPerc}}" | tr -d '%' | awk '$1 > 80' | wc -l)
    local high_mem=$(docker stats --no-stream --format "{{.MemPerc}}" | tr -d '%' | awk '$1 > 80' | wc -l)
    
    if [ $high_cpu -gt 0 ]; then
        echo -e "${YELLOW}⚠️ 发现 $high_cpu 个容器CPU使用率超过80%${NC}"
    fi
    
    if [ $high_mem -gt 0 ]; then
        echo -e "${YELLOW}⚠️ 发现 $high_mem 个容器内存使用率超过80%${NC}"
    fi
    
    pause_prompt
}

# --- 备份加密函数 ---
function backup_with_encryption() {
    local source_dir=$1
    local output_file=$2
    local encrypt=${3:-true}
    
    if [ "$encrypt" = "true" ]; then
        echo -e "${CYAN}>>> 正在加密备份...${NC}"
        tar czf - -C "$source_dir" . | gpg --batch --yes --passphrase "$ENCRYPT_KEY" --symmetric --cipher-algo AES256 -o "$output_file.gpg"
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✔ 备份已加密: $output_file.gpg${NC}"
            return 0
        else
            handle_error "备份加密失败"
            return 1
        fi
    else
        tar czf "$output_file" -C "$source_dir" .
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✔ 备份完成: $output_file${NC}"
            return 0
        else
            handle_error "备份创建失败"
            return 1
        fi
    fi
}

function restore_with_decryption() {
    local backup_file=$1
    local target_dir=$2
    
    if [[ "$backup_file" == *.gpg ]]; then
        echo -e "${CYAN}>>> 正在解密恢复...${NC}"
        mkdir -p "$target_dir"
        gpg --batch --yes --passphrase "$ENCRYPT_KEY" --decrypt "$backup_file" 2>/dev/null | tar xz -C "$target_dir"
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✔ 恢复完成${NC}"
            return 0
        else
            handle_error "解密恢复失败"
            return 1
        fi
    else
        tar xzf "$backup_file" -C "$target_dir"
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✔ 恢复完成${NC}"
            return 0
        else
            handle_error "恢复失败"
            return 1
        fi
    fi
}

# --- 后台脚本生成器 ---
function generate_monitor_script() {
    cat > "$MONITOR_SCRIPT" <<EOF
#!/bin/bash
TG_CONF="$TG_CONF"
CPU_THRESHOLD=90
MEM_THRESHOLD=90
DISK_THRESHOLD=90
COOLDOWN=1800
LAST_ALERT=0

function send_msg() {
    if [ -f "\$TG_CONF" ]; then
        source "\$TG_CONF"
        curl -s -X POST "https://api.telegram.org/bot\$TG_BOT_TOKEN/sendMessage" \
            -d chat_id="\$TG_CHAT_ID" \
            -d text="\$1" \
            -d parse_mode="Markdown" >/dev/null
    fi
}

while true; do
    CPU=\$(grep 'cpu ' /proc/stat | awk '{usage=(\$2+\$4)*100/(\$2+\$4+\$5)} END {print usage}' | cut -d. -f1)
    MEM=\$(free | grep Mem | awk '{print \$3/\$2 * 100.0}' | cut -d. -f1)
    DISK=\$(df / | awk 'NR==2 {print \$5}' | sed 's/%//')
    
    MSG=""
    if [ "\$CPU" -gt "\$CPU_THRESHOLD" ]; then
        MSG="\$MSG\n🚨 CPU过高: \${CPU}%"
    fi
    if [ "\$MEM" -gt "\$MEM_THRESHOLD" ]; then
        MSG="\$MSG\n🚨 内存过高: \${MEM}%"
    fi
    if [ "\$DISK" -gt "\$DISK_THRESHOLD" ]; then
        MSG="\$MSG\n🚨 磁盘爆满: \${DISK}%"
    fi
    
    if [ ! -z "\$MSG" ]; then
        NOW=\$(date +%s)
        DIFF=\$((NOW - LAST_ALERT))
        if [ "\$DIFF" -gt "\$COOLDOWN" ]; then
            send_msg "⚠️ **资源警报** 
主机: \$(hostname)
IP: \$(curl -s4 ifconfig.me || echo '未知')
\$MSG"
            LAST_ALERT=\$NOW
        fi
    fi
    sleep 60
done
EOF
    chmod +x "$MONITOR_SCRIPT"
}

function generate_listener_script() {
    cat > "$LISTENER_SCRIPT" <<EOF
#!/bin/bash
TG_CONF="$TG_CONF"
GATEWAY_DIR="$GATEWAY_DIR"
SITES_DIR="$SITES_DIR"

if [ ! -f "\$TG_CONF" ]; then exit 1; fi
source "\$TG_CONF"
OFFSET=0

function reply() {
    curl -s -X POST "https://api.telegram.org/bot\$TG_BOT_TOKEN/sendMessage" \
        -d chat_id="\$TG_CHAT_ID" \
        -d text="\$1" \
        -d parse_mode="Markdown" >/dev/null
}

while true; do
    updates=\$(curl -s "https://api.telegram.org/bot\$TG_BOT_TOKEN/getUpdates?offset=\$OFFSET&timeout=30")
    status=\$(echo "\$updates" | jq -r '.ok')
    
    if [ "\$status" != "true" ]; then
        sleep 5
        continue
    fi
    
    count=\$(echo "\$updates" | jq '.result | length')
    if [ "\$count" -eq "0" ]; then
        continue
    fi
    
    echo "\$updates" | jq -c '.result[]' | while read row; do
        update_id=\$(echo "\$row" | jq '.update_id')
        message_text=\$(echo "\$row" | jq -r '.message.text')
        sender_id=\$(echo "\$row" | jq -r '.message.chat.id')
        
        if [ "\$sender_id" == "\$TG_CHAT_ID" ]; then
            case "\$message_text" in
                "/status"|"/状态")
                    cpu_load=\$(uptime | awk -F'load average:' '{print \$2}')
                    mem_usage=\$(free -h | grep Mem | awk '{print \$3 "/" \$2 " (" \$3/\$2*100 "% )"}')
                    disk_usage=\$(df -h / | awk 'NR==2 {print \$3 "/" \$2 " (" \$5 ")"}')
                    ip=\$(curl -s4 ifconfig.me)
                    container_count=\$(docker ps -q | wc -l)
                    
                    reply "📊 **系统状态**
💻 IP: \$ip
🧠 负载: \$cpu_load
💾 内存: \$mem_usage
💿 磁盘: \$disk_usage
🐳 容器: \$container_count 个运行中"
                    ;;
                    
                "/reboot_nginx"|"/重启nginx")
                    if [ -d "\$GATEWAY_DIR" ]; then
                        cd "\$GATEWAY_DIR"
                        docker compose restart nginx-proxy
                        reply "✅ Nginx 网关已重启"
                    else
                        reply "❌ 找不到网关目录"
                    fi
                    ;;
                    
                "/sites"|"/站点")
                    sites=\$(ls -1 "\$SITES_DIR" 2>/dev/null | head -10)
                    if [ -z "\$sites" ]; then
                        reply "📂 暂无站点"
                    else
                        reply "📂 **站点列表**
\`\`\`
\$sites
\`\`\`"
                    fi
                    ;;
                    
                "/help"|"/帮助")
                    reply "🤖 **可用命令**
/status - 系统状态
/sites - 站点列表
/reboot_nginx - 重启Nginx
/help - 显示帮助"
                    ;;
            esac
        fi
        next_offset=\$((update_id + 1))
        echo \$next_offset > /tmp/tg_offset.txt
    done
    
    if [ -f /tmp/tg_offset.txt ]; then
        OFFSET=\$(cat /tmp/tg_offset.txt)
    fi
done
EOF
    chmod +x "$LISTENER_SCRIPT"
}

# ================= 3. 业务功能函数 =================

function security_center() {
    while true; do
        clear
        echo -e "${YELLOW}=== 🛡️ 安全防御中心 (V72) ===${NC}"
        
        # 1. 防火墙状态
        if command -v ufw >/dev/null; then
            if ufw status | grep -q "active"; then 
                FW_ST="${GREEN}● 运行中 (UFW)${NC}"
                FW_RULES=$(ufw status numbered | grep -c "^\[")
            else 
                FW_ST="${RED}● 未启动${NC}"
                FW_RULES=0
            fi
        elif command -v firewall-cmd >/dev/null; then
            if firewall-cmd --state 2>&1 | grep -q "running"; then 
                FW_ST="${GREEN}● 运行中 (Firewalld)${NC}"
                FW_RULES=$(firewall-cmd --list-all | grep -c "ports\|services")
            else 
                FW_ST="${RED}● 未启动${NC}"
                FW_RULES=0
            fi
        else
            FW_ST="${YELLOW}● 未安装${NC}"
            FW_RULES=0
        fi

        # 2. Fail2Ban状态
        if command -v fail2ban-client >/dev/null; then
            if systemctl is-active fail2ban >/dev/null 2>&1; then 
                F2B_ST="${GREEN}● 运行中${NC}"
                F2B_JAIL=$(fail2ban-client status | grep -c "Jail list:")
            else 
                F2B_ST="${RED}● 已停止${NC}"
                F2B_JAIL=0
            fi
        else
            F2B_ST="${YELLOW}● 未安装${NC}"
            F2B_JAIL=0
        fi

        # 3. WAF状态
        if [ -z "$(ls -A $SITES_DIR 2>/dev/null)" ]; then
            WAF_ST="${YELLOW}● 无站点${NC}"
            WAF_COUNT=0
        else
            WAF_COUNT=$(grep -r "V69 Ultra WAF Rules" "$SITES_DIR" 2>/dev/null | wc -l)
            if [ $WAF_COUNT -gt 0 ]; then 
                WAF_ST="${GREEN}● 已部署 (增强版)${NC}"
            elif grep -r "waf.conf" "$SITES_DIR" >/dev/null 2>&1; then 
                WAF_ST="${YELLOW}● 已部署 (基础版)${NC}"
                WAF_COUNT=$(grep -r "waf.conf" "$SITES_DIR" 2>/dev/null | wc -l)
            else 
                WAF_ST="${RED}● 未部署${NC}"
                WAF_COUNT=0
            fi
        fi
        
        # 4. SSL证书状态
        SSL_COUNT=0
        if docker ps --format '{{.Names}}' | grep -q "^gateway_acme$"; then
            SSL_COUNT=$(docker exec gateway_acme ls -1 /etc/nginx/certs/*.crt 2>/dev/null | wc -l)
        fi
        if [ $SSL_COUNT -gt 0 ]; then
            SSL_ST="${GREEN}● $SSL_COUNT 个证书${NC}"
        else
            SSL_ST="${YELLOW}● 无证书${NC}"
        fi

        echo -e " 1. 端口防火墙   [$FW_ST] (规则: $FW_RULES)"
        echo -e " 2. 流量访问控制 (Nginx Layer7)"
        echo -e " 3. SSH防暴力破解 [$F2B_ST] (监狱: $F2B_JAIL)"
        echo -e " 4. 网站防火墙    [$WAF_ST] (站点: $WAF_COUNT)"
        echo -e " 5. HTTPS证书管理 [$SSL_ST]"
        echo -e " 6. 防盗链设置"
        echo -e " 7. 安全扫描 (端口/漏洞)"
        echo " 0. 返回主菜单"
        echo "--------------------------"
        read -p "请输入选项 [0-7]: " s
        case $s in 
            0) return;; 
            1) port_manager;; 
            2) traffic_manager;; 
            3) fail2ban_manager;; 
            4) waf_manager;; 
            5) cert_management;; 
            6) manage_hotlink;; 
            7) security_scan;; 
        esac
    done 
}

function security_scan() {
    clear
    echo -e "${YELLOW}=== 🔍 安全扫描 ===${NC}"
    
    echo -e "${CYAN}1. 端口扫描${NC}"
    echo -e "${CYAN}2. 漏洞检查${NC}"
    echo -e "${CYAN}3. 恶意进程检测${NC}"
    echo "0. 返回"
    echo "--------------------------"
    read -p "选择: " scan_opt
    
    case $scan_opt in
        1)
            echo -e "${YELLOW}>>> 扫描开放端口...${NC}"
            if command -v netstat >/dev/null; then
                netstat -tulpn | grep LISTEN
            elif command -v ss >/dev/null; then
                ss -tulpn
            else
                echo -e "${RED}❌ 未找到网络工具${NC}"
            fi
            
            # 检查危险端口
            echo -e "\n${CYAN}>>> 检查危险端口...${NC}"
            local dangerous_ports="21 23 25 110 135 137 138 139 445 1433 3306 3389 5900"
            for port in $dangerous_ports; do
                if ss -tulpn | grep ":$port " >/dev/null; then
                    echo -e "${RED}⚠️ 危险端口 $port 开放${NC}"
                fi
            done
            ;;
            
        2)
            echo -e "${YELLOW}>>> 检查常见漏洞...${NC}"
            
            # 检查Docker权限
            if docker ps 2>&1 | grep -q "permission denied"; then
                echo -e "${GREEN}✔ Docker需要sudo权限${NC}"
            else
                echo -e "${YELLOW}⚠️ Docker无需sudo权限${NC}"
            fi
            
            # 检查SSH配置
            if [ -f /etc/ssh/sshd_config ]; then
                if grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config; then
                    echo -e "${RED}❌ SSH允许root登录${NC}"
                else
                    echo -e "${GREEN}✔ SSH禁止root登录${NC}"
                fi
            fi
            
            # 检查空密码账户
            if [ -f /etc/shadow ]; then
                local empty_pass=$(awk -F: '($2 == "" || $2 == "!" || $2 == "!!") {print $1}' /etc/shadow)
                if [ -n "$empty_pass" ]; then
                    echo -e "${RED}❌ 存在空密码账户: $empty_pass${NC}"
                else
                    echo -e "${GREEN}✔ 无空密码账户${NC}"
                fi
            fi
            ;;
            
        3)
            echo -e "${YELLOW}>>> 检测恶意进程...${NC}"
            # 检查挖矿进程
            local mining_processes="xmrig cpuminer minerd ccminer"
            for proc in $mining_processes; do
                if pgrep -f "$proc" >/dev/null; then
                    echo -e "${RED}❌ 发现挖矿进程: $proc${NC}"
                fi
            done
            
            # 检查异常网络连接
            echo -e "\n${CYAN}>>> 检查异常连接...${NC}"
            if command -v netstat >/dev/null; then
                netstat -anp | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -10
            fi
            ;;
    esac
    
    pause_prompt
}

function telegram_manager() {
    while true; do
        clear
        echo -e "${YELLOW}=== 🤖 Telegram 机器人管理 ===${NC}"
        
        if [ -f "$TG_CONF" ]; then 
            source "$TG_CONF" 2>/dev/null
            if [ ! -z "$TG_BOT_TOKEN" ] && [ ! -z "$TG_CHAT_ID" ]; then
                echo -e "${GREEN}✓ 已配置${NC}"
                echo -e "Token: ${TG_BOT_TOKEN:0:10}***"
                echo -e "ChatID: $TG_CHAT_ID"
            else
                echo -e "${RED}✗ 配置不完整${NC}"
            fi
        else
            echo -e "${YELLOW}⚠️ 未配置${NC}"
        fi
        
        # 检查进程状态
        if [ -f "$MONITOR_PID" ] && kill -0 $(cat "$MONITOR_PID") 2>/dev/null; then 
            M_STAT="${GREEN}运行中${NC} (PID: $(cat $MONITOR_PID))"
        else 
            M_STAT="${RED}未启动${NC}"
        fi
        
        if [ -f "$LISTENER_PID" ] && kill -0 $(cat "$LISTENER_PID") 2>/dev/null; then 
            L_STAT="${GREEN}运行中${NC} (PID: $(cat $LISTENER_PID))"
        else 
            L_STAT="${RED}未启动${NC}"
        fi
        
        echo -e "守护进程: $M_STAT"
        echo -e "指令监听: $L_STAT"
        echo "--------------------------"
        echo " 1. 配置 Token 和 ChatID"
        echo " 2. 启动/重启 资源报警 (守护进程)"
        echo " 3. 启动/重启 指令监听 (交互模式)"
        echo " 4. 停止所有后台进程"
        echo " 5. 发送测试消息"
        echo " 6. 查看日志"
        echo " 0. 返回上一级"
        echo "--------------------------"
        read -p "请输入选项 [0-6]: " t
        
        case $t in
            0) 
                return
                ;;
                
            1) 
                read -p "Bot Token: " tk
                if [ -z "$tk" ]; then
                    echo -e "${RED}❌ Token不能为空${NC}"
                    pause_prompt
                    continue
                fi
                
                read -p "Chat ID: " ci
                if ! [[ "$ci" =~ ^-?[0-9]+$ ]]; then
                    echo -e "${RED}❌ Chat ID必须是数字${NC}"
                    pause_prompt
                    continue
                fi
                
                echo "TG_BOT_TOKEN=\"$tk\"" > "$TG_CONF"
                echo "TG_CHAT_ID=\"$ci\"" >> "$TG_CONF"
                echo -e "${GREEN}✔ 配置已保存${NC}"
                
                # 测试配置
                echo -e "${CYAN}>>> 测试配置...${NC}"
                send_tg_msg "✅ Telegram 机器人配置成功
时间: $(date '+%Y-%m-%d %H:%M:%S')
主机: $(hostname)"
                pause_prompt
                ;;
                
            2) 
                generate_monitor_script
                if [ -f "$MONITOR_PID" ]; then
                    local old_pid=$(cat "$MONITOR_PID")
                    if kill -0 $old_pid 2>/dev/null; then
                        kill $old_pid
                        echo -e "${YELLOW}⚠️ 停止旧进程 (PID: $old_pid)${NC}"
                    fi
                fi
                
                nohup "$MONITOR_SCRIPT" >/dev/null 2>&1 &
                echo $! > "$MONITOR_PID"
                
                send_tg_msg "🔔 资源监控已启动"
                echo -e "${GREEN}✔ 资源监控已启动 (PID: $(cat $MONITOR_PID))${NC}"
                pause_prompt
                ;;
                
            3) 
                check_dependencies
                if ! command -v jq >/dev/null; then
                    echo -e "${RED}❌ 需要 jq 依赖${NC}"
                    pause_prompt
                    continue
                fi
                
                generate_listener_script
                if [ -f "$LISTENER_PID" ]; then
                    local old_pid=$(cat "$LISTENER_PID")
                    if kill -0 $old_pid 2>/dev/null; then
                        kill $old_pid
                        echo -e "${YELLOW}⚠️ 停止旧进程 (PID: $old_pid)${NC}"
                    fi
                fi
                
                nohup "$LISTENER_SCRIPT" >/dev/null 2>&1 &
                echo $! > "$LISTENER_PID"
                
                send_tg_msg "📡 指令监听已启动
可用命令: /status /sites /reboot_nginx /help"
                echo -e "${GREEN}✔ 指令监听已启动 (PID: $(cat $LISTENER_PID))${NC}"
                pause_prompt
                ;;
                
            4) 
                if [ -f "$MONITOR_PID" ]; then
                    kill $(cat "$MONITOR_PID") 2>/dev/null
                    rm -f "$MONITOR_PID"
                    echo -e "${YELLOW}⚠️ 停止监控进程${NC}"
                fi
                
                if [ -f "$LISTENER_PID" ]; then
                    kill $(cat "$LISTENER_PID") 2>/dev/null
                    rm -f "$LISTENER_PID"
                    echo -e "${YELLOW}⚠️ 停止监听进程${NC}"
                fi
                
                send_tg_msg "🛑 所有后台进程已停止"
                echo -e "${GREEN}✔ 所有进程已停止${NC}"
                pause_prompt
                ;;
                
            5) 
                send_tg_msg "🧪 测试消息
时间: $(date '+%Y-%m-%d %H:%M:%S')
主机: $(hostname)
IP: $(curl -s4 ifconfig.me || echo '未知')"
                echo -e "${GREEN}✔ 测试消息已发送${NC}"
                pause_prompt
                ;;
                
            6)
                echo -e "${CYAN}>>> 监控日志 (最后20行)${NC}"
                if [ -f "$BASE_DIR/monitor.log" ]; then
                    tail -20 "$BASE_DIR/monitor.log"
                else
                    echo "暂无日志"
                fi
                pause_prompt
                ;;
        esac
    done
}

function sys_monitor() {
    while true; do
        clear
        echo -e "${YELLOW}=== 🖥️ 系统资源监控 ===${NC}"
        
        # CPU信息
        echo -e "${CYAN}[CPU]${NC}"
        echo -e "  负载 : $(uptime | awk -F'average:' '{print $2}')"
        echo -e "  核心 : $(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo) 核"
        
        # 内存信息
        if command -v free >/dev/null; then
            echo -e "\n${CYAN}[内存]${NC}"
            free -h | awk '
                /Mem:/ {printf "  使用 : %s/%s (%.1f%%)\n", $3, $2, $3/$2*100}
                /Swap:/ {printf "  交换 : %s/%s\n", $3, $2}
            '
        fi
        
        # 磁盘信息
        echo -e "\n${CYAN}[磁盘]${NC}"
        df -h / | awk 'NR==2 {printf "  根目录 : %s/%s (%s)\n", $3, $2, $5}'
        
        # 系统信息
        echo -e "\n${CYAN}[系统]${NC}"
        echo -e "  运行时间 : $(uptime -p | sed 's/up //')"
        echo -e "  系统时间 : $(date '+%Y-%m-%d %H:%M:%S')"
        
        # 网络信息
        echo -e "\n${CYAN}[网络]${NC}"
        echo -e "  公网IP : $(curl -s4 ifconfig.me || echo '未知')"
        
        # Docker信息
        if command -v docker >/dev/null; then
            echo -e "\n${CYAN}[Docker]${NC}"
            echo -e "  容器 : $(docker ps -q | wc -l) 运行中 / $(docker ps -aq | wc -l) 总计"
            echo -e "  镜像 : $(docker images -q | wc -l) 个"
        fi
        
        echo -e "\n${BLUE}----------------------------${NC}"
        echo -e " 1. 容器资源详情"
        echo -e " 2. 实时刷新 (5秒)"
        echo " 0. 返回上一级"
        echo "--------------------------"
        read -t 10 -p "请输入选项 [0-2]: " o
        
        case $o in
            0) return ;;
            1) monitor_container_resources ;;
            2) 
                echo -e "${CYAN}>>> 实时刷新中... (Ctrl+C退出)${NC}"
                for i in {1..5}; do
                    clear
                    # 简化显示实时信息
                    echo -e "${YELLOW}=== 实时监控 ===${NC}"
                    echo -e "CPU负载: $(uptime | awk -F'average:' '{print $2}')"
                    echo -e "内存: $(free -h | grep Mem | awk '{print $3"/"$2 " (" $3/$2*100 "% )"}')"
                    echo -e "时间: $(date '+%H:%M:%S')"
                    sleep 5
                done
                ;;
        esac
    done
}

function log_manager() { 
    while true; do 
        clear
        echo -e "${YELLOW}=== 📜 日志管理系统 ===${NC}"
        
        local log_size=$(du -h "$LOG_FILE" 2>/dev/null | awk '{print $1}')
        local log_lines=$(wc -l "$LOG_FILE" 2>/dev/null | awk '{print $1}')
        
        echo -e "当前日志: $log_lines 行 ($log_size)"
        echo "--------------------------"
        echo " 1. 查看最新日志 (Top 50)"
        echo " 2. 查看错误日志"
        echo " 3. 清空日志文件"
        echo " 4. 配置定时清理任务 (7天)"
        echo " 5. 导出日志"
        echo " 0. 返回上一级"
        echo "--------------------------"
        read -p "请输入选项 [0-5]: " l
        
        case $l in 
            0) 
                return
                ;; 
                
            1) 
                echo -e "${CYAN}>>> 最新50条日志${NC}"
                tail -n 50 "$LOG_FILE" | awk '
                    /ERROR/ {printf "\033[0;31m%s\033[0m\n", $0; next}
                    /WARN/ {printf "\033[1;33m%s\033[0m\n", $0; next}
                    /INFO/ {printf "\033[0;32m%s\033[0m\n", $0; next}
                    {print}
                '
                pause_prompt
                ;; 
                
            2) 
                echo -e "${RED}>>> 错误日志${NC}"
                grep -i "error\|fail\|failed\|异常\|失败" "$LOG_FILE" | tail -20
                pause_prompt
                ;; 
                
            3) 
                echo -n "" > "$LOG_FILE"
                echo -e "${GREEN}✔ 日志已清空${NC}"
                write_log "清空日志文件"
                pause_prompt
                ;; 
                
            4) 
                # 清除旧任务
                crontab -l 2>/dev/null | grep -v "wp-cluster" | crontab -
                
                # 添加新任务
                (crontab -l 2>/dev/null; echo "0 3 * * * find $BASE_DIR -name '*.log' -mtime +7 -delete #wp-cluster-log-clean") | crontab -
                
                echo -e "${GREEN}✔ 定时任务已配置 (每天3点清理7天前日志)${NC}"
                
                # 显示当前crontab
                echo -e "\n${CYAN}当前定时任务:${NC}"
                crontab -l 2>/dev/null | grep -v "^#"
                pause_prompt
                ;; 
                
            5)
                local backup_file="$BASE_DIR/logs_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
                mkdir -p "$BASE_DIR/logs_backup"
                cp "$LOG_FILE" "$BASE_DIR/logs_backup/"
                tar czf "$backup_file" -C "$BASE_DIR/logs_backup" .
                rm -rf "$BASE_DIR/logs_backup"
                echo -e "${GREEN}✔ 日志已导出到: $backup_file${NC}"
                pause_prompt
                ;;
        esac
    done 
}

function container_ops() { 
    while true; do 
        clear
        echo -e "${YELLOW}=== 📊 容器状态监控 ===${NC}"
        
        # 网关状态
        if [ -d "$GATEWAY_DIR" ]; then
            echo -e "${CYAN}【核心网关】${NC}"
            cd "$GATEWAY_DIR"
            if docker compose ps --services 2>/dev/null >/dev/null; then
                docker compose ps --format "table {{.Service}}\t{{.State}}\t{{.Status}}\t{{.Ports}}" | tail -n +2
            else
                echo -e "${YELLOW}⚠️ 网关未运行${NC}"
            fi
            echo ""
        fi
        
        # 站点状态
        local site_count=0
        for d in "$SITES_DIR"/*; do 
            if [ -d "$d" ]; then
                ((site_count++))
                site_name=$(basename "$d")
                echo -e "${CYAN}【站点: $site_name】${NC}"
                cd "$d"
                if docker compose ps --services 2>/dev/null >/dev/null; then
                    docker compose ps --format "table {{.Service}}\t{{.State}}\t{{.Status}}" | tail -n +2
                else
                    echo -e "${YELLOW}⚠️ 未运行${NC}"
                fi
                echo ""
            fi
        done
        
        if [ $site_count -eq 0 ]; then
            echo -e "${YELLOW}暂无站点${NC}"
        fi
        
        echo "--------------------------"
        echo " 1. 全部启动 (Start All)"
        echo " 2. 全部停止 (Stop All)"
        echo " 3. 全部重启 (Restart All)"
        echo " 4. 指定站点操作"
        echo " 5. 清理无用镜像/容器"
        echo " 0. 返回上一级"
        echo "--------------------------"
        read -p "请输入选项 [0-5]: " c
        
        case $c in 
            0) 
                return
                ;; 
                
            1) 
                echo -e "${CYAN}>>> 启动所有容器...${NC}"
                
                # 启动网关
                if [ -d "$GATEWAY_DIR" ]; then
                    cd "$GATEWAY_DIR"
                    docker compose up -d 2>&1 | grep -v "up-to-date"
                    echo -e "网关: ${GREEN}已启动${NC}"
                fi
                
                # 启动站点
                local started=0
                for d in "$SITES_DIR"/*; do
                    if [ -d "$d" ]; then
                        cd "$d"
                        docker compose up -d 2>&1 | grep -v "up-to-date"
                        ((started++))
                    fi
                done
                
                echo -e "${GREEN}✔ 已启动 $started 个站点${NC}"
                write_log "Started all containers"
                pause_prompt
                ;; 
                
            2) 
                read -p "确认停止所有容器？(y/n): " confirm
                if [ "$confirm" != "y" ]; then
                    echo "操作取消"
                    pause_prompt
                    continue
                fi
                
                echo -e "${CYAN}>>> 停止所有容器...${NC}"
                
                # 停止站点
                local stopped=0
                for d in "$SITES_DIR"/*; do
                    if [ -d "$d" ]; then
                        cd "$d"
                        docker compose stop 2>/dev/null
                        ((stopped++))
                    fi
                done
                
                # 停止网关
                if [ -d "$GATEWAY_DIR" ]; then
                    cd "$GATEWAY_DIR"
                    docker compose stop 2>/dev/null
                    echo -e "网关: ${YELLOW}已停止${NC}"
                fi
                
                echo -e "${GREEN}✔ 已停止 $stopped 个站点${NC}"
                write_log "Stopped all containers"
                pause_prompt
                ;; 
                
            3) 
                echo -e "${CYAN}>>> 重启所有容器...${NC}"
                
                # 重启网关
                if [ -d "$GATEWAY_DIR" ]; then
                    cd "$GATEWAY_DIR"
                    docker compose restart 2>&1 | grep -v "up-to-date"
                    echo -e "网关: ${GREEN}已重启${NC}"
                fi
                
                # 重启站点
                local restarted=0
                for d in "$SITES_DIR"/*; do
                    if [ -d "$d" ]; then
                        cd "$d"
                        docker compose restart 2>&1 | grep -v "up-to-date"
                        ((restarted++))
                    fi
                done
                
                echo -e "${GREEN}✔ 已重启 $restarted 个站点${NC}"
                write_log "Restarted all containers"
                pause_prompt
                ;; 
                
            4) 
                if [ ! -d "$SITES_DIR" ] || [ -z "$(ls -A $SITES_DIR 2>/dev/null)" ]; then
                    echo -e "${YELLOW}暂无站点${NC}"
                    pause_prompt
                    continue
                fi
                
                echo -e "${CYAN}可用站点:${NC}"
                ls -1 "$SITES_DIR"
                echo ""
                read -p "输入域名: " site_domain
                
                if [ ! -d "$SITES_DIR/$site_domain" ]; then
                    echo -e "${RED}❌ 站点不存在${NC}"
                    pause_prompt
                    continue
                fi
                
                cd "$SITES_DIR/$site_domain"
                echo -e "当前目录: $(pwd)"
                echo ""
                echo " 1. 启动"
                echo " 2. 停止"
                echo " 3. 重启"
                echo " 4. 查看日志"
                echo " 5. 查看配置"
                echo " 0. 返回"
                echo "--------------------------"
                read -p "选择操作: " site_op
                
                case $site_op in
                    1)
                        docker compose up -d
                        echo -e "${GREEN}✔ 站点已启动${NC}"
                        ;;
                    2)
                        docker compose stop
                        echo -e "${YELLOW}⚠️ 站点已停止${NC}"
                        ;;
                    3)
                        docker compose restart
                        echo -e "${GREEN}✔ 站点已重启${NC}"
                        ;;
                    4)
                        echo -e "${CYAN}>>> 容器日志 (Ctrl+C退出)${NC}"
                        docker compose logs --tail=20 -f
                        ;;
                    5)
                        echo -e "${CYAN}>>> Docker Compose 配置${NC}"
                        cat docker-compose.yml | head -30
                        ;;
                esac
                pause_prompt
                ;; 
                
            5)
                echo -e "${CYAN}>>> 清理无用资源...${NC}"
                
                # 清理无用镜像
                local dangling_images=$(docker images -f "dangling=true" -q)
                if [ -n "$dangling_images" ]; then
                    docker rmi $dangling_images 2>/dev/null | wc -l | awk '{print "删除悬空镜像: "$1" 个"}'
                else
                    echo "无悬空镜像"
                fi
                
                # 清理停止的容器
                local stopped_containers=$(docker ps -aq -f "status=exited")
                if [ -n "$stopped_containers" ]; then
                    docker rm $stopped_containers 2>/dev/null | wc -l | awk '{print "删除停止容器: "$1" 个"}'
                else
                    echo "无停止容器"
                fi
                
                # 清理无用卷
                docker volume prune -f 2>/dev/null | grep -o "deleted.*" || echo "无无用卷"
                
                echo -e "${GREEN}✔ 清理完成${NC}"
                pause_prompt
                ;;
        esac
    done 
}

function component_manager() { 
    while true; do 
        clear
        echo -e "${YELLOW}=== 🆙 组件版本升降级 ===${NC}"
        
        # 列出所有站点
        if [ ! -d "$SITES_DIR" ] || [ -z "$(ls -A $SITES_DIR 2>/dev/null)" ]; then
            echo -e "${YELLOW}暂无站点${NC}"
            pause_prompt
            return
        fi
        
        echo -e "${CYAN}可用站点:${NC}"
        ls -1 "$SITES_DIR"
        echo "--------------------------"
        read -p "输入域名 (0返回): " d
        
        [ "$d" == "0" ] && return
        
        sdir="$SITES_DIR/$d"
        if [ ! -d "$sdir" ]; then
            echo -e "${RED}❌ 站点不存在${NC}"
            pause_prompt
            continue
        fi
        
        # 获取当前版本
        cur_wp=$(grep "image: wordpress" "$sdir/docker-compose.yml" 2>/dev/null | awk '{print $2}' | cut -d: -f2)
        cur_db=$(grep -E "image: (mysql|mariadb)" "$sdir/docker-compose.yml" 2>/dev/null | awk '{print $2}')
        cur_redis=$(grep "image: redis" "$sdir/docker-compose.yml" 2>/dev/null | awk '{print $2}')
        cur_nginx=$(grep "image: nginx" "$sdir/docker-compose.yml" 2>/dev/null | head -1 | awk '{print $2}' | cut -d: -f2)
        
        echo -e "当前版本:"
        echo -e "  PHP    : ${cur_wp:-未知}"
        echo -e "  数据库  : ${cur_db:-未知}"
        echo -e "  Redis  : ${cur_redis:-未知}"
        echo -e "  Nginx  : ${cur_nginx:-未知}"
        echo "--------------------------"
        echo " 1. 切换 PHP 版本"
        echo " 2. 切换 数据库 版本 (高危)"
        echo " 3. 切换 Redis 版本"
        echo " 4. 切换 Nginx 版本"
        echo " 5. 批量升级所有站点"
        echo " 0. 返回上一级"
        echo "--------------------------"
        read -p "请输入选项 [0-5]: " op
        
        case $op in 
            0) 
                break
                ;; 
                
            1) 
                echo -e "${CYAN}选择 PHP 版本:${NC}"
                echo "1. PHP 7.4"
                echo "2. PHP 8.0"
                echo "3. PHP 8.1"
                echo "4. PHP 8.2"
                echo "5. PHP 8.3"
                echo "6. 最新版 (latest)"
                read -p "选择: " p
                
                case $p in
                    1) t="php7.4-fpm-alpine" ;;
                    2) t="php8.0-fpm-alpine" ;;
                    3) t="php8.1-fpm-alpine" ;;
                    4) t="php8.2-fpm-alpine" ;;
                    5) t="php8.3-fpm-alpine" ;;
                    6) t="fpm-alpine" ;;
                    *) 
                        echo -e "${RED}❌ 无效选择${NC}"
                        pause_prompt
                        continue
                        ;;
                esac
                
                # 备份原配置
                cp "$sdir/docker-compose.yml" "$sdir/docker-compose.yml.backup.$(date +%Y%m%d%H%M%S)"
                
                # 更新配置
                sed -i "s|image: wordpress:.*|image: wordpress:$t|g" "$sdir/docker-compose.yml"
                
                # 重启服务
                echo -e "${CYAN}>>> 重启服务...${NC}"
                cd "$sdir" && docker compose up -d --force-recreate
                
                # 验证服务
                sleep 5
                if docker compose ps | grep -q "Up"; then
                    echo -e "${GREEN}✔ PHP版本切换成功: $t${NC}"
                    write_log "PHP update $d to $t"
                else
                    echo -e "${RED}❌ 切换失败，正在恢复备份...${NC}"
                    cp "$sdir/docker-compose.yml.backup" "$sdir/docker-compose.yml"
                    cd "$sdir" && docker compose up -d
                fi
                
                pause_prompt
                ;; 
                
            2) 
                echo -e "${RED}⚠️ 警告: 数据库版本切换可能导致数据丢失!${NC}"
                read -p "确认继续? (输入 yes 继续): " confirm
                if [ "$confirm" != "yes" ]; then
                    echo "操作取消"
                    pause_prompt
                    continue
                fi
                
                echo -e "${CYAN}选择数据库版本:${NC}"
                echo "1. MySQL 5.7"
                echo "2. MySQL 8.0"
                echo "3. MySQL 最新版"
                echo "4. MariaDB 10.6"
                echo "5. MariaDB 最新版"
                read -p "选择: " v
                
                case $v in
                    1) i="mysql:5.7" ;;
                    2) i="mysql:8.0" ;;
                    3) i="mysql:latest" ;;
                    4) i="mariadb:10.6" ;;
                    5) i="mariadb:latest" ;;
                    *)
                        echo -e "${RED}❌ 无效选择${NC}"
                        pause_prompt
                        continue
                        ;;
                esac
                
                # 备份原配置
                cp "$sdir/docker-compose.yml" "$sdir/docker-compose.yml.backup.$(date +%Y%m%d%H%M%S)"
                
                # 备份数据库
                echo -e "${CYAN}>>> 备份数据库...${NC}"
                local db_pass=$(grep MYSQL_ROOT_PASSWORD "$sdir/docker-compose.yml" | awk -F': ' '{print $2}')
                docker compose -f "$sdir/docker-compose.yml" exec -T db mysqldump -u root -p"$db_pass" --all-databases > "$sdir/db_backup_$(date +%Y%m%d%H%M%S).sql"
                
                # 更新配置
                sed -i "s|image: .*sql:.*|image: $i|g" "$sdir/docker-compose.yml"
                sed -i "s|image: mariadb:.*|image: $i|g" "$sdir/docker-compose.yml"
                
                # 重启服务
                echo -e "${CYAN}>>> 重启数据库...${NC}"
                cd "$sdir" && docker compose up -d --force-recreate db
                
                # 等待数据库启动
                echo -e "${CYAN}>>> 等待数据库就绪...${NC}"
                sleep 30
                
                # 检查数据库状态
                if docker compose ps | grep db | grep -q "Up"; then
                    echo -e "${GREEN}✔ 数据库版本切换成功: $i${NC}"
                    write_log "DB update $d to $i"
                else
                    echo -e "${RED}❌ 数据库启动失败，正在恢复...${NC}"
                    cp "$sdir/docker-compose.yml.backup" "$sdir/docker-compose.yml"
                    cd "$sdir" && docker compose up -d
                fi
                
                pause_prompt
                ;; 
                
            3) 
                echo -e "${CYAN}选择 Redis 版本:${NC}"
                echo "1. Redis 6.2"
                echo "2. Redis 7.0"
                echo "3. Redis 最新版"
                read -p "选择: " r
                
                case $r in
                    1) rt="6.2-alpine" ;;
                    2) rt="7.0-alpine" ;;
                    3) rt="alpine" ;;
                    *)
                        echo -e "${RED}❌ 无效选择${NC}"
                        pause_prompt
                        continue
                        ;;
                esac
                
                sed -i "s|image: redis:.*|image: redis:$rt|g" "$sdir/docker-compose.yml"
                cd "$sdir" && docker compose up -d redis
                echo -e "${GREEN}✔ Redis版本切换完成: $rt${NC}"
                write_log "Redis update $d to $rt"
                pause_prompt
                ;; 
                
            4) 
                echo -e "${CYAN}选择 Nginx 版本:${NC}"
                echo "1. Alpine 版"
                echo "2. 最新版"
                read -p "选择: " n
                
                [ "$n" == "2" ] && nt="latest" || nt="alpine"
                sed -i "s|image: nginx:.*|image: nginx:$nt|g" "$sdir/docker-compose.yml"
                cd "$sdir" && docker compose up -d nginx
                echo -e "${GREEN}✔ Nginx版本切换完成: $nt${NC}"
                write_log "Nginx update $d to $nt"
                pause_prompt
                ;;
                
            5)
                echo -e "${RED}⚠️ 批量升级所有站点的 PHP 版本${NC}"
                read -p "目标 PHP 版本 (如: 8.2): " target_php
                
                if [ -z "$target_php" ]; then
                    echo -e "${RED}❌ 版本不能为空${NC}"
                    pause_prompt
                    continue
                fi
                
                case $target_php in
                    7.4) tag="php7.4-fpm-alpine" ;;
                    8.0) tag="php8.0-fpm-alpine" ;;
                    8.1) tag="php8.1-fpm-alpine" ;;
                    8.2) tag="php8.2-fpm-alpine" ;;
                    8.3) tag="php8.3-fpm-alpine" ;;
                    *) tag="fpm-alpine" ;;
                esac
                
                local upgraded=0
                for site_dir in "$SITES_DIR"/*; do
                    if [ -d "$site_dir" ]; then
                        site_name=$(basename "$site_dir")
                        echo -e "${CYAN}>>> 升级 $site_name ...${NC}"
                        
                        # 备份配置
                        cp "$site_dir/docker-compose.yml" "$site_dir/docker-compose.yml.backup"
                        
                        # 更新配置
                        sed -i "s|image: wordpress:.*|image: wordpress:$tag|g" "$site_dir/docker-compose.yml"
                        
                        # 重启服务
                        cd "$site_dir" && docker compose up -d --force-recreate
                        
                        if docker compose ps | grep -q "Up"; then
                            echo -e "  ${GREEN}✔ 成功${NC}"
                            ((upgraded++))
                        else
                            echo -e "  ${RED}❌ 失败，恢复备份${NC}"
                            cp "$site_dir/docker-compose.yml.backup" "$site_dir/docker-compose.yml"
                            cd "$site_dir" && docker compose up -d
                        fi
                    fi
                done
                
                echo -e "\n${GREEN}✔ 批量升级完成: $upgraded 个站点已升级到 PHP $target_php${NC}"
                write_log "Batch PHP update to $target_php ($upgraded sites)"
                pause_prompt
                ;;
        esac
    done 
}

function fail2ban_manager() { 
    while true; do 
        clear
        echo -e "${YELLOW}=== 👮 Fail2Ban 防护专家 ===${NC}"
        
        # 检查Fail2Ban状态
        if command -v fail2ban-client >/dev/null; then
            if systemctl is-active fail2ban >/dev/null 2>&1; then 
                echo -e "${GREEN}✓ Fail2Ban 正在运行${NC}"
                
                # 显示监狱状态
                echo -e "\n${CYAN}监狱状态:${NC}"
                fail2ban-client status | grep -A 50 "Jail list" | tr ',' '\n' | sed 's/^/  /'
                
                # 显示被封禁IP
                local banned_count=0
                for jail in $(fail2ban-client status | grep "Jail list" | cut -d: -f2 | tr ',' ' '); do
                    count=$(fail2ban-client status $jail | grep "Currently banned" | awk '{print $4}')
                    banned_count=$((banned_count + count))
                done
                echo -e "\n当前封禁IP: $banned_count 个"
            else 
                echo -e "${RED}✗ Fail2Ban 已停止${NC}"
            fi
        else
            echo -e "${YELLOW}⚠️ Fail2Ban 未安装${NC}"
        fi
        
        echo "--------------------------"
        echo " 1. 安装/重置 (5次封24h)"
        echo " 2. 查看被封禁 IP"
        echo " 3. 解封指定 IP"
        echo " 4. 查看日志"
        echo " 5. 自定义规则"
        echo " 0. 返回上一级"
        echo "--------------------------"
        read -p "请输入选项 [0-5]: " o
        
        case $o in 
            0) 
                return
                ;; 
                
            1) 
                echo -e "${YELLOW}>>> 安装配置中...${NC}"
                
                # 检测系统
                if [ -f /etc/debian_version ]; then
                    apt-get update && apt-get install -y fail2ban
                    log_path="/var/log/auth.log"
                elif [ -f /etc/redhat-release ]; then
                    yum install -y epel-release
                    yum install -y fail2ban
                    log_path="/var/log/secure"
                else
                    echo -e "${RED}❌ 不支持的系统${NC}"
                    pause_prompt
                    continue
                fi
                
                # 创建配置文件
                cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
bantime = 86400
findtime = 600
maxretry = 5
backend = systemd

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = $log_path
maxretry = 5

[nginx-http-auth]
enabled = true
port = http,https
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 3

[nginx-badbots]
enabled = true
port = http,https
filter = nginx-badbots
logpath = /var/log/nginx/access.log
maxretry = 2
EOF
                
                # 启动服务
                systemctl enable fail2ban
                systemctl restart fail2ban
                
                if systemctl is-active fail2ban >/dev/null; then
                    echo -e "${GREEN}✔ Fail2Ban 安装配置完成${NC}"
                    write_log "Installed Fail2Ban"
                else
                    echo -e "${RED}❌ Fail2Ban 启动失败${NC}"
                fi
                pause_prompt
                ;; 
                
            2) 
                if command -v fail2ban-client >/dev/null; then
                    echo -e "${CYAN}>>> 被封禁的IP:${NC}"
                    for jail in $(fail2ban-client status | grep "Jail list" | cut -d: -f2 | tr ',' ' '); do
                        echo -e "\n监狱: $jail"
                        fail2ban-client status $jail | grep -A 10 "Banned IP list" | tail -n +2
                    done
                else
                    echo -e "${RED}❌ Fail2Ban 未安装${NC}"
                fi
                pause_prompt
                ;; 
                
            3) 
                read -p "输入要解封的 IP: " ip_addr
                if [[ "$ip_addr" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    fail2ban-client set sshd unbanip $ip_addr 2>/dev/null
                    echo -e "${GREEN}✔ IP $ip_addr 已解封${NC}"
                    write_log "Unbanned IP: $ip_addr"
                else
                    echo -e "${RED}❌ 无效的IP地址${NC}"
                fi
                pause_prompt
                ;; 
                
            4)
                echo -e "${CYAN}>>> Fail2Ban 日志 (最后20行)${NC}"
                if [ -f /var/log/fail2ban.log ]; then
                    tail -20 /var/log/fail2ban.log
                else
                    echo "日志文件不存在"
                fi
                pause_prompt
                ;;
                
            5)
                echo -e "${CYAN}>>> 自定义 Fail2Ban 规则${NC}"
                echo "1. 添加自定义监狱"
                echo "2. 添加自定义过滤器"
                echo "0. 返回"
                read -p "选择: " custom_opt
                
                case $custom_opt in
                    1)
                        read -p "监狱名称: " jail_name
                        read -p "端口: " jail_port
                        read -p "日志路径: " jail_log
                        read -p "最大重试次数: " jail_retry
                        
                        cat >> /etc/fail2ban/jail.local <<EOF

[$jail_name]
enabled = true
port = $jail_port
filter = $jail_name
logpath = $jail_log
maxretry = $jail_retry
bantime = 3600
EOF
                        echo -e "${GREEN}✔ 自定义监狱已添加${NC}"
                        systemctl restart fail2ban
                        ;;
                        
                    2)
                        read -p "过滤器名称: " filter_name
                        read -p "正则表达式: " filter_regex
                        
                        cat > /etc/fail2ban/filter.d/$filter_name.conf <<EOF
[Definition]
failregex = $filter_regex
ignoreregex =
EOF
                        echo -e "${GREEN}✔ 自定义过滤器已添加${NC}"
                        ;;
                esac
                pause_prompt
                ;;
        esac
    done 
}

function waf_manager() { 
    while true; do 
        clear
        echo -e "${YELLOW}=== 🛡️ WAF 网站防火墙 (V72) ===${NC}"
        
        # 统计WAF状态
        local total_sites=0
        local waf_enabled=0
        local waf_enhanced=0
        
        for d in "$SITES_DIR"/*; do 
            if [ -d "$d" ]; then
                ((total_sites++))
                if [ -f "$d/waf.conf" ]; then
                    ((waf_enabled++))
                    if grep -q "V69 Ultra WAF Rules" "$d/waf.conf"; then
                        ((waf_enhanced++))
                    fi
                fi
            fi
        done
        
        echo -e "站点统计:"
        echo -e "  总站点数: $total_sites"
        echo -e "  WAF已启用: $waf_enabled"
        echo -e "  增强模式: $waf_enhanced"
        echo "--------------------------"
        echo " 1. 部署增强规则 (强制更新所有站点)"
        echo " 2. 部署基础规则"
        echo " 3. 查看当前规则"
        echo " 4. 自定义规则"
        echo " 5. 测试WAF防护"
        echo " 0. 返回上一级"
        echo "--------------------------"
        read -p "请输入选项 [0-5]: " o
        
        case $o in 
            0) 
                return
                ;; 
                
            1) 
                echo -e "${BLUE}>>> 正在部署增强规则...${NC}"
                
                # 创建增强WAF规则
                cat > /tmp/waf_enhanced <<EOF
# --- V72 Ultra WAF Rules ---
# 文件访问限制
location ~* /\.(git|svn|hg|env|bak|config|sql|db|key|pem|ssh|ftpconfig|htaccess) { 
    deny all; 
    return 403; 
}

# 危险文件类型
location ~* \.(sql|bak|conf|ini|log|sh|yaml|yml|swp|install|dist|phar|phtml|inc)$ { 
    deny all; 
    return 403; 
}

# SQL注入防护
if (\$query_string ~* "union.*select.*\(") { return 403; }
if (\$query_string ~* "concat.*\(") { return 403; }
if (\$query_string ~* "base64_decode\(") { return 403; }
if (\$query_string ~* "eval\(") { return 403; }
if (\$query_string ~* "sleep\(") { return 403; }
if (\$query_string ~* "benchmark\(") { return 403; }

# XSS防护
if (\$query_string ~* "<script>") { return 403; }
if (\$query_string ~* "javascript:") { return 403; }
if (\$query_string ~* "onmouseover=") { return 403; }
if (\$query_string ~* "onclick=") { return 403; }

# 目录遍历
if (\$query_string ~* "\.\./") { return 403; }

# 恶意爬虫/扫描器
if (\$http_user_agent ~* (netcrawler|nikto|wikto|sf|sqlmap|bsqlbf|w3af|acunetix|havij|appscan|nessus|whatweb|dirbuster)) { 
    return 403; 
}

# 空User-Agent
if (\$http_user_agent ~ ^$) { return 403; }

# 请求方法限制
if (\$request_method !~ ^(GET|HEAD|POST)$ ) { return 405; }

# 限制请求大小
client_max_body_size 100M;

# 限制请求速率
limit_req_zone \$binary_remote_addr zone=waf_limit:10m rate=10r/s;
limit_req zone=waf_limit burst=20 nodelay;

# 限制连接数
limit_conn_zone \$binary_remote_addr zone=addr:10m;
limit_conn addr 20;
EOF
                
                count=0
                for d in "$SITES_DIR"/*; do 
                    if [ -d "$d" ]; then 
                        cp /tmp/waf_enhanced "$d/waf.conf" 
                        
                        # 更新nginx配置
                        if [ -f "$d/nginx.conf" ]; then
                            sed -i '1i include /etc/nginx/waf.conf;' "$d/nginx.conf"
                        fi
                        
                        # 重载nginx配置
                        cd "$d" && docker compose exec -T nginx nginx -s reload >/dev/null 2>&1
                        
                        echo -e " - $(basename "$d"): ${GREEN}已更新${NC}"
                        ((count++))
                    fi 
                done
                
                rm /tmp/waf_enhanced
                echo -e "${GREEN}✔ 成功部署 $count 个站点${NC}"
                write_log "Deployed enhanced WAF to $count sites"
                pause_prompt
                ;; 
                
            2) 
                echo -e "${CYAN}>>> 部署基础规则...${NC}"
                
                cat > /tmp/waf_basic <<EOF
# --- 基础WAF规则 ---
location ~* /\.(git|env|sql) { 
    deny all; 
    return 403; 
}

location ~* \.(sql|bak|conf)$ { 
    deny all; 
    return 403; 
}

if (\$query_string ~* "union.*select") { return 403; }
if (\$query_string ~* "base64_decode") { return 403; }
EOF
                
                local basic_count=0
                for d in "$SITES_DIR"/*; do 
                    if [ -d "$d" ]; then 
                        cp /tmp/waf_basic "$d/waf.conf" 
                        cd "$d" && docker compose exec -T nginx nginx -s reload >/dev/null 2>&1
                        ((basic_count++))
                    fi 
                done
                
                rm /tmp/waf_basic
                echo -e "${GREEN}✔ 基础规则部署完成: $basic_count 个站点${NC}"
                pause_prompt
                ;; 
                
            3) 
                echo -e "${CYAN}>>> WAF规则预览${NC}"
                for d in "$SITES_DIR"/*; do 
                    if [ -d "$d" ] && [ -f "$d/waf.conf" ]; then
                        echo -e "\n站点: $(basename "$d")"
                        head -10 "$d/waf.conf"
                    fi
                done
                pause_prompt
                ;; 
                
            4)
                echo -e "${CYAN}>>> 自定义WAF规则${NC}"
                read -p "输入域名 (留空为所有站点): " custom_domain
                
                if [ -z "$custom_domain" ]; then
                    # 所有站点
                    read -p "输入自定义规则: " custom_rule
                    for d in "$SITES_DIR"/*; do 
                        if [ -d "$d" ]; then
                            echo "$custom_rule" >> "$d/waf.conf"
                        fi
                    done
                    echo -e "${GREEN}✔ 规则已添加到所有站点${NC}"
                else
                    # 指定站点
                    if [ -d "$SITES_DIR/$custom_domain" ]; then
                        echo "当前规则:"
                        cat "$SITES_DIR/$custom_domain/waf.conf"
                        echo ""
                        echo "输入新规则 (输入 END 结束):"
                        > "$SITES_DIR/$custom_domain/waf.custom"
                        while IFS= read -r line; do
                            [ "$line" = "END" ] && break
                            echo "$line" >> "$SITES_DIR/$custom_domain/waf.custom"
                        done
                        cat "$SITES_DIR/$custom_domain/waf.custom" >> "$SITES_DIR/$custom_domain/waf.conf"
                        echo -e "${GREEN}✔ 自定义规则已添加${NC}"
                    else
                        echo -e "${RED}❌ 站点不存在${NC}"
                    fi
                fi
                pause_prompt
                ;;
                
            5)
                echo -e "${CYAN}>>> WAF防护测试${NC}"
                read -p "输入测试域名: " test_domain
                
                if [ -d "$SITES_DIR/$test_domain" ]; then
                    local test_url="https://$test_domain"
                    
                    echo -e "\n1. 测试SQL注入防护..."
                    curl -s -o /dev/null -w "响应码: %{http_code}\n" "$test_url/?id=1' UNION SELECT NULL--"
                    
                    echo -e "\n2. 测试XSS防护..."
                    curl -s -o /dev/null -w "响应码: %{http_code}\n" "$test_url/?q=<script>alert(1)</script>"
                    
                    echo -e "\n3. 测试目录遍历..."
                    curl -s -o /dev/null -w "响应码: %{http_code}\n" "$test_url/../../../etc/passwd"
                    
                    echo -e "\n4. 测试敏感文件..."
                    curl -s -o /dev/null -w "响应码: %{http_code}\n" "$test_url/.git/config"
                    
                    echo -e "\n${GREEN}✔ 测试完成${NC}"
                    echo "正常响应应为 403 (禁止访问)"
                else
                    echo -e "${RED}❌ 站点不存在${NC}"
                fi
                pause_prompt
                ;;
        esac
    done 
}

function port_manager() { 
    ensure_firewall_installed || return
    
    # 确保防火墙启动
    if command -v ufw >/dev/null && ! ufw status | grep -q "active"; then 
        ufw allow 22/tcp >/dev/null
        ufw allow 80/tcp >/dev/null
        ufw allow 443/tcp >/dev/null
        echo "y" | ufw enable >/dev/null
    fi
    
    while true; do 
        clear
        echo -e "${YELLOW}=== 🧱 端口防火墙 ===${NC}"
        
        # 显示防火墙状态
        if command -v ufw >/dev/null; then 
            FW="UFW"
            echo -e "防火墙: ${GREEN}UFW${NC}"
            ufw status | head -5
        else 
            FW="Firewalld"
            echo -e "防火墙: ${GREEN}Firewalld${NC}"
            firewall-cmd --state
        fi
        
        # 显示开放端口
        echo -e "\n${CYAN}开放端口:${NC}"
        if [ "$FW" == "UFW" ]; then 
            ufw status numbered | grep ALLOW | head -10
        else 
            firewall-cmd --list-ports | tr ' ' '\n' | head -10
        fi
        
        echo "--------------------------"
        echo " 1. 查看所有开放端口"
        echo " 2. 开放/关闭 端口 (支持多端口)"
        echo " 3. 防 DOS 攻击 (开启/关闭)"
        echo " 4. 一键全开 / 一键全锁"
        echo " 5. 端口扫描检测"
        echo " 0. 返回上一级"
        echo "--------------------------"
        read -p "请输入选项 [0-5]: " f
        
        case $f in 
            0) 
                return
                ;; 
                
            1) 
                echo -e "${CYAN}>>> 所有开放端口${NC}"
                if [ "$FW" == "UFW" ]; then 
                    ufw status numbered
                else 
                    firewall-cmd --list-all
                fi
                pause_prompt
                ;; 
                
            2) 
                read -p "输入端口 (如 80 443): " ports
                echo "操作: 1.开放 2.关闭"
                read -p "选择: " a
                
                for p in $ports; do
                    if [[ "$p" =~ ^[0-9]+$ ]]; then
                        if command -v ufw >/dev/null; then
                            [ "$a" == "1" ] && ufw allow $p/tcp || ufw delete allow $p/tcp
                        else
                            ac=$([ "$a" == "1" ] && echo add || echo remove)
                            firewall-cmd --zone=public --${ac}-port=$p/tcp --permanent
                        fi
                        echo -e "端口 $p: ${GREEN}操作完成${NC}"
                    else
                        echo -e "端口 $p: ${RED}无效${NC}"
                    fi
                done
                
                command -v firewall-cmd >/dev/null && firewall-cmd --reload
                echo -e "${GREEN}✔ 端口操作完成${NC}"
                pause_prompt
                ;; 
                
            3) 
                echo "防DOS攻击: 1.开启 2.关闭"
                read -p "选择: " d
                
                if [ "$d" == "1" ]; then
                    echo -e "${CYAN}>>> 开启防DOS攻击${NC}"
                    
                    # 创建限流配置
                    cat > "$FW_DIR/dos_zones.conf" <<EOF
# 请求频率限制
limit_req_zone \$binary_remote_addr zone=dos_limit:10m rate=10r/s;

# 连接数限制
limit_conn_zone \$binary_remote_addr zone=dos_conn:10m;

# 每个IP的连接数限制
limit_conn dos_conn 20;
EOF
                    
                    mkdir -p "$GATEWAY_DIR/vhost"
                    cat > "$GATEWAY_DIR/vhost/default" <<EOF
limit_req zone=dos_limit burst=20 nodelay;
limit_conn dos_conn 10;
EOF
                    
                    cd "$GATEWAY_DIR" && docker compose up -d >/dev/null 2>&1
                    docker exec gateway_proxy nginx -s reload 2>/dev/null
                    
                    echo -e "${GREEN}✔ 防DOS攻击已开启${NC}"
                    write_log "Enabled DOS protection"
                else
                    rm -f "$FW_DIR/dos_zones.conf" "$GATEWAY_DIR/vhost/default"
                    cd "$GATEWAY_DIR" && docker exec gateway_proxy nginx -s reload 2>/dev/null
                    echo -e "${YELLOW}⚠️ 防DOS攻击已关闭${NC}"
                fi
                pause_prompt
                ;; 
                
            4) 
                echo "模式: 1.全开 (开放所有) 2.全锁 (仅开放22,80,443)"
                read -p "选择: " m
                
                if [ "$m" == "1" ]; then
                    echo -e "${YELLOW}⚠️ 警告: 开放所有端口有安全风险!${NC}"
                    read -p "确认? (y/n): " confirm
                    
                    if [ "$confirm" == "y" ]; then
                        if command -v ufw >/dev/null; then
                            ufw default allow incoming
                        else
                            firewall-cmd --set-default-zone=trusted --permanent
                            firewall-cmd --reload
                        fi
                        echo -e "${GREEN}✔ 已开放所有端口${NC}"
                    fi
                else
                    if command -v ufw >/dev/null; then
                        ufw --force reset
                        ufw allow 22/tcp
                        ufw allow 80/tcp
                        ufw allow 443/tcp
                        ufw default deny incoming
                        echo "y" | ufw enable
                    else
                        firewall-cmd --permanent --remove-service=ssh
                        firewall-cmd --permanent --add-service={ssh,http,https}
                        firewall-cmd --set-default-zone=drop --permanent
                        firewall-cmd --reload
                    fi
                    echo -e "${GREEN}✔ 已锁定端口 (仅开放22,80,443)${NC}"
                fi
                pause_prompt
                ;;
                
            5)
                echo -e "${CYAN}>>> 端口扫描检测${NC}"
                
                # 检查异常连接
                echo -e "\n${CYAN}活动连接:${NC}"
                netstat -an | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -10
                
                # 检查SYN_RECV状态
                echo -e "\n${CYAN}半连接 (可能受到SYN Flood攻击):${NC}"
                netstat -an | grep SYN_RECV | wc -l
                
                # 推荐配置
                echo -e "\n${CYAN}推荐配置:${NC}"
                echo "1. 启用TCP SYN Cookie: sysctl -w net.ipv4.tcp_syncookies=1"
                echo "2. 限制SYN队列: sysctl -w net.ipv4.tcp_max_syn_backlog=2048"
                echo "3. 缩短超时时间: sysctl -w net.ipv4.tcp_synack_retries=2"
                
                pause_prompt
                ;;
        esac
    done 
}

function traffic_manager() { 
    while true; do 
        clear
        echo -e "${YELLOW}=== 🌐 流量控制 (ACL) ===${NC}"
        
        # 显示当前规则统计
        local deny_count=$(grep -c "deny" "$FW_DIR/access.conf" 2>/dev/null || echo 0)
        local allow_count=$(grep -c "allow" "$FW_DIR/access.conf" 2>/dev/null || echo 0)
        local geo_count=$(grep -c "deny" "$FW_DIR/geo.conf" 2>/dev/null || echo 0)
        
        echo -e "规则统计:"
        echo -e "  黑名单IP: $deny_count 个"
        echo -e "  白名单IP: $allow_count 个"
        echo -e "  封禁国家: $geo_count 个"
        echo "--------------------------"
        echo " 1. 添加 黑名单 IP"
        echo " 2. 添加 白名单 IP"
        echo " 3. 封禁 指定国家"
        echo " 4. 批量导入 IP 列表"
        echo " 5. 清空 所有规则"
        echo " 6. 查看当前规则"
        echo " 0. 返回上一级"
        echo "--------------------------"
        read -p "请输入选项 [0-6]: " t
        
        case $t in 
            0) 
                return
                ;; 
                
            1|2) 
                tp="deny"
                [ "$t" == "2" ] && tp="allow"
                
                read -p "IP地址 (支持CIDR格式如 192.168.1.0/24): " ip_addr
                
                if [[ "$ip_addr" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
                    echo "$tp $ip_addr;" >> "$FW_DIR/access.conf"
                    cd "$GATEWAY_DIR" && docker exec gateway_proxy nginx -s reload 2>/dev/null
                    echo -e "${GREEN}✔ 规则已添加${NC}"
                    write_log "Added $tp rule for $ip_addr"
                else
                    echo -e "${RED}❌ 无效的IP地址${NC}"
                fi
                pause_prompt
                ;; 
                
            3) 
                echo -e "${CYAN}常用国家代码:${NC}"
                echo "CN - 中国  US - 美国  RU - 俄罗斯"
                echo "JP - 日本  KR - 韩国  IN - 印度"
                echo "BR - 巴西  DE - 德国  FR - 法国"
                echo ""
                read -p "国家代码 (如 CN): " country_code
                
                if [ -z "$country_code" ]; then
                    echo -e "${RED}❌ 国家代码不能为空${NC}"
                    pause_prompt
                    continue
                fi
                
                echo -e "${CYAN}>>> 下载IP列表...${NC}"
                local zone_file="/tmp/$country_code.zone"
                
                if curl -s "http://www.ipdeny.com/ipblocks/data/countries/$country_code.zone" -o "$zone_file"; then
                    local ip_count=0
                    while read ip; do
                        [ -n "$ip" ] && echo "deny $ip;" >> "$FW_DIR/geo.conf"
                        ((ip_count++))
                    done < "$zone_file"
                    
                    rm -f "$zone_file"
                    
                    cd "$GATEWAY_DIR" && docker exec gateway_proxy nginx -s reload 2>/dev/null
                    echo -e "${GREEN}✔ 已封禁 $country_code ($ip_count 个IP段)${NC}"
                    write_log "Blocked country: $country_code ($ip_count IP blocks)"
                else
                    echo -e "${RED}❌ 下载失败${NC}"
                fi
                pause_prompt
                ;; 
                
            4)
                echo -e "${CYAN}>>> 批量导入IP列表${NC}"
                echo "格式: 每行一个IP (支持CIDR)"
                echo "示例:"
                echo "  192.168.1.1"
                echo "  10.0.0.0/8"
                echo ""
                read -p "文件路径: " ip_file
                
                if [ -f "$ip_file" ]; then
                    local imported=0
                    while read ip; do
                        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
                            echo "deny $ip;" >> "$FW_DIR/access.conf"
                            ((imported++))
                        fi
                    done < "$ip_file"
                    
                    cd "$GATEWAY_DIR" && docker exec gateway_proxy nginx -s reload 2>/dev/null
                    echo -e "${GREEN}✔ 导入完成: $imported 个IP${NC}"
                else
                    echo -e "${RED}❌ 文件不存在${NC}"
                fi
                pause_prompt
                ;;
                
            5) 
                echo -n "" > "$FW_DIR/access.conf"
                echo -n "" > "$FW_DIR/geo.conf"
                cd "$GATEWAY_DIR" && docker exec gateway_proxy nginx -s reload 2>/dev/null
                echo -e "${GREEN}✔ 所有规则已清空${NC}"
                write_log "Cleared all ACL rules"
                pause_prompt
                ;; 
                
            6)
                echo -e "${CYAN}>>> 当前规则${NC}"
                echo -e "\n黑名单/白名单:"
                cat "$FW_DIR/access.conf" 2>/dev/null || echo "无"
                echo -e "\n国家封禁:"
                cat "$FW_DIR/geo.conf" 2>/dev/null | head -10 || echo "无"
                pause_prompt
                ;;
        esac
    done 
}

# --- 网关初始化函数 ---
function init_gateway() { 
    local mode=$1
    
    # 创建网络
    if ! docker network ls | grep -q proxy-net; then
        docker network create proxy-net >/dev/null
        echo -e "${GREEN}✔ 创建网络: proxy-net${NC}"
    fi
    
    # 创建网关目录
    mkdir -p "$GATEWAY_DIR"
    cd "$GATEWAY_DIR"
    
    # 上传大小配置
    cat > upload_size.conf <<EOF
# 上传大小限制
client_max_body_size 1024m;
proxy_read_timeout 600s;
proxy_send_timeout 600s;
proxy_connect_timeout 300s;

# 缓冲区配置
proxy_buffer_size 128k;
proxy_buffers 4 256k;
proxy_busy_buffers_size 256k;
EOF
    
    # Docker Compose配置
    cat > docker-compose.yml <<EOF
version: '3.8'

services:
  nginx-proxy:
    image: nginxproxy/nginx-proxy:latest
    container_name: gateway_proxy
    restart: always
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - conf:/etc/nginx/conf.d
      - vhost:/etc/nginx/vhost.d
      - html:/usr/share/nginx/html
      - certs:/etc/nginx/certs:ro
      - /var/run/docker.sock:/tmp/docker.sock:ro
      - ../firewall/access.conf:/etc/nginx/conf.d/z_access.conf:ro
      - ../firewall/geo.conf:/etc/nginx/conf.d/z_geo.conf:ro
      - ./upload_size.conf:/etc/nginx/conf.d/upload_size.conf:ro
    networks:
      - proxy-net
    environment:
      - DEFAULT_HOST=default
      - TRUST_DOWNSTREAM_PROXY=true
      - ENABLE_IPV6=true

  acme-companion:
    image: nginxproxy/acme-companion:latest
    container_name: gateway_acme
    restart: always
    volumes:
      - conf:/etc/nginx/conf.d
      - vhost:/etc/nginx/vhost.d
      - html:/usr/share/nginx/html
      - certs:/etc/nginx/certs:rw
      - acme:/etc/acme.sh
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      - DEFAULT_EMAIL=admin@localhost.com
      - NGINX_PROXY_CONTAINER=gateway_proxy
      - ACME_CA_URI=https://acme-v02.api.letsencrypt.org/directory
      - DEBUG=false
    networks:
      - proxy-net
    depends_on:
      - nginx-proxy

volumes:
  conf:
  vhost:
  html:
  certs:
  acme:

networks:
  proxy-net:
    external: true
EOF
    
    # 启动网关
    echo -e "${CYAN}>>> 启动网关服务...${NC}"
    
    if docker compose up -d --remove-orphans 2>&1 | grep -v "up-to-date"; then
        # 等待服务启动
        sleep 5
        
        # 检查容器状态
        if docker ps | grep -q "gateway_proxy"; then
            echo -e "${GREEN}✔ 网关启动成功${NC}"
            echo -e "代理地址: http://$(curl -s4 ifconfig.me)"
            echo -e "管理命令: wp (已安装)"
            
            write_log "Initialized gateway"
        else
            echo -e "${RED}❌ 网关启动失败${NC}"
            docker compose logs
        fi
    else
        if [ "$mode" == "force" ]; then
            echo -e "${YELLOW}⚠️ 尝试强制启动...${NC}"
            docker compose up -d --force-recreate
        else
            echo -e "${GREEN}✔ 网关服务已运行${NC}"
        fi
    fi
}

function create_site() {
    echo -e "${YELLOW}=== 🚀 创建 WordPress 站点 ===${NC}"
    
    # 1. 域名输入
    read -p "1. 域名 (例如 example.com): " fd
    if [ -z "$fd" ]; then
        echo -e "${RED}❌ 域名不能为空${NC}"
        pause_prompt
        return
    fi
    
    # 检查域名是否已存在
    if [ -d "$SITES_DIR/$fd" ]; then
        echo -e "${RED}❌ 站点已存在${NC}"
        pause_prompt
        return
    fi
    
    # 2. 邮箱
    read -p "2. 邮箱 (用于SSL证书): " email
    if [ -z "$email" ]; then
        email="admin@$fd"
        echo -e "${YELLOW}⚠️ 使用默认邮箱: $email${NC}"
    fi
    
    # 3. 数据库密码
    while true; do
        read -p "3. 数据库密码: " db_pass
        validate_password "$db_pass" && break
    done
    
    # 4. 验证域名解析
    echo -e "${CYAN}>>> 验证域名解析...${NC}"
    local host_ip=$(curl -s4 ifconfig.me)
    local resolved_ip=""
    
    if command -v dig >/dev/null; then
        resolved_ip=$(dig +short "$fd" | head -1)
    elif command -v nslookup >/dev/null; then
        resolved_ip=$(nslookup "$fd" 2>/dev/null | grep "Address" | tail -1 | awk '{print $2}')
    fi
    
    if [ ! -z "$resolved_ip" ] && [ "$resolved_ip" != "$host_ip" ]; then
        echo -e "${YELLOW}⚠️ 域名解析IP ($resolved_ip) 与服务器IP ($host_ip) 不一致${NC}"
        read -p "继续创建? (y/n): " continue_create
        if [ "$continue_create" != "y" ]; then
            echo "操作取消"
            pause_prompt
            return
        fi
    else
        echo -e "${GREEN}✔ 域名解析正常${NC}"
    fi
    
    # 5. 自定义版本选择
    echo -e "\n${CYAN}>>> 组件版本选择${NC}"
    echo -e "默认: PHP 8.2 / MySQL 8.0 / Redis 7.0"
    read -p "自定义版本? (y/n): " cust
    
    local pt="php8.2-fpm-alpine"
    local di="mysql:8.0"
    local rt="7.0-alpine"
    
    if [ "$cust" == "y" ]; then
        # PHP版本
        echo -e "\n${CYAN}PHP 版本:${NC}"
        echo "1. PHP 7.4"
        echo "2. PHP 8.0"
        echo "3. PHP 8.1"
        echo "4. PHP 8.2"
        echo "5. PHP 8.3"
        echo "6. 最新版"
        read -p "选择: " p
        
        case $p in
            1) pt="php7.4-fpm-alpine" ;;
            2) pt="php8.0-fpm-alpine" ;;
            3) pt="php8.1-fpm-alpine" ;;
            4) pt="php8.2-fpm-alpine" ;;
            5) pt="php8.3-fpm-alpine" ;;
            6) pt="fpm-alpine" ;;
            *) echo -e "${YELLOW}⚠️ 使用默认: PHP 8.2${NC}" ;;
        esac
        
        # 数据库版本
        echo -e "\n${CYAN}数据库版本:${NC}"
        echo "1. MySQL 5.7"
        echo "2. MySQL 8.0"
        echo "3. MySQL 最新版"
        echo "4. MariaDB 10.6"
        echo "5. MariaDB 最新版"
        read -p "选择: " d
        
        case $d in
            1) di="mysql:5.7" ;;
            2) di="mysql:8.0" ;;
            3) di="mysql:latest" ;;
            4) di="mariadb:10.6" ;;
            5) di="mariadb:latest" ;;
            *) echo -e "${YELLOW}⚠️ 使用默认: MySQL 8.0${NC}" ;;
        esac
        
        # Redis版本
        echo -e "\n${CYAN}Redis 版本:${NC}"
        echo "1. Redis 6.2"
        echo "2. Redis 7.0"
        echo "3. Redis 最新版"
        read -p "选择: " r
        
        case $r in
            1) rt="6.2-alpine" ;;
            2) rt="7.0-alpine" ;;
            3) rt="alpine" ;;
            *) echo -e "${YELLOW}⚠️ 使用默认: Redis 7.0${NC}" ;;
        esac
    fi
    
    # 6. 创建站点目录
    echo -e "\n${CYAN}>>> 创建站点结构...${NC}"
    local pname=$(echo $fd | tr '.' '_')
    local sdir="$SITES_DIR/$fd"
    
    mkdir -p "$sdir"
    cd "$sdir"
    
    # 7. 创建配置文件
    
    # WAF配置
    cat > waf.conf <<EOF
# 基础WAF规则
location ~* /\.(git|env|sql) { 
    deny all; 
    return 403; 
}
EOF
    
    # Nginx配置
    cat > nginx.conf <<EOF
server {
    listen 80;
    server_name localhost;
    root /var/www/html;
    index index.php;
    
    # 包含WAF规则
    include /etc/nginx/waf.conf;
    
    # 上传大小限制
    client_max_body_size 512M;
    
    # 安全头
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # 缓存静态文件
    location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
    
    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }
    
    location ~ \.php\$ {
        try_files \$uri =404;
        fastcgi_split_path_info ^(.+\.php)(/.+)\$;
        fastcgi_pass wordpress:9000;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_param PATH_INFO \$fastcgi_path_info;
        fastcgi_read_timeout 600;
    }
}
EOF
    
    # PHP配置
    cat > uploads.ini <<EOF
; WordPress上传配置
file_uploads = On
memory_limit = 512M
upload_max_filesize = 512M
post_max_size = 512M
max_execution_time = 600
max_input_time = 600
EOF
    
    # Docker Compose配置
    cat > docker-compose.yml <<EOF
version: '3.8'

services:
  db:
    image: $di
    container_name: ${pname}_db
    restart: always
    environment:
      MYSQL_ROOT_PASSWORD: $db_pass
      MYSQL_DATABASE: wordpress
      MYSQL_USER: wp_user
      MYSQL_PASSWORD: $db_pass
    volumes:
      - db_data:/var/lib/mysql
    networks:
      - default
    command: >
      --character-set-server=utf8mb4
      --collation-server=utf8mb4_unicode_ci
      --max_connections=1000
      --innodb_buffer_pool_size=256M

  redis:
    image: redis:$rt
    container_name: ${pname}_redis
    restart: always
    networks:
      - default
    command: >
      redis-server
      --maxmemory 256mb
      --maxmemory-policy allkeys-lru
      --save ""
      --appendonly no

  wordpress:
    image: wordpress:$pt
    container_name: ${pname}_app
    restart: always
    depends_on:
      - db
      - redis
    environment:
      WORDPRESS_DB_HOST: db:3306
      WORDPRESS_DB_USER: wp_user
      WORDPRESS_DB_PASSWORD: $db_pass
      WORDPRESS_DB_NAME: wordpress
      WORDPRESS_TABLE_PREFIX: wp_
      WORDPRESS_DEBUG: "false"
      WORDPRESS_CONFIG_EXTRA: |
        define('WP_REDIS_HOST', 'redis');
        define('WP_REDIS_PORT', 6379);
        define('WP_REDIS_TIMEOUT', 1);
        define('WP_REDIS_READ_TIMEOUT', 1);
        define('WP_CACHE', true);
        define('WP_HOME', 'https://' . \$\$_SERVER['HTTP_HOST']);
        define('WP_SITEURL', 'https://' . \$\$_SERVER['HTTP_HOST']);
        if (isset(\$\$_SERVER['HTTP_X_FORWARDED_PROTO']) && strpos(\$\$_SERVER['HTTP_X_FORWARDED_PROTO'], 'https') !== false) {
          \$\$_SERVER['HTTPS'] = 'on';
        }
        @ini_set('display_errors', 0);
    volumes:
      - wp_data:/var/www/html
      - ./uploads.ini:/usr/local/etc/php/conf.d/uploads.ini
    networks:
      - default
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/wp-admin/install.php"]
      interval: 30s
      timeout: 10s
      retries: 3

  nginx:
    image: nginx:alpine
    container_name: ${pname}_nginx
    restart: always
    volumes:
      - wp_data:/var/www/html
      - ./nginx.conf:/etc/nginx/conf.d/default.conf
      - ./waf.conf:/etc/nginx/waf.conf
    environment:
      VIRTUAL_HOST: "$fd"
      LETSENCRYPT_HOST: "$fd"
      LETSENCRYPT_EMAIL: "$email"
      VIRTUAL_PORT: "80"
    networks:
      - default
      - proxy-net
    depends_on:
      - wordpress
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  db_data:
    name: ${pname}_db_data
  wp_data:
    name: ${pname}_wp_data

networks:
  proxy-net:
    external: true
EOF
    
    # 8. 验证配置
    if ! validate_compose "$sdir"; then
        echo -e "${RED}❌ 配置文件验证失败${NC}"
        rm -rf "$sdir"
        pause_prompt
        return
    fi
    
    # 9. 启动服务
    echo -e "${CYAN}>>> 启动服务...${NC}"
    if docker compose up -d; then
        echo -e "${GREEN}✔ 服务启动成功${NC}"
        echo -e "等待容器初始化..."
        sleep 10
        
        # 10. 等待并检查SSL证书
        check_ssl_status "$fd"
        
        # 11. 健康检查
        echo -e "${CYAN}>>> 执行健康检查...${NC}"
        if check_site_health "$fd"; then
            echo -e "${GREEN}✔ 站点运行正常${NC}"
        else
            echo -e "${YELLOW}⚠️ 站点可能还在初始化中${NC}"
        fi
        
        # 12. 显示信息
        echo -e "\n${GREEN}✅ WordPress站点创建完成!${NC}"
        echo -e "访问地址: https://$fd"
        echo -e "数据库信息:"
        echo -e "  主机: db"
        echo -e "  用户: wp_user"
        echo -e "  密码: $db_pass"
        echo -e "  数据库: wordpress"
        echo -e "Redis缓存: 已启用"
        echo -e "备份命令: wp 然后选择备份功能"
        
        write_log "Created WordPress site: $fd"
    else
        echo -e "${RED}❌ 服务启动失败${NC}"
        docker compose logs
        rm -rf "$sdir"
    fi
    
    pause_prompt
}

function create_proxy() {
    echo -e "${YELLOW}=== 🔄 创建反向代理 ===${NC}"
    
    # 1. 域名
    read -p "1. 域名: " d
    if [ -z "$d" ]; then
        echo -e "${RED}❌ 域名不能为空${NC}"
        pause_prompt
        return
    fi
    
    # 检查是否已存在
    if [ -d "$SITES_DIR/$d" ]; then
        echo -e "${RED}❌ 站点已存在${NC}"
        pause_prompt
        return
    fi
    
    # 2. 邮箱
    read -p "2. 邮箱 (用于SSL证书): " e
    if [ -z "$e" ]; then
        e="admin@$d"
        echo -e "${YELLOW}⚠️ 使用默认邮箱: $e${NC}"
    fi
    
    # 3. 代理类型
    echo -e "\n${CYAN}代理类型:${NC}"
    echo "1. 反向代理到 URL (例如 https://example.com)"
    echo "2. 反向代理到 IP:端口 (例如 192.168.1.100:8080)"
    read -p "选择: " t
    
    local tu=""
    local pm="1"  # 默认镜像模式
    
    if [ "$t" == "2" ]; then
        # IP:端口模式
        read -p "目标IP: " ip
        [ -z "$ip" ] && ip="127.0.0.1"
        
        read -p "目标端口: " p
        if [ -z "$p" ] || ! [[ "$p" =~ ^[0-9]+$ ]]; then
            echo -e "${RED}❌ 无效的端口${NC}"
            pause_prompt
            return
        fi
        
        tu="http://$ip:$p"
        pm="2"  # 代理模式
    else
        # URL模式
        read -p "目标URL (例如 https://example.com): " tu
        if [ -z "$tu" ]; then
            echo -e "${RED}❌ URL不能为空${NC}"
            pause_prompt
            return
        fi
        
        tu=$(normalize_url "$tu")
        
        echo -e "\n${CYAN}代理模式:${NC}"
        echo "1. 镜像模式 (修改HTML中的链接)"
        echo "2. 代理模式 (透明转发)"
        read -p "选择: " pm
        [ -z "$pm" ] && pm="1"
    fi
    
    # 4. 创建站点目录
    local sdir="$SITES_DIR/$d"
    mkdir -p "$sdir"
    cd "$sdir"
    
    # 5. 生成Nginx配置
    echo -e "\n${CYAN}>>> 生成Nginx配置...${NC}"
    generate_nginx_conf "$tu" "$d" "$pm"
    
    # 6. 创建Docker Compose配置
    cat > docker-compose.yml <<EOF
version: '3.8'

services:
  proxy:
    image: nginx:alpine
    container_name: ${d//./_}_worker
    restart: always
    volumes:
      - ./nginx-proxy.conf:/etc/nginx/conf.d/default.conf
    extra_hosts:
      - "host.docker.internal:host-gateway"
    environment:
      VIRTUAL_HOST: "$d"
      LETSENCRYPT_HOST: "$d"
      LETSENCRYPT_EMAIL: "$e"
      VIRTUAL_PORT: "80"
    networks:
      - proxy-net
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost"]
      interval: 30s
      timeout: 10s
      retries: 3

networks:
  proxy-net:
    external: true
EOF
    
    # 7. 验证配置
    if ! validate_compose "$sdir"; then
        echo -e "${RED}❌ 配置文件验证失败${NC}"
        rm -rf "$sdir"
        pause_prompt
        return
    fi
    
    # 8. 启动服务
    echo -e "${CYAN}>>> 启动代理服务...${NC}"
    if docker compose up -d; then
        echo -e "${GREEN}✔ 代理服务启动成功${NC}"
        
        # 等待并检查SSL证书
        check_ssl_status "$d"
        
        # 健康检查
        echo -e "${CYAN}>>> 执行健康检查...${NC}"
        if check_site_health "$d"; then
            echo -e "${GREEN}✔ 代理运行正常${NC}"
        else
            echo -e "${YELLOW}⚠️ 代理可能还在初始化中${NC}"
        fi
        
        echo -e "\n${GREEN}✅ 反向代理创建完成!${NC}"
        echo -e "代理地址: https://$d"
        echo -e "目标地址: $tu"
        echo -e "模式: $([ "$pm" == "1" ] && echo "镜像模式" || echo "代理模式")"
        
        write_log "Created proxy: $d -> $tu"
    else
        echo -e "${RED}❌ 代理服务启动失败${NC}"
        docker compose logs
        rm -rf "$sdir"
    fi
    
    pause_prompt
}

function generate_nginx_conf() {
    local target_url=$1
    local domain=$2
    local mode=$3
    
    local target_host=$(echo $target_url | awk -F/ '{print $3}')
    local conf_file="$SITES_DIR/$domain/nginx-proxy.conf"
    
    echo "server {" > "$conf_file"
    echo "    listen 80;" >> "$conf_file"
    echo "    server_name localhost;" >> "$conf_file"
    echo "    resolver 8.8.8.8 valid=30s;" >> "$conf_file"
    echo "" >> "$conf_file"
    echo "    # 安全头" >> "$conf_file"
    echo "    add_header X-Frame-Options \"SAMEORIGIN\" always;" >> "$conf_file"
    echo "    add_header X-XSS-Protection \"1; mode=block\" always;" >> "$conf_file"
    echo "    add_header X-Content-Type-Options \"nosniff\" always;" >> "$conf_file"
    echo "" >> "$conf_file"
    echo "    location / {" >> "$conf_file"
    
    if [ "$mode" == "2" ]; then
        # 代理模式
        echo "        proxy_pass $target_url;" >> "$conf_file"
        echo "        proxy_set_header Host \$host;" >> "$conf_file"
        echo "        proxy_set_header X-Real-IP \$remote_addr;" >> "$conf_file"
        echo "        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;" >> "$conf_file"
        echo "        proxy_set_header X-Forwarded-Proto \$scheme;" >> "$conf_file"
        echo "        proxy_ssl_server_name on;" >> "$conf_file"
        echo "        proxy_redirect off;" >> "$conf_file"
        echo "" >> "$conf_file"
        echo "        # 超时设置" >> "$conf_file"
        echo "        proxy_connect_timeout 60s;" >> "$conf_file"
        echo "        proxy_send_timeout 60s;" >> "$conf_file"
        echo "        proxy_read_timeout 60s;" >> "$conf_file"
    else
        # 镜像模式
        echo "        proxy_pass $target_url;" >> "$conf_file"
        echo "        proxy_set_header Host $target_host;" >> "$conf_file"
        echo "        proxy_set_header Referer $target_url;" >> "$conf_file"
        echo "        proxy_ssl_server_name on;" >> "$conf_file"
        echo "        proxy_set_header Accept-Encoding \"\";" >> "$conf_file"
        echo "        sub_filter \"</head>\" \"<meta name='referrer' content='no-referrer'></head>\";" >> "$conf_file"
        echo "        sub_filter \"$target_host\" \"$domain\";" >> "$conf_file"
        echo "        sub_filter \"https://$target_host\" \"https://$domain\";" >> "$conf_file"
        echo "        sub_filter \"http://$target_host\" \"https://$domain\";" >> "$conf_file"
        
        # 资源聚合
        echo -e "\n${YELLOW}>>> 资源聚合配置 (可选)${NC}"
        echo "输入需要聚合的外部资源URL (一行一个，空行结束):"
        
        local resource_count=0
        > "$conf_file.loc"
        
        while true; do
            read -p "资源URL: " resource_url
            [ -z "$resource_url" ] && break
            
            resource_url=$(normalize_url "$resource_url")
            resource_host=$(echo $resource_url | awk -F/ '{print $3}')
            resource_key="_res_$((++resource_count))"
            
            # 添加sub_filter规则
            echo "        sub_filter \"$resource_host\" \"$domain/$resource_key\";" >> "$conf_file"
            echo "        sub_filter \"https://$resource_host\" \"https://$domain/$resource_key\";" >> "$conf_file"
            echo "        sub_filter \"http://$resource_host\" \"https://$domain/$resource_key\";" >> "$conf_file"
            
            # 添加location规则
            cat >> "$conf_file.loc" <<EOF
    location /$resource_key/ {
        rewrite ^/$resource_key/(.*) /\$1 break;
        proxy_pass $resource_url;
        proxy_set_header Host $resource_host;
        proxy_set_header Referer $resource_url;
        proxy_ssl_server_name on;
        proxy_set_header Accept-Encoding "";
        proxy_redirect off;
    }
EOF
        done
        
        echo "        sub_filter_once off;" >> "$conf_file"
        echo "        sub_filter_types *;" >> "$conf_file"
    fi
    
    echo "    }" >> "$conf_file"
    
    # 添加资源聚合的location配置
    if [ -f "$conf_file.loc" ]; then
        cat "$conf_file.loc" >> "$conf_file"
        rm "$conf_file.loc"
    fi
    
    echo "}" >> "$conf_file"
    
    echo -e "${GREEN}✔ Nginx配置生成完成${NC}"
}

function repair_proxy() { 
    echo -e "${YELLOW}=== 🔧 修复代理配置 ===${NC}"
    
    # 列出站点
    if [ ! -d "$SITES_DIR" ] || [ -z "$(ls -A $SITES_DIR 2>/dev/null)" ]; then
        echo -e "${YELLOW}暂无站点${NC}"
        pause_prompt
        return
    fi
    
    echo -e "${CYAN}可用站点:${NC}"
    ls -1 "$SITES_DIR"
    echo ""
    read -p "输入域名: " d
    
    if [ ! -d "$SITES_DIR/$d" ]; then
        echo -e "${RED}❌ 站点不存在${NC}"
        pause_prompt
        return
    fi
    
    local sdir="$SITES_DIR/$d"
    
    # 检查是否是代理站点
    if [ ! -f "$sdir/nginx-proxy.conf" ]; then
        echo -e "${RED}❌ 这不是代理站点${NC}"
        pause_prompt
        return
    fi
    
    echo -e "\n${CYAN}当前配置:${NC}"
    head -20 "$sdir/nginx-proxy.conf"
    
    echo -e "\n${CYAN}修复选项:${NC}"
    echo "1. 更新目标URL"
    echo "2. 重新生成配置"
    echo "3. 修复SSL证书"
    read -p "选择: " repair_opt
    
    case $repair_opt in
        1)
            read -p "新的目标URL: " new_url
            new_url=$(normalize_url "$new_url")
            
            # 备份原配置
            cp "$sdir/nginx-proxy.conf" "$sdir/nginx-proxy.conf.backup.$(date +%Y%m%d%H%M%S)"
            
            # 重新生成配置
            generate_nginx_conf "$new_url" "$d" "1"
            
            cd "$sdir" && docker compose restart
            echo -e "${GREEN}✔ 代理配置已更新${NC}"
            ;;
            
        2)
            # 从当前配置提取目标URL
            current_url=$(grep "proxy_pass" "$sdir/nginx-proxy.conf" | head -1 | awk '{print $2}' | sed 's/;//')
            
            if [ -n "$current_url" ]; then
                echo -e "当前目标URL: $current_url"
                read -p "确认重新生成? (y/n): " confirm
                
                if [ "$confirm" == "y" ]; then
                    cp "$sdir/nginx-proxy.conf" "$sdir/nginx-proxy.conf.backup"
                    generate_nginx_conf "$current_url" "$d" "1"
                    cd "$sdir" && docker compose restart
                    echo -e "${GREEN}✔ 配置已重新生成${NC}"
                fi
            else
                echo -e "${RED}❌ 无法提取当前配置${NC}"
            fi
            ;;
            
        3)
            echo -e "${CYAN}>>> 修复SSL证书...${NC}"
            docker exec gateway_acme rm -f "/etc/nginx/certs/$d.crt" "/etc/nginx/certs/$d.key" 2>/dev/null
            docker restart gateway_acme
            echo -e "${GREEN}✔ SSL证书已重置，等待自动重新申请${NC}"
            echo -e "请等待1-5分钟，然后访问: https://$d"
            ;;
    esac
    
    pause_prompt
}

function fix_upload_limit() { 
    echo -e "${YELLOW}=== 📁 解除上传限制 ===${NC}"
    
    # 列出站点
    if [ ! -d "$SITES_DIR" ] || [ -z "$(ls -A $SITES_DIR 2>/dev/null)" ]; then
        echo -e "${YELLOW}暂无站点${NC}"
        pause_prompt
        return
    fi
    
    echo -e "${CYAN}可用站点:${NC}"
    ls -1 "$SITES_DIR"
    echo ""
    read -p "输入域名: " d
    
    local s="$SITES_DIR/$d"
    if [ ! -d "$s" ]; then
        echo -e "${RED}❌ 站点不存在${NC}"
        pause_prompt
        return
    fi
    
    echo -e "\n${CYAN}当前限制:${NC}"
    if [ -f "$s/uploads.ini" ]; then
        grep -i "max_filesize\|post_max_size\|memory_limit" "$s/uploads.ini"
    else
        echo "未找到配置文件"
    fi
    
    echo -e "\n${CYAN}设置新的限制:${NC}"
    read -p "最大文件大小 (MB, 默认512): " file_size
    [ -z "$file_size" ] && file_size=512
    
    read -p "POST大小 (MB, 默认512): " post_size
    [ -z "$post_size" ] && post_size=512
    
    read -p "内存限制 (MB, 默认512): " mem_limit
    [ -z "$mem_limit" ] && mem_limit=512
    
    read -p "执行时间 (秒, 默认600): " exec_time
    [ -z "$exec_time" ] && exec_time=600
    
    # 更新PHP配置
    cat > "$s/uploads.ini" <<EOF
; WordPress上传配置
file_uploads = On
memory_limit = ${mem_limit}M
upload_max_filesize = ${file_size}M
post_max_size = ${post_size}M
max_execution_time = $exec_time
max_input_time = $exec_time
EOF
    
    # 更新Nginx配置
    if [ -f "$s/nginx.conf" ]; then
        sed -i "s/client_max_body_size .*/client_max_body_size ${file_size}M;/g" "$s/nginx.conf"
    fi
    
    # 如果是代理站点，更新代理配置
    if [ -f "$s/nginx-proxy.conf" ]; then
        sed -i "s/client_max_body_size .*/client_max_body_size ${file_size}M;/g" "$s/nginx-proxy.conf"
    fi
    
    # 重启服务
    echo -e "\n${CYAN}>>> 重启服务...${NC}"
    cd "$s" && docker compose restart
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✔ 上传限制已更新${NC}"
        echo -e "文件大小: ${file_size}M"
        echo -e "POST大小: ${post_size}M"
        echo -e "内存限制: ${mem_limit}M"
        echo -e "执行时间: ${exec_time}秒"
        write_log "Updated upload limit for $d"
    else
        echo -e "${RED}❌ 重启失败${NC}"
    fi
    
    pause_prompt
}

function create_redirect() { 
    echo -e "${YELLOW}=== 🔀 创建域名重定向 ===${NC}"
    
    read -p "源域名 (将被重定向): " src_domain
    if [ -z "$src_domain" ]; then
        echo -e "${RED}❌ 源域名不能为空${NC}"
        pause_prompt
        return
    fi
    
    # 检查是否已存在
    if [ -d "$SITES_DIR/$src_domain" ]; then
        echo -e "${RED}❌ 站点已存在${NC}"
        pause_prompt
        return
    fi
    
    read -p "目标URL: " target_url
    if [ -z "$target_url" ]; then
        echo -e "${RED}❌ 目标URL不能为空${NC}"
        pause_prompt
        return
    fi
    
    target_url=$(normalize_url "$target_url")
    
    read -p "邮箱 (用于SSL证书): " email
    if [ -z "$email" ]; then
        email="admin@$src_domain"
        echo -e "${YELLOW}⚠️ 使用默认邮箱: $email${NC}"
    fi
    
    # 创建站点目录
    local sdir="$SITES_DIR/$src_domain"
    mkdir -p "$sdir"
    cd "$sdir"
    
    # 创建重定向配置
    cat > redirect.conf <<EOF
server {
    listen 80;
    server_name localhost;
    
    # 安全头
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    
    # 永久重定向 (301)
    return 301 $target_url\$request_uri;
}
EOF
    
    # 创建Docker Compose配置
    cat > docker-compose.yml <<EOF
version: '3.8'

services:
  redirector:
    image: nginx:alpine
    container_name: ${src_domain//./_}_redirect
    restart: always
    volumes:
      - ./redirect.conf:/etc/nginx/conf.d/default.conf
    environment:
      VIRTUAL_HOST: "$src_domain"
      LETSENCRYPT_HOST: "$src_domain"
      LETSENCRYPT_EMAIL: "$email"
      VIRTUAL_PORT: "80"
    networks:
      - proxy-net
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost"]
      interval: 30s
      timeout: 10s
      retries: 3

networks:
  proxy-net:
    external: true
EOF
    
    # 验证配置
    if ! validate_compose "$sdir"; then
        echo -e "${RED}❌ 配置文件验证失败${NC}"
        rm -rf "$sdir"
        pause_prompt
        return
    fi
    
    # 启动服务
    echo -e "${CYAN}>>> 启动重定向服务...${NC}"
    if docker compose up -d; then
        echo -e "${GREEN}✔ 重定向服务启动成功${NC}"
        
        # 等待并检查SSL证书
        check_ssl_status "$src_domain"
        
        echo -e "\n${GREEN}✅ 域名重定向创建完成!${NC}"
        echo -e "重定向: https://$src_domain"
        echo -e "目标: $target_url"
        echo -e "类型: 301 (永久重定向)"
        
        write_log "Created redirect: $src_domain -> $target_url"
    else
        echo -e "${RED}❌ 重定向服务启动失败${NC}"
        docker compose logs
        rm -rf "$sdir"
    fi
    
    pause_prompt
}

function delete_site() { 
    while true; do 
        clear
        echo -e "${YELLOW}=== 🗑️ 删除网站 ===${NC}"
        
        # 列出站点
        if [ ! -d "$SITES_DIR" ] || [ -z "$(ls -A $SITES_DIR 2>/dev/null)" ]; then
            echo -e "${YELLOW}暂无站点${NC}"
            pause_prompt
            return
        fi
        
        echo -e "${CYAN}可用站点:${NC}"
        ls -1 "$SITES_DIR"
        echo "----------------"
        read -p "输入域名 (0返回): " d
        
        [ "$d" == "0" ] && return
        
        if [ -d "$SITES_DIR/$d" ]; then
            echo -e "\n${RED}⚠️ 警告: 将要删除站点 $d${NC}"
            echo -e "这将删除:"
            echo -e "  ✓ 站点目录: $SITES_DIR/$d"
            echo -e "  ✓ Docker容器"
            echo -e "  ✓ Docker卷 (数据库和文件)"
            echo -e "  ✓ SSL证书"
            
            read -p "确认删除? (输入 DELETE 确认): " confirm
            
            if [ "$confirm" == "DELETE" ]; then
                echo -e "${CYAN}>>> 停止并删除容器...${NC}"
                cd "$SITES_DIR/$d" && docker compose down -v 2>/dev/null
                
                echo -e "${CYAN}>>> 删除站点目录...${NC}"
                cd .. && rm -rf "$SITES_DIR/$d"
                
                echo -e "${CYAN}>>> 清理SSL证书...${NC}"
                docker exec gateway_acme rm -f "/etc/nginx/certs/$d.crt" "/etc/nginx/certs/$d.key" 2>/dev/null
                docker exec gateway_proxy nginx -s reload 2>/dev/null
                
                echo -e "${GREEN}✔ 站点 $d 已删除${NC}"
                write_log "Deleted site: $d"
                
                # 询问是否删除备份
                if [ -d "$BASE_DIR/backups/$d" ]; then
                    read -p "是否删除站点备份? (y/n): " del_backup
                    if [ "$del_backup" == "y" ]; then
                        rm -rf "$BASE_DIR/backups/$d"
                        echo -e "${GREEN}✔ 备份已删除${NC}"
                    fi
                fi
            else
                echo "操作取消"
            fi
        else
            echo -e "${RED}❌ 站点不存在${NC}"
        fi
        
        pause_prompt
    done
}

function list_sites() { 
    clear
    echo -e "${YELLOW}=== 📂 站点列表 ===${NC}"
    
    if [ ! -d "$SITES_DIR" ] || [ -z "$(ls -A $SITES_DIR 2>/dev/null)" ]; then
        echo -e "${YELLOW}暂无站点${NC}"
    else
        local total=0
        echo -e "${CYAN}站点列表:${NC}"
        echo -e "┌──────────────────────────────────────┬──────────────┬────────────┐"
        echo -e "│ 域名                                 │ 类型         │ 状态       │"
        echo -e "├──────────────────────────────────────┼──────────────┼────────────┤"
        
        for d in "$SITES_DIR"/*; do
            if [ -d "$d" ]; then
                ((total++))
                domain=$(basename "$d")
                
                # 判断站点类型
                if [ -f "$d/docker-compose.yml" ]; then
                    if grep -q "wordpress" "$d/docker-compose.yml"; then
                        type="WordPress"
                    elif grep -q "redirector" "$d/docker-compose.yml"; then
                        type="重定向"
                    elif grep -q "proxy" "$d/docker-compose.yml"; then
                        type="代理"
                    else
                        type="未知"
                    fi
                else
                    type="未配置"
                fi
                
                # 检查容器状态
                if [ -f "$d/docker-compose.yml" ]; then
                    cd "$d" 2>/dev/null
                    if docker compose ps --services 2>/dev/null >/dev/null; then
                        running_count=$(docker compose ps --services | xargs -I {} sh -c 'docker compose ps {} --format "{{.Status}}" | grep -c "Up"' 2>/dev/null || echo 0)
                        total_count=$(docker compose ps --services | wc -l 2>/dev/null || echo 0)
                        
                        if [ $running_count -eq $total_count ] && [ $total_count -gt 0 ]; then
                            status="${GREEN}运行中${NC}"
                        elif [ $running_count -gt 0 ]; then
                            status="${YELLOW}部分运行${NC}"
                        else
                            status="${RED}停止${NC}"
                        fi
                    else
                        status="${RED}未运行${NC}"
                    fi
                    cd - >/dev/null
                else
                    status="${RED}未配置${NC}"
                fi
                
                # 显示（截断过长的域名）
                display_domain=$(echo "$domain" | awk '{if(length>35) print substr($0,1,32)"..."; else print $0}')
                printf "│ %-36s │ %-12s │ %-10s │\n" "$display_domain" "$type" "$status"
            fi
        done
        
        echo -e "└──────────────────────────────────────┴──────────────┴────────────┘"
        echo -e "\n总计: $total 个站点"
        
        # 显示统计信息
        echo -e "\n${CYAN}统计信息:${NC}"
        echo -e "  WordPress站点: $(ls -d $SITES_DIR/* 2>/dev/null | xargs -I {} grep -l "wordpress" {}/docker-compose.yml 2>/dev/null | wc -l)"
        echo -e "  代理站点: $(ls -d $SITES_DIR/* 2>/dev/null | xargs -I {} grep -l "proxy" {}/docker-compose.yml 2>/dev/null | wc -l)"
        echo -e "  重定向站点: $(ls -d $SITES_DIR/* 2>/dev/null | xargs -I {} grep -l "redirector" {}/docker-compose.yml 2>/dev/null | wc -l)"
    fi
    
    pause_prompt
}

function cert_management() { 
    while true; do 
        clear
        echo -e "${YELLOW}=== 🔐 HTTPS证书管理 ===${NC}"
        
        # 显示证书统计
        local cert_count=0
        if docker ps --format '{{.Names}}' | grep -q "^gateway_acme$"; then
            cert_count=$(docker exec gateway_acme ls -1 /etc/nginx/certs/*.crt 2>/dev/null | wc -l)
        fi
        
        echo -e "证书总数: $cert_count"
        echo "--------------------------"
        echo " 1. 查看证书列表"
        echo " 2. 上传自定义证书"
        echo " 3. 重置证书 (重新申请)"
        echo " 4. 强制续签证书"
        echo " 5. 删除证书"
        echo " 6. 证书监控"
        echo " 0. 返回上一级"
        echo "--------------------------"
        read -p "请输入选项 [0-6]: " c
        
        case $c in 
            0) 
                return
                ;; 
                
            1) 
                echo -e "${CYAN}>>> 证书列表${NC}"
                if docker ps --format '{{.Names}}' | grep -q "^gateway_acme$"; then
                    docker exec gateway_acme ls -lh /etc/nginx/certs/*.crt 2>/dev/null | \
                    awk '{
                        split($9, a, "/");
                        split(a[5], b, ".");
                        printf "域名: %-30s 大小: %-10s 修改时间: %s %s\n", b[1], $5, $6, $7
                    }' || echo "暂无证书"
                else
                    echo -e "${RED}❌ ACME容器未运行${NC}"
                fi
                pause_prompt
                ;; 
                
            2) 
                ls -1 "$SITES_DIR"
                read -p "域名: " d
                
                if [ ! -d "$SITES_DIR/$d" ]; then
                    echo -e "${RED}❌ 站点不存在${NC}"
                    pause_prompt
                    continue
                fi
                
                read -p "证书文件路径 (.crt): " cert_file
                read -p "私钥文件路径 (.key): " key_file
                
                if [ ! -f "$cert_file" ] || [ ! -f "$key_file" ]; then
                    echo -e "${RED}❌ 证书文件不存在${NC}"
                    pause_prompt
                    continue
                fi
                
                # 复制证书到容器
                docker cp "$cert_file" gateway_acme:"/etc/nginx/certs/$d.crt"
                docker cp "$key_file" gateway_acme:"/etc/nginx/certs/$d.key"
                
                # 重载nginx
                docker exec gateway_proxy nginx -s reload
                
                echo -e "${GREEN}✔ 证书上传成功${NC}"
                write_log "Uploaded custom cert for $d"
                pause_prompt
                ;; 
                
            3) 
                read -p "域名: " d
                
                # 删除旧证书
                docker exec gateway_acme rm -f "/etc/nginx/certs/$d.crt" "/etc/nginx/certs/$d.key" 2>/dev/null
                
                # 重启acme容器重新申请
                docker restart gateway_acme
                
                echo -e "${GREEN}✔ 证书已重置，正在重新申请...${NC}"
                echo -e "请等待1-5分钟，然后访问: https://$d"
                write_log "Reset cert for $d"
                pause_prompt
                ;; 
                
            4) 
                echo -e "${CYAN}>>> 强制续签证书${NC}"
                docker exec gateway_acme /app/force_renew 2>/dev/null
                
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}✔ 证书续签任务已触发${NC}"
                    echo -e "续签可能需要几分钟时间"
                else
                    echo -e "${RED}❌ 续签失败${NC}"
                fi
                pause_prompt
                ;; 
                
            5)
                read -p "域名: " d
                
                echo -e "${RED}⚠️ 确认删除 $d 的证书? (y/n): ${NC}"
                read confirm
                
                if [ "$confirm" == "y" ]; then
                    docker exec gateway_acme rm -f "/etc/nginx/certs/$d.crt" "/etc/nginx/certs/$d.key" 2>/dev/null
                    docker exec gateway_proxy nginx -s reload
                    echo -e "${GREEN}✔ 证书已删除${NC}"
                    write_log "Deleted cert for $d"
                fi
                pause_prompt
                ;;
                
            6)
                echo -e "${CYAN}>>> 证书监控${NC}"
                echo -e "检查证书过期时间..."
                
                if docker ps --format '{{.Names}}' | grep -q "^gateway_acme$"; then
                    docker exec gateway_acme find /etc/nginx/certs -name "*.crt" -exec bash -c '
                        echo "检查: $1"
                        openssl x509 -enddate -noout -in "$1" 2>/dev/null | cut -d= -f2
                        echo ""
                    ' _ {} \;
                else
                    echo -e "${RED}❌ ACME容器未运行${NC}"
                fi
                pause_prompt
                ;;
        esac
    done
}

function db_manager() { 
    while true; do 
        clear
        echo -e "${YELLOW}=== 🗄️ 数据库管理 ===${NC}"
        
        # 列出站点
        if [ ! -d "$SITES_DIR" ] || [ -z "$(ls -A $SITES_DIR 2>/dev/null)" ]; then
            echo -e "${YELLOW}暂无站点${NC}"
            pause_prompt
            return
        fi
        
        echo -e "${CYAN}可用站点:${NC}"
        ls -1 "$SITES_DIR"
        echo "--------------------------"
        echo " 1. 导出数据库"
        echo " 2. 导入数据库"
        echo " 3. 优化数据库"
        echo " 4. 修复数据库"
        echo " 5. 查看数据库大小"
        echo " 0. 返回上一级"
        echo "--------------------------"
        read -p "请输入选项 [0-5]: " c
        
        case $c in 
            0) 
                return
                ;; 
                
            1) 
                ls -1 "$SITES_DIR"
                read -p "域名: " d
                
                local s="$SITES_DIR/$d"
                if [ ! -d "$s" ]; then
                    echo -e "${RED}❌ 站点不存在${NC}"
                    pause_prompt
                    continue
                fi
                
                # 获取数据库密码
                local db_pass=$(grep MYSQL_ROOT_PASSWORD "$s/docker-compose.yml" 2>/dev/null | awk -F': ' '{print $2}')
                if [ -z "$db_pass" ]; then
                    echo -e "${RED}❌ 无法获取数据库密码${NC}"
                    pause_prompt
                    continue
                fi
                
                # 导出数据库
                local backup_file="$s/${d}_db_$(date +%Y%m%d_%H%M%S).sql"
                echo -e "${CYAN}>>> 导出数据库...${NC}"
                
                if docker compose -f "$s/docker-compose.yml" exec -T db mysqldump -u root -p"$db_pass" --all-databases --single-transaction --routines --triggers > "$backup_file"; then
                    # 压缩备份
                    gzip "$backup_file"
                    local backup_size=$(du -h "${backup_file}.gz" | awk '{print $1}')
                    
                    echo -e "${GREEN}✔ 数据库导出成功${NC}"
                    echo -e "文件: ${backup_file}.gz"
                    echo -e "大小: $backup_size"
                    
                    # 加密选项
                    read -p "是否加密备份? (y/n): " encrypt_opt
                    if [ "$encrypt_opt" == "y" ]; then
                        backup_with_encryption "$(dirname ${backup_file}.gz)" "${backup_file}.encrypted" "true"
                        rm -f "${backup_file}.gz"
                    fi
                    
                    write_log "Exported DB for $d"
                else
                    echo -e "${RED}❌ 数据库导出失败${NC}"
                    rm -f "$backup_file"
                fi
                pause_prompt
                ;; 
                
            2) 
                ls -1 "$SITES_DIR"
                read -p "域名: " d
                
                local s="$SITES_DIR/$d"
                if [ ! -d "$s" ]; then
                    echo -e "${RED}❌ 站点不存在${NC}"
                    pause_prompt
                    continue
                fi
                
                read -p "SQL文件路径: " sql_file
                if [ ! -f "$sql_file" ]; then
                    echo -e "${RED}❌ SQL文件不存在${NC}"
                    pause_prompt
                    continue
                fi
                
                # 获取数据库密码
                local db_pass=$(grep MYSQL_ROOT_PASSWORD "$s/docker-compose.yml" 2>/dev/null | awk -F': ' '{print $2}')
                if [ -z "$db_pass" ]; then
                    echo -e "${RED}❌ 无法获取数据库密码${NC}"
                    pause_prompt
                    continue
                fi
                
                # 检查文件类型（是否加密）
                if [[ "$sql_file" == *.gpg ]]; then
                    echo -e "${CYAN}>>> 检测到加密文件，正在解密...${NC}"
                    local decrypted_file="/tmp/decrypted_$(basename $sql_file .gpg)"
                    gpg --batch --yes --passphrase "$ENCRYPT_KEY" --decrypt "$sql_file" 2>/dev/null > "$decrypted_file"
                    
                    if [ $? -ne 0 ]; then
                        echo -e "${RED}❌ 解密失败${NC}"
                        rm -f "$decrypted_file"
                        pause_prompt
                        continue
                    fi
                    sql_file="$decrypted_file"
                elif [[ "$sql_file" == *.gz ]]; then
                    echo -e "${CYAN}>>> 解压文件...${NC}"
                    gunzip -c "$sql_file" > "/tmp/$(basename $sql_file .gz)"
                    sql_file="/tmp/$(basename $sql_file .gz)"
                fi
                
                # 导入数据库
                echo -e "${CYAN}>>> 导入数据库...${NC}"
                
                # 备份当前数据库
                echo -e "${YELLOW}>>> 备份当前数据库...${NC}"
                local backup_file="$s/db_pre_import_$(date +%Y%m%d_%H%M%S).sql"
                docker compose -f "$s/docker-compose.yml" exec -T db mysqldump -u root -p"$db_pass" --all-databases > "$backup_file" 2>/dev/null
                
                # 导入新数据
                if cat "$sql_file" | docker compose -f "$s/docker-compose.yml" exec -T db mysql -u root -p"$db_pass"; then
                    echo -e "${GREEN}✔ 数据库导入成功${NC}"
                    echo -e "备份文件: $backup_file"
                    write_log "Imported DB for $d"
                else
                    echo -e "${RED}❌ 数据库导入失败${NC}"
                    echo -e "${YELLOW}⚠️ 正在恢复备份...${NC}"
                    cat "$backup_file" | docker compose -f "$s/docker-compose.yml" exec -T db mysql -u root -p"$db_pass"
                fi
                
                # 清理临时文件
                if [[ "$sql_file" == /tmp/* ]]; then
                    rm -f "$sql_file"
                fi
                
                pause_prompt
                ;; 
                
            3)
                ls -1 "$SITES_DIR"
                read -p "域名: " d
                
                local s="$SITES_DIR/$d"
                if [ ! -d "$s" ]; then
                    echo -e "${RED}❌ 站点不存在${NC}"
                    pause_prompt
                    continue
                fi
                
                # 获取数据库密码
                local db_pass=$(grep MYSQL_ROOT_PASSWORD "$s/docker-compose.yml" 2>/dev/null | awk -F': ' '{print $2}')
                if [ -z "$db_pass" ]; then
                    echo -e "${RED}❌ 无法获取数据库密码${NC}"
                    pause_prompt
                    continue
                fi
                
                echo -e "${CYAN}>>> 优化数据库...${NC}"
                docker compose -f "$s/docker-compose.yml" exec -T db mysql -u root -p"$db_pass" -e "USE wordpress; OPTIMIZE TABLE wp_posts, wp_postmeta, wp_options, wp_comments, wp_commentmeta;" 2>/dev/null
                
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}✔ 数据库优化完成${NC}"
                else
                    echo -e "${YELLOW}⚠️ 优化可能已完成或有错误${NC}"
                fi
                pause_prompt
                ;;
                
            4)
                ls -1 "$SITES_DIR"
                read -p "域名: " d
                
                local s="$SITES_DIR/$d"
                if [ ! -d "$s" ]; then
                    echo -e "${RED}❌ 站点不存在${NC}"
                    pause_prompt
                    continue
                fi
                
                # 获取数据库密码
                local db_pass=$(grep MYSQL_ROOT_PASSWORD "$s/docker-compose.yml" 2>/dev/null | awk -F': ' '{print $2}')
                if [ -z "$db_pass" ]; then
                    echo -e "${RED}❌ 无法获取数据库密码${NC}"
                    pause_prompt
                    continue
                fi
                
                echo -e "${CYAN}>>> 修复数据库...${NC}"
                docker compose -f "$s/docker-compose.yml" exec -T db mysqlcheck -u root -p"$db_pass" --auto-repair --all-databases 2>/dev/null
                
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}✔ 数据库修复完成${NC}"
                else
                    echo -e "${RED}❌ 数据库修复失败${NC}"
                fi
                pause_prompt
                ;;
                
            5)
                ls -1 "$SITES_DIR"
                read -p "域名: " d
                
                local s="$SITES_DIR/$d"
                if [ ! -d "$s" ]; then
                    echo -e "${RED}❌ 站点不存在${NC}"
                    pause_prompt
                    continue
                fi
                
                # 获取数据库密码
                local db_pass=$(grep MYSQL_ROOT_PASSWORD "$s/docker-compose.yml" 2>/dev/null | awk -F': ' '{print $2}')
                if [ -z "$db_pass" ]; then
                    echo -e "${RED}❌ 无法获取数据库密码${NC}"
                    pause_prompt
                    continue
                fi
                
                echo -e "${CYAN}>>> 数据库大小统计${NC}"
                docker compose -f "$s/docker-compose.yml" exec -T db mysql -u root -p"$db_pass" -e "
                    SELECT table_schema '数据库', 
                    ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) '大小(MB)'
                    FROM information_schema.tables 
                    GROUP BY table_schema;
                " 2>/dev/null
                
                echo -e "\n${CYAN}数据表大小 (前10):${NC}"
                docker compose -f "$s/docker-compose.yml" exec -T db mysql -u root -p"$db_pass" -e "
                    SELECT table_name '表名',
                    ROUND((data_length + index_length) / 1024 / 1024, 2) '大小(MB)',
                    ROUND((data_free) / 1024 / 1024, 2) '碎片(MB)'
                    FROM information_schema.tables 
                    WHERE table_schema = 'wordpress'
                    ORDER BY (data_length + index_length) DESC
                    LIMIT 10;
                " 2>/dev/null
                pause_prompt
                ;;
        esac
    done 
}

function change_domain() { 
    echo -e "${YELLOW}=== 🔄 更换网站域名 ===${NC}"
    
    # 列出站点
    if [ ! -d "$SITES_DIR" ] || [ -z "$(ls -A $SITES_DIR 2>/dev/null)" ]; then
        echo -e "${YELLOW}暂无站点${NC}"
        pause_prompt
        return
    fi
    
    echo -e "${CYAN}可用站点:${NC}"
    ls -1 "$SITES_DIR"
    echo ""
    read -p "旧域名: " old_domain
    
    if [ ! -d "$SITES_DIR/$old_domain" ]; then
        echo -e "${RED}❌ 站点不存在${NC}"
        pause_prompt
        return
    fi
    
    read -p "新域名: " new_domain
    
    if [ -z "$new_domain" ]; then
        echo -e "${RED}❌ 新域名不能为空${NC}"
        pause_prompt
        return
    fi
    
    if [ -d "$SITES_DIR/$new_domain" ]; then
        echo -e "${RED}❌ 新域名已存在${NC}"
        pause_prompt
        return
    fi
    
    echo -e "\n${RED}⚠️ 警告: 更换域名会影响以下内容${NC}"
    echo -e "  ✓ 网站访问地址"
    echo -e "  ✓ SSL证书"
    echo -e "  ✓ WordPress配置"
    echo -e "  ✓ 数据库内容"
    
    read -p "确认更换? (y/n): " confirm
    
    if [ "$confirm" != "y" ]; then
        echo "操作取消"
        pause_prompt
        return
    fi
    
    # 备份原站点
    echo -e "${CYAN}>>> 备份原站点...${NC}"
    cp -r "$SITES_DIR/$old_domain" "$SITES_DIR/${old_domain}_backup_$(date +%Y%m%d%H%M%S)"
    
    # 停止原服务
    echo -e "${CYAN}>>> 停止原服务...${NC}"
    cd "$SITES_DIR/$old_domain" && docker compose down
    
    # 重命名目录
    echo -e "${CYAN}>>> 更新目录结构...${NC}"
    cd "$SITES_DIR" && mv "$old_domain" "$new_domain"
    
    # 更新配置文件
    echo -e "${CYAN}>>> 更新配置文件...${NC}"
    cd "$SITES_DIR/$new_domain"
    
    # 更新docker-compose.yml中的域名
    sed -i "s/$old_domain/$new_domain/g" docker-compose.yml
    
    # 更新nginx配置中的域名
    if [ -f "nginx.conf" ]; then
        sed -i "s/server_name localhost/server_name $new_domain/g" nginx.conf
    fi
    
    if [ -f "nginx-proxy.conf" ]; then
        sed -i "s/server_name localhost/server_name $new_domain/g" nginx-proxy.conf
    fi
    
    # 更新环境变量
    sed -i "s/VIRTUAL_HOST: \"$old_domain\"/VIRTUAL_HOST: \"$new_domain\"/g" docker-compose.yml
    sed -i "s/LETSENCRYPT_HOST: \"$old_domain\"/LETSENCRYPT_HOST: \"$new_domain\"/g" docker-compose.yml
    
    # 启动新服务
    echo -e "${CYAN}>>> 启动新服务...${NC}"
    docker compose up -d
    
    # 如果是WordPress站点，更新数据库
    if grep -q "wordpress" docker-compose.yml; then
        echo -e "${CYAN}>>> 更新WordPress数据库...${NC}"
        
        # 获取WordPress容器ID
        local wp_container=$(docker compose ps -q wordpress 2>/dev/null)
        
        if [ -n "$wp_container" ]; then
            # 更新数据库中的域名
            docker exec $wp_container wp search-replace "$old_domain" "$new_domain" --all-tables --skip-columns=guid 2>/dev/null
            
            # 更新站点URL
            docker exec $wp_container wp option update home "https://$new_domain" 2>/dev/null
            docker exec $wp_container wp option update siteurl "https://$new_domain" 2>/dev/null
            
            echo -e "${GREEN}✔ WordPress数据库已更新${NC}"
        fi
    fi
    
    # 重载网关
    echo -e "${CYAN}>>> 更新网关配置...${NC}"
    docker exec gateway_proxy nginx -s reload 2>/dev/null
    
    # 等待SSL证书申请
    echo -e "${CYAN}>>> 等待SSL证书申请...${NC}"
    check_ssl_status "$new_domain"
    
    echo -e "\n${GREEN}✅ 域名更换完成!${NC}"
    echo -e "原域名: $old_domain"
    echo -e "新域名: $new_domain"
    echo -e "访问地址: https://$new_domain"
    
    write_log "Changed domain: $old_domain -> $new_domain"
    pause_prompt
}

function manage_hotlink() { 
    while true; do 
        clear
        echo -e "${YELLOW}=== 🛡️ 防盗链设置 ===${NC}"
        
        # 列出站点
        if [ ! -d "$SITES_DIR" ] || [ -z "$(ls -A $SITES_DIR 2>/dev/null)" ]; then
            echo -e "${YELLOW}暂无站点${NC}"
            pause_prompt
            return
        fi
        
        echo -e "${CYAN}可用站点:${NC}"
        ls -1 "$SITES_DIR"
        echo "--------------------------"
        echo " 1. 开启防盗链"
        echo " 2. 关闭防盗链"
        echo " 3. 查看当前设置"
        echo " 0. 返回上一级"
        echo "--------------------------"
        read -p "请输入选项 [0-3]: " h
        
        case $h in 
            0) 
                return
                ;; 
                
            1) 
                ls -1 "$SITES_DIR"
                read -p "域名: " d
                
                local s="$SITES_DIR/$d"
                if [ ! -d "$s" ]; then
                    echo -e "${RED}❌ 站点不存在${NC}"
                    pause_prompt
                    continue
                fi
                
                read -p "白名单域名 (空格分隔, 例如: example.com google.com): " whitelist
                
                # 生成防盗链配置
                cat > "$s/nginx.conf" <<EOF
server {
    listen 80;
    server_name localhost;
    root /var/www/html;
    index index.php;
    include /etc/nginx/waf.conf;
    client_max_body_size 512M;
    
    # 安全头
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    
    # 防盗链设置
    location ~* \.(gif|jpg|jpeg|png|webp|bmp|ico|svg|mp4|webm|ogg|mp3|wav|flac|avi|mov|wmv|flv|mkv)$ {
        valid_referers none blocked server_names $d *.$d $whitelist;
        if (\$invalid_referer) {
            return 403;
            # 或者返回一张默认图片
            # return 301 https://$d/default-image.jpg;
        }
        try_files \$uri \$uri/ /index.php?\$args;
        
        # 缓存设置
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
    
    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }
    
    location ~ \.php\$ {
        try_files \$uri =404;
        fastcgi_split_path_info ^(.+\.php)(/.+)\$;
        fastcgi_pass wordpress:9000;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_param PATH_INFO \$fastcgi_path_info;
        fastcgi_read_timeout 600;
    }
}
EOF
                
                cd "$s" && docker compose restart nginx
                
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}✔ 防盗链已开启${NC}"
                    echo -e "保护域名: $d"
                    echo -e "白名单: $whitelist"
                    write_log "Enabled hotlink protection for $d"
                else
                    echo -e "${RED}❌ 配置失败${NC}"
                fi
                pause_prompt
                ;; 
                
            2) 
                ls -1 "$SITES_DIR"
                read -p "域名: " d
                
                local s="$SITES_DIR/$d"
                if [ ! -d "$s" ]; then
                    echo -e "${RED}❌ 站点不存在${NC}"
                    pause_prompt
                    continue
                fi
                
                # 恢复默认配置
                cat > "$s/nginx.conf" <<EOF
server {
    listen 80;
    server_name localhost;
    root /var/www/html;
    index index.php;
    include /etc/nginx/waf.conf;
    client_max_body_size 512M;
    
    # 安全头
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    
    # 缓存静态文件
    location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
    
    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }
    
    location ~ \.php\$ {
        try_files \$uri =404;
        fastcgi_split_path_info ^(.+\.php)(/.+)\$;
        fastcgi_pass wordpress:9000;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_param PATH_INFO \$fastcgi_path_info;
        fastcgi_read_timeout 600;
    }
}
EOF
                
                cd "$s" && docker compose restart nginx
                
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}✔ 防盗链已关闭${NC}"
                    write_log "Disabled hotlink protection for $d"
                else
                    echo -e "${RED}❌ 配置失败${NC}"
                fi
                pause_prompt
                ;; 
                
            3)
                ls -1 "$SITES_DIR"
                read -p "域名: " d
                
                local s="$SITES_DIR/$d"
                if [ ! -d "$s" ]; then
                    echo -e "${RED}❌ 站点不存在${NC}"
                    pause_prompt
                    continue
                fi
                
                echo -e "${CYAN}>>> 当前防盗链设置${NC}"
                if grep -q "valid_referers" "$s/nginx.conf"; then
                    grep -A 5 "valid_referers" "$s/nginx.conf"
                else
                    echo -e "${YELLOW}未启用防盗链${NC}"
                fi
                pause_prompt
                ;;
        esac
    done 
}

function backup_restore_ops() { 
    while true; do 
        clear
        echo -e "${YELLOW}=== 💾 备份与恢复 ===${NC}"
        
        # 创建备份目录
        mkdir -p "$BASE_DIR/backups"
        
        echo "--------------------------"
        echo " 1. 备份站点"
        echo " 2. 恢复站点"
        echo " 3. 管理备份文件"
        echo " 4. 自动备份设置"
        echo " 0. 返回上一级"
        echo "--------------------------"
        read -p "请输入选项 [0-4]: " b
        
        case $b in 
            0) 
                return
                ;; 
                
            1) 
                echo -e "${CYAN}>>> 备份站点${NC}"
                
                # 列出站点
                if [ ! -d "$SITES_DIR" ] || [ -z "$(ls -A $SITES_DIR 2>/dev/null)" ]; then
                    echo -e "${YELLOW}暂无站点${NC}"
                    pause_prompt
                    continue
                fi
                
                echo -e "${CYAN}可用站点:${NC}"
                ls -1 "$SITES_DIR"
                echo ""
                read -p "域名 (留空备份所有): " backup_domain
                
                local backup_timestamp=$(date +%Y%m%d_%H%M%S)
                
                if [ -z "$backup_domain" ]; then
                    # 备份所有站点
                    echo -e "${CYAN}>>> 备份所有站点...${NC}"
                    
                    local total_backup=0
                    for d in "$SITES_DIR"/*; do
                        if [ -d "$d" ]; then
                            site_name=$(basename "$d")
                            echo -e "\n备份: $site_name"
                            
                            if backup_single_site "$site_name" "$backup_timestamp"; then
                                ((total_backup++))
                            fi
                        fi
                    done
                    
                    echo -e "\n${GREEN}✔ 备份完成: $total_backup 个站点${NC}"
                    
                else
                    # 备份单个站点
                    if [ ! -d "$SITES_DIR/$backup_domain" ]; then
                        echo -e "${RED}❌ 站点不存在${NC}"
                        pause_prompt
                        continue
                    fi
                    
                    backup_single_site "$backup_domain" "$backup_timestamp"
                fi
                
                pause_prompt
                ;; 
                
            2) 
                echo -e "${CYAN}>>> 恢复站点${NC}"
                
                # 显示备份列表
                if [ ! -d "$BASE_DIR/backups" ] || [ -z "$(ls -A $BASE_DIR/backups 2>/dev/null)" ]; then
                    echo -e "${YELLOW}暂无备份${NC}"
                    pause_prompt
                    continue
                fi
                
                echo -e "${CYAN}可用备份:${NC}"
                find "$BASE_DIR/backups" -name "*.tar.gz" -o -name "*.tar.gz.gpg" 2>/dev/null | \
                xargs -I {} basename {} | \
                sort -r | head -20
                
                echo ""
                read -p "备份文件名: " backup_file
                
                local full_backup_path=$(find "$BASE_DIR/backups" -name "$backup_file" 2>/dev/null)
                
                if [ -z "$full_backup_path" ] || [ ! -f "$full_backup_path" ]; then
                    echo -e "${RED}❌ 备份文件不存在${NC}"
                    pause_prompt
                    continue
                fi
                
                # 提取备份信息
                local backup_name=$(basename "$backup_file")
                local site_name=$(echo "$backup_name" | cut -d_ -f1)
                local backup_date=$(echo "$backup_name" | cut -d_ -f2- | sed 's/\.tar\.gz.*//')
                
                echo -e "\n${CYAN}备份信息:${NC}"
                echo -e "站点: $site_name"
                echo -e "时间: $backup_date"
                echo -e "文件: $backup_file"
                
                read -p "确认恢复? (y/n): " confirm
                
                if [ "$confirm" != "y" ]; then
                    echo "操作取消"
                    pause_prompt
                    continue
                fi
                
                # 恢复站点
                restore_single_site "$full_backup_path" "$site_name"
                pause_prompt
                ;; 
                
            3)
                echo -e "${CYAN}>>> 管理备份文件${NC}"
                
                if [ ! -d "$BASE_DIR/backups" ]; then
                    echo -e "${YELLOW}暂无备份${NC}"
                    pause_prompt
                    continue
                fi
                
                # 显示备份统计
                local total_backups=$(find "$BASE_DIR/backups" -name "*.tar.gz" -o -name "*.tar.gz.gpg" 2>/dev/null | wc -l)
                local total_size=$(du -sh "$BASE_DIR/backups" 2>/dev/null | awk '{print $1}')
                
                echo -e "备份总数: $total_backups"
                echo -e "总大小: $total_size"
                echo ""
                
                echo " 1. 查看备份列表"
                echo " 2. 删除旧备份"
                echo " 3. 清理加密备份"
                echo " 0. 返回"
                echo "--------------------------"
                read -p "选择: " manage_opt
                
                case $manage_opt in
                    1)
                        echo -e "${CYAN}>>> 备份文件列表${NC}"
                        find "$BASE_DIR/backups" -name "*.tar.gz" -o -name "*.tar.gz.gpg" 2>/dev/null | \
                        xargs -I {} sh -c '
                            file={}
                            size=$(du -h "$file" | cut -f1)
                            date=$(stat -c %y "$file" | cut -d" " -f1)
                            echo "$(basename "$file") - $size - $date"
                        ' | sort -r | head -20
                        ;;
                        
                    2)
                        echo -e "${CYAN}>>> 删除旧备份${NC}"
                        read -p "保留最近几天的备份? (默认30): " keep_days
                        [ -z "$keep_days" ] && keep_days=30
                        
                        local deleted_count=$(find "$BASE_DIR/backups" -name "*.tar.gz" -mtime +$keep_days 2>/dev/null | wc -l)
                        
                        if [ $deleted_count -gt 0 ]; then
                            find "$BASE_DIR/backups" -name "*.tar.gz" -mtime +$keep_days -delete 2>/dev/null
                            echo -e "${GREEN}✔ 已删除 $deleted_count 个旧备份${NC}"
                        else
                            echo -e "${YELLOW}⚠️ 没有可删除的旧备份${NC}"
                        fi
                        ;;
                        
                    3)
                        echo -e "${CYAN}>>> 清理加密备份${NC}"
                        local encrypted_count=$(find "$BASE_DIR/backups" -name "*.gpg" 2>/dev/null | wc -l)
                        
                        if [ $encrypted_count -gt 0 ]; then
                            echo -e "找到 $encrypted_count 个加密备份"
                            read -p "是否全部删除? (y/n): " del_encrypted
                            
                            if [ "$del_encrypted" == "y" ]; then
                                find "$BASE_DIR/backups" -name "*.gpg" -delete 2>/dev/null
                                echo -e "${GREEN}✔ 已删除所有加密备份${NC}"
                            fi
                        else
                            echo -e "${YELLOW}⚠️ 没有加密备份${NC}"
                        fi
                        ;;
                esac
                pause_prompt
                ;;
                
            4)
                echo -e "${CYAN}>>> 自动备份设置${NC}"
                
                # 检查现有任务
                local existing_cron=$(crontab -l 2>/dev/null | grep "wp-cluster-backup")
                
                if [ -n "$existing_cron" ]; then
                    echo -e "当前自动备份设置:"
                    echo "$existing_cron"
                    echo ""
                    echo " 1. 修改设置"
                    echo " 2. 删除设置"
                    read -p "选择: " auto_opt
                    
                    case $auto_opt in
                        1)
                            crontab -l 2>/dev/null | grep -v "wp-cluster-backup" | crontab -
                            ;;
                        2)
                            crontab -l 2>/dev/null | grep -v "wp-cluster-backup" | crontab -
                            echo -e "${GREEN}✔ 自动备份已禁用${NC}"
                            pause_prompt
                            continue
                            ;;
                    esac
                fi
                
                # 设置新任务
                echo -e "\n${CYAN}设置自动备份${NC}"
                echo "1. 每天备份"
                echo "2. 每周备份"
                echo "3. 每月备份"
                read -p "选择频率: " freq_opt
                
                local cron_time="0 2"  # 默认凌晨2点
                read -p "备份时间 (小时 分钟, 如 2 0): " backup_time
                [ -n "$backup_time" ] && cron_time="$backup_time"
                
                case $freq_opt in
                    1) cron_freq="* * *" ;;  # 每天
                    2) cron_freq="* * 0" ;;  # 每周日
                    3) cron_freq="1 * *" ;;  # 每月1号
                    *) cron_freq="* * *" ;;  # 默认每天
                esac
                
                # 添加cron任务
                (crontab -l 2>/dev/null; echo "$cron_time $cron_freq $0 --auto-backup #wp-cluster-backup") | crontab -
                
                echo -e "${GREEN}✔ 自动备份已设置${NC}"
                echo -e "时间: $cron_time $cron_freq"
                echo -e "命令: $0 --auto-backup"
                
                pause_prompt
                ;;
        esac
    done 
}

function backup_single_site() {
    local site_name=$1
    local timestamp=$2
    local sdir="$SITES_DIR/$site_name"
    
    if [ ! -d "$sdir" ]; then
        echo -e "  ${RED}❌ 站点不存在${NC}"
        return 1
    fi
    
    # 创建备份目录
    local backup_dir="$BASE_DIR/backups/$site_name"
    mkdir -p "$backup_dir"
    
    # 备份文件
    local backup_file="$backup_dir/${site_name}_${timestamp}.tar.gz"
    
    echo -e "  ${CYAN}备份目录: $sdir${NC}"
    
    # 备份数据库
    echo -e "  ${CYAN}备份数据库...${NC}"
    local db_pass=$(grep MYSQL_ROOT_PASSWORD "$sdir/docker-compose.yml" 2>/dev/null | awk -F': ' '{print $2}')
    
    if [ -n "$db_pass" ]; then
        docker compose -f "$sdir/docker-compose.yml" exec -T db mysqldump -u root -p"$db_pass" --all-databases --single-transaction > "$sdir/db_backup.sql" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            echo -e "    ${GREEN}✔ 数据库备份成功${NC}"
        else
            echo -e "    ${YELLOW}⚠️ 数据库备份失败${NC}"
            rm -f "$sdir/db_backup.sql"
        fi
    fi
    
    # 备份WordPress文件
    echo -e "  ${CYAN}备份文件...${NC}"
    local wp_container=$(docker compose -f "$sdir/docker-compose.yml" ps -q wordpress 2>/dev/null)
    
    if [ -n "$wp_container" ]; then
        docker run --rm --volumes-from $wp_container -v "$sdir:/backup" alpine tar czf /backup/wp_files.tar.gz /var/www/html/wp-content 2>/dev/null
        echo -e "    ${GREEN}✔ 文件备份成功${NC}"
    fi
    
    # 备份配置文件
    echo -e "  ${CYAN}备份配置文件...${NC}"
    cp "$sdir/docker-compose.yml" "$sdir/docker-compose.yml.backup" 2>/dev/null
    
    # 创建压缩包
    echo -e "  ${CYAN}创建压缩包...${NC}"
    cd "$sdir" && tar czf "$backup_file" \
        docker-compose.yml \
        nginx.conf \
        waf.conf \
        uploads.ini \
        db_backup.sql \
        wp_files.tar.gz 2>/dev/null
    
    # 清理临时文件
    rm -f "$sdir/db_backup.sql" "$sdir/wp_files.tar.gz" "$sdir/docker-compose.yml.backup"
    
    local backup_size=$(du -h "$backup_file" | awk '{print $1}')
    
    echo -e "  ${GREEN}✔ 站点备份完成${NC}"
    echo -e "    文件: $(basename $backup_file)"
    echo -e "    大小: $backup_size"
    
    # 加密选项
    read -p "    是否加密备份? (y/n): " encrypt_backup
    
    if [ "$encrypt_backup" == "y" ]; then
        backup_with_encryption "$backup_dir" "$backup_file" "true"
        rm -f "$backup_file"
        backup_file="$backup_file.gpg"
    fi
    
    write_log "Backed up site: $site_name"
    return 0
}

function restore_single_site() {
    local backup_file=$1
    local site_name=$2
    
    echo -e "\n${CYAN}>>> 恢复站点: $site_name${NC}"
    
    # 检查目标站点是否存在
    if [ -d "$SITES_DIR/$site_name" ]; then
        echo -e "${YELLOW}⚠️ 目标站点已存在${NC}"
        read -p "是否覆盖? (y/n): " overwrite
        
        if [ "$overwrite" != "y" ]; then
            echo "操作取消"
            return 1
        fi
        
        # 停止并删除原站点
        echo -e "${CYAN}>>> 清理原站点...${NC}"
        cd "$SITES_DIR/$site_name" && docker compose down -v 2>/dev/null
        cd .. && rm -rf "$SITES_DIR/$site_name"
    fi
    
    # 创建临时目录
    local temp_dir="/tmp/restore_${site_name}_$(date +%s)"
    mkdir -p "$temp_dir"
    
    # 解压备份
    echo -e "${CYAN}>>> 解压备份文件...${NC}"
    
    if [[ "$backup_file" == *.gpg ]]; then
        # 解密
        gpg --batch --yes --passphrase "$ENCRYPT_KEY" --decrypt "$backup_file" 2>/dev/null | tar xz -C "$temp_dir"
        
        if [ $? -ne 0 ]; then
            echo -e "${RED}❌ 解密失败${NC}"
            rm -rf "$temp_dir"
            return 1
        fi
    else
        # 直接解压
        tar xzf "$backup_file" -C "$temp_dir"
        
        if [ $? -ne 0 ]; then
            echo -e "${RED}❌ 解压失败${NC}"
            rm -rf "$temp_dir"
            return 1
        fi
    fi
    
    # 创建站点目录
    mkdir -p "$SITES_DIR/$site_name"
    
    # 复制配置文件
    echo -e "${CYAN}>>> 复制配置文件...${NC}"
    cp "$temp_dir/docker-compose.yml" "$SITES_DIR/$site_name/"
    cp "$temp_dir/nginx.conf" "$SITES_DIR/$site_name/" 2>/dev/null
    cp "$temp_dir/waf.conf" "$SITES_DIR/$site_name/" 2>/dev/null
    cp "$temp_dir/uploads.ini" "$SITES_DIR/$site_name/" 2>/dev/null
    
    # 启动服务
    echo -e "${CYAN}>>> 启动服务...${NC}"
    cd "$SITES_DIR/$site_name" && docker compose up -d
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}❌ 服务启动失败${NC}"
        rm -rf "$temp_dir"
        return 1
    fi
    
    # 恢复数据库
    if [ -f "$temp_dir/db_backup.sql" ]; then
        echo -e "${CYAN}>>> 恢复数据库...${NC}"
        
        # 等待数据库启动
        sleep 20
        
        local db_pass=$(grep MYSQL_ROOT_PASSWORD docker-compose.yml 2>/dev/null | awk -F': ' '{print $2}')
        
        if [ -n "$db_pass" ]; then
            cat "$temp_dir/db_backup.sql" | docker compose exec -T db mysql -u root -p"$db_pass" 2>/dev/null
            
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}✔ 数据库恢复成功${NC}"
            else
                echo -e "${YELLOW}⚠️ 数据库恢复失败${NC}"
            fi
        fi
    fi
    
    # 恢复文件
    if [ -f "$temp_dir/wp_files.tar.gz" ]; then
        echo -e "${CYAN}>>> 恢复文件...${NC}"
        
        local wp_container=$(docker compose ps -q wordpress 2>/dev/null)
        
        if [ -n "$wp_container" ]; then
            docker run --rm -v "$temp_dir/wp_files.tar.gz:/backup.tar.gz" --volumes-from $wp_container alpine sh -c "tar xzf /backup.tar.gz -C /" 2>/dev/null
            
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}✔ 文件恢复成功${NC}"
                
                # 修复文件权限
                docker exec $wp_container chown -R www-data:www-data /var/www/html 2>/dev/null
            else
                echo -e "${YELLOW}⚠️ 文件恢复失败${NC}"
            fi
        fi
    fi
    
    # 清理临时文件
    rm -rf "$temp_dir"
    
    echo -e "\n${GREEN}✅ 站点恢复完成!${NC}"
    echo -e "站点: $site_name"
    echo -e "目录: $SITES_DIR/$site_name"
    echo -e "访问: https://$site_name"
    
    write_log "Restored site: $site_name"
    return 0
}

function uninstall_cluster() { 
    clear
    echo -e "${RED}=== ⚠️ 危险: 卸载集群 ===${NC}"
    echo -e "\n${RED}这将删除所有数据!${NC}"
    echo -e "包括:"
    echo -e "  ✓ 所有站点 ($SITES_DIR)"
    echo -e "  ✓ 网关服务 ($GATEWAY_DIR)"
    echo -e "  ✓ 防火墙配置 ($FW_DIR)"
    echo -e "  ✓ 所有Docker容器和卷"
    echo -e "  ✓ 所有备份 ($BASE_DIR/backups)"
    echo -e "  ✓ 日志文件 ($LOG_FILE)"
    echo -e "  ✓ 快捷命令 (/usr/bin/wp)"
    
    echo -e "\n${YELLOW}输入 'DELETE_ALL' 确认卸载: ${NC}"
    read confirm
    
    if [ "$confirm" == "DELETE_ALL" ]; then
        echo -e "\n${RED}>>> 正在卸载...${NC}"
        
        # 停止所有站点
        echo -e "${CYAN}1. 停止所有站点...${NC}"
        for d in "$SITES_DIR"/*; do
            if [ -d "$d" ]; then
                cd "$d" && docker compose down -v 2>/dev/null
                echo -e "  ${YELLOW}停止: $(basename $d)${NC}"
            fi
        done
        
        # 停止网关
        echo -e "${CYAN}2. 停止网关服务...${NC}"
        if [ -d "$GATEWAY_DIR" ]; then
            cd "$GATEWAY_DIR" && docker compose down -v 2>/dev/null
        fi
        
        # 删除Docker网络
        echo -e "${CYAN}3. 清理Docker网络...${NC}"
        docker network rm proxy-net 2>/dev/null
        
        # 删除目录
        echo -e "${CYAN}4. 删除数据目录...${NC}"
        rm -rf "$BASE_DIR"
        
        # 删除快捷命令
        echo -e "${CYAN}5. 删除快捷命令...${NC}"
        rm -f /usr/bin/wp
        
        # 清理Telegram进程
        echo -e "${CYAN}6. 清理后台进程...${NC}"
        [ -f "$MONITOR_PID" ] && kill $(cat "$MONITOR_PID") 2>/dev/null
        [ -f "$LISTENER_PID" ] && kill $(cat "$LISTENER_PID") 2>/dev/null
        rm -f "$MONITOR_PID" "$LISTENER_PID"
        
        # 清理cron任务
        echo -e "${CYAN}7. 清理定时任务...${NC}"
        crontab -l 2>/dev/null | grep -v "wp-cluster" | crontab -
        
        echo -e "\n${GREEN}✅ 集群已完全卸载${NC}"
        echo -e "所有数据已删除，再见!"
        write_log "Uninstalled cluster"
        
        # 等待3秒后退出
        sleep 3
        exit 0
    else
        echo -e "${GREEN}✅ 卸载操作已取消${NC}"
        pause_prompt
    fi
}

# ================= 4. 菜单显示函数 =================
function show_menu() {
    clear
    echo -e "${GREEN}=== WordPress Docker 集群管理 ($VERSION) ===${NC}"
    echo -e "${CYAN}GitHub: lje02/wp-manager${NC}"
    echo "-----------------------------------------"
    echo -e "${YELLOW}[新建站点]${NC}"
    echo " 1. 部署 WordPress 新站"
    echo " 2. 新建 反向代理 (IP:端口 / 域名)"
    echo " 3. 新建 域名重定向 (301)"
    echo ""
    echo -e "${YELLOW}[站点运维]${NC}"
    echo " 4. 查看站点列表"
    echo " 5. 容器状态监控"
    echo " 6. 销毁指定站点"
    echo " 7. 更换网站域名"
    echo " 8. 修复反代配置"
    echo -e " 9. ${CYAN}组件版本升降级 (PHP/DB/Redis)${NC}"
    echo " 10. 解除上传限制 (一键扩容)"
    echo ""
    echo -e "${YELLOW}[数据管理]${NC}"
    echo " 11. 数据库 导出/导入"
    echo " 12. 整站 备份与还原 (智能扫描)"
    echo ""
    echo -e "${RED}[安全与监控]${NC}"
    echo " 13. 安全防御中心 (防火墙/WAF/证书)"
    echo " 14. Telegram 通知 (报警/指令)"
    echo " 15. 系统资源监控"
    echo " 16. 日志管理系统"
    echo "-----------------------------------------"
    echo -e "${BLUE} u. 检查更新${NC} | ${RED}x. 卸载${NC} | 0. 退出"
    echo -n "请选择: "
    read option
}

# ================= 5. 主程序循环 =================

# 检查参数
if [ "$1" == "--auto-backup" ]; then
    echo -e "${CYAN}>>> 执行自动备份...${NC}"
    backup_single_site "all" "auto_$(date +%Y%m%d_%H%M%S)"
    exit 0
fi

# 主程序开始
echo -e "${GREEN}=== WordPress Docker 集群管理启动 ===${NC}"

# 检查依赖
check_dependencies

# 安装快捷命令
install_shortcut

# 初始化网关（如果不存在）
if ! docker ps --format '{{.Names}}' | grep -q "^gateway_proxy$"; then
    echo -e "${CYAN}>>> 初始化网关...${NC}"
    init_gateway "auto"
fi

# 检查网关状态
if docker ps --format '{{.Names}}' | grep -q "^gateway_proxy$"; then
    echo -e "${GREEN}✔ 网关运行正常${NC}"
else
    echo -e "${YELLOW}⚠️ 网关未运行，尝试启动...${NC}"
    init_gateway "force"
fi

# 显示欢迎信息
echo -e "\n${CYAN}欢迎使用 WordPress 集群管理${NC}"
echo -e "版本: $VERSION"
echo -e "快捷命令: wp"
echo -e "数据目录: $BASE_DIR"
echo -e "站点数量: $(ls -1 $SITES_DIR 2>/dev/null | wc -l)"
echo ""

sleep 1

while true; do 
    show_menu 
    case $option in 
        u|U) update_script;; 
        1) create_site;; 
        2) create_proxy;; 
        3) create_redirect;; 
        4) list_sites;; 
        5) container_ops;; 
        6) delete_site;; 
        7) change_domain;; 
        8) repair_proxy;; 
        9) component_manager;; 
        10) fix_upload_limit;; 
        11) db_manager;; 
        12) backup_restore_ops;; 
        13) security_center;; 
        14) telegram_manager;; 
        15) sys_monitor;; 
        16) log_manager;; 
        x|X) uninstall_cluster;; 
        0) 
            echo -e "${GREEN}再见!${NC}"
            exit 0
            ;; 
        *)
            echo -e "${RED}❌ 无效选项${NC}"
            sleep 1
            ;;
    esac
done
