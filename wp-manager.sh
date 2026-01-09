#!/bin/bash

# ================= 1. 配置区域 =================
# 脚本版本号
VERSION="V10.3.5(快捷方式: mmp)"
DOCKER_COMPOSE_CMD="docker compose"

# 数据存储路径
BASE_DIR="/home/docker/web"

# 子目录定义
SITES_DIR="$BASE_DIR/sites"
GATEWAY_DIR="$BASE_DIR/gateway"
FW_DIR="$BASE_DIR/firewall"
LOG_DIR="$BASE_DIR/logs"
TG_CONF="$BASE_DIR/telegram.conf"
LOG_FILE="$BASE_DIR/operation.log"
REMARK_FILE="$BASE_DIR/site_remarks.txt"
MONITOR_PID="$BASE_DIR/monitor.pid"
MONITOR_SCRIPT="$BASE_DIR/monitor_daemon.sh"
LISTENER_PID="$BASE_DIR/tg_listener.pid"
LISTENER_SCRIPT="$BASE_DIR/tg_listener.sh"
# 自动更新源
UPDATE_URL="https://raw.githubusercontent.com/lje02/wp-manager/main/wp-manager.sh"

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m'

# [新增] 强制 Root 身份检查
if [ "$(id -u)" != "0" ]; then
    echo -e "${RED}❌ 错误: 此脚本必须使用 Root 权限运行。${NC}"
    echo -e "请尝试输入: ${GREEN}sudo -i${NC} 切换用户后重试。"
    exit 1
fi

# 初始化目录
mkdir -p "$SITES_DIR" "$GATEWAY_DIR" "$FW_DIR" "$LOG_DIR"
touch "$FW_DIR/access.conf" "$FW_DIR/geo.conf"
[ ! -f "$LOG_FILE" ] && touch "$LOG_FILE"
[ ! -f "$REMARK_FILE" ] && touch "$REMARK_FILE"

# ================= 2. 基础工具函数 =================

function write_log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

function pause_prompt() {
    echo -e "\n${YELLOW}>>> 操作完成，按回车键返回...${NC}"
    read -r
}

# [修改点] 快捷方式改为 mmp
function install_shortcut() {
    local script_path=$(readlink -f "$0")
    if [ ! -L "/usr/bin/mmp" ] || [ "$(readlink -f "/usr/bin/mmp")" != "$script_path" ]; then
        ln -sf "$script_path" /usr/bin/mmp && chmod +x "$script_path"
        echo -e "${GREEN}>>> 快捷指令 'mmp' 已安装 (输入 mmp 即可启动)${NC}"
    fi
}
# === Rclone 依赖检查与配置 ===
function check_rclone() {
    if ! command -v rclone >/dev/null 2>&1; then
        echo -e "${YELLOW}>>> 正在安装 Rclone (用于云端备份)...${NC}"
        curl https://rclone.org/install.sh | bash
    fi
}

function configure_rclone() {
    check_rclone
    clear
    echo -e "${YELLOW}=== ☁️ 配置云端存储 (Rclone) ===${NC}"
    echo -e "你需要配置一个远程存储 (如 Google Drive, OneDrive, S3)。"
    echo -e "配置名称(Name)请务必填写: ${GREEN}remote${NC}"
    echo "------------------------------------------------"
    echo "按回车开始配置，配置完成后输入 q 退出..."
    read
    rclone config
    pause_prompt
}

function check_dependencies() {
    echo -e "${YELLOW}>>> 正在检查系统环境...${NC}"

    # 1. 解决新机器 apt 锁被占用问题 (Debian/Ubuntu)
    if [ -f /etc/debian_version ]; then
        if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; then
            echo -e "${YELLOW}⚠️  检测到系统后台正在更新，尝试释放锁...${NC}"
            killall apt apt-get 2>/dev/null
            rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock
        fi
    fi

    # 2. 检查基础依赖 (jq, openssl, net-tools)
    # 注意：curl 已在主程序入口处预装，这里只检查其他的
    local deps=("jq" "openssl" "netstat:net-tools") 
    for dep in "${deps[@]}"; do
        cmd="${dep%%:*}"
        pkg="${dep##*:}"
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo -e "${YELLOW}>>> 正在安装依赖组件 ($pkg)...${NC}"
            if [ -f /etc/debian_version ]; then 
                apt-get update -y && apt-get install -y "$pkg"
            else 
                yum install -y "$pkg"
            fi
        fi
    done

    # 3. Docker 智能检测与安装
    if command -v docker >/dev/null 2>&1; then
        local d_ver=$(docker -v | awk '{print $3}' | tr -d ',')
        echo -e "${GREEN}✔ 检测到 Docker 已安装 (版本: $d_ver)${NC}"
        if ! systemctl is-active docker >/dev/null 2>&1; then
            systemctl start docker
        fi
    else
        echo -e "${YELLOW}>>> 未检测到 Docker，正在自动安装...${NC}"
        if curl -fsSL https://get.docker.com | bash; then
            systemctl enable docker && systemctl start docker
            write_log "Installed Docker"
            echo -e "${GREEN}✔ Docker 安装成功${NC}"
        else
            echo -e "${RED}❌ Docker 安装失败，请检查网络或更换系统镜像。${NC}"
            exit 1
        fi
    fi

    # 4. 补全 Docker Compose 插件
    if ! docker compose version >/dev/null 2>&1; then
        echo -e "${YELLOW}>>> 正在补全 Docker Compose 插件...${NC}"
        if [ -f /etc/debian_version ]; then 
            apt-get install -y docker-compose-plugin
        else 
            yum install -y docker-compose-plugin
        fi
    fi
}

# [补全] 容器冲突检测函数
function check_container_conflict() {
    local base_name=$1
    local has_conflict=0
    
    # 检测常见后缀的容器是否存在 (_app, _db, _redis, _nginx, _worker)
    conflict_list=$(docker ps -a --format '{{.Names}}' | grep -E "^${base_name}_(app|db|redis|nginx|worker|redirect)$")
    
    if [ ! -z "$conflict_list" ]; then
        echo -e "${RED}⚠️  检测到命名冲突！以下容器已存在 (可能是之前的残留):${NC}"
        echo "$conflict_list"
        echo "-----------------------------------------"
        echo -e "${YELLOW}如果不清理，部署将失败。${NC}"
        read -p "是否强制删除这些旧容器? (y/n): " confirm
        
        if [ "$confirm" == "y" ]; then
            echo -e "${YELLOW}>>> 正在清理旧容器...${NC}"
            echo "$conflict_list" | xargs docker rm -f
            echo -e "${GREEN}✔ 清理完成${NC}"
            return 0
        else
            echo -e "${RED}❌ 操作取消，请手动处理冲突。${NC}"
            return 1
        fi
    fi
    return 0
}

function ensure_firewall_installed() {
    if command -v ufw >/dev/null || command -v firewall-cmd >/dev/null; then return 0; fi
    echo -e "${YELLOW}>>> 正在安装防火墙...${NC}"
    if [ -f /etc/debian_version ]; then apt-get update && apt-get install -y ufw; ufw allow 22/tcp; ufw allow 80/tcp; ufw allow 443/tcp; echo "y" | ufw enable
    elif [ -f /etc/redhat-release ]; then yum install -y firewalld; systemctl enable firewalld --now; firewall-cmd --permanent --add-service={ssh,http,https}; firewall-cmd --reload
    else echo -e "${RED}❌ 系统不支持自动安装防火墙${NC}"; pause_prompt; return 1; fi
    echo -e "${GREEN}✔ 防火墙就绪${NC}"; sleep 1
}

function check_ssl_status() {
    local d=$1; echo -e "${CYAN}>>> [SSL] 正在申请证书...${NC}"; for ((i=1; i<=20; i++)); do if docker exec gateway_acme test -f "/etc/nginx/certs/$d.crt"; then echo -e "${GREEN}✔ SSL 成功: https://$d${NC}"; pause_prompt; return 0; fi; echo -n "."; sleep 5; done; echo -e "\n${YELLOW}⚠️ 证书暂未生成 (可能是DNS延迟)${NC}"; pause_prompt;
}

function normalize_url() {
    local url=$1; url=${url%/}; if [[ "$url" != http* ]]; then echo "https://$url"; else echo "$url"; fi
}

function update_script() {
    clear; echo -e "${GREEN}=== 脚本自动更新 ===${NC}"; echo -e "版本: $VERSION"; echo -e "源: GitHub (lje02/wp-manager)"
    temp_file="/tmp/wp_manager_update.sh"
    if curl -f -L -s -o "$temp_file" "$UPDATE_URL" && head -n 1 "$temp_file" | grep -q "/bin/bash"; then
        mv "$temp_file" "$0"; chmod +x "$0"; echo -e "${GREEN}✔ 更新成功，正在重启...${NC}"; write_log "Updated script"; sleep 1; exec "$0"
    else echo -e "${RED}❌ 更新失败! 请检查网络或源地址。${NC}"; rm -f "$temp_file"; fi; pause_prompt
}

function create_systemd_service() {
    local service_name=$1
    local script_path=$2
    local description=$3
    local service_file="/etc/systemd/system/${service_name}.service"

    echo -e "${YELLOW}>>> 正在注册系统服务: ${service_name}...${NC}"

    cat > "$service_file" <<EOF
[Unit]
Description=$description
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
ExecStart=/bin/bash $script_path
Restart=always
RestartSec=10
User=root
# 确保环境变量正确
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$service_name"
    systemctl start "$service_name"
    echo -e "${GREEN}✔ 服务已启动并设置开机自启${NC}"
}

function send_tg_msg() {
    local msg=$1; if [ -f "$TG_CONF" ]; then source "$TG_CONF"; if [ ! -z "$TG_BOT_TOKEN" ] && [ ! -z "$TG_CHAT_ID" ]; then curl -s -X POST "https://api.telegram.org/bot$TG_BOT_TOKEN/sendMessage" -d chat_id="$TG_CHAT_ID" -d text="$msg" >/dev/null; fi; fi
}

# --- 后台脚本生成器 ---
function generate_monitor_script() {
cat > "$MONITOR_SCRIPT" <<EOF
#!/bin/bash
TG_CONF="$TG_CONF"; CPU_THRESHOLD=90; MEM_THRESHOLD=90; DISK_THRESHOLD=90; COOLDOWN=1800; LAST_ALERT=0
function send_msg() { if [ -f "\$TG_CONF" ]; then source "\$TG_CONF"; curl -s -X POST "https://api.telegram.org/bot\$TG_BOT_TOKEN/sendMessage" -d chat_id="\$TG_CHAT_ID" -d text="\$1" >/dev/null; fi }
while true; do
    CPU=\$(grep 'cpu ' /proc/stat | awk '{usage=(\$2+\$4)*100/(\$2+\$4+\$5)} END {print usage}' | cut -d. -f1)
    MEM=\$(free | grep Mem | awk '{print \$3/\$2 * 100.0}' | cut -d. -f1)
    DISK=\$(df / | awk 'NR==2 {print \$5}' | sed 's/%//')
    MSG=""
    if [ "\$CPU" -gt "\$CPU_THRESHOLD" ]; then MSG="\$MSG\n🚨 CPU过高: \${CPU}%"; fi
    if [ "\$MEM" -gt "\$MEM_THRESHOLD" ]; then MSG="\$MSG\n🚨 内存过高: \${MEM}%"; fi
    if [ "\$DISK" -gt "\$DISK_THRESHOLD" ]; then MSG="\$MSG\n🚨 磁盘爆满: \${DISK}%"; fi
    if [ ! -z "\$MSG" ]; then
        NOW=\$(date +%s); DIFF=\$((NOW - LAST_ALERT))
        if [ "\$DIFF" -gt "\$COOLDOWN" ]; then send_msg "⚠️ **资源警报** \nHostname: \$(hostname) \$MSG"; LAST_ALERT=\$NOW; fi
    fi
    sleep 60
done
EOF
chmod +x "$MONITOR_SCRIPT"
}

function generate_listener_script() {
    # 确保日志目录存在
    [ ! -d "$LOG_DIR" ] && mkdir -p "$LOG_DIR"
    
cat > "$LISTENER_SCRIPT" <<EOF
#!/bin/bash
# ==========================================
#  MMP Robot Listener (HTML Fix Version)
# ==========================================

TG_CONF="$TG_CONF"
GATEWAY_DIR="$GATEWAY_DIR"
SITES_DIR="$SITES_DIR"
MMP_CMD="/usr/bin/mmp"

# 加载配置
if [ ! -f "\$TG_CONF" ]; then exit 1; fi
source "\$TG_CONF"

OFFSET=0

# --- [核心修复] 发送回复函数 (HTML模式) ---
function reply() {
    local chat_id=\$1
    local text=\$2
    
    # 使用 --data-urlencode 自动处理换行和特殊字符
    # 使用 HTML 模式，兼容性更好
    result=\$(curl -s -X POST "https://api.telegram.org/bot\$TG_BOT_TOKEN/sendMessage" \
        -d chat_id="\$chat_id" \
        -d parse_mode="HTML" \
        --data-urlencode "text=\$text")
        
    # 简单的错误检测日志
    if echo "\$result" | grep -q '"ok":false'; then
        echo "❌ 发送失败: \$result"
    fi
}

function send_action() {
    curl -s -X POST "https://api.telegram.org/bot\$TG_BOT_TOKEN/sendChatAction" \
        -d chat_id="\$1" \
        -d action="typing" >/dev/null
}

echo "Bot listener started... (HTML Mode)"

while true; do
    updates=\$(curl -s "https://api.telegram.org/bot\$TG_BOT_TOKEN/getUpdates?offset=\$OFFSET&timeout=30")
    
    if [ \$? -ne 0 ]; then sleep 5; continue; fi
    status=\$(echo "\$updates" | jq -r '.ok')
    if [ "\$status" != "true" ]; then sleep 5; continue; fi
    
    count=\$(echo "\$updates" | jq '.result | length')
    if [ "\$count" -eq "0" ]; then continue; fi

    echo "\$updates" | jq -c '.result[]' | while read row; do
        update_id=\$(echo "\$row" | jq '.update_id')
        message_text=\$(echo "\$row" | jq -r '.message.text // empty')
        sender_id=\$(echo "\$row" | jq -r '.message.chat.id // empty')
        
        # 只响应管理员
        if [ "\$sender_id" == "\$TG_CHAT_ID" ] && [ ! -z "\$message_text" ]; then
            
            # 显示正在输入...
            send_action "\$sender_id"

            case "\$message_text" in
                "/start" | "/help")
                    # 使用 HTML 标签 <b> </b> 进行加粗，换行直接用 \n (curl会自动处理)
                    msg="🤖 <b>MMP 运维机器人 V2.1</b>\n"
                    msg="\${msg}-----------------------------\n"
                    msg="\${msg}📊 /status - 查看系统详细状态\n"
                    msg="\${msg}💾 /backup - 立即执行全量备份\n"
                    msg="\${msg}🔄 /reboot_nginx - 重启核心网关\n"
                    msg="\${msg}🚑 /restart_all - 重启所有站点容器\n"
                    msg="\${msg}🔍 /check_ip - 检查服务器公网IP\n"
                    reply "\$sender_id" "\$msg"
                    ;;

                "/status")
                    load=\$(uptime | awk -F'load average:' '{print \$2}' | sed 's/,//g')
                    mem_used=\$(free -m | awk 'NR==2{print \$3}')
                    mem_total=\$(free -m | awk 'NR==2{print \$2}')
                    disk_usage=\$(df -h / | awk 'NR==2 {print \$5}')
                    container_running=\$(docker ps -q | wc -l)
                    
                    msg="📊 <b>系统实时状态</b>\n"
                    msg="\${msg}-----------------------------\n"
                    msg="\${msg}🧠 负载: <code>\$load</code>\n"
                    msg="\${msg}💾 内存: \${mem_used}MB / \${mem_total}MB\n"
                    msg="\${msg}💿 硬盘: \$disk_usage 已用\n"
                    msg="\${msg}🐳 容器: 运行 \$container_running 个\n"
                    msg="\${msg}⏱ 运行: \$(uptime -p)"
                    reply "\$sender_id" "\$msg"
                    ;;

                "/reboot_nginx")
                    reply "\$sender_id" "🔄 正在平滑重载 Nginx 网关..."
                    if docker exec gateway_proxy nginx -s reload >/dev/null 2>&1; then
                        reply "\$sender_id" "✅ 网关配置已刷新"
                    else
                        cd "\$GATEWAY_DIR" && docker compose restart nginx-proxy
                        reply "\$sender_id" "⚠️ 刷新失败，已强制重启网关"
                    fi
                    ;;

                "/backup")
                    if [ -f "\$MMP_CMD" ]; then
                        nohup \$MMP_CMD backup_all > /dev/null 2>&1 &
                        reply "\$sender_id" "⏳ <b>备份任务已启动</b>\n请稍后检查云端或本地目录。"
                    else
                         reply "\$sender_id" "❌ 错误: 找不到 mmp 主程序"
                    fi
                    ;;
                
                "/restart_all")
                    docker restart \$(docker ps -q)
                    reply "\$sender_id" "✅ 所有容器已重启。"
                    ;;

                "/check_ip")
                    myip=\$(curl -s4 ifconfig.me)
                    reply "\$sender_id" "🌐 公网 IP: <code>\$myip</code>"
                    ;;
                    
                *)
                    # 不回复未知指令，避免刷屏
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

# === [修复版] 强制刷新网关配置 (带延迟等待) ===
function reload_gateway_config() {
    echo -e "${YELLOW}>>> 正在同步网关配置...${NC}"
    
    # 1. 【核心修复】强制等待 5 秒
    # 让新启动的容器有足够的时间完成网络注册和 IP 分配
    # 否则网关重启太快，会读不到新容器的 IP，导致 502 或 404
    echo -n "   等待新容器网络就绪 (5秒)..."
    for i in {1..5}; do 
        echo -n "."
        sleep 1
    done
    echo ""

    if docker ps | grep -q "gateway_proxy"; then
        # 2. 强制重启网关
        # Restart 比 reload 更彻底，它会强制 nginx-proxy 重新扫描整个 Docker 网络
        docker restart gateway_proxy >/dev/null 2>&1
        
        # 3. 连带重启 ACME
        # 网关重启后，ACME 容器有时会断开 Socket 连接，顺手重启它最稳妥
        if docker ps | grep -q "gateway_acme"; then
             docker restart gateway_acme >/dev/null 2>&1
        fi
        
        echo -e "${GREEN}✔ 网关已重启，新站点路由已生效${NC}"
    else
        echo -e "${RED}⚠️  警告: 网关容器未运行，跳过刷新${NC}"
    fi
}

# ================= 3. 业务功能函数 =================

# === [V9.5 升级版] 主机深度审计与隐藏进程猎杀 ===
function server_audit() {
    # 内部函数：安装 Unhide
    function install_unhide() {
        if ! command -v unhide >/dev/null 2>&1; then
            echo -e "${YELLOW}>>> 正在安装 Unhide (隐藏进程扫描神器)...${NC}"
            if [ -f /etc/debian_version ]; then
                apt-get update && apt-get install -y unhide
            else
                yum install -y unhide
            fi
        fi
    }

    while true; do
        clear; echo -e "${RED}=== 🕵️ 主机深度审计 (Hunter Mode) ===${NC}"
        echo -e "${YELLOW}此模块用于检测 Rootkit、挖矿病毒及隐藏进程。${NC}"
        echo "--------------------------"
        echo -e " 1. 端口与连接审计 (Netstat)"
        echo -e " 2. ${CYAN}幽灵进程检测 (对比 /proc vs ps)${NC}"
        echo -e " 3. ${RED}暴力枚举隐藏进程 (Unhide - 内核级查杀)${NC}"
        echo -e " 4. 恶意进程与文件扫描 (CPU/Temp)"
        echo -e " 5. 检查系统预加载劫持 (LD_PRELOAD)"
        echo " 0. 返回"
        echo "--------------------------"
        read -p "请输入选项 [0-5]: " o
        case $o in
            0) return;;
            
            1) 
                echo -e "\n${GREEN}>>> 正在扫描监听端口...${NC}"
                check_dependencies # 确保 netstat 存在
                echo "--------------------------------------------------------"
                printf "%-8s %-25s %-15s %-20s\n" "协议" "本地地址:端口" "状态" "进程PID/名称"
                echo "--------------------------------------------------------"
                netstat -tunlp | grep LISTEN | awk '{printf "%-8s %-25s %-15s %-20s\n", $1, $4, $6, $7}'
                echo "--------------------------------------------------------"
                echo -e "${YELLOW}提示: 如果发现没有 PID 的端口 (显示为 -)，说明该进程可能已隐藏！${NC}"
                pause_prompt;;

            2)
                echo -e "\n${GREEN}>>> 正在执行幽灵进程检测...${NC}"
                echo -e "原理: 对比 '/proc/PID' 目录与 'ps' 命令的输出差异。"
                echo "--------------------------------------------------------"
                
                # 获取所有 /proc 下的数字目录 (真实的进程)
                ls -d /proc/[0-9]* | cut -d/ -f3 | sort -n > /tmp/procs_raw.txt
                # 获取 ps 命令能看到的进程
                ps -e -o pid= | tr -d ' ' | sort -n > /tmp/procs_ps.txt
                
                # 对比差异
                hidden_pids=$(comm -23 /tmp/procs_raw.txt /tmp/procs_ps.txt)
                
                if [ ! -z "$hidden_pids" ]; then
                    echo -e "${RED}🚨 警告！发现 'ps' 命令看不到的幽灵进程：${NC}"
                    for pid in $hidden_pids; do
                        # 过滤掉极短命进程（可能刚才运行完就结束了）
                        if [ -d "/proc/$pid" ]; then
                            cmdline=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')
                            echo -e "PID: ${RED}$pid${NC} | Cmd: $cmdline"
                        fi
                    done
                else
                    echo -e "${GREEN}✔ 未发现用户态隐藏进程 (ps命令未被篡改)${NC}"
                fi
                rm -f /tmp/procs_raw.txt /tmp/procs_ps.txt
                pause_prompt;;
                
            3)
                echo -e "\n${RED}>>> 正在启动 Unhide 暴力猎杀模式...${NC}"
                install_unhide
                if command -v unhide >/dev/null 2>&1; then
                    echo -e "${YELLOW}正在暴力轮询 PID (可能需要几十秒)...${NC}"
                    # 使用 brute 和 proc 混合模式
                    unhide proc
                    echo "----------------------------------------"
                    unhide sys
                    echo "----------------------------------------"
                    echo -e "${CYAN}如果上面列出了 PID，请立即使用 'kill -9 PID' 尝试杀掉。${NC}"
                    echo -e "如果杀不掉，说明可能已深入内核模块，建议重装系统。"
                else
                    echo -e "${RED}❌ Unhide 安装失败，无法执行。${NC}"
                fi
                pause_prompt;;
            
            4)
                echo -e "\n${GREEN}>>> 正在执行常规恶意扫描...${NC}"
                # CPU Top 5
                echo -e "\n${CYAN}[1] CPU 占用最高的 5 个进程:${NC}"
                ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -n 6
                
                # 检查可疑目录
                echo -e "\n${CYAN}[2] 检查可疑目录运行的进程 (/tmp, /dev/shm):${NC}"
                suspicious_found=0
                for pid in $(ls /proc | grep -E '^[0-9]+$'); do
                    if [ -d "/proc/$pid" ]; then
                        exe_link=$(readlink -f /proc/$pid/exe 2>/dev/null)
                        if [[ "$exe_link" == /tmp/* ]] || [[ "$exe_link" == /var/tmp/* ]] || [[ "$exe_link" == /dev/shm/* ]]; then
                            echo -e "${RED}⚠️  发现可疑进程 PID: $pid${NC}"
                            echo -e "   路径: $exe_link"
                            suspicious_found=1
                        fi
                    fi
                done
                [ "$suspicious_found" -eq 0 ] && echo -e "${GREEN}✔ 暂无发现${NC}"
                
                # 检查已删除但仍在运行
                echo -e "\n${CYAN}[3] 检查已删除但仍在运行的二进制文件:${NC}"
                ls -l /proc/*/exe 2>/dev/null | grep '(deleted)' | grep -vE "docker|containerd|runc"
                pause_prompt;;
                
            5)
                echo -e "\n${YELLOW}>>> 检查 LD_PRELOAD 劫持...${NC}"
                echo "Rootkit 常通过环境变量劫持系统函数。"
                if [ ! -z "$LD_PRELOAD" ] || grep -q "LD_PRELOAD" /etc/ld.so.preload 2>/dev/null; then
                     echo -e "${RED}🚨 严重警告！检测到 LD_PRELOAD 设置！${NC}"
                     echo "环境变量: $LD_PRELOAD"
                     echo "配置文件: $(cat /etc/ld.so.preload 2>/dev/null)"
                     echo -e "如果这不是你配置的，请立即检查！"
                else
                     echo -e "${GREEN}✔ 未检测到 LD_PRELOAD 劫持。${NC}"
                fi
                pause_prompt;;
        esac
    done
}

# === [修复版] Cloudflare Real IP 修复 ===
function fix_cloudflare_ip() {
    echo -e "${YELLOW}>>> 正在配置 Cloudflare 真实 IP 透传...${NC}"
    
    local cf_conf="$GATEWAY_DIR/cloudflare.conf"
    local yml_file="$GATEWAY_DIR/docker-compose.yml"
    
    # 1. 生成配置文件
    echo "# Cloudflare IP Ranges" > "$cf_conf"
    echo "real_ip_header CF-Connecting-IP;" >> "$cf_conf"
    echo -e "正在下载 Cloudflare IP 列表..."
    curl -s https://www.cloudflare.com/ips-v4 | sed 's/^/set_real_ip_from /; s/$/;/' >> "$cf_conf"
    curl -s https://www.cloudflare.com/ips-v6 | sed 's/^/set_real_ip_from /; s/$/;/' >> "$cf_conf"
    
    # 2. 精准挂载 (修复 YAML 格式错误)
    if ! grep -q "cloudflare.conf" "$yml_file"; then
        echo -e "${YELLOW}正在修改 docker-compose.yml...${NC}"
        
        # 备份原文件
        cp "$yml_file" "$yml_file.bak"
        
        # 逻辑：寻找 "conf:/etc/nginx/conf.d" 这一行（这是网关肯定有的），在它下面插入新行
        # 这样能保证缩进和位置绝对正确
        sed -i '\|conf:/etc/nginx/conf.d|a \      - ./cloudflare.conf:/etc/nginx/conf.d/cloudflare.conf:ro' "$yml_file"
        
        echo -e "${GREEN}✔ 挂载配置已注入${NC}"
        
        # 3. 验证并重启
        # 先尝试 config 检查，如果报错则还原
        if ! docker compose -f "$yml_file" config >/dev/null 2>&1; then
             echo -e "${RED}❌ YAML 语法校验失败，正在回滚...${NC}"
             mv "$yml_file.bak" "$yml_file"
             echo -e "请尝试手动编辑 $yml_file 添加挂载。"
        else
             rm "$yml_file.bak"
             reload_gateway_config
        fi
    else
        docker exec gateway_proxy nginx -s reload
        echo -e "${GREEN}✔ 配置已更新并重载${NC}"
    fi
    
    pause_prompt
}

# === [增强版] Webshell 恶意文件查杀 (带清理功能) ===
function malware_scan() {
    while true; do
        clear
        echo -e "${RED}=== 🦠 Webshell 深度查杀 (Iron Wall) ===${NC}"
        echo -e "${YELLOW}提示: 自动删除仅针对 uploads 目录的高危文件，其他目录仅报警。${NC}"
        echo "------------------------------------------------"
        echo " 1. 快速扫描 & 清理 (检查 uploads 目录下的 PHP 文件)"
        echo " 2. 深度扫描 (检查 eval/base64 等危险函数 - 仅报告)"
        echo " 3. 权限加固 (锁定 uploads 目录禁止执行 PHP)"
        echo " 0. 返回"
        echo "------------------------------------------------"
        read -p "请选择: " o
        
        case $o in
            0) return;;
            1)
                echo -e "${YELLOW}>>> 正在扫描 uploads 目录下的非法 PHP 文件...${NC}"
                echo -e "原理: WordPress 的 uploads 目录只应存放图片/附件，绝不该有 PHP 脚本。"
                echo "------------------------------------------------"
                
                # 定义一个临时文件存放扫描结果
                tmp_list="/tmp/malware_list.txt"
                > "$tmp_list"

                # 扫描所有站点的 uploads 目录
                find "$SITES_DIR" -type d -name "uploads" | while read dir; do
                    # 查找该目录下的 php 文件
                    find "$dir" -name "*.php" >> "$tmp_list"
                done

                if [ ! -s "$tmp_list" ]; then
                    echo -e "${GREEN}✔ 恭喜！未发现明显的 uploads 目录木马。${NC}"
                else
                    echo -e "${RED}🚨 发现以下高危文件：${NC}"
                    cat -n "$tmp_list"
                    echo "------------------------------------------------"
                    
                    # 交互式清理逻辑
                    echo -e "${YELLOW}这些文件极大概率是 Webshell 木马。${NC}"
                    read -p "是否进入交互式清理模式? (y/n): " confirm
                    if [ "$confirm" == "y" ]; then
                        # 逐行读取文件进行处理
                        while read file_path; do
                            echo -e "\n文件: ${CYAN}$file_path${NC}"
                            echo -e "内容预览: $(head -n 1 "$file_path" | cut -c 1-50)..."
                            read -p "👉 确认删除此文件? (y=删除, n=跳过): " del_opt
                            if [ "$del_opt" == "y" ]; then
                                rm -f "$file_path"
                                echo -e "${GREEN}已删除。${NC}"
                            else
                                echo "已跳过。"
                            fi
                        done < "$tmp_list"
                    else
                        echo "操作已取消，请手动处理。"
                    fi
                fi
                rm -f "$tmp_list"
                pause_prompt;;
            
            2)
                echo -e "${YELLOW}>>> 正在执行特征码扫描...${NC}"
                echo "此模式仅报告文件路径和行号，请手动核实（存在误报可能）。"
                echo "------------------------------------------------"
                # 排除日志、图片、缓存目录
                grep -r --include="*.php" \
                     --exclude-dir="node_modules" \
                     --exclude-dir="vendor" \
                     --exclude-dir="cache" \
                     --exclude-dir="logs" \
                     -E "eval\(|assert\(|base64_decode\('|shell_exec\(|passthru\(" "$SITES_DIR" | cut -c 1-120
                echo "------------------------------------------------"
                echo -e "${CYAN}分析指南：${NC}"
                echo -e "1. ${GREEN}eval(\$_POST[...]);${NC} -> 100% 木马，立即删除。"
                echo -e "2. ${GREEN}base64_decode('...');${NC} -> 检查解码内容，可能是加密的木马。"
                echo -e "3. 如果出现在正常插件(plugins)目录，可能是误报，请谨慎。"
                pause_prompt;;
                
            3)
                echo -e "${YELLOW}>>> 正在生成 uploads 目录防执行配置...${NC}"
                # 为每个站点生成禁止 uploads 运行 php 的配置
                for dir in "$SITES_DIR"/*; do
                    if [ -d "$dir" ]; then
                        conf_file="$dir/waf_uploads.conf"
                        # 增强版配置：禁止 php 执行
                        cat > "$conf_file" <<EOF
location ~* ^/wp-content/uploads/.*\.php$ {
    deny all;
}
EOF
                        # 注入到 nginx.conf
                        if [ -f "$dir/nginx.conf" ] && ! grep -q "waf_uploads.conf" "$dir/nginx.conf"; then
                            sed -i '/include \/etc\/nginx\/waf.conf;/a \    include /etc/nginx/waf_uploads.conf;' "$dir/nginx.conf"
                             # 挂载
                            if ! grep -q "waf_uploads.conf" "$dir/docker-compose.yml"; then
                                 sed -i '/waf.conf:\/etc\/nginx\/waf.conf/a \      - ./waf_uploads.conf:/etc/nginx/waf_uploads.conf' "$dir/docker-compose.yml"
                                 cd "$dir" && docker compose up -d
                            fi
                            echo -e " - $(basename "$dir"): ${GREEN}已加固${NC}"
                        fi
                    fi
                done
                reload_gateway_config
                echo -e "${GREEN}✔ 所有站点的上传目录已锁定，即便上传了木马也无法运行。${NC}"
                pause_prompt;;
        esac
    done
}

# === [增强] 宿主机自动安全更新 ===
function enable_auto_updates() {
    echo -e "${YELLOW}>>> 正在配置操作系统自动安全更新...${NC}"
    
    if command -v apt-get >/dev/null; then
        apt-get update
        apt-get install -y unattended-upgrades
        
        # 启用自动更新
        echo "unattended-upgrades unattended-upgrades/enable_auto_updates boolean true" | debconf-set-selections
        dpkg-reconfigure -f noninteractive unattended-upgrades
        
        echo -e "${GREEN}✔ 已启用: 每天自动安装安全补丁 (Security Updates)${NC}"
        echo -e "这能有效防止内核级漏洞逃逸。"
    else
        echo -e "${RED}❌ 当前系统不支持 (仅支持 Debian/Ubuntu)${NC}"
    fi
    pause_prompt
}

# === [新增] Cloudflare防火墙白名单 (只允许CF访问) ===
function whitelist_cloudflare_firewall() {
    # 检测防火墙类型
    if command -v ufw >/dev/null; then FW_TYPE="UFW";
    elif command -v firewall-cmd >/dev/null; then FW_TYPE="FIREWALLD";
    else echo -e "${RED}❌ 未检测到 UFW 或 Firewalld，无法配置。${NC}"; pause_prompt; return; fi

    while true; do
        clear
        echo -e "${RED}=== 🧱 Cloudflare 专属白名单 (Source IP Lock) ===${NC}"
        echo -e "防火墙类型: $FW_TYPE"
        echo -e "------------------------------------------------"
        echo -e "${YELLOW}功能说明：${NC}"
        echo -e "此功能将删除 80/443 的【全网允许】规则，并添加【Cloudflare IP】允许规则。"
        echo -e "生效后，只有经过 Cloudflare 代理的流量才能访问你的网站。"
        echo -e "扫描器、直接通过 IP 访问的黑客将被防火墙直接丢弃包。"
        echo -e "------------------------------------------------"
        echo -e " 1. ${GREEN}开启白名单限制 (Lock Down)${NC}"
        echo -e " 2. 关闭限制 (恢复全网访问)"
        echo -e " 0. 返回"
        echo -e "------------------------------------------------"
        read -p "请选择: " o
        
        case $o in
            0) return;;
            
            1)
                echo -e "${RED}⚠️  高危操作确认${NC}"
                echo -e "1. 请确保你的域名在 CF 后台已开启【小云朵 (Proxied)】，否则网站将无法访问！"
                echo -e "2. 脚本会自动放行 SSH (22端口)，防止失联。"
                read -p "我确认已开启小云朵代理 (yes/no): " confirm
                if [ "$confirm" != "yes" ]; then continue; fi

                echo -e "${YELLOW}>>> 正在获取 Cloudflare 最新 IP 列表...${NC}"
                cf_ipv4=$(curl -s https://www.cloudflare.com/ips-v4)
                cf_ipv6=$(curl -s https://www.cloudflare.com/ips-v6)

                if [ -z "$cf_ipv4" ]; then echo -e "${RED}❌ 获取 IP 列表失败，请检查网络。${NC}"; pause_prompt; continue; fi

                echo -e "${YELLOW}>>> 正在配置防火墙规则 (可能需要几十秒)...${NC}"

                if [ "$FW_TYPE" == "UFW" ]; then
                    # === UFW 逻辑 ===
                    # 1. 保命：先允许 SSH
                    ufw allow 22/tcp >/dev/null
                    
                    # 2. 清理旧规则 (删除通用的 80/443 允许)
                    # 注意：UFW 删除规则如果不匹配会报错，所以重定向错误输出
                    ufw delete allow 80/tcp >/dev/null 2>&1
                    ufw delete allow 443/tcp >/dev/null 2>&1
                    ufw delete allow 80 >/dev/null 2>&1
                    ufw delete allow 443 >/dev/null 2>&1

                    # 3. 循环添加白名单
                    for ip in $cf_ipv4; do 
                        ufw allow from $ip to any port 80 proto tcp >/dev/null
                        ufw allow from $ip to any port 443 proto tcp >/dev/null
                    done
                    for ip in $cf_ipv6; do 
                        ufw allow from $ip to any port 80 proto tcp >/dev/null
                        ufw allow from $ip to any port 443 proto tcp >/dev/null
                    done
                    
                    ufw reload
                else
                    # === Firewalld 逻辑 ===
                    # 1. 保命
                    firewall-cmd --permanent --add-service=ssh >/dev/null
                    
                    # 2. 移除通用服务
                    firewall-cmd --permanent --remove-service=http >/dev/null 2>&1
                    firewall-cmd --permanent --remove-service=https >/dev/null 2>&1
                    
                    # 3. 添加 Rich Rules
                    echo -e "正在写入规则..."
                    for ip in $cf_ipv4; do 
                        firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$ip' port protocol='tcp' port='80' accept" >/dev/null
                        firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$ip' port protocol='tcp' port='443' accept" >/dev/null
                    done
                    for ip in $cf_ipv6; do
                        firewall-cmd --permanent --add-rich-rule="rule family='ipv6' source address='$ip' port protocol='tcp' port='80' accept" >/dev/null
                        firewall-cmd --permanent --add-rich-rule="rule family='ipv6' source address='$ip' port protocol='tcp' port='443' accept" >/dev/null
                    done
                    
                    firewall-cmd --reload
                fi
                echo -e "${GREEN}✔ 已开启白名单限制！现在只有 Cloudflare 能连接你的 80/443 端口。${NC}"
                pause_prompt
                ;;
                
            2)
                echo -e "${YELLOW}>>> 正在恢复全网访问...${NC}"
                if [ "$FW_TYPE" == "UFW" ]; then
                    ufw allow 80/tcp
                    ufw allow 443/tcp
                    # 注意：我们不自动删除刚才加的几百条 CF 规则，因为加上通用规则后，白名单就自动失效了（变得不重要了）
                    # 这样处理速度最快，而且不影响使用
                else
                    firewall-cmd --permanent --add-service=http
                    firewall-cmd --permanent --add-service=https
                    firewall-cmd --reload
                fi
                echo -e "${GREEN}✔ 已恢复全网访问。${NC}"
                pause_prompt
                ;;
        esac
    done
}

function security_center() {
    while true; do
        clear; echo -e "${YELLOW}=== 🛡️ 安全防御中心 (Iron Wall V11.1) ===${NC}"
        
        # 1. 防火墙状态
        if command -v ufw >/dev/null; then FW_ST="${GREEN}● UFW${NC}"; else FW_ST="${RED}● Off${NC}"; fi
        
        # 2. Fail2Ban状态
        if systemctl is-active fail2ban >/dev/null 2>&1; then F2B_ST="${GREEN}● On${NC}"; else F2B_ST="${RED}● Off${NC}"; fi

        # 3. WAF状态
        if [ -z "$(ls -A $SITES_DIR)" ]; then
            WAF_ST="${YELLOW}● 无站点${NC}"
        else
            if grep -r "V10.3" "$SITES_DIR" >/dev/null 2>&1; then 
                WAF_ST="${GREEN}● 增强版 (V10.3)${NC}"
            elif grep -r "waf.conf" "$SITES_DIR" >/dev/null 2>&1; then 
                WAF_ST="${YELLOW}● 已部署 (基础版)${NC}"
            else 
                WAF_ST="${RED}● 未部署${NC}"
            fi
        fi

        echo -e " 1. 端口防火墙   [$FW_ST]"
        echo -e " 2. 流量访问控制 (Nginx Layer7)"
        echo -e " 3. SSH防暴力破解 [$F2B_ST]"
        echo -e " 4. 网站防火墙    [$WAF_ST]" 
        echo -e " 5. HTTPS证书管理"
        echo -e " 6. 防盗链设置"
        echo -e " 7. 主机安全审计 (进程扫描)"
        echo "--------------------------"
        echo -e " 8. ${CYAN}Cloudflare 真实 IP 修复${NC} (日志显示真IP)"
        echo -e " 9. ${RED}Webshell 查杀与加固${NC} (防木马)"
        echo -e " 10. ${GREEN}宿主机自动安全更新${NC} (防漏洞)"
        echo -e " 11. ${RED}Cloudflare 防火墙白名单${NC} (防源站泄露)"
        echo -e " 12. ${GREEN}全站 PHP 安全加固${NC} (禁用高危函数)"
        echo "--------------------------"
        echo " 0. 返回主菜单"
        echo "--------------------------"
        read -p "请输入选项 [0-11]: " s
        case $s in 
            0) return;; 
            1) port_manager;; 
            2) traffic_manager;; 
            3) fail2ban_manager;; 
            4) waf_manager;; 
            5) cert_management;; 
            6) manage_hotlink;; 
            7) server_audit;; 
            8) fix_cloudflare_ip;;
            9) malware_scan;;
            10) enable_auto_updates;;
            11) whitelist_cloudflare_firewall;;
            12) harden_php_security;;
        esac
    done 
}

function socat_manager() {
    # 依赖检查
    if ! command -v socat >/dev/null 2>&1; then
        echo -e "${YELLOW}>>> 正在安装 Socat (用于端口转发)...${NC}"
        if [ -f /etc/debian_version ]; then 
            apt-get update && apt-get install -y socat
        else 
            yum install -y socat
        fi
    fi

    # 智能获取 Docker 网桥 IP (容器看到的宿主机IP)
    # 尝试获取 docker0 的 IP，如果获取不到则默认 172.17.0.1
    local bridge_ip=$(ip -4 addr show docker0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
    [ -z "$bridge_ip" ] && bridge_ip="172.17.0.1"

    while true; do
        clear
        echo -e "${YELLOW}=== 🌉 宿主机应用穿透 (Localhost Proxy) ===${NC}"
        echo -e "功能: 让容器能访问宿主机的 127.0.0.1 应用"
        echo -e "原理: Docker网桥($bridge_ip:Port) -> 转发 -> 宿主机(127.0.0.1:Port)"
        echo "------------------------------------------------"
        
        # 列出当前已存在的转发服务
        echo -e "${CYAN}当前转发列表:${NC}"
        local count=0
        for s in /etc/systemd/system/mmp-socat-*.service; do
            if [ -f "$s" ]; then
                # 从文件名提取端口 mmp-socat-8080.service -> 8080
                local p=$(basename "$s" | sed 's/mmp-socat-//;s/.service//')
                # 检查运行状态
                if systemctl is-active --quiet "mmp-socat-$p"; then st="${GREEN}● 运行中${NC}"; else st="${RED}● 已停止${NC}"; fi
                echo -e " - 转发端口: ${GREEN}$p${NC} \t状态: $st"
                ((count++))
            fi
        done
        [ "$count" -eq 0 ] && echo " (暂无转发配置)"
        
        echo "------------------------------------------------"
        echo " 1. 添加新的转发规则"
        echo " 2. 删除/停止 转发规则"
        echo " 0. 返回"
        echo "------------------------------------------------"
        read -p "请选择: " o

        case $o in
            0) return;;
            
            1)
                echo -e "${YELLOW}>>> 新增转发规则${NC}"
                read -p "1. 请输入宿主机应用端口 (例如 3000): " host_port
                read -p "2. 请输入容器访问端口 (留空同上): " docker_port
                [ -z "$docker_port" ] && docker_port="$host_port"

                service_name="mmp-socat-${docker_port}"
                service_file="/etc/systemd/system/${service_name}.service"

                # 写入 Systemd 服务文件
                cat > "$service_file" <<EOF
[Unit]
Description=MMP Socat Forwarder ($docker_port -> 127.0.0.1:$host_port)
After=network.target docker.service

[Service]
Type=simple
User=root
# 核心命令：监听 Docker 网桥 IP，转发到 本地回环 IP
ExecStart=/usr/bin/socat TCP-LISTEN:${docker_port},bind=${bridge_ip},fork TCP:127.0.0.1:${host_port}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
                # 启动服务
                systemctl daemon-reload
                systemctl enable "$service_name" >/dev/null 2>&1
                systemctl start "$service_name"
                
                echo -e "${GREEN}✔ 穿透服务已启动！${NC}"
                echo "------------------------------------------------"
                echo -e "🚀 你的容器现在可以通过以下地址访问宿主机应用："
                echo -e "   ${CYAN}http://${bridge_ip}:${docker_port}${NC}"
                echo "------------------------------------------------"
                pause_prompt
                ;;

            2)
                read -p "请输入要删除的【容器访问端口】: " d_port
                service_name="mmp-socat-${d_port}"
                
                if [ -f "/etc/systemd/system/${service_name}.service" ]; then
                    systemctl stop "$service_name"
                    systemctl disable "$service_name" >/dev/null 2>&1
                    rm -f "/etc/systemd/system/${service_name}.service"
                    systemctl daemon-reload
                    echo -e "${GREEN}✔ 已删除规则: $d_port${NC}"
                else
                    echo -e "${RED}❌ 规则不存在${NC}"
                fi
                pause_prompt
                ;;
        esac
    done
}

function ssh_key_manager() {
    # 定义 SSH 配置文件路径
    SSHD_CONFIG="/etc/ssh/sshd_config"
    SSHD_BACKUP="/etc/ssh/sshd_config.bak"
    
    # --- [修正] 内部函数：智能安全重启 SSH ---
    function safe_restart_ssh() {
        echo -e "${YELLOW}>>> 正在进行配置安全检查 (sshd -t)...${NC}"
        
        # 1. 寻找 sshd 二进制文件 (兼容不同系统路径)
        SSHD_BIN=$(command -v sshd || echo "/usr/sbin/sshd")
        
        # 2. 检查语法
        if $SSHD_BIN -t -f "$SSHD_CONFIG"; then
            echo -e "${GREEN}✔ 配置文件语法正确。${NC}"
            
            # 3. 智能判定服务名称 (ssh vs sshd)
            if command -v systemctl >/dev/null; then
                # 尝试检测 sshd 服务是否存在
                if systemctl list-unit-files | grep -q "^sshd.service"; then
                    SVC_NAME="sshd"
                else
                    SVC_NAME="ssh"
                fi
                
                echo -e "${YELLOW}>>> 正在重启服务 ($SVC_NAME)...${NC}"
                systemctl restart "$SVC_NAME"
            else
                # 非 Systemd 系统 (如部分 Docker 容器或老系统)
                service ssh restart 2>/dev/null || service sshd restart
            fi
            
            echo -e "${GREEN}✔ SSH 服务已重启生效。${NC}"
        else
            # 4. 语法错误处理：自动回滚
            echo -e "${RED}❌ 严重错误：配置文件语法检查失败！${NC}"
            echo -e "${RED}❌ 系统拒绝重启 SSH 服务，以防止失联。${NC}"
            echo -e "${YELLOW}>>> 正在回滚配置文件...${NC}"
            if [ -f "$SSHD_BACKUP" ]; then
                cp "$SSHD_BACKUP" "$SSHD_CONFIG"
                echo -e "${GREEN}✔ 已还原至修改前的状态。${NC}"
            else
                echo -e "${RED}⚠️  未找到备份文件，请手动检查 $SSHD_CONFIG${NC}"
            fi
        fi
    }
    # -----------------------------

    while true; do
        clear
        echo -e "${YELLOW}=== 🔑 SSH 密钥安全管理 (Safe Mode) ===${NC}"
        echo -e "当前状态检查："
        
        # 检查公钥认证是否开启
        if grep -q "^PubkeyAuthentication yes" $SSHD_CONFIG; then
            echo -e " - 公钥认证: ${GREEN}已开启${NC}"
        else
            echo -e " - 公钥认证: ${YELLOW}未显式开启 (默认可能支持)${NC}"
        fi
        
        # 检查密码登录是否开启
        if grep -q "^PasswordAuthentication no" $SSHD_CONFIG; then
            echo -e " - 密码登录: ${GREEN}已关闭 (安全)${NC}"
        else
            echo -e " - 密码登录: ${RED}已开启 (存在爆破风险)${NC}"
        fi

        echo "------------------------------------------------"
        echo " 1. 一键生成密钥 + 部署 (这是第一步)"
        echo " 2. 关闭密码登录 (这是第二步，需先完成第一步)"
        echo " 3. 恢复密码登录 (救急用)"
        echo " 0. 返回上一级"
        echo "------------------------------------------------"
        read -p "请输入选项 [0-3]: " o
        
        case $o in
            0) return;;
            
            1)
                echo -e "${YELLOW}>>> 正在生成 4096位 RSA 密钥对...${NC}"
                # 1. 生成临时密钥
                TEMP_KEY="/root/temp_ssh_key"
                rm -f "$TEMP_KEY" "$TEMP_KEY.pub"
                ssh-keygen -t rsa -b 4096 -f "$TEMP_KEY" -N "" -q
                
                # 2. 部署公钥
                mkdir -p /root/.ssh
                chmod 700 /root/.ssh
                cat "$TEMP_KEY.pub" >> /root/.ssh/authorized_keys
                chmod 600 /root/.ssh/authorized_keys
                
                # 3. 开启 SSH 公钥支持 (需要修改配置)
                if ! grep -q "^PubkeyAuthentication yes" $SSHD_CONFIG; then
                    echo -e "${YELLOW}>>> 检测到需开启 PubkeyAuthentication，正在修改配置...${NC}"
                    cp "$SSHD_CONFIG" "$SSHD_BACKUP" # 备份
                    sed -i '/^#\?PubkeyAuthentication/d' $SSHD_CONFIG
                    echo "PubkeyAuthentication yes" >> $SSHD_CONFIG
                    safe_restart_ssh
                fi
                
                # 4. 显示私钥
                clear
                echo -e "${RED}====================================================${NC}"
                echo -e "${RED}⚠️  请立即复制下面的私钥内容并保存到本地电脑！${NC}"
                echo -e "${RED}⚠️  保存为 .pem 文件，或导入到 Xshell/Putty 中。${NC}"
                echo -e "${RED}====================================================${NC}"
                echo ""
                cat "$TEMP_KEY"
                echo ""
                echo -e "${RED}====================================================${NC}"
                echo -e "${GREEN}✔ 公钥已自动部署到服务器。${NC}"
                rm -f "$TEMP_KEY" "$TEMP_KEY.pub"
                
                echo -e "${YELLOW}提示: 请现在打开一个新的终端窗口，使用刚才的密钥尝试连接服务器。${NC}"
                echo -e "确认可以连接后，再执行 [2] 关闭密码登录。"
                pause_prompt
                ;;
                
            2)
                echo -e "${RED}⚠️  高危操作警告${NC}"
                echo -e "在执行此操作前，请确保你已经：\n1. 生成并保存了密钥。\n2. 使用密钥成功测试了登录。"
                echo -e "如果未配置好密钥就关闭密码登录，你将【彻底失去】服务器连接！"
                echo "------------------------------------------------"
                read -p "我确认已测试密钥登录成功 (输入 yes 确认): " confirm
                
                if [ "$confirm" == "yes" ]; then
                    echo -e "${YELLOW}>>> 正在修改配置以禁用密码登录...${NC}"
                    cp "$SSHD_CONFIG" "$SSHD_BACKUP" # 备份
                    
                    # 修改配置文件：禁止密码登录
                    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/g' $SSHD_CONFIG
                    # 确保 ChallengeResponseAuthentication 也是关闭的
                    sed -i 's/^#\?ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/g' $SSHD_CONFIG
                    
                    safe_restart_ssh
                    echo -e "${GREEN}✔ 策略已应用。${NC}"
                else
                    echo "操作已取消。"
                fi
                pause_prompt
                ;;
                
            3)
                echo -e "${YELLOW}>>> 正在恢复密码登录功能...${NC}"
                cp "$SSHD_CONFIG" "$SSHD_BACKUP" # 备份
                sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/g' $SSHD_CONFIG
                safe_restart_ssh
                echo -e "${GREEN}✔ 策略已应用。${NC}"
                pause_prompt
                ;;
        esac
    done
}

function wp_toolbox() {
    # WP-CLI 工具箱
    while true; do
        clear; echo -e "${YELLOW}=== 🛠️ WP-CLI 工具 ===${NC}"
        ls -1 "$SITES_DIR"; echo "--------------------------"
        read -p "请输入要操作的域名 (0返回): " d; [ "$d" == "0" ] && return
        sdir="$SITES_DIR/$d"
        if [ ! -d "$sdir" ]; then echo -e "${RED}目录不存在${NC}"; sleep 1; continue; fi
        
        # 动态获取容器名
        if [ -f "$sdir/docker-compose.yml" ]; then
            container_name=$(grep "container_name: .*_app" "$sdir/docker-compose.yml" | awk '{print $2}')
        fi
        
        if [ -z "$container_name" ]; then echo -e "${RED}无法识别WP容器，请确认是标准WP站点${NC}"; sleep 2; continue; fi

        echo -e "当前操作站点: ${CYAN}$d${NC} (容器: $container_name)"
        echo "--------------------------"
        echo " 1. 重置管理员密码 (user=admin)"
        echo " 2. 列出所有插件"
        echo " 3. 禁用所有插件 (救砖用)"
        echo " 4. 清理对象缓存 (Object Cache)"
        echo " 5. 修复文件权限 (chown www-data)"
        echo " 6. 替换数据库中的域名 (Search-Replace)"
        echo " 0. 返回上一级"
        echo "--------------------------"
        read -p "请输入选项 [0-6]: " op
        
        case $op in
            0) break;;
            1) read -p "请输入新密码: " newpass
               echo -e "${YELLOW}正在重置...${NC}"
               docker exec -u www-data "$container_name" wp user update admin --user_pass="$newpass"
               echo -e "${GREEN}✔ 密码已重置${NC}"; pause_prompt;;
            2) docker exec -u www-data "$container_name" wp plugin list; pause_prompt;;
            3) docker exec -u www-data "$container_name" wp plugin deactivate --all; echo -e "${GREEN}✔ 所有插件已禁用${NC}"; pause_prompt;;
            4) docker exec -u www-data "$container_name" wp cache flush; echo -e "${GREEN}✔ 缓存已刷新${NC}"; pause_prompt;;
            5) echo -e "${YELLOW}正在修复权限 (可能需要几秒)...${NC}"
               # 需要 root 权限运行 chown
               docker compose -f "$sdir/docker-compose.yml" exec -T -u root wordpress chown -R www-data:www-data /var/www/html
               echo -e "${GREEN}✔ 权限已修复 (www-data)${NC}"; pause_prompt;;
            6) read -p "旧域名: " old_d; read -p "新域名: " new_d
               echo -e "${YELLOW}正在执行全库替换...${NC}"
               docker exec -u www-data "$container_name" wp search-replace "$old_d" "$new_d" --all-tables
               echo -e "${GREEN}✔ 替换完成，请记得清理缓存${NC}"; pause_prompt;;
        esac
    done
}

function telegram_manager() {
    # 定义服务名称
    local MON_SVC="mmp-monitor"
    local LIS_SVC="mmp-listener"

    while true; do
        clear; echo -e "${YELLOW}=== 🤖 Telegram 机器人管理 (Systemd 版) ===${NC}"
        
        # 加载配置
        if [ -f "$TG_CONF" ]; then source "$TG_CONF"; fi
        
        # 检查服务状态
        if systemctl is-active --quiet "$MON_SVC"; then M_STAT="${GREEN}● 运行中 (自启)${NC}"; else M_STAT="${RED}● 已停止${NC}"; fi
        if systemctl is-active --quiet "$LIS_SVC"; then L_STAT="${GREEN}● 运行中 (自启)${NC}"; else L_STAT="${RED}● 已停止${NC}"; fi
        
        echo -e "配置: Token=${TG_BOT_TOKEN:0:5}*** | ChatID=$TG_CHAT_ID"
        echo -e "守护进程: $M_STAT"
        echo -e "指令监听: $L_STAT"
        echo "--------------------------"
        echo " 1. 配置 Token 和 ChatID"
        echo " 2. 启动/重启 资源报警 (守护进程)"
        echo " 3. 启动/重启 指令监听 (交互模式)"
        echo " 4. 停止所有服务"
        echo " 5. 发送测试消息"
        echo " 6. 查看运行日志"
        echo " 0. 返回上一级"
        echo "--------------------------"
        read -p "请输入选项 [0-6]: " t
        case $t in
            0) return;;
            
            1) 
                read -p "Token: " tk; echo "TG_BOT_TOKEN=\"$tk\"" > "$TG_CONF"
                read -p "ChatID: " ci; echo "TG_CHAT_ID=\"$ci\"" >> "$TG_CONF"
                echo "已保存"; pause_prompt;;
            
            2) 
                # 1. 生成脚本文件
                generate_monitor_script
                # 2. 注册为 Systemd 服务 (实现开机自启)
                create_systemd_service "$MON_SVC" "$MONITOR_SCRIPT" "MMP Resource Monitor"
                send_tg_msg "✅ 资源报警服务已启动 (Systemd)"
                pause_prompt;;
            
            3) 
                # 1. 检查依赖 & 生成脚本
                check_dependencies
                generate_listener_script
                # 2. 注册为 Systemd 服务
                create_systemd_service "$LIS_SVC" "$LISTENER_SCRIPT" "MMP Bot Listener"
                send_tg_msg "✅ 指令监听服务已启动 (Systemd)"
                pause_prompt;;
            
            4) 
                echo -e "${YELLOW}正在停止服务...${NC}"
                systemctl stop "$MON_SVC" 2>/dev/null
                systemctl disable "$MON_SVC" 2>/dev/null
                systemctl stop "$LIS_SVC" 2>/dev/null
                systemctl disable "$LIS_SVC" 2>/dev/null
                # 清理旧的 PID 文件 (如果存在)
                rm -f "$MONITOR_PID" "$LISTENER_PID"
                echo -e "${GREEN}✔ 所有后台服务已停止并取消自启${NC}"
                pause_prompt;;
            
            5) 
                send_tg_msg "🔔 测试消息 OK"; echo "已发送"; pause_prompt;;
            
            6)
                echo -e "${CYAN}=== 资源监控日志 ===${NC}"
                journalctl -u "$MON_SVC" -n 10 --no-pager
                echo -e "\n${CYAN}=== 指令监听日志 ===${NC}"
                journalctl -u "$LIS_SVC" -n 10 --no-pager
                pause_prompt;;
        esac
    done
}

function sys_monitor() {
    # --- 内部工具函数 ---
    function draw_bar() {
        local pct=$1; local color=$2; local width=20; local num=$((pct * width / 100)); local bar=""
        for ((i=0; i<num; i++)); do bar="${bar}█"; done
        for ((i=num; i<width; i++)); do bar="${bar}░"; done
        echo -e "${color}[${bar}] ${pct}%${NC}"
    }
    function format_bytes() {
        local bytes=$1
        if (( $(echo "$bytes < 1024" | bc -l 2>/dev/null || awk 'BEGIN {print ('$bytes' < 1024)}') )); then echo "${bytes} B/s"
        elif (( $(echo "$bytes < 1048576" | bc -l 2>/dev/null || awk 'BEGIN {print ('$bytes' < 1048576)}') )); then echo "$(awk "BEGIN {printf \"%.1f\", $bytes/1024}") KB/s"
        else echo "$(awk "BEGIN {printf \"%.1f\", $bytes/1048576}") MB/s"; fi
    }

    # === 获取终端尺寸 (用于判断是否开启 btop) ===
    read rows cols < <(stty size 2>/dev/null || echo "24 80")

    # === Level 1: 智能启动 btop ===
    if command -v btop >/dev/null 2>&1; then
        if [ "$cols" -ge 80 ] && [ "$rows" -ge 24 ]; then
            btop; return
        else
            echo -e "${YELLOW}提示: 窗口太小，已降级模式。${NC}"; sleep 1
        fi
    fi

    # === Level 2: htop (如果不喜欢 htop 也可以注释掉这段) ===
    if command -v htop >/dev/null 2>&1; then
        htop; return
    fi

    # === Level 3: 原生 Bash 面板 (支持按 q 退出) ===
    local net_interface=$(ip route | grep default | awk '{print $5}' | head -n1)
    
    echo -e "${YELLOW}>>> 启动面板 (按 'q' 或 '0' 退出)...${NC}"
    
    # 隐藏光标，看起来更像专业软件
    echo -e "\033[?25l"
    
    while true; do
        # 1. 采集数据 (开始)
        read cpu_user1 cpu_nice1 cpu_sys1 cpu_idle1 cpu_iowait1 cpu_irq1 cpu_softirq1 cpu_steal1 < <(grep 'cpu ' /proc/stat | awk '{print $2,$3,$4,$5,$6,$7,$8,$9}')
        read rx1 tx1 < <(grep "$net_interface" /proc/net/dev | awk '{print $2,$10}')
        
        # [核心改进] 使用 read 等待 1 秒
        # -t 1: 超时1秒 (相当于 sleep 1)
        # -n 1: 只读取 1 个字符 (不需要按回车)
        # -s: 静默模式 (不把按键显示在屏幕上)
        read -t 1 -n 1 -s key
        
        # 检查按键
        if [[ "$key" == "q" ]] || [[ "$key" == "0" ]]; then
            echo -e "\n${GREEN}>>> 已退出监控${NC}"
            break
        fi
        
        # 2. 采集数据 (结束)
        read cpu_user2 cpu_nice2 cpu_sys2 cpu_idle2 cpu_iowait2 cpu_irq2 cpu_softirq2 cpu_steal2 < <(grep 'cpu ' /proc/stat | awk '{print $2,$3,$4,$5,$6,$7,$8,$9}')
        read rx2 tx2 < <(grep "$net_interface" /proc/net/dev | awk '{print $2,$10}')

        # 3. 计算逻辑
        cpu_total1=$((cpu_user1 + cpu_nice1 + cpu_sys1 + cpu_idle1 + cpu_iowait1 + cpu_irq1 + cpu_softirq1 + cpu_steal1))
        cpu_total2=$((cpu_user2 + cpu_nice2 + cpu_sys2 + cpu_idle2 + cpu_iowait2 + cpu_irq2 + cpu_softirq2 + cpu_steal2))
        cpu_diff=$((cpu_total2 - cpu_total1))
        cpu_idle_diff=$((cpu_idle2 - cpu_idle1))
        [ $cpu_diff -eq 0 ] && cpu_usage=0 || cpu_usage=$(( (cpu_diff - cpu_idle_diff) * 100 / cpu_diff ))

        mem_total=$(free -m | awk 'NR==2{print $2}')
        mem_used=$(free -m | awk 'NR==2{print $3}')
        mem_pct=$(( mem_used * 100 / mem_total ))
        disk_pct=$(df -h / | awk 'NR==2 {print $5}' | tr -d '%')

        rx_rate=$((rx2 - rx1)); tx_rate=$((tx2 - tx1))
        rx_fmt=$(format_bytes $rx_rate); tx_fmt=$(format_bytes $tx_rate)

        # 4. 渲染界面
        clear
        echo -e "${GREEN}=== 🖥️  原生监控 (按 'q' 退出) ===${NC}"
        echo -e "IP: $(hostname -I | awk '{print $1}') | 运行: $(uptime -p)"
        echo "----------------------------------------"
        echo -n "🧠 CPU : "; draw_bar $cpu_usage $CYAN
        echo -n "💾 RAM : "; draw_bar $mem_pct $PURPLE
        echo -n "💿 DISK: "; draw_bar $disk_pct $YELLOW
        echo "----------------------------------------"
        echo -e "⬇️  下载: ${GREEN}$rx_fmt${NC}"
        echo -e "⬆️  上传: ${BLUE}$tx_fmt${NC}"
        echo "----------------------------------------"
        echo -e "🏆 Top 3: "
        ps -eo comm,%cpu,%mem --sort=-%cpu | head -n 4 | tail -n 3 | awk '{printf "   %-10s C:%-3s%% M:%-3s%%\n", $1, $2, $3}'
        echo "----------------------------------------"
    done
    
    # 恢复光标显示
    echo -e "\033[?25h"
}

# ================= 📜 容器日志查看器 =================
function view_container_logs() {
    while true; do
        clear
        echo -e "${YELLOW}=== 🔍 容器日志查看器 ===${NC}"
        echo -e "用于找回初始密码、Token 或排查启动错误。"
        echo "--------------------------"
        
        # 列出站点
        ls -1 "$SITES_DIR"
        echo "--------------------------"
        echo "输入 0 返回上一级"
        echo "--------------------------"
        read -p "请输入要查看的域名: " domain
        
        if [ "$domain" == "0" ]; then return; fi
        
        sdir="$SITES_DIR/$domain"
        if [ ! -d "$sdir" ]; then 
            echo -e "${RED}目录不存在${NC}"; sleep 1; continue
        fi
        
        cd "$sdir"
        
        echo "--------------------------"
        echo " 1. 查看最后 50 行 (标准模式)"
        echo " 2. 实时追踪日志 (Ctrl+C 退出)"
        echo -e " 3. ${GREEN}🔍 搜索敏感信息 (密码/Token)${NC}"
        echo "--------------------------"
        read -p "请选择日志模式 [1-3]: " log_opt
        
        case $log_opt in
            1) 
                echo -e "${YELLOW}>>> 正在获取日志...${NC}"
                docker compose logs --tail=50
                pause_prompt
                ;;
            2)
                echo -e "${YELLOW}>>> 进入实时模式 (按 Ctrl+C 退出)...${NC}"
                sleep 1
                docker compose logs -f --tail=20
                ;;
            3)
                echo -e "${YELLOW}>>> 正在搜索 Password, Token, Key, Admin...${NC}"
                echo "------------------------------------------------"
                # 使用 grep 搜索常见关键词，-i 忽略大小写，-E 支持多个词
                docker compose logs | grep -iE "pass|token|key|secret|admin|user|generated"
                echo "------------------------------------------------"
                echo -e "如果上面是空的，说明日志里没打印密码，或者已被滚动清理。"
                pause_prompt
                ;;
            *) echo "无效选项"; sleep 1;;
        esac
    done
}

function log_manager() { 
    while true; do 
        clear; echo -e "${YELLOW}=== 📜 日志管理系统 ===${NC}"
        echo " 1. 查看最新操作日志 (Top 50)"
        echo " 2. 清空日志文件"
        echo " 3. 配置定时清理任务 (7天)"
        echo " 0. 返回上一级"
        echo "--------------------------"
        read -p "请输入选项 [0-3]: " l
        case $l in 
            0) return;; 
            1) tail -n 50 "$LOG_FILE"; pause_prompt;; 
            2) echo "">"$LOG_FILE"; echo "日志已清空"; pause_prompt;; 
            3) crontab -l 2>/dev/null|grep -v "wp-cluster"|crontab -; (crontab -l 2>/dev/null; echo "0 3 * * * find $BASE_DIR -name '*.log' -mtime +7 -delete #wp-cluster-log-clean")|crontab -; echo "定时任务已配置"; pause_prompt;; 
        esac
    done 
}

function container_ops() { 
    while true; do 
        clear; echo -e "${YELLOW}=== 📊 容器状态监控 ===${NC}"
        echo -e "【核心网关】"; cd "$GATEWAY_DIR" && docker compose ps --format "table {{.Service}}\t{{.State}}\t{{.Status}}"|tail -n +2
        for d in "$SITES_DIR"/*; do [ -d "$d" ] && echo -e "【站点: $(basename "$d")】" && cd "$d" && docker compose ps --all --format "table {{.Service}}\t{{.State}}\t{{.Status}}"|tail -n +2; done
        echo "--------------------------"
        echo " 1. 全部启动 (Start All)"
        echo " 2. 全部停止 (Stop All)"
        echo " 3. 全部重启 (Restart All)"
        echo " 4. 指定站点操作"
        echo " 0. 返回上一级"
        echo "--------------------------"
        read -p "请输入选项 [0-4]: " c
        case $c in 
            0) return;; 
            1) cd "$GATEWAY_DIR" && docker compose up -d; for d in "$SITES_DIR"/*; do cd "$d" && docker compose up -d; done; echo "执行完成"; pause_prompt;; 
            2) for d in "$SITES_DIR"/*; do cd "$d" && docker compose stop; done; cd "$GATEWAY_DIR" && docker compose stop; echo "执行完成"; pause_prompt;; 
            3) cd "$GATEWAY_DIR" && docker compose restart; for d in "$SITES_DIR"/*; do cd "$d" && docker compose restart; done; echo "执行完成"; pause_prompt;; 
            4) ls -1 "$SITES_DIR"; read -p "输入域名: " d; cd "$SITES_DIR/$d" && read -p "1.启动 2.停止 3.重启: " a && ([ "$a" == "1" ] && docker compose up -d || ([ "$a" == "2" ] && docker compose stop || docker compose restart)); echo "执行完成"; pause_prompt;; 
        esac
    done 
}

# === [新增] 全站 PHP 安全加固 (批量部署) ===
function harden_php_security() {
    echo -e "${RED}=== 🔒 PHP 深度安全加固 (Security Hardening) ===${NC}"
    echo -e "${YELLOW}此功能将为所有现有 WordPress 站点执行以下操作：${NC}"
    echo -e "1. 生成 php_security.ini (禁用 exec, system, shell_exec 等高危函数)。"
    echo -e "2. 修改 docker-compose.yml 挂载该配置。"
    echo -e "3. 重启站点容器以生效。"
    echo "------------------------------------------------"
    echo -e "${RED}注意：某些依赖系统命令的插件(如特定备份/压缩插件)可能会失效。${NC}"
    read -p "确认执行? (y/n): " confirm
    if [ "$confirm" != "y" ]; then return; fi

    for d in "$SITES_DIR"/*; do
        if [ -d "$d" ]; then
            domain=$(basename "$d")
            echo -e "\n正在处理: ${CYAN}$domain${NC} ..."
            
            # 1. 写入安全配置文件
            cat > "$d/php_security.ini" <<EOF
[PHP]
; === 基础隐藏 ===
expose_php = Off
display_errors = Off
display_startup_errors = Off
log_errors = On

; === 资源限制 ===
memory_limit = 512M
upload_max_filesize = 512M
post_max_size = 512M
max_execution_time = 300
max_input_time = 300

; === 安全核心 ===
allow_url_fopen = On
allow_url_include = Off
session.cookie_httponly = 1
session.use_only_cookies = 1
session.cookie_secure = 1

; === 禁用高危函数 (防 Webshell) ===
disable_functions = passthru,exec,system,chroot,chgrp,chown,shell_exec,proc_get_status,popen,ini_alter,ini_restore,dl,readlink,symlink,popepassthru,stream_socket_server,fsocket,popen

; === 目录锁定 ===
open_basedir = /var/www/html:/tmp
EOF

            # 2. 修改 docker-compose.yml 挂载
            yml_file="$d/docker-compose.yml"
            need_restart=0
            
            # 情况 A: 以前挂载过 uploads.ini (旧版脚本) -> 替换为 php_security.ini
            if grep -q "uploads.ini" "$yml_file"; then
                sed -i 's|./uploads.ini:/usr/local/etc/php/conf.d/uploads.ini|./php_security.ini:/usr/local/etc/php/conf.d/security.ini|g' "$yml_file"
                echo -e "  - [配置] 已替换旧版 uploads.ini"
                need_restart=1
            
            # 情况 B: 以前挂载过 php_security.ini (已经是新版) -> 只更新了文件内容
            elif grep -q "php_security.ini" "$yml_file"; then
                echo -e "  - [配置] 配置文件内容已更新"
                need_restart=1
                
            # 情况 C: 从未挂载过任何 ini -> 插入新挂载
            else
                # 备份
                cp "$yml_file" "$yml_file.bak"
                # 在 volumes: 下寻找 wp_data 行，在下面插入
                # 如果找不到 wp_data 锚点，尝试直接在 volumes: 下插入
                if grep -q "wp_data:/var/www/html" "$yml_file"; then
                    sed -i '/wp_data:\/var\/www\/html/a \      - ./php_security.ini:/usr/local/etc/php/conf.d/security.ini' "$yml_file"
                    echo -e "  - [配置] 已添加挂载规则"
                    need_restart=1
                else
                    echo -e "  - ${RED}[错误] 无法定位挂载点，请手动检查 $yml_file${NC}"
                fi
            fi

            # 3. 重启容器
            if [ "$need_restart" -eq 1 ]; then
                echo -e "  - [重启] 正在应用更改..."
                cd "$d" && docker compose up -d
                echo -e "  - ${GREEN}✔ 完成${NC}"
            fi
        fi
    done
    echo -e "\n${GREEN}✔ 所有站点 PHP 加固完成。${NC}"
    pause_prompt
}

function component_manager() { 
    while true; do 
        clear
        echo -e "${YELLOW}=== 🆙 组件版本升降级 ===${NC}"
        echo -e "${RED}⚠️  警告: 修改版本即重建容器。请确保配置兼容！${NC}"
        
        # 1. 选择站点
        ls -1 "$SITES_DIR"
        echo "--------------------------"
        read -p "输入域名 (0返回): " d
        [ "$d" == "0" ] && return
        
        sdir="$SITES_DIR/$d"
        yml="$sdir/docker-compose.yml"
        
        if [ ! -f "$yml" ]; then echo -e "${RED}配置文件不存在${NC}"; sleep 1; continue; fi
        
        # 获取当前版本用于显示
        cur_wp=$(grep "image: wordpress" "$yml" | head -1 | awk '{print $2}')
        cur_db=$(grep "image: .*sql" "$yml" | head -1 | awk '{print $2}')
        cur_redis=$(grep "image: redis" "$yml" | head -1 | awk '{print $2}')

        echo -e "当前配置:"
        echo -e " - WP:    $cur_wp"
        echo -e " - DB:    $cur_db"
        echo -e " - Redis: $cur_redis"
        echo "--------------------------"
        echo " 1. 切换 PHP 版本 (WordPress Image)"
        echo " 2. 切换 数据库 版本 (⚠️ 高危)"
        echo " 3. 切换 Redis 版本"
        echo " 4. 切换 Nginx 版本 (推荐 Alpine)"
        echo " 0. 返回上一级"
        echo "--------------------------"
        read -p "请输入选项 [0-4]: " op
        
        case $op in 
            0) break;; 
            
            1) 
                echo -e "${CYAN}--- 选择 PHP (FPM) 版本 ---${NC}"
                echo "注意: 必须使用 FPM 版本以配合 Nginx 网关"
                echo "1. PHP 7.4 (旧版)"
                echo "2. PHP 8.0"
                echo "3. PHP 8.1"
                echo "4. PHP 8.2 (稳定)"
                echo "5. PHP 8.3 (最新)"
                echo "6. Latest FPM (始终最新)"
                read -p "选择: " p
                case $p in 
                    1) t="php7.4-fpm-alpine";; 
                    2) t="php8.0-fpm-alpine";; 
                    3) t="php8.1-fpm-alpine";; 
                    4) t="php8.2-fpm-alpine";; 
                    5) t="php8.3-fpm-alpine";; 
                    6) t="fpm-alpine";; # 修正点：确保是 fpm-alpine，不是 latest
                    *) continue;; 
                esac
                # 使用更精确的正则，只替换 image: wordpress 开头的行
                sed -i "s|image: wordpress:.*|image: wordpress:$t|g" "$yml"
                write_log "PHP update $d -> $t"
                ;; 
            
            2) 
                echo -e "${RED}🛑 严重警告: 数据库版本变更可能导致数据无法读取！${NC}"
                echo -e "${YELLOW}特别是【降级】(如 8.0 -> 5.7) 通常会导致容器无法启动。${NC}"
                echo -e "${YELLOW}跨类型切换 (MySQL <-> MariaDB) 也可能存在兼容问题。${NC}"
                read -p "我已备份数据，确认继续? (yes/no): " confirm
                if [ "$confirm" != "yes" ]; then continue; fi

                echo "1. MySQL 5.7"
                echo "2. MySQL 8.0"
                echo "3. MySQL 8.4 LTS"
                echo "4. MariaDB 10.6"
                echo "5. MariaDB 11.4"
                read -p "选择: " v
                case $v in 
                    1) i="mysql:5.7";; 
                    2) i="mysql:8.0";; 
                    3) i="mysql:8.4";; 
                    4) i="mariadb:10.6";; 
                    5) i="mariadb:11.4";; 
                    *) continue;; 
                esac
                # 同时处理 mysql 和 mariadb 的匹配情况
                if grep -q "image: mysql" "$yml"; then
                    sed -i "s|image: mysql:.*|image: $i|g" "$yml"
                elif grep -q "image: mariadb" "$yml"; then
                    sed -i "s|image: mariadb:.*|image: $i|g" "$yml"
                fi
                write_log "DB update $d -> $i"
                ;; 
            
            3) 
                echo "1. Redis 6.2"
                echo "2. Redis 7.0"
                echo "3. Redis 7.2"
                read -p "选择: " r
                case $r in 
                    1) rt="6.2-alpine";; 
                    2) rt="7.0-alpine";; 
                    3) rt="7.2-alpine";; 
                    *) continue;; 
                esac
                sed -i "s|image: redis:.*|image: redis:$rt|g" "$yml"
                write_log "Redis update $d -> $rt"
                ;; 
            
            4) 
                echo "1. Nginx Alpine (推荐)"
                echo "2. Nginx Latest (不推荐)"
                read -p "选择: " n
                if [ "$n" == "2" ]; then nt="latest"; else nt="alpine"; fi
                sed -i "s|image: nginx:.*|image: nginx:$nt|g" "$yml"
                write_log "Nginx update $d -> $nt"
                ;;
        esac

        # 应用更改
        echo -e "${YELLOW}>>> 正在重构容器...${NC}"
        cd "$sdir"
        $DOCKER_COMPOSE_CMD up -d
        echo -e "${GREEN}✔ 更新完成${NC}"
        pause_prompt
    done 
}

function add_basic_auth() {
    # 依赖检查
    if ! command -v htpasswd >/dev/null 2>&1; then
        echo -e "${YELLOW}>>> 正在安装 apache2-utils...${NC}"
        if [ -f /etc/debian_version ]; then apt-get update && apt-get install -y apache2-utils
        else yum install -y httpd-tools; fi
    fi

    while true; do
        clear
        echo -e "${YELLOW}=== 🔐 通用型二级密码锁 (Universal Auth) ===${NC}"
        echo -e "功能：为任何站点/应用添加 HTTP Basic Auth 认证。"
        echo "--------------------------"
        
        ls -1 "$SITES_DIR"
        echo "--------------------------"
        read -p "请输入要加锁的域名 (0返回): " d
        [ "$d" == "0" ] && return
        
        sdir="$SITES_DIR/$d"
        if [ ! -d "$sdir" ]; then echo -e "${RED}目录不存在${NC}"; sleep 1; continue; fi
        
        # 1. 智能探测配置文件
        nginx_conf=""
        docker_yml="$sdir/docker-compose.yml"
        
        if [ -f "$sdir/nginx.conf" ]; then
            nginx_conf="$sdir/nginx.conf"      # WordPress 或 标准站点
            conf_type="std"
        elif [ -f "$sdir/nginx-proxy.conf" ]; then
            nginx_conf="$sdir/nginx-proxy.conf" # 反向代理站点
            conf_type="proxy"
        else
            echo -e "${RED}未找到支持的 Nginx 配置文件，无法加锁。${NC}"
            echo "目前仅支持通过本脚本部署的 WP 或 Proxy 站点。"
            pause_prompt; continue
        fi

        echo -e "当前选中: ${CYAN}$d${NC} (类型: $conf_type)"
        echo "--------------------------"
        echo " 1. 开启/重置 密码锁"
        echo " 2. 关闭 密码锁"
        echo " 0. 返回"
        read -p "选择: " op
        
        if [ "$op" == "1" ]; then
            echo -e "\n${YELLOW}--- 模式选择 ---${NC}"
            echo " A. 全站加锁 (访问域名就需要密码，适合私有应用)"
            echo " B. 仅登录页加锁 (适合 WordPress，仅保护 wp-login.php)"
            read -p "请选择模式 [A/B]: " mode
            
            # 输入用户名密码
            read -p "设置用户名 (默认admin): " u; [ -z "$u" ] && u="admin"
            read -p "设置密码: " p
            if [ -z "$p" ]; then echo "密码不能为空"; sleep 1; continue; fi

            # 生成密码文件
            echo -e "${YELLOW}>>> 生成密码文件...${NC}"
            htpasswd -bc "$sdir/.htpasswd" "$u" "$p"
            
            # --- 核心逻辑：挂载 .htpasswd 到容器 ---
            # 检查 docker-compose.yml 是否已经挂载了 .htpasswd
            # 我们利用 grep 检查，如果没有，就用 sed 插入
            if ! grep -q "\.htpasswd" "$docker_yml"; then
                echo -e "${YELLOW}>>> 正在注入挂载配置...${NC}"
                # 寻找挂载 Nginx 配置的那一行，在它下面追加一行
                # 兼容 nginx.conf 和 nginx-proxy.conf 的挂载写法
                if grep -q "nginx.conf:/etc/nginx/conf.d/default.conf" "$docker_yml"; then
                     sed -i '/nginx.conf:\/etc\/nginx\/conf.d\/default.conf/a \      - ./.htpasswd:/etc/nginx/conf.d/.htpasswd' "$docker_yml"
                elif grep -q "nginx-proxy.conf:/etc/nginx/conf.d/default.conf" "$docker_yml"; then
                     sed -i '/nginx-proxy.conf:\/etc\/nginx\/conf.d\/default.conf/a \      - ./.htpasswd:/etc/nginx/conf.d/.htpasswd' "$docker_yml"
                else
                     echo -e "${RED}⚠️  自动挂载失败，请手动修改 docker-compose.yml 挂载 .htpasswd${NC}"
                fi
                need_restart=1
            else
                need_restart=0
            fi

            # --- 核心逻辑：修改 Nginx 配置 ---
            # 先清理旧的 auth 配置，防止重复
            sed -i '/auth_basic/d' "$nginx_conf"
            
            if [ "$mode" == "A" ] || [ "$mode" == "a" ]; then
                # === 模式 A: 全站加锁 ===
                # 在 "location / {" 后面插入认证指令
                sed -i '/location \/ {/a \        auth_basic "Private Site";\n        auth_basic_user_file /etc/nginx/conf.d/.htpasswd;' "$nginx_conf"
                echo -e "${GREEN}✔ 已配置全站锁定${NC}"
                
            else
                # === 模式 B: 特定路径 (WP专用) ===
                if [ "$conf_type" != "std" ]; then
                    echo -e "${RED}❌ 代理模式暂不支持路径锁，已自动切换为全站锁。${NC}"
                    sed -i '/location \/ {/a \        auth_basic "Private Site";\n        auth_basic_user_file /etc/nginx/conf.d/.htpasswd;' "$nginx_conf"
                else
                    # 针对 WordPress 结构，寻找 wp-login.php 的 location
                    if grep -q "location = /wp-login.php" "$nginx_conf"; then
                        sed -i '/location = \/wp-login.php {/a \        auth_basic "Admin Only";\n        auth_basic_user_file /etc/nginx/conf.d/.htpasswd;' "$nginx_conf"
                    else
                        # 如果没找到 location (旧版配置)，提示用户重建
                        echo -e "${RED}⚠️  未找到 wp-login.php 配置段，请先升级站点配置(重建站点)。${NC}"
                        pause_prompt; continue
                    fi
                fi
                echo -e "${GREEN}✔ 已配置登录页锁定${NC}"
            fi

            # 应用更改
            echo -e "${YELLOW}>>> 正在应用更改...${NC}"
            if [ "$need_restart" -eq 1 ]; then
                # 如果修改了挂载，必须 recreate
                cd "$sdir" && docker compose up -d --force-recreate
            else
                # 如果只是改了 Nginx 配置，reload 即可 (极速)
                # 获取容器名进行 reload
                container_name=$(docker compose -f "$docker_yml" ps -q | head -n 1) # 简单粗暴获取第一个容器ID作为上下文
                # 更精准的方法：
                if [ "$conf_type" == "std" ]; then svc="nginx"; else svc="proxy"; fi
                cd "$sdir" && docker compose exec "$svc" nginx -s reload
            fi
            
            echo -e "${GREEN}✔ 部署完成！${NC}"
            
        elif [ "$op" == "2" ]; then
            echo -e "${YELLOW}>>> 正在移除密码锁...${NC}"
            sed -i '/auth_basic/d' "$nginx_conf"
            if [ "$conf_type" == "std" ]; then svc="nginx"; else svc="proxy"; fi
            cd "$sdir" && docker compose exec "$svc" nginx -s reload
            echo -e "${GREEN}✔ 密码锁已关闭${NC}"
        fi
        
        pause_prompt
    done
}

function fail2ban_manager() {
    # 定义日志路径
    local nginx_log="$LOG_DIR/access.log"
    
    while true; do
        clear
        echo -e "${YELLOW}=== 👮 Fail2Ban 严厉模式 (3次即封) ===${NC}"
        echo -e "当前状态: $(systemctl is-active fail2ban 2>/dev/null || echo '未安装')"
        echo "--------------------------"
        echo " 1. 应用严厉策略 (SSH + Nginx防扫)"
        echo " 2. 查看被封禁 IP"
        echo " 3. 解封指定 IP"
        echo " 4. 查看拦截日志"
        echo " 0. 返回"
        echo "--------------------------"
        read -p "请输入选项 [0-4]: " o
        
        case $o in
            0) return;;
            
            1)
                echo -e "${YELLOW}>>> 正在配置 Fail2Ban (严厉模式)...${NC}"
                
                # 1. 检查日志
                if [ ! -f "$nginx_log" ]; then
                    echo -e "${RED}未找到 Nginx 日志: $nginx_log${NC}"
                    echo -e "请先执行 [99] 重建网关以挂载日志。"
                    pause_prompt; continue
                fi

                # 2. 安装
                if [ -f /etc/debian_version ]; then 
                    apt-get update && apt-get install -y fail2ban
                    ssh_log="/var/log/auth.log"
                else 
                    yum install -y fail2ban
                    ssh_log="/var/log/secure"
                fi

                # 3. 写入过滤规则
                cat > /etc/fail2ban/filter.d/nginx-scan.conf <<EOF
[Definition]
failregex = ^<HOST> -.*"(GET|POST|HEAD).*" (404|444|403|401|429) .*$
            ^<HOST> -.*"POST .*wp-login.php.*" 200 .*$ 
            # 上面这行可选：如果你觉得有人不停POST登录页(即使返回200也是在试密码)也该封，就加上
ignoreregex =
EOF

                # 4. 写入 Jail 配置 (核心修改点)
                cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
bantime  = 86400    ; 封禁 1 天
findtime = 3000      ; 50分钟内
maxretry = 3        ; 只有3次机会

[sshd]
enabled = true
port    = ssh
logpath = $ssh_log
backend = systemd
maxretry = 3

[nginx-scan]
enabled = true
filter  = nginx-scan
logpath = $nginx_log
port    = http,https
maxretry = 5        ; 触发5次 Nginx 错误(含限速/404)即封禁
action  = iptables-allports[name=nginx-scan]
EOF

                # 5. 重启生效
                systemctl enable fail2ban
                systemctl restart fail2ban
                
                echo -e "${GREEN}✔ 严厉策略已生效！${NC}"
                echo -e "规则: 5分钟内错误 3 次 -> 封禁 24 小时"
                pause_prompt
                ;;
                
            2)
                echo -e "${CYAN}=== 监狱名单 ===${NC}"
                echo -e "【SSH】"
                fail2ban-client status sshd 2>/dev/null | grep "Banned IP list:"
                echo -e "\n【Web扫描】"
                fail2ban-client status nginx-scan 2>/dev/null | grep "Banned IP list:"
                pause_prompt
                ;;
                
            3)
                read -p "输入解封 IP: " ip
                if [ ! -z "$ip" ]; then
                    fail2ban-client set sshd unbanip $ip
                    fail2ban-client set nginx-scan unbanip $ip
                    echo "已解封"
                fi
                pause_prompt
                ;;
            
            4) grep "Ban " /var/log/fail2ban.log | tail -n 20; pause_prompt;;
        esac
    done
}

# === [修复版] WAF 管理器 (移除网关专用变量) ===
function waf_manager() { 
    while true; do 
        clear; echo -e "${YELLOW}=== 🛡️ WAF 网站防火墙 (V10.3 Stable) ===${NC}"
        echo " 1. 部署/更新 究极防御规则"
        echo " 2. 查看当前规则内容"
        echo " 0. 返回上一级"
        echo "--------------------------"
        read -p "请输入选项 [0-2]: " o
        case $o in 
            0) return;; 
            1) 
                echo -e "${BLUE}>>> 正在生成 V10.3 稳定版规则...${NC}"
                
                # 修复核心：移除了 $block_bot 检查
                # 爬虫拦截由网关负责，站点容器只负责防注入
                cat >/tmp/w <<EOF
# ==================================================
#   V10.3 Ultimate WAF Rules (Site Level)
# ==================================================
# 1. 禁用非法 HTTP 方法 (只允许标准方法)
if (\$request_method !~ ^(GET|POST|HEAD)$ ) { return 405; }

# 2. 禁止空 User-Agent 或异常 UA
if (\$http_user_agent = "") { return 403; }
if (\$http_user_agent ~* "WinHttp|WebZIP|Fetch") { return 403; }

# --- [1] 系统与敏感文件保护 ---
location ~* \.(engine|inc|info|install|make|module|profile|test|po|sh|.*sql|theme|tpl(\.php)?|xtmpl)$ { return 403; }
location ~* \.(bak|config|sql|fla|psd|ini|log|sh|inc|swp|dist|exe|bat|dll)$ { return 403; }
location ~* /\.(git|svn|hg|env|ssh|vscode|idea) { return 403; }
location ~* (wp-config\.php|readme\.html|license\.txt|debug\.log)$ { return 403; }
location = /xmlrpc.php { deny all; return 403; }

# --- [2] SQL 注入防御 ---
set \$block_sql_injections 0;
if (\$query_string ~* "union.*select") { set \$block_sql_injections 1; } 
if (\$query_string ~* "union.*all.*select") { set \$block_sql_injections 1; }
if (\$query_string ~* "concat.*\(") { set \$block_sql_injections 1; }
if (\$query_string ~* "(0x[0-9a-f][0-9a-f]|/\*|--|\|\|)") { set \$block_sql_injections 1; }
if (\$block_sql_injections = 1) { return 403; }

# --- [3] 文件包含与目录遍历 ---
set \$block_file_injections 0;
if (\$query_string ~* "(\.\./|\.\.)") { set \$block_file_injections 1; }
if (\$query_string ~* "(boot\.ini|etc/passwd|self/environ)") { set \$block_file_injections 1; }
if (\$query_string ~* "(mosconfig|base64_encode|base64_decode|eval\(|popen\(|proc_open)") { set \$block_file_injections 1; }
if (\$block_file_injections = 1) { return 403; }

# --- [4] XSS 跨站脚本 ---
set \$block_xss 0;
if (\$query_string ~* "(<|%3C).*script") { set \$block_xss 1; }
if (\$query_string ~* "javascript:") { set \$block_xss 1; }
if (\$query_string ~* "(onload|onerror|onmouseover)=") { set \$block_xss 1; }
if (\$block_xss = 1) { return 403; }

# --- [5] 备用爬虫拦截 (站内硬编码) ---
if (\$http_user_agent ~* (Acunetix|AppScan|ApacheBench|Burp|Dirbuster|Havij|Hydra|Jorgee|masscan|Nessus|Netsparker|Nikto|OpenVAS|Pangolin|SF|ZmEu)) { return 403; }
EOF
                count=0
                for d in "$SITES_DIR"/*; do 
                    if [ -d "$d" ]; then 
                        # 确保引用
                        if [ -f "$d/nginx.conf" ] && ! grep -q "waf.conf" "$d/nginx.conf"; then
                             sed -i '/server_name localhost;/a \    include /etc/nginx/waf.conf;' "$d/nginx.conf"
                        fi

                        cp /tmp/w "$d/waf.conf" 
                        # 重启站点容器
                        cd "$d" && docker compose exec -T nginx nginx -s reload >/dev/null 2>&1
                        echo -e " - $(basename "$d"): ${GREEN}V10.3 规则已生效${NC}"
                        ((count++))
                    fi 
                done
                rm /tmp/w; echo -e "${GREEN}✔ 已部署 ${count} 个站点${NC}"; pause_prompt;; 
            2) cat "$SITES_DIR/"*"/waf.conf" 2>/dev/null|head -30; pause_prompt;; 
        esac
    done 
}

function port_manager() { 
    ensure_firewall_installed || return
    if command -v ufw >/dev/null && ! ufw status | grep -q "active"; then ufw allow 22/tcp >/dev/null; ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null; echo "y" | ufw enable >/dev/null; fi
    while true; do 
        clear; echo -e "${YELLOW}=== 🧱 端口防火墙 ===${NC}"
        if command -v ufw >/dev/null; then FW="UFW"; else FW="Firewalld"; fi; echo "当前防火墙: $FW"
        echo "--------------------------"
        echo " 1. 查看开放端口"
        echo " 2. 开放/关闭 端口 (支持多端口)"
        echo " 3. 防 DOS 攻击 (开启/关闭)"
        echo " 4. 一键全开 / 一键全关"
        echo " 0. 返回上一级"
        echo "--------------------------"
        read -p "请输入选项 [0-4]: " f
        case $f in 
            0) return;; 
            1) if [ "$FW" == "UFW" ]; then ufw status; else firewall-cmd --list-ports; fi; pause_prompt;; 
            2) read -p "输入端口 (如 80 443): " ports; echo "1.开放 2.关闭"; read -p "选: " a; for p in $ports; do if command -v ufw >/dev/null; then [ "$a" == "1" ] && ufw allow $p/tcp || ufw delete allow $p/tcp; else ac=$([ "$a" == "1" ] && echo add || echo remove); firewall-cmd --zone=public --${ac}-port=$p/tcp --permanent; fi; done; command -v firewall-cmd >/dev/null && firewall-cmd --reload; echo "完成"; pause_prompt;; 
            3) echo "1.开启防DOS 2.关闭"; read -p "选: " d; if [ "$d" == "1" ]; then echo "limit_req_zone \$binary_remote_addr zone=one:10m rate=10r/s; limit_conn_zone \$binary_remote_addr zone=addr:10m;" > "$FW_DIR/dos_zones.conf"; mkdir -p "$GATEWAY_DIR/vhost"; echo "limit_req zone=one burst=15 nodelay; limit_conn addr 15;" > "$GATEWAY_DIR/vhost/default"; cd "$GATEWAY_DIR" && docker compose up -d >/dev/null 2>&1 && docker exec gateway_proxy nginx -s reload; echo "已开启"; else rm -f "$FW_DIR/dos_zones.conf" "$GATEWAY_DIR/vhost/default"; cd "$GATEWAY_DIR" && docker exec gateway_proxy nginx -s reload; echo "已关闭"; fi; pause_prompt;; 
            4) echo "1.全开 2.全关"; read -p "选: " m; if [ "$m" == "1" ]; then [ -x "$(command -v ufw)" ] && ufw default allow incoming || firewall-cmd --set-default-zone=trusted; else if [ -x "$(command -v ufw)" ]; then ufw allow 22/tcp; ufw allow 80/tcp; ufw allow 443/tcp; ufw default deny incoming; else firewall-cmd --permanent --add-service={ssh,http,https}; firewall-cmd --set-default-zone=drop; firewall-cmd --reload; fi; fi; echo "完成"; pause_prompt;; 
        esac
    done 
}

function traffic_manager() { 
    # 依赖检查
    if [ ! -f "$FW_DIR/access.conf" ]; then touch "$FW_DIR/access.conf"; fi
    if [ ! -f "$FW_DIR/geo.conf" ]; then touch "$FW_DIR/geo.conf"; fi
    if [ ! -f "$FW_DIR/bots.conf" ]; then touch "$FW_DIR/bots.conf"; fi

    # 内部函数：安全重载 Nginx
    function safe_reload() {
        echo -e "${YELLOW}>>> 正在测试 Nginx 配置...${NC}"
        # 预检配置
        if docker exec gateway_proxy nginx -t >/dev/null 2>&1; then
            reload_gateway_config # 调用之前修复过的带等待的重启函数
            echo -e "${GREEN}✔ 配置生效${NC}"
        else
            echo -e "${RED}❌ 配置有误，Nginx 拒绝加载！${NC}"
            echo -e "请尝试清空规则。"
        fi
    }

    # 内部函数：校验 IP 格式
    function validate_ip() {
        local ip=$1
        if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then return 0; else return 1; fi
    }

    while true; do 
        clear; echo -e "${YELLOW}=== 🌐 流量控制加强版 (Traffic ACL) ===${NC}"
        echo -e "当前规则数: IP[$(wc -l < "$FW_DIR/access.conf")] | 国家[$(wc -l < "$FW_DIR/geo.conf")]"
        # 检查爬虫规则是否开启 (检查文件内容是否包含 map)
        if grep -q "map \$http_user_agent" "$FW_DIR/bots.conf"; then
            BOT_ST="${GREEN}已开启${NC}"
        else
            BOT_ST="${YELLOW}未开启${NC}"
        fi
        echo -e "爬虫拦截状态: $BOT_ST"
        echo "--------------------------"
        echo " 1. 添加 黑/白 名单 IP"
        echo " 2. 查看 已封禁/放行 列表"
        echo " 3. 删除 指定 IP 规则"
        echo "--------------------------"
        echo " 4. 封禁 指定国家 (GeoIP)"
        echo " 5. 屏蔽 恶意爬虫/扫描器 (User-Agent)"
        echo "--------------------------"
        echo " 6. 清空 所有规则"
        echo " 0. 返回上一级"
        echo "--------------------------"
        read -p "请输入选项 [0-6]: " t
        
        case $t in 
            0) return;; 
            
            1) 
                echo -e "1. 黑名单 (Deny) - 禁止访问"
                echo -e "2. 白名单 (Allow) - 允许访问 (需配合 deny all 使用)"
                read -p "请选择类型 [1/2]: " type
                if [ "$type" == "1" ]; then rule="deny"; else rule="allow"; fi
                read -p "请输入 IP 或网段: " ip
                if validate_ip "$ip"; then
                    if grep -q "$ip;" "$FW_DIR/access.conf"; then
                        echo -e "${YELLOW}该 IP 已存在${NC}"
                    else
                        echo "$rule $ip;" >> "$FW_DIR/access.conf"
                        safe_reload
                    fi
                else
                    echo -e "${RED}❌ IP 格式错误${NC}"
                fi
                pause_prompt;; 
            
            2) 
                echo -e "${CYAN}=== IP 规则列表 ===${NC}"
                [ -s "$FW_DIR/access.conf" ] && cat -n "$FW_DIR/access.conf" || echo "列表为空"
                pause_prompt;;

            3) 
                [ ! -s "$FW_DIR/access.conf" ] && echo "列表为空" && pause_prompt && continue
                cat -n "$FW_DIR/access.conf"
                read -p "请输入要删除的 IP: " del_ip
                if [ ! -z "$del_ip" ]; then
                    sed -i "/$del_ip;/d" "$FW_DIR/access.conf"
                    echo -e "${GREEN}已删除${NC}"
                    safe_reload
                fi
                pause_prompt;;

            4) 
                read -p "请输入国家代码 (如 cn, ru, us): " c
                c=$(echo "$c" | tr '[:upper:]' '[:lower:]')
                echo -e "${YELLOW}>>> 正在下载 $c IP 段...${NC}"
                if curl -sL "http://www.ipdeny.com/ipblocks/data/countries/$c.zone" -o /tmp/ip_list.txt; then
                    if [ -s /tmp/ip_list.txt ] && ! grep -q "DOCTYPE" /tmp/ip_list.txt; then
                        while read line; do echo "deny $line;" >> "$FW_DIR/geo.conf"; done < /tmp/ip_list.txt
                        rm /tmp/ip_list.txt
                        safe_reload
                    else
                        echo -e "${RED}❌ 国家代码无效${NC}"
                    fi
                else
                    echo -e "${RED}❌ 下载失败${NC}"
                fi
                pause_prompt;; 
            
            5)
                echo -e "屏蔽常见扫描器: curl, wget, python, go-http, sqlmap, nmap 等。"
                read -p "是否开启? (y=开启, n=关闭): " bot_confirm
                if [ "$bot_confirm" == "y" ]; then
                    # 【核心修复】使用 map 代替 if
                    # 如果匹配到爬虫，将变量 $block_bot 置为 1，否则为 0
                    cat > "$FW_DIR/bots.conf" <<EOF
map \$http_user_agent \$block_bot {
    default 0;
    "~*(Scrapy|Curl|HttpClient|Java|Wget|Python|Go-http-client|SQLMap|Nmap|Nikto|Havij|Indy Library)" 1;
}
EOF
                    echo -e "${GREEN}>>> 已写入爬虫拦截规则 (Map模式)${NC}"
                    echo -e "${YELLOW}注意: 需要更新 WAF 规则 (菜单 30-1) 才能在站点生效。${NC}"
                    safe_reload
                else
                    echo "" > "$FW_DIR/bots.conf"
                    echo -e "${YELLOW}>>> 已关闭爬虫拦截${NC}"
                    safe_reload
                fi
                pause_prompt;; 

            6) 
                read -p "确定清空所有规则吗? (y/n): " confirm
                if [ "$confirm" == "y" ]; then
                    echo "" > "$FW_DIR/access.conf"
                    echo "" > "$FW_DIR/geo.conf"
                    echo "" > "$FW_DIR/bots.conf"
                    safe_reload
                fi
                pause_prompt;; 
        esac
    done 
}

# ================= 🆕 动态云端应用商店 =================

# 仓库基础配置 (请根据实际情况修改 URL)
# 确保这是 raw 文件的访问地址前缀
REPO_ROOT="https://raw.githubusercontent.com/lje02/wp-manager/main"

function install_remote_app() {
    local app_key=$1
    local app_name=$2
    
    echo "-----------------------------------------"
    echo -e "正在准备安装: ${GREEN}$app_name${NC}"
    read -p "请输入域名 (例如 $app_key.example.com): " domain
    if [ -z "$domain" ]; then echo -e "${RED}域名不能为空${NC}"; return; fi

    # 1. 冲突检测与目录创建
    pname=$(echo $domain | tr '.' '_')
    if ! check_container_conflict "$pname"; then pause_prompt; return; fi
    
       sdir="$SITES_DIR/$domain"
    
    # [修改点] 智能目录检查 ===========================
    if [ -d "$sdir" ]; then
        echo -e "${RED}⚠️  检测到目录已存在: $sdir${NC}"
        echo -e "${YELLOW}这通常意味着之前安装过，或者卸载不彻底。${NC}"
        read -p "是否删除旧目录并强制重装? (y/n): " confirm_del
        
        if [ "$confirm_del" == "y" ]; then
            echo -e "${YELLOW}>>> 正在清理旧文件...${NC}"
            # 先尝试停止可能存在的容器（双重保险）
            cd "$sdir" 2>/dev/null && docker compose down >/dev/null 2>&1
            # 删除目录
            rm -rf "$sdir"
            echo -e "${GREEN}✔ 旧目录已清理${NC}"
        else
            echo "❌ 操作已取消"; pause_prompt; return
        fi
    fi
    # ===============================================
    
    mkdir -p "$sdir"


    # 2. 下载模板 (路径规则：apps/key/template.yml)
    template_url="$REPO_ROOT/apps/$app_key/template.yml"
    target_file="$sdir/docker-compose.yml"
    
    echo -e "${YELLOW}>>> 正在下载配置模板...${NC}"
    if ! curl -f -sL "$template_url" -o "$target_file"; then
        echo -e "${RED}❌ 下载失败！${NC}"
        echo "请求地址: $template_url"
        rm -rf "$sdir"
        pause_prompt; return
    fi

    # 3. 渲染模板
    echo -e "${YELLOW}>>> 正在配置参数...${NC}"
    email="admin@localhost.com"
    sed -i "s|{{DOMAIN}}|$domain|g" "$target_file"
    sed -i "s|{{EMAIL}}|$email|g" "$target_file"
    sed -i "s|{{APP_NAME}}|$pname|g" "$target_file"

    # 4. 启动
    cd "$sdir" && docker compose up -d
    reload_gateway_config
    write_log "Installed Cloud App ($app_key) on $domain"
    echo -e "${GREEN}✔ $app_name 部署成功！${NC}"
    check_ssl_status "$domain"

    echo -e "${YELLOW}------------------------------------------------${NC}"
    echo -e "正在尝试从日志中自动抓取初始密码/Token..."
    echo -e "${YELLOW}------------------------------------------------${NC}"
    
    # [改进] 等待5秒让容器初始化，然后尝试抓取日志
    sleep 5
    # 获取当前目录下 docker-compose.yml 里的第一个服务名对应的容器ID
    # 这样不管容器叫什么名字都能找到
    cid=$(docker compose ps -q | head -n 1)
    
    if [ ! -z "$cid" ]; then
        # 搜索常见密码关键词
        logs=$(docker logs $cid 2>&1 | grep -iE "pass|token|key|secret|admin|user|generated" | tail -n 5)
        if [ ! -z "$logs" ]; then
             echo -e "${GREEN}🔍 发现可能的凭证信息：${NC}"
             echo "$logs"
        else
             echo -e "${CYAN}ℹ️  未在日志最后5行发现明显密码。${NC}"
             echo -e "可能是默认密码 (admin/admin)，或需要手动执行命令。"
             echo -e "你可以使用菜单 [34] -> [3] 深度搜索日志。"
        fi
        echo -e "${YELLOW}------------------------------------------------${NC}"
        echo -e "容器ID: ${CYAN}${cid:0:12}${NC}"
    else
        echo -e "${RED}⚠️ 无法获取容器ID，请手动检查。${NC}"
    fi
    
    pause_prompt
}
function traffic_stats() {
    # 检查日志是否存在
    local log_file="$LOG_DIR/access.log"
    if [ ! -f "$log_file" ]; then
        echo -e "${RED}❌ 未找到日志文件: $log_file${NC}"
        echo -e "${YELLOW}提示: 如果你是刚更新脚本，请先执行 '99. 重建网关' (你需要手动添加这个选项或重启网关) 以挂载日志目录。${NC}"
        pause_prompt
        return
    fi

    while true; do
        clear
        echo -e "${YELLOW}=== 📈 站点访问流量统计 ===${NC}"
        echo -e "日志大小: $(du -h $log_file | awk '{print $1}')"
        echo "--------------------------"
        echo " 1. 实时可视化面板 (GoAccess CLI)"
        echo " 2. 生成 HTML 报表 (下载到本地看)"
        echo " 3. 快速文本统计 (Top 10 IP)"
        echo " 4. 快速文本统计 (Top 10 URL)"
        echo " 5. 清空旧日志"
        echo " 0. 返回上一级"
        echo "--------------------------"
        read -p "请输入选项 [0-5]: " s
        case $s in
            0) return;;
            1)
                echo -e "${GREEN}>>> 正在启动 GoAccess 面板...${NC}"
                echo -e "(操作提示: 按 F1 查看帮助, q 退出)"
                sleep 2
                # 使用 Docker 运行 GoAccess，无需在宿主机安装
                docker run --rm -it -v "$LOG_DIR":/srv/logs xavierh/goaccess-for-nginxproxymanager goaccess /srv/logs/access.log --log-format=COMBINED --real-time-html=false
                ;;
            2)
                echo -e "${GREEN}>>> 正在生成 Report...${NC}"
                docker run --rm -v "$LOG_DIR":/srv/logs xavierh/goaccess-for-nginxproxymanager goaccess /srv/logs/access.log --log-format=COMBINED -o /srv/logs/report.html
                echo -e "✅ 报表已生成: ${CYAN}$LOG_DIR/report.html${NC}"
                echo -e "你可以通过 FTP/SFTP 下载该文件，或临时移动到网站目录查看。"
                pause_prompt
                ;;
            3)
                echo -e "\n${CYAN}--- Top 10 访问 IP ---${NC}"
                awk '{print $1}' "$log_file" | sort | uniq -c | sort -rn | head -n 10
                pause_prompt
                ;;
            4)
                echo -e "\n${CYAN}--- Top 10 访问 URL ---${NC}"
                awk -F\" '{print $2}' "$log_file" | awk '{print $2}' | sort | uniq -c | sort -rn | head -n 10
                pause_prompt
                ;;
            5)
                echo -e "${YELLOW}确定要清空访问日志吗？(y/n)${NC}"
                read -p "> " c
                if [ "$c" == "y" ]; then
                    echo "" > "$log_file"
                    echo "已清空。"
                fi
                pause_prompt
                ;;
        esac
    done
}
# --- 5. 系统清理模块 ---
function system_cleanup() {
    while true; do
        clear
        echo -e "${YELLOW}=== 🧹 系统垃圾清理大师 ===${NC}"
        echo -e "当前磁盘使用率: $(df -h / | awk 'NR==2 {print $5}')"
        echo "--------------------------"
        echo " 1. Docker 深度瘦身 (删除未使用的镜像/缓存)"
        echo " 2. 扫描并清理 孤儿证书 (已删站点的残留SSL)"
        echo " 3. 强制刷新 网关配置 (Nginx Reload)"
        echo " 0. 返回"
        echo "--------------------------"
        read -p "请选择 [0-3]: " c
        case $c in
            0) return;;
            
            1) 
                echo -e "${YELLOW}>>> 正在执行 Docker 深度清理...${NC}"
                echo -e "这将删除所有停止的容器、无用的网络和**未被使用的镜像**。"
                read -p "确认执行? (y/n): " confirm
                if [ "$confirm" == "y" ]; then
                    docker system prune -f
                    echo -e "${GREEN}✔ 清理完成！空间已释放。${NC}"
                else
                    echo "已取消"
                fi
                pause_prompt
                ;;
                
            2)
                echo -e "${YELLOW}>>> 正在扫描孤儿证书...${NC}"
                # 逻辑：遍历 certs 容器内的证书，对比 SITES_DIR 目录
                # 如果证书存在，但 sites 目录下没有对应文件夹，视为垃圾
                
                # 1. 获取所有证书文件名 (去除后缀)
                certs=$(docker exec gateway_acme ls /etc/nginx/certs 2>/dev/null | grep "\.crt$" | sed 's/\.crt//g')
                
                if [ -z "$certs" ]; then
                    echo "未找到任何证书。"; pause_prompt; continue
                fi

                count=0
                found_orphan=0
                
                for domain in $certs; do
                    # 忽略 default 证书
                    if [ "$domain" == "default" ]; then continue; fi
                    
                    # 检查是否存在对应的站点目录
                    if [ ! -d "$SITES_DIR/$domain" ]; then
                        echo -e "${RED}发现残留证书: $domain${NC}"
                        read -p "  └─ 确认删除该证书? (y/n): " del
                        if [ "$del" == "y" ]; then
                            docker exec gateway_acme rm -f "/etc/nginx/certs/$domain.crt" "/etc/nginx/certs/$domain.key" "/etc/nginx/certs/$domain.chain.pem" "/etc/nginx/certs/$domain.dhparam.pem" 2>/dev/null
                            echo -e "     ${GREEN}✔ 已删除${NC}"
                            ((count++))
                        fi
                        found_orphan=1
                    fi
                done
                
                if [ "$found_orphan" -eq 0 ]; then
                    echo -e "${GREEN}✔ 太棒了，你的系统很干净，没有残留证书。${NC}"
                else
                    echo -e "共清理了 $count 个残留域名证书。"
                fi
                pause_prompt
                ;;
                
            3)
                echo -e "${YELLOW}>>> 正在重载 Nginx 网关...${NC}"
                if docker exec gateway_proxy nginx -s reload; then
                    echo -e "${GREEN}✔ 网关刷新成功${NC}"
                else
                    echo -e "${RED}❌ 刷新失败，请检查网关容器状态${NC}"
                fi
                pause_prompt
                ;;
        esac
    done
}

function app_store() {
    # 依赖检查：我们需要 jq 来解析 JSON
    if ! command -v jq >/dev/null 2>&1; then
        echo -e "${RED}错误: 未安装 jq 组件，请先运行脚本依赖检查。${NC}"
        pause_prompt; return
    fi

    local list_file="/tmp/wp_apps_list.json"
    local list_url="$REPO_ROOT/apps.json"

    while true; do
        clear
        echo -e "${YELLOW}=== ☁️ 动态应用商店 (Dynamic Store) ===${NC}"
        echo -e "正在从云端获取最新应用列表..."
        
        # 1. 下载应用列表 JSON
        if ! curl -sL "$list_url" -o "$list_file"; then
            echo -e "${RED}❌ 获取列表失败，请检查网络或仓库地址。${NC}"
            pause_prompt; return
        fi

        # 检查 JSON 是否合法
        if ! jq -e . "$list_file" >/dev/null 2>&1; then
             echo -e "${RED}❌ 获取的数据格式错误。${NC}"
             pause_prompt; return
        fi

        echo "-----------------------------------------"
        
        # 2. 使用 jq 动态生成菜单
        # 逻辑：读取数组，输出 "序号. 名称 (描述)"
        jq -r 'to_entries[] | " \(.key + 1). " + .value.name + " \t- " + .value.description' "$list_file"
        
        echo " 0. 返回上一级"
        echo "-----------------------------------------"
        
        read -p "请选择应用编号: " idx
        
        if [ "$idx" == "0" ]; then return; fi
        
        # 校验输入是否为数字
        if ! [[ "$idx" =~ ^[0-9]+$ ]]; then continue; fi

        # 3. 根据序号提取 Key 和 Name
        # 数组下标 = 序号 - 1
        array_index=$((idx - 1))
        
        # 使用 jq 提取对应下标的数据
        selected_key=$(jq -r ".[$array_index].key // empty" "$list_file")
        selected_name=$(jq -r ".[$array_index].name // empty" "$list_file")

        if [ -z "$selected_key" ] || [ "$selected_key" == "null" ]; then
            echo -e "${RED}无效的选择${NC}"
            sleep 1
        else
            # 调用安装函数
            install_remote_app "$selected_key" "$selected_name"
        fi
    done
}
# ================= 🔄 通用更新模块 =================
function app_update_manager() {
    while true; do
        clear
        echo -e "${YELLOW}=== 🆙 应用/站点更新中心 ===${NC}"
        echo -e "原理: 拉取 Docker 最新镜像并重建容器 (Image Pull & Recreate)"
        echo -e "适用: 所有通过本脚本安装的应用 (Portainer, Alist, WP等)"
        echo "--------------------------"
        
        # 列出所有站点
        ls -1 "$SITES_DIR"
        
        echo "--------------------------"
        echo "输入 0 返回上一级"
        echo "--------------------------"
        read -p "请输入要更新的域名: " domain
        
        if [ "$domain" == "0" ]; then return; fi
        
        sdir="$SITES_DIR/$domain"
        if [ ! -d "$sdir" ]; then 
            echo -e "${RED}❌ 目录不存在: $sdir${NC}"
            sleep 1
            continue
        fi
        
        echo -e "${YELLOW}>>> 正在更新 $domain ...${NC}"
        cd "$sdir"
        
        # 1. 拉取最新镜像
        echo -e "${CYAN}[1/3] 正在拉取最新镜像 (docker compose pull)...${NC}"
        if ! docker compose pull; then
            echo -e "${RED}❌ 拉取失败，请检查网络或镜像名。${NC}"
            pause_prompt
            continue
        fi
        
        # 2. 重建容器
        echo -e "${CYAN}[2/3] 正在重建容器 (docker compose up -d)...${NC}"
        docker compose up -d
        
        # 3. 清理旧镜像 (可选，释放磁盘空间)
        echo -e "${CYAN}[3/3] 清理无用的旧镜像...${NC}"
        docker image prune -f
        
        write_log "Updated app/site: $domain"
        echo -e "${GREEN}✔ 更新成功！${NC}"
        pause_prompt
    done
}

# --- 基础操作函数 ---
function init_gateway() { 
    local m=$1
    # 1. 确保网络和目录
    if ! docker network ls | grep -q proxy-net; then docker network create proxy-net >/dev/null; fi
    mkdir -p "$GATEWAY_DIR" "$LOG_DIR" "$FW_DIR"
    
    # 2. 初始化空配置文件
    touch "$FW_DIR/access.conf" "$FW_DIR/geo.conf" "$FW_DIR/bots.conf"

    cd "$GATEWAY_DIR"
    
    # 3. Nginx 优化配置 (包含隐藏版本号)
    echo "client_max_body_size 1024m;" > upload_size.conf
    echo "proxy_read_timeout 600s;" >> upload_size.conf
    echo "proxy_send_timeout 600s;" >> upload_size.conf
    echo "server_tokens off;" >> upload_size.conf
    echo "large_client_header_buffers 4 16k;" >> upload_size.conf
    echo "client_header_buffer_size 4k;" >> upload_size.conf
    echo "client_body_buffer_size 128k;" >> upload_size.conf
    # 4. 生成 Docker Compose (已修复 Logging 格式)
    cat > docker-compose.yml <<EOF
services:
  # [安全盾牌] Socket 代理
  socket-proxy:
    image: tecnativa/docker-socket-proxy
    container_name: gateway_socket_proxy
    restart: always
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      - CONTAINERS=1
      - NETWORKS=1
      - INFO=1
      - POST=0
    networks:
      - "proxy-net"

  # [核心网关] Nginx
  nginx-proxy:
    image: nginxproxy/nginx-proxy
    container_name: gateway_proxy
    ports: 
      - "80:80"
      - "443:443"
    logging: 
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    volumes: 
      - conf:/etc/nginx/conf.d
      - vhost:/etc/nginx/vhost.d
      - html:/usr/share/nginx/html
      - certs:/etc/nginx/certs:ro
      - ../firewall/access.conf:/etc/nginx/conf.d/z_access.conf:ro
      - ../firewall/geo.conf:/etc/nginx/conf.d/z_geo.conf:ro
      - ../firewall/bots.conf:/etc/nginx/conf.d/z_bots.conf:ro
      - ./upload_size.conf:/etc/nginx/conf.d/upload_size.conf:ro
      - ../logs:/var/log/nginx
    environment: 
      - "TRUST_DOWNSTREAM_PROXY=true"
      - "DOCKER_HOST=tcp://gateway_socket_proxy:2375"
      - "HTTPS_METHOD=redirect"
      - "HSTS=on"
      - "HSTS_MAX_AGE=31536000"
    networks: 
      - "proxy-net"
    depends_on:
      - socket-proxy
    restart: always

  # [证书伴侣] ACME
  acme-companion:
    image: nginxproxy/acme-companion
    container_name: gateway_acme
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    volumes: 
      - conf:/etc/nginx/conf.d
      - vhost:/etc/nginx/vhost.d
      - html:/usr/share/nginx/html
      - certs:/etc/nginx/certs:rw
      - acme:/etc/acme.sh
    environment: 
      - "DEFAULT_EMAIL=admin@localhost.com"
      - "NGINX_PROXY_CONTAINER=gateway_proxy"
      - "ACME_CA_URI=https://acme-v02.api.letsencrypt.org/directory"
      - "DOCKER_HOST=tcp://gateway_socket_proxy:2375"
    networks: 
      - "proxy-net"
    depends_on: 
      - "nginx-proxy"
      - "socket-proxy"
    restart: always

  # [自动更新] Watchtower
  watchtower:
    image: containrrr/watchtower
    container_name: gateway_watchtower
    restart: always
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - DOCKER_API_VERSION=1.44
      - WATCHTOWER_CLEANUP=true
      - WATCHTOWER_SCHEDULE=0 0 4 * * *
      - WATCHTOWER_INCLUDE_STOPPED=true
    networks:
      - "proxy-net"

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

    # 5. 启动
    local cmd=${DOCKER_COMPOSE_CMD:-"docker compose"}
    if $cmd up -d --remove-orphans >/dev/null 2>&1; then 
        [ "$m" == "force" ] && echo -e "${GREEN}✔ 网关重建完成${NC}"
    else 
        echo -e "${RED}✘ 网关启动失败${NC}"
        $cmd config
        [ "$m" == "force" ] && $cmd up -d
    fi 
}

function create_site() {
    read -p "1. 域名: " fd
    host_ip=$(curl -s4 ifconfig.me)
    if command -v dig >/dev/null; then dip=$(dig +short $fd|head -1); else dip=$(getent hosts $fd|awk '{print $1}'); fi
    if [ ! -z "$dip" ] && [ "$dip" != "$host_ip" ]; then echo -e "${RED}IP不符${NC}"; read -p "继续? (y/n): " f; [ "$f" != "y" ] && return; fi
    
    read -p "2. 邮箱: " email
    read -p "3. DB密码: " db_pass
    
    echo -e "${YELLOW}自定义版本? (默:PHP8.3/MySQL8.0/Redis7)${NC}"; read -p "y/n: " cust
    pt="php8.3-fpm-alpine"; di="mysql:8.0"; rt="7.0-alpine"
    if [ "$cust" == "y" ]; then 
        echo "PHP: 1.7.4 2.8.0 3.8.1 4.8.2 5.8.3 6.最新"; read -p "选: " p
        case $p in 1) pt="php7.4-fpm-alpine";; 2) pt="php8.0-fpm-alpine";; 3) pt="php8.1-fpm-alpine";; 4) pt="php8.2-fpm-alpine";; 5) pt="php8.3-fpm-alpine";; 6) pt="fpm-alpine";; esac
        echo "DB: 1.M5.7 2.M8.0 3.最新 4.Ma10.6 5.最新"; read -p "选: " d
        case $d in 1) di="mysql:5.7";; 2) di="mysql:8.0";; 3) di="mysql:latest";; 4) di="mariadb:10.6";; 5) di="mariadb:latest";; esac
        echo "Redis: 1.6.2 2.7.0 3.最新"; read -p "选: " r
        case $r in 1) rt="6.2-alpine";; 2) rt="7.0-alpine";; 3) rt="alpine";; esac
    fi
    
    pname=$(echo $fd|tr '.' '_'); sdir="$SITES_DIR/$fd"; [ -d "$sdir" ] && echo -e "已存在" && pause_prompt && return; mkdir -p "$sdir"

    # 1. 生成 WAF 配置
    cat > "$sdir/waf.conf" <<EOF
location ~* /\.(git|env|sql) { deny all; return 403; }
location ~* wp-config\.php$ { deny all; return 403; }
EOF

    # 2. 生成 Nginx 配置
    cat > "$sdir/nginx.conf" <<EOF
# 定义限速区：以IP为key，内存10M，速率限制为每秒1次请求
limit_req_zone \$binary_remote_addr zone=wp_login_limit:10m rate=1r/s;

server { 
    listen 80; 
    server_name localhost;
    server_tokens off;
    root /var/www/html; 
    index index.php; 
    include /etc/nginx/waf.conf; 
    client_max_body_size 512M; 
    
    location / { 
        try_files \$uri \$uri/ /index.php?\$args; 
    } 
    
    # [新增] 专门保护登录页
    location = /wp-login.php {
        # 应用限速：允许瞬间突发3个请求，超过则返回 429 错误
        limit_req zone=wp_login_limit burst=3 nodelay;
        # 返回 429 状态码 (Too Many Requests)，方便 Fail2Ban 抓取
        limit_req_status 429; 
        
        include fastcgi_params;
        fastcgi_pass wordpress:9000;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_param PATH_INFO \$fastcgi_path_info;
    }

    location ~ \.php$ { 
        try_files \$uri =404; 
        fastcgi_split_path_info ^(.+\.php)(/.+)$; 
        fastcgi_pass wordpress:9000; 
        fastcgi_index index.php; 
        include fastcgi_params; 
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name; 
        fastcgi_param PATH_INFO \$fastcgi_path_info; 
        fastcgi_read_timeout 600; 
    } 
}
EOF

     # 3. 生成 PHP 安全加固配置
    cat > "$sdir/php_security.ini" <<EOF
[PHP]
; === 基础安全 ===
expose_php = Off
display_errors = Off
display_startup_errors = Off
log_errors = On
error_log = /var/log/php_errors.log

; === 资源限制 (防DoS) ===
memory_limit = 512M
max_execution_time = 300
max_input_time = 300
post_max_size = 512M
upload_max_filesize = 512M
max_file_uploads = 20

; === 远程包含防御 (防RFI) ===
allow_url_fopen = On
allow_url_include = Off

; === 会话安全 ===
session.cookie_httponly = 1
session.use_only_cookies = 1
session.cookie_secure = 1

; === 核心函数禁用 (废掉 Webshell) ===
; 已修复拼写错误: popepassthru -> fpassthru
disable_functions = passthru,exec,system,chroot,chgrp,chown,shell_exec,proc_get_status,popen,ini_alter,ini_restore,dl,readlink,symlink,fpassthru,stream_socket_server,fsocket

; === 目录锁定 (防跨站/读系统文件) ===
open_basedir = /var/www/html:/tmp
EOF

          # 4. 生成 Docker Compose (完整版：修复了变量转义、YAML格式、Nginx配置)
    cat > "$sdir/docker-compose.yml" <<EOF
services:
  db:
    image: $di
    container_name: ${pname}_db
    restart: always
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    environment:
      MYSQL_ROOT_PASSWORD: "$db_pass"
      MYSQL_DATABASE: wordpress
      MYSQL_USER: wp_user
      MYSQL_PASSWORD: "$db_pass"
    volumes:
      - db_data:/var/lib/mysql
    networks:
      - default

  redis:
    image: redis:$rt
    container_name: ${pname}_redis
    restart: always
    command: redis-server --appendonly yes
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    volumes:
      - redis_data:/data
    networks:
      - default

  wordpress:
    image: wordpress:$pt
    container_name: ${pname}_app
    restart: always
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    depends_on:
      - db
      - redis
    environment:
      WORDPRESS_DB_HOST: db
      WORDPRESS_DB_USER: wp_user
      WORDPRESS_DB_PASSWORD: "$db_pass"
      WORDPRESS_DB_NAME: wordpress
      WORDPRESS_CONFIG_EXTRA: |
        define('WP_REDIS_HOST', 'redis');
        define('WP_REDIS_PORT', 6379);
        define('WP_HOME', 'https://' . \$\$_SERVER['HTTP_HOST']);
        define('WP_SITEURL', 'https://' . \$\$_SERVER['HTTP_HOST']);
        if (isset(\$\$_SERVER['HTTP_X_FORWARDED_PROTO']) && strpos(\$\$_SERVER['HTTP_X_FORWARDED_PROTO'], 'https') !== false) {
            \$\$_SERVER['HTTPS'] = 'on';
        }
    volumes:
      - wp_data:/var/www/html
      - ./php_security.ini:/usr/local/etc/php/conf.d/security.ini
    networks:
      - default

  nginx:
    image: nginx:alpine
    container_name: ${pname}_nginx
    restart: always
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    volumes:
      - wp_data:/var/www/html
      - ./nginx.conf:/etc/nginx/conf.d/default.conf
      - ./waf.conf:/etc/nginx/waf.conf
    environment:
      VIRTUAL_HOST: "$fd"
      LETSENCRYPT_HOST: "$fd"
      LETSENCRYPT_EMAIL: "$email"
    networks:
      - default
      - proxy-net

volumes:
  db_data:
  wp_data:
  redis_data:

networks:
  proxy-net:
    external: true
EOF

    # 5. 启动容器
    echo -e "${GREEN}>>> 正在启动容器...${NC}"
    $DOCKER_COMPOSE_CMD -f "$sdir/docker-compose.yml" up -d
    reload_gateway_config
    
    check_ssl_status "$fd"
    write_log "Created site $fd (PHP:$pt DB:$di Redis:$rt)"
}

function create_proxy() {
    read -p "1. 已解析到本机域名: " d; fd="$d"; read -p "2. 邮箱: " e; sdir="$SITES_DIR/$d"; mkdir -p "$sdir"
    echo -e "1.域名模式 2.IP:端口"; read -p "类型: " t
    if [ "$t" == "2" ]; then 
        read -p "IP: " ip; [ -z "$ip" ] && ip="127.0.0.1"
        read -p "端口: " p; tu="http://$ip:$p"; pm="2"
    else 
        read -p "目标URL: " tu; tu=$(normalize_url "$tu")
        echo "1.多源聚合 2.普通代理"; read -p "模式: " pm; [ -z "$pm" ] && pm="1"
    fi
    
    generate_nginx_conf "$tu" "$d" "$pm"
    
    # 修复：改用多行 YAML 格式，避免逗号错误
    cat > "$sdir/docker-compose.yml" <<EOF
services:
  proxy:
    image: nginx:alpine
    container_name: ${d//./_}_worker
    restart: always
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    volumes:
      - ./nginx-proxy.conf:/etc/nginx/conf.d/default.conf
    extra_hosts:
      - "host.docker.internal:host-gateway"
    environment:
      VIRTUAL_HOST: "$fd"
      LETSENCRYPT_HOST: "$fd"
      LETSENCRYPT_EMAIL: "$e"
    networks:
      - proxy-net

networks:
  proxy-net:
    external: true
EOF

    cd "$sdir" && docker compose up -d
    reload_gateway_config
    check_ssl_status "$d"
    write_log "Created proxy $d"
}

function generate_nginx_conf() {
    local u=$1; local d=$2; local m=$3; local h=$(echo $u|awk -F/ '{print $3}'); local f="$SITES_DIR/$d/nginx-proxy.conf"
    echo "server { listen 80; server_name localhost; resolver 1.1.1.1; location / {" > "$f"
    if [ "$m" == "2" ]; then echo "proxy_pass $u; proxy_set_header Host $h; proxy_set_header X-Real-IP \$remote_addr; proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; proxy_ssl_server_name on;" >> "$f"
    else echo "proxy_pass $u; proxy_set_header Host $h; proxy_set_header Referer $u; proxy_ssl_server_name on; proxy_set_header Accept-Encoding \"\"; sub_filter \"</head>\" \"<meta name='referrer' content='no-referrer'></head>\"; sub_filter \"$h\" \"$d\"; sub_filter \"https://$h\" \"https://$d\"; sub_filter \"http://$h\" \"https://$d\";" >> "$f"; echo -e "${YELLOW}资源聚合(回车结束)${NC}"; c=1; while true; do read -p "URL: " re; [ -z "$re" ] && break; re=$(normalize_url "$re"); rh=$(echo $re|awk -F/ '{print $3}'); k="_res_$c"; cat >> "$f" <<EOF
sub_filter "$rh" "$d/$k"; sub_filter "https://$rh" "https://$d/$k"; sub_filter "http://$rh" "https://$d/$k";
EOF
cat >> "$f.loc" <<EOF
location /$k/ { rewrite ^/$k/(.*) /\$1 break; proxy_pass $re; proxy_set_header Host $rh; proxy_set_header Referer $re; proxy_ssl_server_name on; proxy_set_header Accept-Encoding ""; }
EOF
((c++)); done; echo "sub_filter_once off; sub_filter_types *;" >> "$f"; fi; echo "}" >> "$f"; [ -f "$f.loc" ] && cat "$f.loc" >> "$f" && rm "$f.loc"; echo "}" >> "$f"
}

function create_redirect() { 
    read -p "已解析到本机域名: " s
    read -p "跳转域名 URL: " t; t=$(normalize_url "$t")
    read -p "Email: " e
    sdir="$SITES_DIR/$s"; mkdir -p "$sdir"
    
       # 使用 cat EOF 写入，避免单行 echo 的引号混乱和自动纠错风险
    cat > "$sdir/redirect.conf" <<EOF
server {
    listen 80;
    server_name localhost;
    location / {
        return 301 $t\$request_uri;
    }
}
EOF
    
    cat > "$sdir/docker-compose.yml" <<EOF
services:
  redirector:
    image: nginx:alpine
    container_name: ${s//./_}_redirect
    restart: always
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    volumes:
      - ./redirect.conf:/etc/nginx/conf.d/default.conf
    environment:
      VIRTUAL_HOST: "$s"
      LETSENCRYPT_HOST: "$s"
      LETSENCRYPT_EMAIL: "$e"
    networks:
      - proxy-net

networks:
  proxy-net:
    external: true
EOF

    cd "$sdir" && docker compose up -d
    reload_gateway_config
    check_ssl_status "$s"
}

function delete_site() { while true; do clear; echo "=== 🗑️ 删除网站 ==="; ls -1 "$SITES_DIR"; echo "----------------"; read -p "域名(0返回): " d; [ "$d" == "0" ] && return; if [ -d "$SITES_DIR/$d" ]; then read -p "确认? (y/n): " c; [ "$c" == "y" ] && cd "$SITES_DIR/$d" && docker compose down -v >/dev/null 2>&1 && cd .. && rm -rf "$SITES_DIR/$d" && echo "Deleted"; write_log "Deleted site $d"; fi; pause_prompt; done; }

function list_sites() {
    clear
    echo -e "${YELLOW}=== 📂 站点列表与状态 ===${NC}"
    # 表头格式化
    printf "${CYAN}%-3s %-25s %-12s %-20s${NC}\n" "No." "域名 (Domain)" "状态" "备注 (Remark)"
    echo "---------------------------------------------------------------"
    
    local i=1
    # 遍历站点目录
    for dir in "$SITES_DIR"/*; do
        if [ -d "$dir" ]; then
            domain=$(basename "$dir")
            
            # 1. 获取备注
            remark=$(grep "^$domain|" "$REMARK_FILE" | cut -d'|' -f2)
            if [ -z "$remark" ]; then remark="-"; fi

            # 2. 获取容器状态 (简单的检查是否有Up状态的容器)
            cd "$dir"
            if docker compose ps | grep -q "Up"; then
                status="${GREEN}● 运行中${NC}"
            else
                status="${RED}● 已停止${NC}"
            fi

            # 3. 输出表格行
            printf "%-3s %-25s %-12b %-20s\n" "$i" "$domain" "$status" "$remark"
            ((i++))
        fi
    done
    echo "---------------------------------------------------------------"
    echo -e "提示: 使用菜单 [18] 可修改站点备注"
    pause_prompt
}

function manage_remarks() {
    while true; do
        clear
        echo -e "${YELLOW}=== 📝 站点备注管理 ===${NC}"
        # 显示简易列表
        local i=1
        declare -A domain_map
        for dir in "$SITES_DIR"/*; do
            if [ -d "$dir" ]; then
                d=$(basename "$dir")
                r=$(grep "^$d|" "$REMARK_FILE" | cut -d'|' -f2)
                echo -e " $i. $d \t [${CYAN}${r:-无}${NC}]"
                domain_map[$i]=$d
                ((i++))
            fi
        done
        echo " 0. 返回"
        echo "--------------------------"
        read -p "请选择要修改备注的站点编号: " idx
        
        if [ "$idx" == "0" ]; then return; fi
        
        target_domain=${domain_map[$idx]}
        if [ -z "$target_domain" ]; then echo "无效选择"; sleep 1; continue; fi
        
        echo -e "当前站点: ${GREEN}$target_domain${NC}"
        read -p "请输入新备注 (例如: 个人博客 / 图床): " new_remark
        
        # 写入逻辑: 先删除旧的，再追加新的
        if [ ! -z "$new_remark" ]; then
            sed -i "/^$target_domain|/d" "$REMARK_FILE"
            echo "$target_domain|$new_remark" >> "$REMARK_FILE"
            echo -e "${GREEN}✔ 备注已更新${NC}"
        fi
        sleep 1
    done
}

# === [V3.1 完善版] HTTPS 证书高级管理中心 ===
function cert_management() {
    # 依赖工具函数：计算剩余天数
    function get_cert_days() {
        local end_date=$1
        local end_timestamp=$(date -d "$end_date" +%s 2>/dev/null)
        if [ -z "$end_timestamp" ]; then echo "未知"; return; fi
        local now_timestamp=$(date +%s)
        echo $(( (end_timestamp - now_timestamp) / 86400 ))
    }

    while true; do
        clear
        echo -e "${YELLOW}=== 🔐 HTTPS 证书高级管理中心 (Final) ===${NC}"
        echo -e "核心网关: gateway_proxy | 签发容器: gateway_acme"
        echo "---------------------------------------------------------"
        echo -e " 1. ${GREEN}证书状态看板${NC} (显示过期时间/剩余天数)"
        echo " 2. 查看申请日志 (排查申请卡住/失败原因)"
        echo " 3. ${GREEN}强制重签所有证书 (推荐，最稳妥)${NC}"
        echo " 4. 部署自定义证书 (上传 .crt 和 .key)"
        echo " 5. 删除/重置指定证书 (慎用)"
        echo " 6. 备份所有证书到本地"
        echo -e " 7. ${CYAN}强制重签 [指定] 域名 (单域名 Force Renew)${NC}" 
        echo " 0. 返回上一级"
        echo "---------------------------------------------------------"
        read -p "请输入选项 [0-7]: " c
        
        case $c in
            0) return;;
            
            1)
                clear
                echo -e "${YELLOW}>>> 正在扫描证书信息...${NC}"
                printf "${CYAN}%-25s %-30s %-10s${NC}\n" "域名 (Domain)" "过期时间 (Expire)" "剩余天数"
                echo "----------------------------------------------------------------------"
                certs=$(docker exec gateway_acme find /etc/nginx/certs -name "*.crt" 2>/dev/null)
                if [ -z "$certs" ]; then
                    echo "⚠️  暂无证书。"
                else
                    for cert_path in $certs; do
                        domain=$(basename "$cert_path" .crt)
                        if [ "$domain" == "default" ]; then continue; fi
                        end_date=$(docker exec gateway_acme openssl x509 -in "$cert_path" -noout -enddate 2>/dev/null | cut -d= -f2)
                        if [ ! -z "$end_date" ]; then
                            days_left=$(get_cert_days "$end_date")
                            color=$GREEN
                            if [[ "$days_left" != "未知" ]]; then
                                if [ "$days_left" -lt 7 ]; then color=$RED
                                elif [ "$days_left" -lt 30 ]; then color=$YELLOW
                                fi
                            fi
                            printf "%-25s %-30s ${color}%-10s${NC}\n" "$domain" "$end_date" "${days_left}天"
                        fi
                    done
                fi
                echo "----------------------------------------------------------------------"
                pause_prompt
                ;;
                
            2)
                echo -e "${YELLOW}>>> 正在获取最近 50 条 ACME 日志...${NC}"
                docker logs --tail 50 gateway_acme
                pause_prompt
                ;;
                
            3)
                echo -e "${YELLOW}>>> 正在执行全量强制续签 (Force Renew All)...${NC}"
                # 使用官方内置脚本
                docker exec gateway_acme /app/force_renew
                echo -e "${GREEN}✔ 命令已发送。${NC}"
                echo -e "ACME 容器正在后台逐个处理，请稍后通过 [1] 检查状态。"
                pause_prompt
                ;;
                
            4)
                echo -e "${YELLOW}>>> 部署自定义证书${NC}"
                ls -1 "$SITES_DIR"
                read -p "请输入绑定的域名: " d
                if [ ! -d "$SITES_DIR/$d" ]; then echo "目录不存在"; pause_prompt; continue; fi
                read -p "请输入 .crt 文件路径: " crt_file
                read -p "请输入 .key 文件路径: " key_file
                if [ -f "$crt_file" ] && [ -f "$key_file" ]; then
                    docker cp "$crt_file" gateway_acme:"/etc/nginx/certs/$d.crt"
                    docker cp "$key_file" gateway_acme:"/etc/nginx/certs/$d.key"
                    docker exec gateway_acme chmod 644 "/etc/nginx/certs/$d.crt" "/etc/nginx/certs/$d.key"
                    docker exec gateway_proxy nginx -s reload
                    echo -e "${GREEN}✔ 部署成功${NC}"
                else
                    echo "文件不存在"
                fi
                pause_prompt
                ;;
                
            5)
                read -p "请输入要删除的域名: " d
                read -p "确认删除? (y/n): " confirm
                if [ "$confirm" == "y" ]; then
                    docker exec gateway_acme rm -f "/etc/nginx/certs/$d.crt" "/etc/nginx/certs/$d.key"
                    docker restart gateway_acme
                    echo -e "${GREEN}✔ 已删除。${NC}"
                fi
                pause_prompt
                ;;
            
            6)
                local backup_dir="$BASE_DIR/certs_backup_$(date +%Y%m%d)"
                mkdir -p "$backup_dir"
                docker cp gateway_acme:/etc/nginx/certs/. "$backup_dir"
                echo -e "${GREEN}✔ 备份至 $backup_dir${NC}"
                pause_prompt
                ;;

            7)
                echo -e "${YELLOW}>>> 强制重签 [指定] 域名 (Single Domain Force)${NC}"
                echo -e "原理: 直接调用 ACME 协议进行强制更新，不依赖文件删除。"
                read -p "请输入域名: " d
                if [ -z "$d" ]; then continue; fi
                
                echo -e "${CYAN}正在请求 Let's Encrypt 强制续签 $d ...${NC}"
                
                # 【核心修复】使用 sh -c 包装命令，让容器自己去找 acme.sh 在哪
                # 这样就解决了 "/etc/acme.sh/acme.sh no such file" 的问题
                if docker exec gateway_acme sh -c "acme.sh --renew -d $d --force"; then
                    echo -e "${GREEN}✔ 续签成功！${NC}"
                    echo "请稍后通过 [1] 查看证书过期时间是否更新。"
                else
                    echo -e "${RED}❌ 执行失败${NC}"
                    echo -e "可能原因：\n1. 域名解析未生效\n2. Cloudflare 拦截 (请尝试开启 DNS Only)\n3. 1小时内申请次数过多 (Rate Limit)"
                fi
                pause_prompt
                ;;
        esac
    done
}

function db_manager() { while true; do clear; echo "1.导出 2.导入 0.返回"; read -p "选: " c; case $c in 0) return;; 1) ls -1 "$SITES_DIR"; read -p "域名: " d; s="$SITES_DIR/$d"; pwd=$(grep MYSQL_ROOT_PASSWORD "$s/docker-compose.yml"|awk -F': ' '{print $2}'); docker compose -f "$s/docker-compose.yml" exec -T db mysqldump -u root -p"$pwd" --all-databases > "$s/${d}.sql"; echo "OK: $s/${d}.sql";; 2) ls -1 "$SITES_DIR"; read -p "域名: " d; read -p "SQL File: " f; s="$SITES_DIR/$d"; pwd=$(grep MYSQL_ROOT_PASSWORD "$s/docker-compose.yml"|awk -F': ' '{print $2}'); cat "$f" | docker compose -f "$s/docker-compose.yml" exec -T db sh -c 'mysql -u root -p"$MYSQL_ROOT_PASSWORD"'; echo "OK";; esac; pause_prompt; done; }

function change_domain() { 
    while true; do
        clear
        echo -e "${YELLOW}=== 🔄 网站域名更换向导 ===${NC}"
        ls -1 "$SITES_DIR"
        echo "--------------------------"
        read -p "请输入旧域名 (0返回): " o
        [ "$o" == "0" ] && return
        
        if [ ! -d "$SITES_DIR/$o" ]; then 
            echo -e "${RED}目录不存在${NC}"; sleep 1; continue
        fi
        
        read -p "请输入新域名: " n
        if [ -z "$n" ]; then continue; fi
        
        echo -e "${YELLOW}>>> 正在执行变更: $o -> $n${NC}"
        
        # 1. 停止旧服务
        cd "$SITES_DIR/$o" && docker compose down
        
        # 2. 修改目录名
        cd "$SITES_DIR"
        mv "$o" "$n"
        cd "$n"
        
        # 3. 替换配置文件 (docker-compose.yml 和 nginx.conf)
        sed -i "s/$o/$n/g" docker-compose.yml
        if [ -f "nginx.conf" ]; then sed -i "s/$o/$n/g" nginx.conf; fi
        
        # 4. 启动新服务 (触发 ACME 申请证书)
        echo -e "${CYAN}>>> 正在启动新容器...${NC}"
        docker compose up -d
        
        # 5. 替换数据库内容 (WordPress Search-Replace)
        echo -e "${CYAN}>>> 正在替换数据库中的域名记录...${NC}"
        # 等待数据库初始化
        sleep 5
        wp_c=$(docker compose ps -q wordpress 2>/dev/null)
        if [ ! -z "$wp_c" ]; then
            docker run --rm --volumes-from $wp_c --network container:$wp_c wordpress:cli wp search-replace "$o" "$n" --all-tables --skip-columns=guid
        else
            echo -e "${YELLOW}未检测到 WordPress 容器，跳过数据库替换。${NC}"
        fi
        
        # 6. 刷新网关
        reload_gateway_config
        
        # 7. [新增] 自动申请并检查证书
        echo -e "${YELLOW}>>> 正在自动申请 SSL 证书，请稍候...${NC}"
        check_ssl_status "$n"
        
        write_log "Changed domain $o to $n"
        echo -e "${GREEN}✔ 域名更换完成！${NC}"
        pause_prompt
        return
    done
}

function manage_hotlink() { while true; do clear; echo "1.开 2.关 0.返"; read -p "选: " h; case $h in 0) return;; 1) ls -1 "$SITES_DIR"; read -p "域名: " d; s="$SITES_DIR/$d"; read -p "白名单: " w; cat > "$s/nginx.conf" <<EOF
server { listen 80; server_name localhost; root /var/www/html; index index.php; include /etc/nginx/waf.conf; client_max_body_size 512M; location ~* \.(gif|jpg|png|webp)$ { valid_referers none blocked server_names $d *.$d $w; if (\$invalid_referer) { return 403; } try_files \$uri \$uri/ /index.php?\$args; } location / { try_files \$uri \$uri/ /index.php?\$args; } location ~ \.php$ { try_files \$uri =404; fastcgi_split_path_info ^(.+\.php)(/.+)$; fastcgi_pass wordpress:9000; fastcgi_index index.php; include fastcgi_params; fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name; fastcgi_param PATH_INFO \$fastcgi_path_info; fastcgi_read_timeout 600; } }
EOF
cd "$s" && docker compose restart nginx; echo "OK";; 2) ls -1 "$SITES_DIR"; read -p "域名: " d; s="$SITES_DIR/$d"; cat > "$s/nginx.conf" <<EOF
server { listen 80; server_name localhost; root /var/www/html; index index.php; include /etc/nginx/waf.conf; client_max_body_size 512M; location / { try_files \$uri \$uri/ /index.php?\$args; } location ~ \.php$ { try_files \$uri =404; fastcgi_split_path_info ^(.+\.php)(/.+)$; fastcgi_pass wordpress:9000; fastcgi_index index.php; include fastcgi_params; fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name; fastcgi_param PATH_INFO \$fastcgi_path_info; fastcgi_read_timeout 600; } }
EOF
cd "$s" && docker compose restart nginx; echo "OK";; esac; pause_prompt; done; }

# === [V3.0 通用版] 核心备份逻辑 ===
function perform_backup_logic() {
    local site_domain=$1
    local s_path="$SITES_DIR/$site_domain"
    
    if [ ! -d "$s_path" ]; then echo "跳过: $site_domain"; return; fi
    
    check_rclone
    local has_remote=0
    if rclone listremotes 2>/dev/null | grep -q "remote:"; then has_remote=1; fi

    local b_name="${site_domain}_$(date +%Y%m%d_%H%M%S)"
    local temp_dir="/tmp/$b_name"
    local archive_name="$b_name.tar.gz"
    
    echo -e "${CYAN}>>> [Backup] 正在备份: $site_domain${NC}"
    mkdir -p "$temp_dir"

    # 1. 备份配置文件 (yml, conf, env 等)
    # 使用 find 排除 data 目录，防止重复备份 (如果 data 很大)
    find "$s_path" -maxdepth 1 -type f -exec cp {} "$temp_dir/" \;

    # 2. [通用] 备份本地挂载的 data 目录 (应用商店应用通常用这个)
    if [ -d "$s_path/data" ]; then
        echo " - 发现本地数据目录 (data)，正在打包..."
        # 将 data 目录打包成一个独立文件，方便还原
        tar czf "$temp_dir/local_data.tar.gz" -C "$s_path" data
    fi

    # 3. [WP专用] 备份 Docker 卷 (wp-content)
    app_container=$(docker compose -f "$s_path/docker-compose.yml" ps -q wordpress 2>/dev/null)
    if [ ! -z "$app_container" ]; then
        echo " - [WP] 提取 Docker 数据卷..."
        docker run --rm --volumes-from "$app_container" -v "$temp_dir":/backup alpine tar czf /backup/wp_content.tar.gz -C /var/www/html wp-content 2>/dev/null
    fi

    # 4. [数据库] 尝试导出 MySQL (如果存在)
    if [ -f "$s_path/docker-compose.yml" ]; then
        pwd=$(grep "MYSQL_ROOT_PASSWORD" "$s_path/docker-compose.yml" | head -n 1 | awk -F': ' '{print $2}' | tr -d '"' | tr -d "'" | tr -d '\r')
        db_container=$(docker compose -f "$s_path/docker-compose.yml" ps -q db 2>/dev/null)
        
        # 只有当找到了密码 且 找到了db容器，才尝试导出
        if [ ! -z "$db_container" ] && [ ! -z "$pwd" ]; then
            echo " - [DB] 尝试导出 MySQL..."
            if docker exec "$db_container" mysqldump -u root -p"$pwd" --all-databases > "$temp_dir/db.sql" 2>/dev/null; then
                echo -e "   ${GREEN}✔ SQL 导出成功${NC}"
            else
                # 失败不报错，因为可能是 Postgres 或其他库，不强制
                echo -e "   ℹ️  未检测到兼容的 MySQL，跳过 SQL 导出 (可能是 SQLite/PG)"
            fi
        fi
    fi

    # 5. 打包总文件
    echo " - 生成最终压缩包..."
    cd /tmp && tar czf "$archive_name" "$b_name"
    
    local local_backup_dir="$BASE_DIR/backups"
    mkdir -p "$local_backup_dir"
    mv "/tmp/$archive_name" "$local_backup_dir/"
    echo -e "${GREEN}✔ 备份完成: $archive_name${NC}"

    if [ "$has_remote" -eq 1 ]; then
        echo -e "${YELLOW} - 上传至云端...${NC}"
        rclone copy "$local_backup_dir/$archive_name" "remote:wp_backups/"
    fi
    rm -rf "$temp_dir"
}

# === [V3.3 终极修复版] 核心还原逻辑 (特殊字符兼容+强制TCP) ===
function perform_restore_logic() {
    local backup_file=$1
    local target_domain=$2
    local target_dir="$SITES_DIR/$target_domain"

    if [ ! -f "$backup_file" ]; then echo "错误: 文件不存在"; return; fi

    echo -e "${YELLOW}>>> [Restore] 正在还原: $target_domain${NC}"
    echo -e "${RED}⚠️  警告: 将强制覆盖目标目录并重建容器！${NC}"
    read -p "确认执行? (yes/no): " confirm
    if [ "$confirm" != "yes" ]; then return; fi
    
    # 1. 解压准备
    local tar_dir=$(tar tf "$backup_file" | head -1 | cut -f1 -d"/")
    tar xzf "$backup_file" -C /tmp
    local restore_path="/tmp/$tar_dir"

    # 2. 彻底清理旧环境
    if [ -d "$target_dir" ]; then
        echo " - 正在清理旧环境..."
        cd "$target_dir" && docker compose down -v --remove-orphans >/dev/null 2>&1
        cd "$BASE_DIR" && rm -rf "$target_dir"
    fi
    mkdir -p "$target_dir"

    # 3. 恢复配置文件
    echo " - 恢复配置文件..."
    find "$restore_path" -maxdepth 1 -type f ! -name "*.tar.gz" ! -name "*.sql" -exec cp {} "$target_dir/" \;

    # 4. [通用] 恢复本地 data 目录
    local raw_db_restored=0
    if [ -f "$restore_path/local_data.tar.gz" ]; then
        echo " - [通用] 恢复本地数据目录 (data)..."
        tar xzf "$restore_path/local_data.tar.gz" -C "$target_dir"
        
        # 检查是否还原了原始数据库文件
        if [ -d "$target_dir/data/mysql" ] || [ -d "$target_dir/mysql" ] || [ -d "$target_dir/db_data" ]; then
            raw_db_restored=1
            echo -e "${GREEN}   ✔ 检测到原始数据库文件，将跳过 SQL 导入。${NC}"
        fi
    fi

    # 5. 启动容器
    echo " - 启动容器..."
    cd "$target_dir" && docker compose up -d

    # 6. [WP专用] 恢复 Docker 卷
    if [ -f "$restore_path/wp_content.tar.gz" ]; then
        echo " - [WP] 恢复 wp-content 卷..."
        sleep 2
        app_c=$(docker compose ps -q wordpress 2>/dev/null)
        if [ ! -z "$app_c" ]; then
            docker run --rm --volumes-from "$app_c" -v "$restore_path":/backup alpine sh -c "tar xzf /backup/wp_content.tar.gz -C /var/www/html"
        fi
    fi

    # 7. [DB] 导入 MySQL (修复 Access Denied)
    if [ -f "$restore_path/db.sql" ]; then
        if [ "$raw_db_restored" -eq 1 ]; then
            echo -e " - [DB] ${CYAN}跳过 SQL 导入 (原始数据已恢复)。${NC}"
        else
            echo " - [DB] 检测到纯 SQL 备份，准备导入..."
            
            echo -n "   等待数据库启动"
            db_ready=0
            # 循环检查数据库状态
            for i in {1..60}; do
                # 使用 MYSQL_PWD 避免特殊字符干扰，强制使用 127.0.0.1 走 TCP 协议
                if docker compose exec -T db sh -c 'export MYSQL_PWD="$MYSQL_ROOT_PASSWORD"; mysqladmin ping -h 127.0.0.1 -u root --silent' >/dev/null 2>&1; then
                    db_ready=1; break
                fi
                echo -n "."
                sleep 2
            done
            echo ""
            
            if [ "$db_ready" -eq 1 ]; then
                echo "   正在导入数据 (请勿中断)..."
                # 再次等待 3 秒，防止 MySQL 刚 responding ping 但还没准备好接收 write
                sleep 3
                
                # 【关键修复】使用 MYSQL_PWD 传递密码，使用 -h 127.0.0.1 强制 TCP
                if docker compose exec -T db sh -c 'export MYSQL_PWD="$MYSQL_ROOT_PASSWORD"; mysql -h 127.0.0.1 -u root < /dev/stdin' < "$restore_path/db.sql"; then
                     echo -e "   ${GREEN}✔ 数据库导入成功${NC}"
                else
                     echo -e "   ${RED}❌ SQL 导入失败!${NC}"
                     echo -e "   请尝试手动导入: docker compose exec db mysql -u root -p (回车输密码)"
                fi
            else
                echo -e "${RED}❌ 数据库启动超时。${NC}"
            fi
        fi
    fi
    
    # 8. 刷新网关
    if type reload_gateway_config >/dev/null 2>&1; then reload_gateway_config; else docker exec gateway_proxy nginx -s reload >/dev/null 2>&1; fi

    rm -rf "$restore_path"
    echo -e "${GREEN}✔ 还原操作结束${NC}"
    write_log "Restored $target_domain"
}

function backup_restore_ops() { 
    check_rclone
    local has_remote=0
    if rclone listremotes 2>/dev/null | grep -q "remote:"; then has_remote=1; fi
    
    # 确保本地备份目录存在
    local local_backup_dir="$BASE_DIR/backups"
    mkdir -p "$local_backup_dir"

    while true; do 
        clear; echo -e "${YELLOW}=== 📦 超级备份系统 (本地+云端) ===${NC}"
        if [ "$has_remote" -eq 1 ]; then echo -e "☁️ 云端状态: ${GREEN}已连接 (remote:)${NC}"; else echo -e "☁️ 云端状态: ${RED}未配置 (仅本地)${NC}"; fi
        echo "--------------------------"
        echo " 1. 立即备份 (支持 导出SQL + 提取卷)"
        echo " 2. 还原备份 (支持 本地/云端)"
        echo " 3. 配置云端存储 (Rclone)"
        echo " 4. 添加每日自动备份任务 (Cron)"
        echo " 0. 返回上一级"
        echo "--------------------------"
        read -p "请输入选项 [0-4]: " b
        
        case $b in 
            0) return;; 
            
            3) configure_rclone; has_remote=1;;

            4) 
                # 添加定时任务: 每天凌晨 02:00
                (crontab -l 2>/dev/null | grep -v "wp-backup-daily"; echo "0 2 * * * /usr/bin/mmp backup_all >> $LOG_DIR/backup.log 2>&1 #wp-backup-daily") | crontab -
                echo -e "${GREEN}✔ 已添加定时任务 (02:00)${NC}"
                pause_prompt
                ;;

            1) 
                ls -1 "$SITES_DIR"; echo "----------------"
                read -p "输入域名 (输入 all 备份全部): " d
                if [ "$d" == "all" ]; then
                    for dir in "$SITES_DIR"/*; do [ -d "$dir" ] && perform_backup_logic "$(basename "$dir")"; done
                else
                    perform_backup_logic "$d"
                fi
                pause_prompt
                ;;
            
            2) 
                echo -e "${YELLOW}=== 还原向导 ===${NC}"
                echo "1. 从本地文件还原"
                echo "2. 从云端下载并还原"
                read -p "选择源 [1/2]: " src
                
                local backup_file=""
                
                # === 分支 2: 云端下载 ===
                if [ "$src" == "2" ]; then
                    if [ "$has_remote" -eq 0 ]; then echo "未配置云端"; pause_prompt; continue; fi
                    rclone lsl "remote:wp_backups" | tail -n 10
                    read -p "输入要下载的文件名: " fname
                    echo "下载中..."
                    rclone copy "remote:wp_backups/$fname" "/tmp/"
                    backup_file="/tmp/$fname"
                
                # === 分支 1: 本地选择 (核心修复部分) ===
                else
                    echo -e "${CYAN}=== 本地备份列表 ===${NC}"
                    # 1. 获取所有 tar.gz 文件到数组
                    files=("$local_backup_dir"/*.tar.gz)
                    
                    # 2. 检查是否有文件
                    if [ ! -e "${files[0]}" ]; then
                        echo -e "${RED}❌ 目录 $local_backup_dir 下没有找到备份文件。${NC}"
                        pause_prompt
                        continue
                    fi

                    # 3. 循环显示菜单
                    local i=1
                    for f in "${files[@]}"; do
                        echo -e " $i. $(basename "$f")  \t [$(du -h "$f" | awk '{print $1}')]"
                        ((i++))
                    done
                    echo "--------------------------------"
                    
                    # 4. 用户输入编号
                    read -p "请输入文件编号: " choice
                    
                    # 5. 校验并获取完整路径
                    if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -lt "$i" ]; then
                        # 数组下标从0开始，所以要减1
                        backup_file="${files[$((choice-1))]}"
                        echo -e "已选择: ${GREEN}$backup_file${NC}"
                    else
                        echo -e "${RED}无效的编号${NC}"
                        pause_prompt
                        continue
                    fi
                fi

                # === 执行还原 ===
                if [ -f "$backup_file" ]; then
                    ls -1 "$SITES_DIR"
                    echo "--------------------------------"
                    read -p "请输入要还原到的【目标域名】: " target_domain
                    if [ -z "$target_domain" ]; then echo "域名不能为空"; pause_prompt; continue; fi
                    
                    perform_restore_logic "$backup_file" "$target_domain"
                else
                    echo -e "${RED}错误：文件未找到 ($backup_file)${NC}"
                fi
                
                # 如果是云端下载的临时文件，还原后清理
                [ "$src" == "2" ] && rm -f "$backup_file"
                pause_prompt
                ;;
        esac
    done 
}

function rebuild_gateway_action() {
    clear
    echo -e "${RED}⚠️  危险操作：重建核心网关${NC}"
    echo "----------------------------------------"
    echo -e "此操作将会："
    echo -e "1. 停止并删除当前的 Nginx 网关容器"
    echo -e "2. 重新生成 docker-compose.yml 配置文件"
    echo -e "3. 重新拉起网关服务"
    echo -e "${YELLOW}适用场景：开启日志分析功能、修复网关报错、更新网关配置。${NC}"
    echo "----------------------------------------"
    read -p "确认执行吗? (输入 yes 确认): " confirm
    
    if [ "$confirm" == "yes" ]; then
        echo -e "${GREEN}>>> 开始重建网关...${NC}"
        # 调用 init_gateway 函数，传入 "force" 参数强制重建
        init_gateway "force"
        pause_prompt
    else
        echo "操作已取消"
        sleep 1
    fi
}

function uninstall_cluster() {
    clear
    echo -e "${RED}⚠️  高危操作：卸载脚本及所有数据${NC}"
    echo -e "此操作将执行以下清理："
    echo -e " 1. 停止并删除所有 Docker 容器 (站点 + 网关)"
    echo -e " 2. 删除所有数据文件 ($BASE_DIR)"
    echo -e " 3. 删除快捷指令 (/usr/bin/mmp)"
    echo "------------------------------------------------"
    echo -e "${YELLOW}请输入 DELETE 确认卸载，输入其他内容取消。${NC}"
    read -p "> " c
    
    if [ "$c" == "DELETE" ]; then
        echo -e "${YELLOW}>>> 正在停止容器并清理数据...${NC}"
        
        # 1. 尝试停止所有站点
        if [ -d "$SITES_DIR" ]; then
            ls "$SITES_DIR" | while read d; do 
                s_path="$SITES_DIR/$d"
                if [ -d "$s_path" ]; then
                    cd "$s_path" && docker compose down -v >/dev/null 2>&1
                fi
            done
        fi

        # 2. 停止网关
        if [ -d "$GATEWAY_DIR" ]; then
            cd "$GATEWAY_DIR" && docker compose down -v >/dev/null 2>&1
        fi

        # 3. 清理网络和文件
        docker network rm proxy-net >/dev/null 2>&1
        rm -rf "$BASE_DIR"
        rm -f /usr/bin/mmp
        
        echo -e "${GREEN}✔ 已彻底卸载。江湖路远，有缘再见！${NC}"
        
        # 核心修复：直接结束脚本进程
        exit 0
    else
        echo "❌ 操作已取消"
        sleep 1
    fi
}

function check_and_fix_network() {
    echo -e "${YELLOW}>>> [自愈] 正在优化网络连接...${NC}"
    
    # 1. 定义多个测试目标 (避免单点故障误判)
    # 包含国内域名以确保在国内服务器上也能正确检测 IPv4
    local test_targets=("www.baidu.com" "www.google.com" "github.com" "1.1.1.1")
    local ipv4_ok=0
    
    # 2. 检查当前配置状态
    if grep -q "^precedence ::ffff:0:0/96" /etc/gai.conf 2>/dev/null; then
        echo -e " - 网络偏好: ${GREEN}IPv4 优先 (已配置)${NC}"
        return
    fi

    # 3. 轮询测试 IPv4 连通性
    echo -e " - 正在检测 IPv4 通道 (多节点)..."
    for target in "${test_targets[@]}"; do
        # -4: 强制IPv4, -I: 仅Head请求(省流量), -m 3: 超时3秒
        # 兼容 http 和 https
        if curl -4 -I -s -m 3 "https://$target" >/dev/null 2>&1 || curl -4 -I -s -m 3 "http://$target" >/dev/null 2>&1; then
            ipv4_ok=1
            echo -e " - 连接测试 [${CYAN}$target${NC}]: ${GREEN}成功${NC}"
            break
        fi
    done

    if [ "$ipv4_ok" -eq 1 ]; then
        echo -e "${YELLOW}>>> 检测到 IPv4 可用，正在开启 IPv4 优先 (解决拉取镜像卡顿)...${NC}"
        
        # 确保文件存在
        [ ! -f /etc/gai.conf ] && touch /etc/gai.conf
        
        # [核心修复] 使用模糊匹配删除旧配置 (防止因空格不同导致删除失败)
        sed -i '/^precedence ::ffff:0:0\/96/d' /etc/gai.conf
        
        # 写入标准配置
        echo "precedence ::ffff:0:0/96  100" >> /etc/gai.conf
        
        echo -e "${GREEN}✔ 已设置 IPv4 优先 (Precedence Set)${NC}"
    else
        echo -e "${RED}❌ IPv4 连接检测失败 (所有目标均超时)${NC}"
        echo -e "${YELLOW}⚠️  警告: 服务器可能仅有 IPv6 网络，或 DNS 配置错误。跳过优化。${NC}"
    fi
}

# === 手动管理协议 (修复版) ===
function net_protocol_manager() {
    while true; do
        clear
        echo -e "${YELLOW}=== 🌐 IPv4/IPv6 协议偏好设置 ===${NC}"
        
        # 检查状态 (使用更宽容的正则)
        if grep -q "^precedence ::ffff:0:0/96" /etc/gai.conf 2>/dev/null; then
            prio_status="${GREEN}IPv4 优先${NC}"
        else
            prio_status="${YELLOW}默认 (IPv6 优先)${NC}"
        fi
        
        echo -e "当前状态: $prio_status"
        echo "------------------------------------------------"
        echo " 1. 优先使用 IPv4 (解决拉取慢/连接超时)"
        echo " 2. 恢复默认设置 (系统自动选择)"
        echo " 3. 彻底禁用 IPv6 (仅在极端情况下使用)"
        echo " 0. 返回"
        echo "------------------------------------------------"
        read -p "请选择: " o
        case $o in
            0) return;;
            1) 
               # 修复: 模糊匹配删除，避免重复
               [ ! -f /etc/gai.conf ] && touch /etc/gai.conf
               sed -i '/^precedence ::ffff:0:0\/96/d' /etc/gai.conf
               echo "precedence ::ffff:0:0/96  100" >> /etc/gai.conf
               echo -e "${GREEN}✔ 已设置 IPv4 优先${NC}"; pause_prompt;;
            2) 
               sed -i '/^precedence ::ffff:0:0\/96/d' /etc/gai.conf
               echo -e "${GREEN}✔ 已恢复默认${NC}"; pause_prompt;;
            3) 
               echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
               sysctl -p >/dev/null 2>&1
               echo -e "${GREEN}✔ IPv6 已禁用${NC}"; pause_prompt;;
        esac
    done
}

function system_optimizer() {
    while true; do
        clear
        echo -e "${YELLOW}=== 🚀 系统性能调优箱 ===${NC}"
        
        # 检查 Swap 状态
        swap_total=$(free -m | grep Swap | awk '{print $2}')
        if [ "$swap_total" -eq 0 ]; then 
            swap_status="${RED}未开启${NC}"
        else 
            swap_status="${GREEN}已开启 (${swap_total}MB)${NC}"
        fi
        
        # 检查 BBR 状态
        if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then 
            bbr_status="${GREEN}已开启${NC}"
        else 
            bbr_status="${YELLOW}未开启${NC}"
        fi

        echo -e "当前 Swap: $swap_status | BBR: $bbr_status"
        echo "------------------------------------------------"
        echo " 1. 开启/设置 虚拟内存 (Swap) - 防止内存不足崩溃"
        echo " 2. 开启 TCP BBR 加速 - 优化网络连接速度"
        echo " 3. 系统网络测速 (Speedtest)"
        echo " 4. 自启检测 (检查 Docker/网关 重启策略)"
        echo -e " 5. ${CYAN}IPv4/IPv6 协议偏好设置${NC} "
        echo " 0. 返回"
        echo "------------------------------------------------"
        read -p "请选择 [0-5]: " o
        
        case $o in
            0) return;;
            
            1)
                echo -e "${YELLOW}>>> 设置 Swap 虚拟内存${NC}"
                echo "1. 1024MB (推荐 1G 内存机器)"
                echo "2. 2048MB (推荐 2G+ 内存机器)"
                echo "3. 关闭 Swap"
                read -p "请选择大小: " s
                if [ "$s" == "3" ]; then
                    swapoff -a
                    rm -f /swapfile
                    sed -i '/\/swapfile/d' /etc/fstab
                    echo -e "${GREEN}✔ Swap 已关闭${NC}"
                else
                    [ "$s" == "1" ] && sz="1G" || sz="2G"
                    echo "正在创建 /swapfile (大小: $sz)..."
                    fallocate -l $sz /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=$([ "$sz" == "1G" ] && echo 1024 || echo 2048)
                    chmod 600 /swapfile
                    mkswap /swapfile
                    swapon /swapfile
                    if ! grep -q "/swapfile" /etc/fstab; then echo "/swapfile none swap sw 0 0" >> /etc/fstab; fi
                    echo -e "${GREEN}✔ Swap 设置成功!${NC}"
                fi
                pause_prompt;;
                
            2)
                echo -e "${YELLOW}>>> 开启 BBR 加速${NC}"
                if grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
                    echo "配置已存在，尝试重载..."
                else
                    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
                    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
                fi
                sysctl -p
                if sysctl net.ipv4.tcp_congestion_control | grep -q bbr; then 
                    echo -e "${GREEN}✔ BBR 启动成功${NC}"
                else 
                    echo -e "${RED}❌ 启动失败，可能内核版本太低${NC}"
                fi
                pause_prompt;;
                
            3)
                check_dependencies
                echo -e "${YELLOW}>>> 正在安装 Speedtest CLI...${NC}"
                docker run --rm --net=host gists/speedtest-cli
                pause_prompt;;
            
            4) 
                check_boot_status;;
            
            5)
                # 调用新写的协议管理函数
                net_protocol_manager;;
        esac
    done
}

function check_boot_status() {
    clear
    echo -e "${YELLOW}=== 🔌 开机自启状态深度检测 ===${NC}"
    echo -e "检测原理：检查各服务的 Systemd 配置及 Docker 重启策略。"
    echo "------------------------------------------------"

    # 1. 检测 Docker 主程序
    echo -n "1. Docker 守护进程: "
    if systemctl is-enabled docker >/dev/null 2>&1; then
        echo -e "${GREEN}✔ 已设置自启${NC}"
    else
        echo -e "${RED}❌ 未设置 (重启后网站将无法启动)${NC}"
        echo -e "   └─ 修复: systemctl enable docker"
    fi

    # 2. 检测 核心网关 (Nginx Proxy)
    echo -n "2. 核心网关容器:    "
    if [ -f "$GATEWAY_DIR/docker-compose.yml" ]; then
        if grep -q "restart: always" "$GATEWAY_DIR/docker-compose.yml"; then
            echo -e "${GREEN}✔ 策略正确 (restart: always)${NC}"
        else
            echo -e "${RED}⚠️  策略缺失${NC} (建议执行 [99] 重建网关)"
        fi
    else
        echo -e "${YELLOW}❓ 未安装网关${NC}"
    fi

    # 3. 检测 Telegram 监控服务
    echo -n "3. TG 资源监控服务: "
    if [ -f "/etc/systemd/system/mmp-monitor.service" ]; then
        if systemctl is-enabled mmp-monitor >/dev/null 2>&1; then
            echo -e "${GREEN}✔ 已设置自启 (Systemd)${NC}"
        else
            echo -e "${RED}❌ 已安装但未自启${NC}"
            echo -e "   └─ 修复: systemctl enable mmp-monitor"
        fi
    else
        echo -e "${YELLOW}⚪ 未安装/未配置${NC}"
    fi

    # 4. 检测 Swap 挂载
    echo -n "4. Swap 虚拟内存:   "
    if grep -q "swap" /etc/fstab; then
        echo -e "${GREEN}✔ 已配置 fstab (重启自动挂载)${NC}"
    elif free | grep -q Swap; then
        echo -e "${YELLOW}⚠️  当前已开启，但未写入 fstab (重启后会丢失)${NC}"
    else
        echo -e "${YELLOW}⚪ 未启用${NC}"
    fi

    echo "------------------------------------------------"
    echo -e "${CYAN}结论说明：${NC}"
    echo -e "只要前两项 (Docker & 网关) 为 ${GREEN}✔${NC}，网站重启后即可自动恢复。"
    pause_prompt
}

function db_admin_tool() {
    clear
    echo -e "${YELLOW}=== 🛢️ 数据库应急管理 (Adminer) ===${NC}"
    echo -e "功能: 启动一个临时的 Web 管理面板来管理所有数据库。"
    echo -e "注意: 使用完毕后请务必【销毁】，以保安全。"
    echo "------------------------------------------------"
    
    # 检查是否已运行
    if docker ps | grep -q "temp_adminer"; then
        status="${GREEN}运行中${NC}"
        port=$(docker port temp_adminer 8080 | awk -F: '{print $2}')
        echo -e "状态: $status"
        echo -e "地址: ${CYAN}http://$(curl -s4 ifconfig.me):$port${NC}"
    else
        echo -e "状态: ${RED}未启动${NC}"
    fi
    echo "------------------------------------------------"
    echo " 1. 启动 Adminer (随机端口)"
    echo " 2. 销毁 Adminer (安全退出)"
    echo " 0. 返回"
    echo "------------------------------------------------"
    read -p "请选择: " o
    
    case $o in
        0) return;;
        1)
            echo "正在启动..."
            # 随机生成一个 10000-60000 的端口
            rand_port=$(shuf -i 10000-60000 -n 1)
            # 关键：连接到 proxy-net 和 default 网络，这样它能访问所有的数据库容器
            docker run -d --name temp_adminer \
                -p $rand_port:8080 \
                --network proxy-net \
                --restart no \
                adminer >/dev/null 2>&1
            
            # 再连接到 default 网络 (如果你的数据库在 default)
            docker network connect default temp_adminer >/dev/null 2>&1
            
            echo -e "${GREEN}✔ 启动成功!${NC}"
            echo -e "访问地址: http://$(curl -s4 ifconfig.me):$rand_port"
            echo -e "系统类型选 MySQL，服务器地址填写容器名 (如 ${CYAN}blog_db${NC} 或 ${CYAN}halo_db${NC})"
            pause_prompt;;
            
        2)
            docker rm -f temp_adminer >/dev/null 2>&1
            echo -e "${GREEN}✔ 已销毁，安全无忧。${NC}"
            pause_prompt;;
    esac
}

# ================= 4. 菜单显示函数 =================
function show_menu() {
    clear
    echo -e "${GREEN}=== Docker 智能部署系统 ($VERSION) ===${NC}"
    echo -e "${RED}=== 仅供个人使用，请勿用于生产环境 ===${NC}" 
	echo "----------------------------------------------------------------"
    
    # --- 1. 部署中心 ---
    echo -e "${YELLOW}[🚀 部署中心]${NC}"
    echo -e " 1. 新建 WordPress             2.新建 反向代理"
    echo -e " 3. 新建 301 重定向            4. ${GREEN}应用商店 (App Store)${NC}"
    
    echo "" 
    
    # --- 2. 运维管理 ---
    echo -e "${YELLOW}[🔧 运维管理]${NC}"
    echo -e " 10. 站点列表 (含备注)         11. 容器状态监控"
    echo -e " 12. 删除指定站点              13. 更新应用/站点"
    echo -e " 14. 流量统计 (GoAccess)       15. 组件版本升降级"
    echo -e " 16. 更换网站域名              17. 系统清理 (证书/垃圾)"
    echo -e " 18. 管理站点备注              19. 自启检测/ip/Swap/BBR"
    
    echo ""
    
    # --- 3. 数据与工具 ---
    echo -e "${YELLOW}[💾 数据与工具]${NC}"
    echo -e " 20. WP-CLI                      21. 备份/还原 (云端)"
    echo -e " 22. 数据库管理 (Adminer)      23. 数据库 导入/导出 (CLI)"
	echo -e " 24. 宿主机应用穿透"
    
    echo ""

       # --- 4. 安全与审计 ---
    echo -e "${YELLOW}[🛡️ 安全与审计]${NC}"
    echo -e " 30. 安全防御中心 (WAF)        31. Telegram 通知"
    echo -e " 32. 系统资源监控              33. 脚本操作日志"
    # === 新增下面这一行 ===
    echo -e " 34. 容器日志 (找密码)         35. SSH 密钥管理"
	echo -e " 36. 网站二级密码锁"
    echo -e " 99. 重建核心网关"


    echo "----------------------------------------------------------------"
    echo -e "${BLUE} u. 更新脚本${NC} | ${RED}x. 卸载脚本${NC} | 0. 退出"
    echo -n "请选择: "
    read option
}

# ================= 5. 主程序循环 =================

# [新增] 1. 强制 Root 检查
if [ "$(id -u)" != "0" ]; then
    echo -e "${RED}错误: 必须使用 Root 权限运行。${NC}"
    echo -e "请输入 ${GREEN}sudo -i${NC} 切换用户。"
    exit 1
fi

# 2. 定时备份任务入口 (Cron用)
if [ "$1" == "backup_all" ]; then
    check_rclone
    echo "Starting Daily Backup: $(date)"
    for dir in "$SITES_DIR"/*; do 
        if [ -d "$dir" ]; then
             perform_backup_logic "$(basename "$dir")"
        fi
    done
    echo "Daily Backup Finished: $(date)"
    exit 0
fi

# [核心修复] 3. 网络自愈逻辑
# 在安装 Docker 之前，先确保 curl 存在，并修复 IPv6 优先级
if ! command -v curl >/dev/null 2>&1; then
    echo ">>> 初始化基础组件 (curl)..."
    if command -v apt-get >/dev/null 2>&1; then 
        apt-get update && apt-get install -y curl
    elif command -v yum >/dev/null 2>&1; then 
        yum install -y curl
    fi
fi
# 调用网络修复 (解决 Docker 拉取卡死)
check_and_fix_network

# 4. 执行常规依赖检查 (安装 Docker)
check_dependencies
install_shortcut

# 5. 初始化网关
if ! docker ps --format '{{.Names}}' | grep -q "^gateway_proxy$"; then 
    echo "初始化网关..."
    init_gateway "auto"
fi

# 6. 进入菜单循环
while true; do 
    show_menu 
    case $option in 
        1) create_site;; 
        2) create_proxy;; 
        3) create_redirect;; 
        4) app_store;;
        10) list_sites;; 
        11) container_ops;; 
        12) delete_site;; 
        13) app_update_manager;; 
        14) traffic_stats;; 
        15) component_manager;; 
        16) change_domain;;
        17) system_cleanup;; 
        18) manage_remarks;; 
        19) system_optimizer;;
        20) wp_toolbox;; 
        21) backup_restore_ops;; 
        22) db_admin_tool;;
        23) db_manager;;
		24) socat_manager;;
        30) security_center;; 
        31) telegram_manager;; 
        32) sys_monitor;; 
        33) log_manager;; 
        34) view_container_logs;;
        35) ssh_key_manager;;
		36) add_basic_auth;;
        99) rebuild_gateway_action;;
        u|U) update_script;; 
        x|X) uninstall_cluster;; 
        0) exit 0;;
        *) echo "无效选项"; sleep 1;;
    esac
done
