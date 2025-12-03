#!/bin/bash

# Xray Reality 管理脚本


# --- 全局常量和默认值 (用户修改) ---
SCRIPT_VERSION="2.0.5-bbr-fix"
DEFAULT_SNI="amd.com" # <--- 已修改为 amd.com
DEFAULT_LISTEN_PORT_OPTION1="8443"
DEFAULT_FP_OPTION="chrome"
AVAILABLE_FPS=("chrome" "firefox" "safari" "edge" "ios" "android" "random")

STATE_FILE_DIR="/etc/xray_reality_manager"
STATE_FILE="${STATE_FILE_DIR}/install_details.json"
GAI_CONF_FILE="/etc/gai.conf"
IPV4_PRECEDENCE_LINE="precedence ::ffff:0:0/96 100"

XRAY_INSTALL_PATH="/usr/local/bin/xray"
XRAY_CONFIG_PATH="/usr/local/etc/xray"
XRAY_CONFIG_FILE="${XRAY_CONFIG_PATH}/config.json"
XRAY_SERVICE_FILE="/etc/systemd/system/xray.service"
XRAY_OFFICIAL_INSTALLER_URL="https://github.com/XTLS/Xray-install/raw/main/install-release.sh"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0;33m'

# --- 基础函数 ---
check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        echo -e "${RED}错误: 此脚本必须以 root 权限运行.${NC}"
        exit 1
    fi
}

check_os_compatibility() {
    echo -e "${BLUE}正在检查操作系统兼容性...${NC}"
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
        if [[ "$ID" == "debian" || "$ID_LIKE" == "debian" || "$ID" == "ubuntu" || "$ID_LIKE" == "ubuntu" ]]; then
            echo -e "${GREEN}操作系统 ($OS $VER) 兼容 (支持 Debian 13+ / Ubuntu 22+).${NC}"
            return 0
        else
            echo -e "${RED}错误: 当前操作系统 ($OS $VER) 不受支持. 此脚本仅支持 Debian/Ubuntu 及其衍生系统.${NC}"
            return 1
        fi
    elif type lsb_release >/dev/null 2>&1; then
        local os_name=$(lsb_release -si)
        if [[ "$os_name" == "Debian" || "$os_name" == "Ubuntu" ]]; then
             echo -e "${GREEN}操作系统 ($os_name) 兼容.${NC}"
             return 0
        else
            echo -e "${RED}错误: 当前操作系统 ($os_name) 不受支持. 此脚本仅支持 Debian/Ubuntu 及其衍生系统.${NC}"
            return 1
        fi
    else
        echo -e "${RED}错误: 无法确定操作系统类型. 请确保您的系统是 Debian/Ubuntu 或其衍生版本.${NC}"
        return 1
    fi
}

install_dependencies() {
    echo -e "${BLUE}准备更新软件包列表 (apt-get update)...${NC}"
    if ! apt-get update -qq; then # -qq for quieter output
        echo -e "${YELLOW}警告: 更新软件包列表失败. 可能会影响依赖安装.${NC}"
    else
        echo -e "${GREEN}软件包列表更新成功.${NC}"
    fi

    echo -e "${BLUE}正在检查并安装依赖 (curl, unzip, openssl, socat, jq)...${NC}"
    local deps=("curl" "unzip" "openssl" "socat" "jq") # shuf 包含在 coreutils 中
    local missing_deps=()
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        echo -e "${YELLOW}以下依赖缺失: ${missing_deps[*]}. 正在尝试安装...${NC}"
        if ! DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing_deps[@]}"; then
             echo -e "${RED}错误: 部分或全部缺失依赖未能自动安装. 请尝试手动安装: ${missing_deps[*]}${NC}"
             return 1
        fi
        for dep in "${missing_deps[@]}"; do
            if ! command -v "$dep" &> /dev/null; then
                echo -e "${RED}错误: 依赖 $dep 安装后仍未找到. 请手动检查.${NC}"
                return 1
            fi
        done
        echo -e "${GREEN}依赖安装成功.${NC}"
    else
        echo -e "${GREEN}所有依赖已满足.${NC}"
    fi
    return 0
}

# --- 系统优化函数 (已修改: 适配 Debian 13 + 自定义参数) ---
enable_system_optimizations() {
    echo -e "\n${BLUE}--- 正在应用系统优化 (BBR, TCP, 文件描述符) ---${NC}"

    # 1. 配置文件描述符限制 (limits.conf)
    local limits_conf="/etc/security/limits.conf"
    local limits_applied=false
    echo -e "${BLUE}正在配置文件描述符限制...${NC}"
    local limit_settings=(
        "* soft nofile 65536"
        "* hard nofile 1048576"
        "root soft nofile 65536"
        "root hard nofile 1048576"
    )

    for setting in "${limit_settings[@]}"; do
        if ! grep -qF "$setting" "$limits_conf"; then
            echo "$setting" >> "$limits_conf"
            limits_applied=true
        fi
    done

    if $limits_applied; then
        echo -e "${GREEN}文件描述符限制 (/etc/security/limits.conf) 已更新.${NC}"
        echo -e "${YELLOW}注意: limits.conf 的更改需要您重新登录 (re-login) 才能对您的 shell 生效.${NC}"
        echo -e "${BLUE}(Xray 服务将通过 systemd 配置获得高限制, 不受此影响)${NC}"
    else
        echo -e "${GREEN}文件描述符限制已是最新.${NC}"
    fi

    # 2. 配置 Sysctl (BBR & 网络优化) - 核心修改部分
    # 使用 /etc/sysctl.d/99-reality-custom.conf 确保在 Debian 13 上正确加载
    local sysctl_file="/etc/sysctl.d/99-reality-custom.conf"
    
    echo -e "${BLUE}正在配置 BBR 和网络参数 (写入 ${sysctl_file})...${NC}"

    # 写入哥哥指定的详细参数
    cat << EOF > "$sysctl_file"
fs.file-max = 6815744
net.ipv4.tcp_no_metrics_save=1
net.ipv4.tcp_ecn=0
net.ipv4.tcp_frto=0
net.ipv4.tcp_mtu_probing=0
net.ipv4.tcp_rfc1337=0
net.ipv4.tcp_sack=1
net.ipv4.tcp_fack=1
net.ipv4.tcp_window_scaling=1
net.ipv4.tcp_adv_win_scale=1
net.ipv4.tcp_moderate_rcvbuf=1
net.core.rmem_max=33554432
net.core.wmem_max=33554432
net.ipv4.tcp_rmem=4096 87380 33554432
net.ipv4.tcp_wmem=4096 16384 33554432
net.ipv4.udp_rmem_min=8192
net.ipv4.udp_wmem_min=8192
net.ipv4.ip_forward=1
net.ipv4.conf.all.route_localnet=1
net.ipv4.conf.all.forwarding=1
net.ipv4.conf.default.forwarding=1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.default.forwarding=1
net.ipv6.conf.all.accept_ra = 2
EOF

    echo -e "${GREEN}Sysctl 配置文件已创建成功: ${sysctl_file}${NC}"
    
    echo -e "${BLUE}正在加载新的内核参数 (sysctl --system)...${NC}"
    # 使用 --system 确保加载所有目录下的配置
    if sysctl --system &>/dev/null; then
        echo -e "${GREEN}系统优化参数已成功应用!${NC}"
        
        # 检查 BBR 状态
        local bbr_status=$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')
        if [[ "$bbr_status" == "bbr" ]]; then
            echo -e "${GREEN}验证成功: TCP BBR 已开启 (当前状态: ${bbr_status}).${NC}"
        else
            echo -e "${YELLOW}警告: BBR 似乎未立即生效 (当前: ${bbr_status}). 建议重启服务器.${NC}"
        fi
    else
        echo -e "${RED}应用 Sysctl 设置时出错. 请检查日志.${NC}"
        return 1
    fi

    echo -e "${GREEN}系统优化应用完成.${NC}"
    return 0
}

install_xray_core() {
    echo -e "${BLUE}正在安装/更新 Xray-core...${NC}"
    if systemctl is-active --quiet xray; then
        echo -e "${YELLOW}Xray 正在运行, 将尝试停止它以便更新...${NC}"
        systemctl stop xray
    fi
    bash -c "$(curl -L ${XRAY_OFFICIAL_INSTALLER_URL})" @ install
    if [[ $? -ne 0 || ! -x "$XRAY_INSTALL_PATH" ]]; then
        echo -e "${RED}Xray 安装失败或未找到 Xray 执行文件. 请检查错误信息.${NC}"
        return 1
    fi
    echo -e "${GREEN}Xray 安装/更新成功.${NC}"
    return 0
}

is_managed_install() {
    if [ -f "$STATE_FILE" ]; then return 0; else return 1; fi
}

load_install_details() {
    if is_managed_install; then
        current_sni=$(jq -r '.sni // empty' "$STATE_FILE")
        current_listen_port=$(jq -r '.listen_port // empty' "$STATE_FILE")
        current_user_uuid=$(jq -r '.uuid // empty' "$STATE_FILE")
        current_short_id_for_link=$(jq -r '.short_id_for_link // empty' "$STATE_FILE")
        current_fingerprint=$(jq -r '.fingerprint // empty' "$STATE_FILE")
        return 0
    else 
        current_sni=""
        current_listen_port=""
        current_user_uuid=""
        current_short_id_for_link=""
        current_fingerprint=""
        return 1
    fi
}

save_install_details() {
    local sni_to_save="$1" listen_port_to_save="$2" uuid_to_save="$3" short_id_to_save="$4"
    local public_key_to_save="$5" fingerprint_to_save="$6" dest_server_to_save="$7"
    local install_date; install_date=$(date +"%Y-%m-%d %H:%M:%S")
    mkdir -p "$STATE_FILE_DIR"
    jq -n \
      --arg script_version "$SCRIPT_VERSION" --arg installation_date "$install_date" \
      --arg sni "$sni_to_save" --arg listen_port "$listen_port_to_save" --arg uuid "$uuid_to_save" \
      --arg short_id_for_link "$short_id_to_save" --arg public_key "$public_key_to_save" \
      --arg fingerprint "$fingerprint_to_save" --arg dest_server "$dest_server_to_save" \
      '{script_version: $script_version, installation_date: $installation_date, sni: $sni, listen_port: $listen_port, uuid: $uuid, short_id_for_link: $short_id_for_link, public_key: $public_key, fingerprint: $fingerprint, dest_server: $dest_server}' > "$STATE_FILE"
    if [[ $? -eq 0 ]]; then echo -e "${GREEN}安装详情已保存到: $STATE_FILE${NC}"; else echo -e "${RED}错误: 保存安装详情失败.${NC}"; fi
}

get_user_input_no_xray_deps() {
    echo -e "\n${BLUE}请输入 Reality 配置参数 (无需Xray依赖):${NC}"
    
    # --- SNI 输入 ---
    local prompt_sni="1. 请输入 SNI (当前: ${current_sni:-$DEFAULT_SNI}, 直接回车使用显示值): "
    read -rp "$prompt_sni" user_sni_input </dev/tty; final_sni=${user_sni_input:-${current_sni:-$DEFAULT_SNI}}
    if [[ -z "$final_sni" ]]; then echo -e "${RED}SNI 不能为空.${NC}"; return 1; fi
    echo -e "${GREEN}SNI 设置为: ${final_sni}${NC}"; final_dest_server="${final_sni}:443"; echo -e "${GREEN}目标服务器 (dest) 将自动设置为: ${final_dest_server}${NC}"

    # --- 端口输入 (已简化) ---
    local port_prompt_default="${current_listen_port:-$DEFAULT_LISTEN_PORT_OPTION1}"
    local prompt_port=$'\n'"2. 请输入 Reality 监听端口 (当前/默认: $port_prompt_default, 'random'可生成随机端口): "
    read -rp "$prompt_port" user_port_input </dev/tty
    user_port_input=${user_port_input:-$port_prompt_default}
    
    if [[ "$user_port_input" == "random" ]]; then
        final_listen_port=$(shuf -i 10000-60000 -n 1)
        echo -e "${GREEN}   已选择随机端口: $final_listen_port${NC}"
    elif [[ "$user_port_input" =~ ^[0-9]+$ ]] && [ "$user_port_input" -ge 1 ] && [ "$user_port_input" -le 65535 ]; then
        final_listen_port=$user_port_input
    else
        echo -e "${YELLOW}   无效输入...将使用端口 $port_prompt_default.${NC}"
        final_listen_port=$port_prompt_default
    fi
    echo -e "${GREEN}监听端口设置为: ${final_listen_port}${NC}"

    # --- UUID 输入 ---
    local prompt_uuid=$'\n'"3. 请输入 UUID (当前: ${current_user_uuid:-自动生成}, 留空则自动生成/使用当前值): "
    read -rp "$prompt_uuid" user_uuid_input </dev/tty; final_user_uuid_placeholder=${user_uuid_input:-${current_user_uuid:-"AUTO_GENERATE"}} 
    echo -e "${GREEN}UUID 行为设置为: ${final_user_uuid_placeholder}${NC}"

    # --- Short ID 输入 ---
    local prompt_short_id=$'\n'"4. 请输入 Short ID (当前: ${current_short_id_for_link:-自动生成}, 逗号分隔, 留空则自动生成/使用当前值): "
    read -rp "$prompt_short_id" short_ids_input_str </dev/tty; final_short_id_placeholder=${short_ids_input_str:-${current_short_id_for_link:-"AUTO_GENERATE"}}
    echo -e "${GREEN}Short ID 行为设置为: ${final_short_id_placeholder}${NC}"

    # --- 指纹输入 ---
    echo -e $'\n'"5. 请选择客户端 TLS 指纹 (Fingerprint/fp):"
    local fp_to_display_default="${current_fingerprint:-$DEFAULT_FP_OPTION}"
    for i in "${!AVAILABLE_FPS[@]}"; do local opt_num=$((i+1)); local opt_name="${AVAILABLE_FPS[$i]}"; if [[ "$opt_name" == "$fp_to_display_default" ]]; then echo -e "   $opt_num) $opt_name (当前/默认)"; else echo -e "   $opt_num) $opt_name"; fi; done
    read -rp "   请输入选项 [1-${#AVAILABLE_FPS[@]}] (直接回车默认使用 ${fp_to_display_default}): " fp_choice </dev/tty
    if [[ -z "$fp_choice" ]]; then final_fingerprint="$fp_to_display_default"
    elif [[ "$fp_choice" =~ ^[0-9]+$ ]] && [ "$fp_choice" -ge 1 ] && [ "$fp_choice" -le ${#AVAILABLE_FPS[@]} ]; then final_fingerprint="${AVAILABLE_FPS[$((fp_choice - 1))]}"
    else echo -e "${YELLOW}   无效的选择...将使用指纹 ${fp_to_display_default}.${NC}"; final_fingerprint="$fp_to_display_default"; fi
    echo -e "${GREEN}客户端指纹设置为: ${final_fingerprint}${NC}"
    return 0
}

# --- v2.0.2: 适配新版 xray x25519 输出 (PrivateKey: 和 Password:) ---
generate_reality_keys_interactive() {
    echo -e "\n${BLUE}正在生成 Reality 密钥对...${NC}"
    if ! command -v $XRAY_INSTALL_PATH &> /dev/null || [[ ! -x "$XRAY_INSTALL_PATH" ]]; then 
        echo -e "${RED}错误: Xray 命令 ($XRAY_INSTALL_PATH) 未找到或不可执行.${NC}"; 
        return 1; 
    fi
    
    local key_pair_output
    # 捕获 stdout 和 stderr (2>&1)
    key_pair_output=$($XRAY_INSTALL_PATH x25519 2>&1)
    local exit_code=$? # 获取命令的退出状态码

    if [[ $exit_code -ne 0 ]]; then
         echo -e "${RED}错误: 'xray x25519' 命令执行失败. 退出码: $exit_code${NC}"
         echo -e "${YELLOW}Xray 错误详情:${NC}"
         echo -e "${RED}---(START)---${NC}"
         echo "$key_pair_output"
         echo -e "${RED}---(END)---${NC}"
         return 1
    fi

    # 适配新版 (PrivateKey:) 和旧版 (Private key:)
    final_private_key=$(echo "$key_pair_output" | grep -i "PrivateKey:" | awk '{print $NF}')
    
    # 适配新版 (Password:) 和旧版 (Public key:)
    # 新版 xray x25519 输出的 'Password' 字段即为客户端所需的 'pbk' (公钥)
    final_public_key=$(echo "$key_pair_output" | grep -i "Password:" | awk '{print $NF}')
    if [[ -z "$final_public_key" ]]; then
        # 如果找不到 Password:, 尝试找 Public key:
        final_public_key=$(echo "$key_pair_output" | grep -i "Public key:" | awk '{print $NF}')
    fi
    
    if [[ -z "$final_private_key" || -z "$final_public_key" ]]; then 
        echo -e "${RED}错误: 生成 Reality 密钥对失败. (无法从命令输出中解析私钥或公钥).${NC}"
        echo -e "${YELLOW}Xray 命令 ($XRAY_INSTALL_PATH x25519) 的原始输出为:${NC}"
        echo -e "${YELLOW}---(START)---${NC}"
        echo "$key_pair_output"
        echo -e "${YELLOW}---(END)---${NC}"
        return 1; 
    fi
    
    echo -e "${GREEN}Reality 密钥对生成成功.${NC}"; 
    return 0
}

create_xray_config_interactive() {
    echo -e "\n${BLUE}正在创建 Xray 配置文件: $XRAY_CONFIG_FILE ${NC}"
    mkdir -p "$XRAY_CONFIG_PATH"
    # 使用"最佳配置": vless + xtls-rprx-vision + reality
    # v2.0.4 修正: "listen" 必须为 "::" 才能同时监听 v4 和 v6
    # v2.0.4 修正: "bittrent" -> "bittorrent"
    cat << EOF > "$XRAY_CONFIG_FILE"
{
  "log": {"loglevel": "warning"}, 
  "routing": {"domainStrategy": "AsIs", "rules": [{"type": "field", "outboundTag": "direct", "protocol": ["bittorrent"]}, {"type": "field", "outboundTag": "block", "protocol": ["stun", "quic"]}]},
  "inbounds": [{"listen": "::", "port": ${final_listen_port}, "protocol": "vless", "settings": {"clients": [{"id": "${final_user_uuid}", "flow": "xtls-rprx-vision"}], "decryption": "none"}, "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {"show": false, "dest": "${final_dest_server}", "xver": 0, "serverNames": ["${final_sni}"], "privateKey": "${final_private_key}", "minClientVer": "", "maxClientVer": "", "maxTimeDiff": 60000, "shortIds": [${final_short_id_for_config_array}]}}, "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"]}}],
  "outbounds": [{"protocol": "freedom", "tag": "direct"}, {"protocol": "blackhole", "tag": "block"}]
}
EOF
    $XRAY_INSTALL_PATH run -test -config $XRAY_CONFIG_FILE
    if [[ $? -ne 0 ]]; then echo -e "${RED}Xray 配置文件 (${XRAY_CONFIG_FILE}) 格式错误. 请检查.${NC}"; return 1; fi
    echo -e "${GREEN}Xray 配置文件创建成功并已通过检查.${NC}"; return 0
}

setup_systemd_service_interactive() {
    echo -e "\n${BLUE}正在设置 systemd 服务...${NC}"
    cat << EOF > "$XRAY_SERVICE_FILE"
[Unit]
Description=Xray Service (Managed by reality_script v${SCRIPT_VERSION})
Documentation=https://github.com/xtls
After=network.target nss-lookup.target
[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=${XRAY_INSTALL_PATH} run -config ${XRAY_CONFIG_FILE}
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload; systemctl enable xray
    if systemctl is-active --quiet xray; then echo -e "${YELLOW}Xray 服务已在运行, 正在重启...${NC}"; systemctl restart xray
    else systemctl start xray; fi
    sleep 2
    if systemctl is-active --quiet xray; then echo -e "${GREEN}Xray 服务已成功启动并正在运行.${NC}"; else echo -e "${RED}错误: Xray 服务启动失败. 请查看日志: journalctl -u xray ${NC}"; return 1; fi
    return 0
}

display_client_config_info() {
    # 接收 v4 和 v6 IP
    local disp_pub_ip_v4="$1" disp_pub_ip_v6="$2" disp_port="$3" disp_uuid="$4" disp_sni="$5" disp_fp="$6" disp_pbk="$7" disp_sid="$8" disp_dest="$9"
    
    # 默认使用 IPv4
    local node_name_v4="Reality_v4_${disp_pub_ip_v4}"
    
    # 警告
    if [[ "$disp_pub_ip_v4" == "YOUR_SERVER_IPV4" ]]; then 
        echo -e "${YELLOW}警告: 无法自动获取公网 IPv4 地址. 请手动替换下面链接中的 'YOUR_SERVER_IPV4'.${NC}"
    fi
    if [[ -n "$disp_pub_ip_v6" ]]; then
         echo -e "${BLUE}检测到 IPv6 地址: $disp_pub_ip_v6 ${NC}"
    else
         echo -e "${YELLOW}未检测到或获取公网 IPv6 地址失败.${NC}"
    fi

    echo -e "\n${BLUE}==================== 客户端配置信息 (IPv4 优先) ====================${NC}"
    echo -e "协议 (Protocol): ${GREEN}VLESS${NC}"
    echo -e "地址 (Address): ${GREEN}${disp_pub_ip_v4}${NC}" # 优先显示 V4
    echo -e "端口 (Port): ${GREEN}${disp_port}${NC}"
    echo -e "用户ID (UUID): ${GREEN}${disp_uuid}${NC}"
    echo -e "流控 (Flow): ${GREEN}xtls-rprx-vision${NC}"
    echo -e "加密 (Encryption): ${GREEN}none${NC}"
    echo -e "传输协议 (Network): ${GREEN}tcp${NC}"
    echo -e "伪装类型 (Type): ${GREEN}none${NC}"
    echo -e "安全类型 (Security): ${GREEN}reality${NC}"
    echo -e "SNI (ServerName / host): ${GREEN}${disp_sni}${NC}"
    echo -e "公钥 (PublicKey / pbk): ${GREEN}${disp_pbk}${NC}"
    echo -e "Short ID (sid): ${GREEN}${disp_sid}${NC}"
    echo -e "指纹 (Fingerprint / fp): ${GREEN}${disp_fp}${NC}"
    echo -e "Reality目标 (dest - 服务器参数): ${YELLOW}${disp_dest}${NC}"
    
    echo -e "\n${BLUE}--- VLESS Reality 订阅链接 (IPv4) ---${NC}"
    echo -e "${GREEN}vless://${disp_uuid}@${disp_pub_ip_v4}:${disp_port}?encryption=none&security=reality&sni=${disp_sni}&fp=${disp_fp}&pbk=${disp_pbk}&sid=${disp_sid}&type=tcp&flow=xtls-rprx-vision#${node_name_v4}${NC}"

    # 检查 V6
    if [[ -n "$disp_pub_ip_v6" ]]; then
        # IPv6 地址在 URL 中需要用 [] 括起来
        local node_name_v6="Reality_v6_[${disp_pub_ip_v6}]"
        echo -e "\n${BLUE}--- VLESS Reality 订阅链接 (IPv6) ---${NC}"
        echo -e "${GREEN}vless://${disp_uuid}@[${disp_pub_ip_v6}]:${disp_port}?encryption=none&security=reality&sni=${disp_sni}&fp=${disp_fp}&pbk=${disp_pbk}&sid=${disp_sid}&type=tcp&flow=xtls-rprx-vision#${node_name_v6}${NC}"
    fi

    echo -e "\n${YELLOW}请注意: 如果您的服务器位于 NAT 后或有防火墙, 请确保端口 ${disp_port} 已正确放行 TCP 流量 (IPv4 和/或 IPv6).${NC}"
    echo -e "${BLUE}===============================================================${NC}"
}


# --- 菜单功能实现 ---
install_reality() {
    echo -e "\n${BLUE}--- 开始一键安装 Reality 代理 ---${NC}"
    if is_managed_install; then
        echo -n -e "${YELLOW}检测到已存在的 Reality 安装. 您想覆盖并重新安装吗? [y/N]: ${NC}"
        read -r confirm_reinstall </dev/tty
        if [[ ! "$confirm_reinstall" =~ ^[Yy]$ ]]; then echo -e "${BLUE}安装取消.${NC}"; return; fi
        echo -e "${YELLOW}将执行覆盖安装...${NC}"
    fi

    echo -e "\n${BLUE}阶段 1: 收集配置参数...${NC}"
    load_install_details
    if ! get_user_input_no_xray_deps; then
        echo -e "${RED}参数输入有误或被取消, 中止安装.${NC}"; return
    fi

    echo -e "\n${BLUE}--- 请确认以下配置参数 ---${NC}"
    echo -e "SNI: ${GREEN}${final_sni}${NC}"
    echo -e "监听端口: ${GREEN}${final_listen_port}${NC}"
    echo -e "UUID (行为): ${GREEN}${final_user_uuid_placeholder}${NC}"
    echo -e "Short ID (行为): ${GREEN}${final_short_id_placeholder}${NC}"
    echo -e "客户端指纹: ${GREEN}${final_fingerprint}${NC}"
    echo -e "目标服务器 (dest - 自动设置): ${GREEN}${final_dest_server}${NC}"
    echo -e "-------------------------------------"
    echo -n -e "${YELLOW}以上参数是否正确并开始安装环境和配置服务? [Y/n]: ${NC}"
    read -r confirm_params </dev/tty
    if [[ "$confirm_params" =~ ^[Nn]$ ]]; then
        echo -e "${BLUE}参数确认取消. 返回主菜单.${NC}"; return
    fi

    echo -e "\n${BLUE}阶段 2: 开始安装环境和配置服务...${NC}"
    check_os_compatibility || { return; }
    install_dependencies || { echo -e "${RED}依赖安装失败, 中止安装.${NC}"; return; }
    
    # --- 自动应用系统优化 ---
    enable_system_optimizations || { echo -e "${YELLOW}系统优化步骤出现问题, 但安装将继续...${NC}"; }
    
    install_xray_core || { echo -e "${RED}Xray核心安装失败, 中止安装.${NC}"; return; }

    # --- v2.0.1: 增强了 UUID 生成的错误捕获 ---
    if [[ "$final_user_uuid_placeholder" == "AUTO_GENERATE" ]]; then
        final_user_uuid=$($XRAY_INSTALL_PATH uuid 2>&1)
        if [[ $? -ne 0 || -z "$final_user_uuid" || "$final_user_uuid" == *error* ]]; then
            echo -e "${RED}错误: 'xray uuid' 命令执行失败.${NC}"
            echo -e "${YELLOW}Xray 错误详情: $final_user_uuid${NC}"
            return 1
        fi
        echo -e "${GREEN}已自动生成 UUID: $final_user_uuid${NC}"
    else
        final_user_uuid=$final_user_uuid_placeholder; echo -e "${GREEN}UUID 设置为: $final_user_uuid${NC}"
    fi
    if [[ -z "$final_user_uuid" ]]; then echo -e "${RED}UUID 处理失败.${NC}"; return 1; fi

    if [[ "$final_short_id_placeholder" == "AUTO_GENERATE" ]]; then
        local gen_hex; gen_hex=$(openssl rand -hex 4)
        final_short_id_for_config_array="\"${gen_hex}\""; final_short_id_for_link="${gen_hex}"
        echo -e "${GREEN}已自动生成 Short ID: ${gen_hex}${NC}"
    else
        final_short_id_for_config_array=$(echo "$final_short_id_placeholder" | awk -F, '{for(i=1;i<=NF;i++) {gsub(/^[ \t]+|[ \t]+$/, "", $i); printf "\"%s\"%s", $i, (i==NF?"":",")}}')
        final_short_id_for_link=$(echo "$final_short_id_placeholder" | cut -d',' -f1 | sed 's/^[ \t]*//;s/[ \t]*$//')
        echo -e "${GREEN}Short ID(s) 设置为: ${final_short_id_placeholder} (客户端链接将使用: ${final_short_id_for_link})${NC}"
    fi
     if [[ -z "$final_short_id_for_link" ]]; then echo -e "${RED}Short ID 处理失败.${NC}"; return 1; fi

    generate_reality_keys_interactive || { echo -e "${RED}密钥生成失败, 中止安装.${NC}"; return; }
    create_xray_config_interactive || { echo -e "${RED}配置文件创建失败, 中止安装.${NC}"; return; }
    setup_systemd_service_interactive || { echo -e "${RED}服务设置失败, 中止安装.${NC}"; return; }

    save_install_details "$final_sni" "$final_listen_port" "$final_user_uuid" "$final_short_id_for_link" "$final_public_key" "$final_fingerprint" "$final_dest_server"

    local public_ip_v4; local public_ip_v6
    public_ip_v4=$(curl -4 -s --max-time 5 ip.sb || curl -4 -s --max-time 5 ifconfig.me || curl -4 -s --max-time 5 api.ipify.org)
    public_ip_v6=$(curl -6 -s --max-time 5 ip.sb || curl -6 -s --max-time 5 ifconfig.me || curl -6 -s --max-time 5 api6.ipify.org)
    if [[ -z "$public_ip_v4" ]]; then public_ip_v4="YOUR_SERVER_IPV4"; fi
    if [[ -z "$public_ip_v6" ]]; then public_ip_v6=""; fi
    display_client_config_info "$public_ip_v4" "$public_ip_v6" "$final_listen_port" "$final_user_uuid" "$final_sni" "$final_fingerprint" "$final_public_key" "$final_short_id_for_link" "$final_dest_server"
    
    echo -e "\n${GREEN}Reality 代理节点安装/配置完成!${NC}"
}

view_configuration() {
    echo -e "\n${BLUE}--- 查看当前 Reality 配置 ---${NC}"
    if ! is_managed_install; then echo -e "${YELLOW}未找到由本脚本管理的 Reality 安装信息. 请先安装.${NC}"; return; fi
    if ! load_install_details; then echo -e "${RED}无法加载安装详情.${NC}"; return; fi
    local stored_sni; stored_sni=$(jq -r '.sni // empty' "$STATE_FILE");
    local stored_listen_port=$(jq -r '.listen_port // empty' "$STATE_FILE"); local stored_uuid=$(jq -r '.uuid // empty' "$STATE_FILE")
    local stored_short_id=$(jq -r '.short_id_for_link // empty' "$STATE_FILE"); local stored_public_key=$(jq -r '.public_key // empty' "$STATE_FILE")
    local stored_fingerprint=$(jq -r '.fingerprint // empty' "$STATE_FILE"); local stored_dest_server=$(jq -r '.dest_server // empty' "$STATE_FILE")

    if [[ -z "$stored_sni" || -z "$stored_listen_port" || -z "$stored_uuid" || -z "$stored_public_key" ]]; then echo -e "${RED}错误: 存储的配置信息不完整. 可能需要重新配置.${NC}"; return; fi
    
    local public_ip_v4; local public_ip_v6
    public_ip_v4=$(curl -4 -s --max-time 5 ip.sb || curl -4 -s --max-time 5 ifconfig.me || curl -4 -s --max-time 5 api.ipify.org)
    public_ip_v6=$(curl -6 -s --max-time 5 ip.sb || curl -6 -s --max-time 5 ifconfig.me || curl -6 -s --max-time 5 api6.ipify.org)
    if [[ -z "$public_ip_v4" ]]; then public_ip_v4="YOUR_SERVER_IPV4"; fi
    if [[ -z "$public_ip_v6" ]]; then public_ip_v6=""; fi
    display_client_config_info "$public_ip_v4" "$public_ip_v6" "$stored_listen_port" "$stored_uuid" "$stored_sni" "$stored_fingerprint" "$stored_public_key" "$stored_short_id" "$stored_dest_server"
}

modify_configuration() {
    echo -e "\n${BLUE}--- 修改 Reality 配置 ---${NC}"
    if ! is_managed_install; then echo -e "${YELLOW}未找到由本脚本管理的 Reality 安装信息. 请先安装.${NC}"; return; fi
    echo -e "${YELLOW}这将重新配置 Reality 服务, 但不会重装依赖.${NC}"
    echo -e "${YELLOW}当前的 Reality 密钥对将会被重新生成.${NC}"

    load_install_details 

    if ! get_user_input_no_xray_deps; then
        echo -e "${RED}参数输入有误或被取消, 中止修改.${NC}"; return
    fi

    echo -e "\n${BLUE}--- 请确认以下修改后的配置参数 ---${NC}"
    echo -e "SNI: ${GREEN}${final_sni}${NC}"
    echo -e "监听端口: ${GREEN}${final_listen_port}${NC}"
    echo -e "UUID (行为): ${GREEN}${final_user_uuid_placeholder}${NC}"
    echo -e "Short ID (行为): ${GREEN}${final_short_id_placeholder}${NC}"
    echo -e "客户端指纹: ${GREEN}${final_fingerprint}${NC}"
    echo -e "目标服务器 (dest - 自动设置): ${GREEN}${final_dest_server}${NC}"
    echo -e "-------------------------------------"
    echo -n -e "${YELLOW}是否应用以上修改? (密钥将重新生成) [Y/n]: ${NC}"
    read -r confirm_mods </dev/tty
    if [[ "$confirm_mods" =~ ^[Nn]$ ]]; then echo -e "${BLUE}修改取消. 返回主菜单.${NC}"; return; fi

    echo -e "\n${BLUE}正在应用修改...${NC}"
    install_xray_core || { echo -e "${RED}Xray核心更新失败, 中止修改.${NC}"; return; } # 确保 Xray 是最新的

    # --- v2.0.1: 增强了 UUID 生成的错误捕获 ---
    if [[ "$final_user_uuid_placeholder" == "AUTO_GENERATE" ]]; then
        final_user_uuid=$($XRAY_INSTALL_PATH uuid 2>&1)
        if [[ $? -ne 0 || -z "$final_user_uuid" || "$final_user_uuid" == *error* ]]; then
            echo -e "${RED}错误: 'xray uuid' 命令执行失败.${NC}"
            echo -e "${YELLOW}Xray 错误详情: $final_user_uuid${NC}"
            return 1
        fi
        echo -e "${GREEN}已自动生成 UUID: $final_user_uuid${NC}"
    else
        final_user_uuid=$final_user_uuid_placeholder; echo -e "${GREEN}UUID 设置为: $final_user_uuid${NC}"
    fi
    if [[ -z "$final_user_uuid" ]]; then echo -e "${RED}UUID 处理失败.${NC}"; return 1; fi

    if [[ "$final_short_id_placeholder" == "AUTO_GENERATE" ]]; then
        local gen_hex; gen_hex=$(openssl rand -hex 4)
        final_short_id_for_config_array="\"${gen_hex}\""; final_short_id_for_link="${gen_hex}"
        echo -e "${GREEN}已自动生成 Short ID: ${gen_hex}${NC}"
    else 
        final_short_id_for_config_array=$(echo "$final_short_id_placeholder" | awk -F, '{for(i=1;i<=NF;i++) {gsub(/^[ \t]+|[ \t]+$/, "", $i); printf "\"%s\"%s", $i, (i==NF?"":",")}}')
        final_short_id_for_link=$(echo "$final_short_id_placeholder" | cut -d',' -f1 | sed 's/^[ \t]*//;s/[ \t]*$//')
        echo -e "${GREEN}Short ID(s) 设置为: ${final_short_id_placeholder} (客户端链接将使用: ${final_short_id_for_link})${NC}"
    fi
    if [[ -z "$final_short_id_for_link" ]]; then echo -e "${RED}Short ID 处理失败.${NC}"; return 1; fi

    generate_reality_keys_interactive || { echo -e "${RED}密钥生成失败, 中止修改.${NC}"; return; }
    create_xray_config_interactive || { echo -e "${RED}配置文件创建失败, 中止修改.${NC}"; return; }
    setup_systemd_service_interactive || { echo -e "${RED}服务设置失败, 中止修改.${NC}"; return; }
    
    save_install_details "$final_sni" "$final_listen_port" "$final_user_uuid" "$final_short_id_for_link" "$final_public_key" "$final_fingerprint" "$final_dest_server"
    local public_ip_v4; local public_ip_v6
    public_ip_v4=$(curl -4 -s --max-time 5 ip.sb || curl -4 -s --max-time 5 ifconfig.me || curl -4 -s --max-time 5 api.ipify.org)
    public_ip_v6=$(curl -6 -s --max-time 5 ip.sb || curl -6 -s --max-time 5 ifconfig.me || curl -6 -s --max-time 5 api6.ipify.org)
    if [[ -z "$public_ip_v4" ]]; then public_ip_v4="YOUR_SERVER_IPV4"; fi
    if [[ -z "$public_ip_v6" ]]; then public_ip_v6=""; fi
    display_client_config_info "$public_ip_v4" "$public_ip_v6" "$final_listen_port" "$final_user_uuid" "$final_sni" "$final_fingerprint" "$final_public_key" "$final_short_id_for_link" "$final_dest_server"
    
    echo -e "\n${GREEN}Reality 配置修改完成!${NC}"
}

uninstall_reality() {
    echo -e "\n${BLUE}--- 卸载 Reality 代理 ---${NC}"
    if ! is_managed_install && ! systemctl list-unit-files | grep -q "xray.service"; then echo -e "${YELLOW}未检测到 Reality 安装 (通过本脚本或独立的 Xray 服务).${NC}"; return; fi
    echo -n -e "${RED}警告: 这将停止并移除 Xray 服务, 配置文件及本脚本存储的信息. 确定要卸载吗? [y/N]: ${NC}"
    read -r confirm_uninstall </dev/tty
    if [[ ! "$confirm_uninstall" =~ ^[Yy]$ ]]; then echo -e "${BLUE}卸载取消.${NC}"; return; fi

    if systemctl is-active --quiet xray; then echo -e "${YELLOW}正在停止 Xray 服务...${NC}"; systemctl stop xray; else echo -e "${BLUE}Xray 服务未在运行.${NC}"; fi
    if systemctl is-enabled --quiet xray; then echo -e "${YELLOW}正在禁用 Xray 服务...${NC}"; systemctl disable xray; else echo -e "${BLUE}Xray 服务未设置为开机自启.${NC}"; fi
    if [ -f "$XRAY_SERVICE_FILE" ]; then echo -e "${YELLOW}正在移除 systemd 服务文件 ($XRAY_SERVICE_FILE)...${NC}"; rm -f "$XRAY_SERVICE_FILE"; systemctl daemon-reload; else echo -e "${BLUE}Systemd 服务文件 ($XRAY_SERVICE_FILE) 不存在.${NC}"; fi

    echo -e "${YELLOW}正在尝试使用 Xray 官方脚本卸载 Xray 核心...${NC}"
    local xray_uninstalled_successfully=false
    if [ -f "/usr/local/bin/xray-uninstall.sh" ]; then 
        if bash /usr/local/bin/xray-uninstall.sh remove --purge &>/dev/null; then xray_uninstalled_successfully=true; fi
    fi
    if ! $xray_uninstalled_successfully ; then 
        if bash -c "$(curl -L ${XRAY_OFFICIAL_INSTALLER_URL})" @ remove --purge &>/dev/null; then xray_uninstalled_successfully=true; fi
    fi
    if $xray_uninstalled_successfully; then echo -e "${GREEN}Xray 核心卸载命令执行成功 (不代表所有文件都已清除).${NC}"; else echo -e "${YELLOW}Xray 核心卸载命令执行失败或未找到卸载脚本. 可能需要手动清理.${NC}"; fi
    echo -e "${YELLOW}正在强制清理 Xray 相关目录和文件...${NC}"
    rm -rf "$XRAY_CONFIG_PATH"; rm -f "$XRAY_INSTALL_PATH"; rm -rf "/usr/local/share/xray"; rm -rf "/var/log/xray"
    echo -e "${YELLOW}正在移除本脚本存储的安装信息...${NC}"; rm -rf "$STATE_FILE_DIR"
    echo -e "${GREEN}Reality 代理及相关组件卸载完成.${NC}"
    echo -n -e "${YELLOW}是否删除此管理脚本 (${0}) 本身? [y/N]: ${NC}"; read -r delete_script_choice </dev/tty
    if [[ "$delete_script_choice" =~ ^[Yy]$ ]]; then echo -e "${YELLOW}正在删除管理脚本...${NC}"; rm -- "$0"; echo -e "${GREEN}管理脚本已删除. 再见!${NC}"; fi
}

# --- 新增功能: 管理 IP 栈优先级 ---
manage_ip_priority() {
    echo -e "\n${BLUE}--- 管理服务器 IP 栈优先级 ---${NC}"
    echo -e "此功能通过修改 ${GAI_CONF_FILE} 来控制系统默认是优先使用 IPv4 还是 IPv6."
    echo -e "这会影响如 curl, apt, Xray出站等程序的默认网络行为."

    local current_status="${GREEN}优先 IPv6 (系统默认)${NC}"
    if [ -f "$GAI_CONF_FILE" ] && grep -qE "^[[:space:]]*${IPV4_PRECEDENCE_LINE}" "$GAI_CONF_FILE"; then
        current_status="${YELLOW}优先 IPv4${NC}"
    fi

    echo -e "\n当前状态: ${current_status}"
    echo -e "---------------------------------------------"
    echo -e "   1) 设置为: ${YELLOW}优先 IPv4${NC}"
    echo -e "   2) 设置为: ${GREEN}优先 IPv6 (系统默认)${NC}"
    echo -e "   0) 返回主菜单"
    echo -e "---------------------------------------------"
    read -rp "请输入选项 [0-2]: " gai_choice </dev/tty

    case $gai_choice in
        1)
            echo -e "${YELLOW}正在设置为 [优先 IPv4]...${NC}"
            if ! [ -f "$GAI_CONF_FILE" ]; then
                echo -e "${BLUE}文件 ${GAI_CONF_FILE} 不存在, 正在创建...${NC}"
                touch "$GAI_CONF_FILE"
            fi
            
            # 检查是否被注释
            if grep -qE "^[[:space:]]*#[[:space:]]*${IPV4_PRECEDENCE_LINE}" "$GAI_CONF_FILE"; then
                echo -e "${BLUE}在 ${GAI_CONF_FILE} 中找到已注释的行, GNC}"
                sed -i -E "s/^[[:space:]]*#[[:space:]]*${IPV4_PRECEDENCE_LINE}/${IPV4_PRECEDENCE_LINE}/" "$GAI_CONF_FILE"
            # 检查是否已存在且未被注释
            elif grep -qE "^[[:space:]]*${IPV4_PRECEDENCE_LINE}" "$GAI_CONF_FILE"; then
                echo -e "${GREEN}设置已生效, 无需更改.${NC}"
            # 如果不存在, 则添加
            else
                echo -e "${BLUE}正在向 ${GAI_CONF_FILE} 添加 IPv4 优先规则...${NC}"
                echo "${IPV4_PRECEDENCE_LINE}" >> "$GAI_CONF_FILE"
            fi
            echo -e "${GREEN}设置 [优先 IPv4] 完成.${NC}"
            ;;
        2)
            echo -e "${YELLOW}正在设置为 [优先 IPv6 (系统默认)]...${NC}"
            if [ -f "$GAI_CONF_FILE" ]; then
                # 检查是否存在未注释的行, 如果有, 则注释它
                if grep -qE "^[[:space:]]*${IPV4_PRECEDENCE_LINE}" "$GAI_CONF_FILE"; then
                    echo -e "${BLUE}正在 ${GAI_CONF_FILE} 中注释 IPv4 优先规则...${NC}"
                    sed -i -E "s/^[[:space:]]*${IPV4_PRECEDENCE_LINE}/#${IPV4_PRECEDENCE_LINE}/" "$GAI_CONF_FILE"
                    echo -e "${GREEN}设置 [优先 IPv6 (系统默认)] 完成.${NC}"
                else
                    echo -e "${GREEN}系统已处于默认状态, 无需更改.${NC}"
                fi
            else
                echo -e "${GREEN}系统已处于默认状态 (文件不存在), 无需更改.${NC}"
            fi
            ;;
        0)
            echo -e "${BLUE}返回主菜单...${NC}"
            ;;
        *)
            echo -e "${RED}无效选项!${NC}"; sleep 2;
            ;;
    esac
}


# --- 主菜单 ---
main_menu() {
    clear
    echo -e "${BLUE}=============================================${NC}"
    echo -e "${GREEN}    Xray Reality 代理管理脚本 v${SCRIPT_VERSION}${NC}"
    echo -e "${GREEN}      (默认端口: ${DEFAULT_LISTEN_PORT_OPTION1}, 带 BBR 优化)${NC}"
    echo -e "${BLUE}=============================================${NC}"
    echo -e "当前日期: $(date +"%Y-%m-%d %A")"
    echo -e "---------------------------------------------"
    if is_managed_install; then
        local current_sni_for_menu; local current_port_for_menu
        current_sni_for_menu=$(jq -r '.sni // "未配置"' "$STATE_FILE")
        current_port_for_menu=$(jq -r '.listen_port // "未配置"' "$STATE_FILE")
        echo -e "${GREEN}状态: 已安装 (SNI: $current_sni_for_menu, 端口: $current_port_for_menu)${NC}"
    else
        echo -e "${YELLOW}状态: 未安装或不由本脚本管理${NC}"
    fi
    echo -e "---------------------------------------------"
    echo -e "请选择操作:"
    echo -e "   ${GREEN}1)${NC} 安装 Reality 代理 (若已安装则为覆盖安装)"
    echo -e "   ${GREEN}2)${NC} 查看当前配置"
    echo -e "   ${GREEN}3)${NC} 修改 Reality 配置"
    echo -e "   ${YELLOW}4)${NC} 应用系统优化 (BBR等)"
    echo -e "   ${RED}5)${NC} 卸载 Reality 代理"
    echo -e "   ${BLUE}6)${NC} 设置服务器IP栈优先级 (v4/v6)"
    echo -e "---------------------------------------------"
    echo -e "   ${YELLOW}0)${NC} 退出脚本"
    echo -e "---------------------------------------------"
    read -rp "请输入选项 [0-6]: " choice </dev/tty # <--- 强制从TTY读取

    local post_action_pause=false 

    case $choice in
        1) install_reality; post_action_pause=true ;; 
        2) view_configuration; post_action_pause=true ;; 
        3) modify_configuration; post_action_pause=true ;;
        4) enable_system_optimizations; post_action_pause=true ;;
        5) uninstall_reality; post_action_pause=true ;;
        6) manage_ip_priority; post_action_pause=true ;;
        0) echo -e "${GREEN}感谢使用, 真正退出...${NC}"; exit 0 ;;
        *) 
            echo -e "${RED}无效选项! 请重新输入.${NC}"; sleep 2;
            main_menu 
            return    
            ;;
    esac

    if $post_action_pause; then 
        echo 
        read -rp "按任意键返回主菜单..." -n 1 -s </dev/tty # <--- 强制从TTY读取
    fi
    main_menu 
}

# --- 脚本开始执行 ---
trap 'echo -e "\n${YELLOW}操作被用户中断.${NC}"; exit 130' INT QUIT TERM
check_root
main_menu
