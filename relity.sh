#!/bin/bash

# Xray Reality 管理脚本
# 版本: 1.0.2
# 最后更新: 2025-05-09
# by fs

# --- 全局常量和默认值 ---
SCRIPT_VERSION="1.0.2"
DEFAULT_SNI="genshin.hoyoverse.com"
DEFAULT_LISTEN_PORT_OPTION1="443"
DEFAULT_FP_OPTION="chrome"
AVAILABLE_FPS=("chrome" "firefox" "safari" "edge" "ios" "android" "random")

STATE_FILE_DIR="/etc/xray_reality_manager"
STATE_FILE="${STATE_FILE_DIR}/install_details.json"

XRAY_INSTALL_PATH="/usr/local/bin/xray"
XRAY_CONFIG_PATH="/usr/local/etc/xray"
XRAY_CONFIG_FILE="${XRAY_CONFIG_PATH}/config.json"
XRAY_SERVICE_FILE="/etc/systemd/system/xray.service"
XRAY_OFFICIAL_INSTALLER_URL="https://github.com/XTLS/Xray-install/raw/main/install-release.sh"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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
            echo -e "${GREEN}操作系统 ($OS $VER) 兼容.${NC}"
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
        # 不直接退出，允许用户在某些情况下继续尝试
    else
        echo -e "${GREEN}软件包列表更新成功.${NC}"
    fi

    echo -e "${BLUE}正在检查并安装依赖 (curl, unzip, openssl, socat, shuf, jq)...${NC}"
    local deps=("curl" "unzip" "openssl" "socat" "shuf" "jq")
    local missing_deps=()
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        echo -e "${YELLOW}以下依赖缺失: ${missing_deps[*]}. 正在尝试安装...${NC}"
        # DEBIAN_FRONTEND=noninteractive 避免apt-get在某些情况下卡住等待用户输入
        if ! DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing_deps[@]}"; then
             echo -e "${RED}错误: 部分或全部缺失依赖未能自动安装. 请尝试手动安装: ${missing_deps[*]}${NC}"
             return 1
        fi
        # 再次验证
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
    else # 清空以确保使用脚本内置默认值
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

get_user_input_interactive() {
    echo -e "\n${BLUE}请输入 Reality 配置参数:${NC}"
    local prompt_sni="1. 请输入 SNI (当前: ${current_sni:-$DEFAULT_SNI}, 直接回车使用显示值): "
    read -rp "$prompt_sni" user_sni_input
    final_sni=${user_sni_input:-${current_sni:-$DEFAULT_SNI}}
    if [[ -z "$final_sni" ]]; then echo -e "${RED}SNI 不能为空.${NC}"; return 1; fi # 基本验证
    echo -e "${GREEN}SNI 设置为: ${final_sni}${NC}"
    final_dest_server="${final_sni}:443"
    echo -e "${GREEN}目标服务器 (dest) 将自动设置为: ${final_dest_server}${NC}"

    echo -e "\n2. 请选择 Reality 监听端口:"
    local port_option1_display="${current_listen_port:-$DEFAULT_LISTEN_PORT_OPTION1}"
    echo -e "   1) $port_option1_display (当前/默认推荐)"
    echo -e "   2) 10000-60000 之间的随机端口"
    echo -e "   3) 自定义端口"
    read -rp "   请输入选项 [1-3], 或直接输入具体端口号 (直接回车默认使用 $port_option1_display): " port_choice
    if [[ -z "$port_choice" ]]; then final_listen_port=$port_option1_display
    elif [[ "$port_choice" == "1" ]]; then final_listen_port=$port_option1_display
    elif [[ "$port_choice" == "2" ]]; then final_listen_port=$(shuf -i 10000-60000 -n 1); echo -e "${GREEN}   已选择随机端口: $final_listen_port${NC}"
    elif [[ "$port_choice" == "3" ]]; then
        while true; do
            read -rp "   请输入自定义端口 (1-65535): " custom_port
            if [[ "$custom_port" =~ ^[0-9]+$ ]] && [ "$custom_port" -ge 1 ] && [ "$custom_port" -le 65535 ]; then final_listen_port=$custom_port; break
            else echo -e "${YELLOW}   无效的端口号. 请输入 1-65535 之间的数字.${NC}"; fi
        done
    elif [[ "$port_choice" =~ ^[0-9]+$ ]] && [ "$port_choice" -ge 1 ] && [ "$port_choice" -le 65535 ]; then final_listen_port=$port_choice
    else echo -e "${YELLOW}   无效的选择或端口号. 将使用端口 $port_option1_display.${NC}"; final_listen_port=$port_option1_display; fi
    echo -e "${GREEN}监听端口设置为: $final_listen_port${NC}"

    local prompt_uuid=$'\n'"3. 请输入 UUID (当前: ${current_user_uuid:-无, 将自动生成}, 留空则自动生成/使用当前值): "
    read -rp "$prompt_uuid" user_uuid_input
    if [[ -z "$user_uuid_input" ]]; then
        if [[ -n "$current_user_uuid" ]]; then final_user_uuid=$current_user_uuid; echo -e "${GREEN}UUID 保持为: $final_user_uuid${NC}"
        else final_user_uuid=$($XRAY_INSTALL_PATH uuid); echo -e "${GREEN}已自动生成 UUID: $final_user_uuid${NC}"; fi
    else final_user_uuid=$user_uuid_input; echo -e "${GREEN}UUID 设置为: $final_user_uuid${NC}"; fi
    if [[ -z "$final_user_uuid" ]]; then echo -e "${RED}UUID 生成或输入失败.${NC}"; return 1; fi

    local prompt_short_id=$'\n'"4. 请输入 Short ID (当前: ${current_short_id_for_link:-无, 将自动生成}, 逗号分隔, 留空则自动生成/使用当前值): "
    read -rp "$prompt_short_id" short_ids_input_str
    if [[ -z "$short_ids_input_str" ]]; then
        if [[ -n "$current_short_id_for_link" ]]; then final_short_id_for_link=$current_short_id_for_link; final_short_id_for_config_array="\"${final_short_id_for_link}\""; echo -e "${GREEN}Short ID 保持为: ${final_short_id_for_link}${NC}"
        else local gen_hex; gen_hex=$(openssl rand -hex 4); final_short_id_for_config_array="\"${gen_hex}\""; final_short_id_for_link="${gen_hex}"; echo -e "${GREEN}已自动生成 Short ID: ${gen_hex}${NC}"; fi
    else
        final_short_id_for_config_array=$(echo "$short_ids_input_str" | awk -F, '{for(i=1;i<=NF;i++) {gsub(/^[ \t]+|[ \t]+$/, "", $i); printf "\"%s\"%s", $i, (i==NF?"":",")}}')
        final_short_id_for_link=$(echo "$short_ids_input_str" | cut -d',' -f1 | sed 's/^[ \t]*//;s/[ \t]*$//')
        echo -e "${GREEN}Short ID(s) 设置为: ${short_ids_input_str} (客户端链接将使用: ${final_short_id_for_link})${NC}"
    fi
    if [[ -z "$final_short_id_for_link" ]]; then echo -e "${RED}Short ID 处理失败.${NC}"; return 1; fi

    echo -e $'\n'"5. 请选择客户端 TLS 指纹 (Fingerprint/fp):"
    local fp_to_display_default="${current_fingerprint:-$DEFAULT_FP_OPTION}"
    for i in "${!AVAILABLE_FPS[@]}"; do local opt_num=$((i+1)); local opt_name="${AVAILABLE_FPS[$i]}"; if [[ "$opt_name" == "$fp_to_display_default" ]]; then echo -e "   $opt_num) $opt_name (当前/默认)"; else echo -e "   $opt_num) $opt_name"; fi; done
    read -rp "   请输入选项 [1-${#AVAILABLE_FPS[@]}] (直接回车默认使用 ${fp_to_display_default}): " fp_choice
    if [[ -z "$fp_choice" ]]; then final_fingerprint="$fp_to_display_default"
    elif [[ "$fp_choice" =~ ^[0-9]+$ ]] && [ "$fp_choice" -ge 1 ] && [ "$fp_choice" -le ${#AVAILABLE_FPS[@]} ]; then final_fingerprint="${AVAILABLE_FPS[$((fp_choice - 1))]}"
    else echo -e "${YELLOW}   无效的选择. 将使用指纹 ${fp_to_display_default}.${NC}"; final_fingerprint="$fp_to_display_default"; fi
    echo -e "${GREEN}客户端指纹设置为: ${final_fingerprint}${NC}"
    return 0 # 假设所有输入都通过或有合理默认
}

generate_reality_keys_interactive() {
    echo -e "\n${BLUE}正在生成 Reality 密钥对...${NC}"
    if ! command -v $XRAY_INSTALL_PATH &> /dev/null || [[ ! -x "$XRAY_INSTALL_PATH" ]]; then echo -e "${RED}错误: Xray 命令 ($XRAY_INSTALL_PATH) 未找到或不可执行.${NC}"; return 1; fi
    local key_pair_output; key_pair_output=$($XRAY_INSTALL_PATH x25519)
    final_private_key=$(echo "$key_pair_output" | grep "Private key:" | awk '{print $3}')
    final_public_key=$(echo "$key_pair_output" | grep "Public key:" | awk '{print $3}')
    if [[ -z "$final_private_key" || -z "$final_public_key" ]]; then echo -e "${RED}错误: 生成 Reality 密钥对失败.${NC}"; return 1; fi
    echo -e "${GREEN}Reality 密钥对生成成功.${NC}"; return 0
}

create_xray_config_interactive() {
    echo -e "\n${BLUE}正在创建 Xray 配置文件: $XRAY_CONFIG_FILE ${NC}"
    mkdir -p "$XRAY_CONFIG_PATH"
    cat << EOF > "$XRAY_CONFIG_FILE"
{
  "log": {"loglevel": "warning"}, "routing": {"domainStrategy": "AsIs", "rules": [{"type": "field", "outboundTag": "direct", "protocol": ["bittorrent"]}, {"type": "field", "outboundTag": "block", "protocol": ["stun", "quic"]}]},
  "inbounds": [{"listen": "0.0.0.0", "port": ${final_listen_port}, "protocol": "vless", "settings": {"clients": [{"id": "${final_user_uuid}", "flow": "xtls-rprx-vision"}], "decryption": "none"}, "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {"show": false, "dest": "${final_dest_server}", "xver": 0, "serverNames": ["${final_sni}"], "privateKey": "${final_private_key}", "minClientVer": "", "maxClientVer": "", "maxTimeDiff": 60000, "shortIds": [${final_short_id_for_config_array}]}}, "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"]}}],
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
    local disp_pub_ip="$1" disp_port="$2" disp_uuid="$3" disp_sni="$4" disp_fp="$5" disp_pbk="$6" disp_sid="$7" disp_dest="$8"
    local node_name="Reality_${disp_pub_ip}"
    if [[ "$disp_pub_ip" == "YOUR_SERVER_IP" ]]; then echo -e "${YELLOW}警告: 无法自动获取公网 IP 地址. 请手动替换下面链接中的 'YOUR_SERVER_IP'.${NC}"; fi
    echo -e "\n${BLUE}==================== 客户端配置信息 ====================${NC}"
    echo -e "协议 (Protocol): ${GREEN}VLESS${NC}" ; echo -e "地址 (Address): ${GREEN}${disp_pub_ip}${NC}" ; echo -e "端口 (Port): ${GREEN}${disp_port}${NC}"
    echo -e "用户ID (UUID): ${GREEN}${disp_uuid}${NC}" ; echo -e "流控 (Flow): ${GREEN}xtls-rprx-vision${NC}" ; echo -e "加密 (Encryption): ${GREEN}none${NC}"
    echo -e "传输协议 (Network): ${GREEN}tcp${NC}" ; echo -e "伪装类型 (Type): ${GREEN}none${NC}" ; echo -e "安全类型 (Security): ${GREEN}reality${NC}"
    echo -e "SNI (ServerName / host): ${GREEN}${disp_sni}${NC}" ; echo -e "公钥 (PublicKey / pbk): ${GREEN}${disp_pbk}${NC}"
    echo -e "Short ID (sid): ${GREEN}${disp_sid}${NC}" ; echo -e "指纹 (Fingerprint / fp): ${GREEN}${disp_fp}${NC}"
    echo -e "Reality目标 (dest - 服务器参数): ${YELLOW}${disp_dest}${NC}"
    echo -e "\n${BLUE}以下是您的 VLESS Reality 订阅链接 (分享链接):${NC}"
    echo -e "${BLUE}请复制完整的链接并在您的客户端中导入:${NC}"
    echo -e "${GREEN}vless://${disp_uuid}@${disp_pub_ip}:${disp_port}?encryption=none&security=reality&sni=${disp_sni}&fp=${disp_fp}&pbk=${disp_pbk}&sid=${disp_sid}&type=tcp&flow=xtls-rprx-vision#${node_name}${NC}"
    echo -e "\n${YELLOW}请注意: 如果您的服务器位于 NAT 后或有防火墙, 请确保端口 ${disp_port} 已正确放行 TCP 流量.${NC}"
    echo -e "${BLUE}========================================================${NC}"
}

# --- 菜单功能实现 ---
install_reality() {
    echo -e "\n${BLUE}--- 开始一键安装 Reality 代理 ---${NC}"
    if is_managed_install; then
        echo -n -e "${YELLOW}检测到已存在的 Reality 安装. 您想覆盖并重新安装吗? [y/N]: ${NC}"
        read -r confirm_reinstall
        if [[ ! "$confirm_reinstall" =~ ^[Yy]$ ]]; then echo -e "${BLUE}安装取消.${NC}"; return; fi
        echo -e "${YELLOW}将执行覆盖安装...${NC}"
    fi

    echo -e "\n${BLUE}阶段 1: 收集配置参数...${NC}"
    # 确保Xray已安装才能调用其uuid功能, 若要完全分离参数收集和环境安装, uuid生成需调整
    # 暂时假设Xray-core会在环境安装阶段早期被安装, 或在参数收集前单独安装
    # 为了满足严格的“先参数后环境”要求, Xray核心的安装要提前, 或者UUID生成方式改变
    # 折中：先安装Xray核心，以便使用其uuid和x25519功能, 然后收集参数
    # 或者，如果用户不输入uuid，就在环境安装后再生成并更新config。这会更复杂。

    # 调整：先进行必要的环境检查和Xray核心安装，以便参数收集阶段能顺利进行
    # 如果在get_user_input_interactive中需要调用xray命令(如uuid)，则xray core需先安装。
    # 这是一个两难：要么参数收集不依赖xray命令，要么xray命令相关的环境要先准备。
    # 我们让UUID/密钥生成依赖XRAY_INSTALL_PATH，所以Xray核心必须在参数收集前或参数收集中途可用。
    # 为简单起见，我们假设Xray安装脚本本身是安全的，不修改系统除非用户确认安装。
    # 更好的方法：get_user_input不依赖Xray命令，UUID/密钥在环境安装阶段生成。
    # 重新设计get_user_input，使其不依赖xray命令。
    # UUID和密钥对的生成将移至环境安装阶段。

    # 新get_user_input (不依赖xray命令)
    get_user_input_no_xray_deps() {
        echo -e "\n${BLUE}请输入 Reality 配置参数 (无需Xray依赖):${NC}"
        local prompt_sni="1. 请输入 SNI (当前: ${current_sni:-$DEFAULT_SNI}, 直接回车使用显示值): "
        read -rp "$prompt_sni" user_sni_input; final_sni=${user_sni_input:-${current_sni:-$DEFAULT_SNI}}
        if [[ -z "$final_sni" ]]; then echo -e "${RED}SNI 不能为空.${NC}"; return 1; fi
        echo -e "${GREEN}SNI 设置为: ${final_sni}${NC}"; final_dest_server="${final_sni}:443"; echo -e "${GREEN}目标服务器 (dest) 将自动设置为: ${final_dest_server}${NC}"

        echo -e "\n2. 请选择 Reality 监听端口:" # (端口选择逻辑同前)
        local port_option1_display="${current_listen_port:-$DEFAULT_LISTEN_PORT_OPTION1}"
        echo -e "   1) $port_option1_display (当前/默认推荐)"; echo -e "   2) 10000-60000 之间的随机端口"; echo -e "   3) 自定义端口"
        read -rp "   请输入选项 [1-3], 或直接输入具体端口号 (直接回车默认使用 $port_option1_display): " port_choice
        if [[ -z "$port_choice" ]]; then final_listen_port=$port_option1_display
        elif [[ "$port_choice" == "1" ]]; then final_listen_port=$port_option1_display
        elif [[ "$port_choice" == "2" ]]; then final_listen_port=$(shuf -i 10000-60000 -n 1); echo -e "${GREEN}   已选择随机端口: $final_listen_port${NC}"
        elif [[ "$port_choice" == "3" ]]; then while true; do read -rp "   请输入自定义端口 (1-65535): " custom_port; if [[ "$custom_port" =~ ^[0-9]+$ ]] && [ "$custom_port" -ge 1 ] && [ "$custom_port" -le 65535 ]; then final_listen_port=$custom_port; break; else echo -e "${YELLOW}   无效的端口号...${NC}"; fi; done
        elif [[ "$port_choice" =~ ^[0-9]+$ ]] && [ "$port_choice" -ge 1 ] && [ "$port_choice" -le 65535 ]; then final_listen_port=$port_choice
        else echo -e "${YELLOW}   无效的选择...将使用端口 $port_option1_display.${NC}"; final_listen_port=$port_option1_display; fi
        echo -e "${GREEN}监听端口设置为: $final_listen_port${NC}"

        local prompt_uuid=$'\n'"3. 请输入 UUID (当前: ${current_user_uuid:-留空将自动生成}, 留空则自动生成/使用当前值): "
        read -rp "$prompt_uuid" user_uuid_input; final_user_uuid_placeholder=${user_uuid_input:-${current_user_uuid:-"AUTO_GENERATE"}} # Placeholder
        echo -e "${GREEN}UUID 行为设置为: ${final_user_uuid_placeholder}${NC}"

        local prompt_short_id=$'\n'"4. 请输入 Short ID (当前: ${current_short_id_for_link:-留空将自动生成}, 逗号分隔, 留空则自动生成/使用当前值): "
        read -rp "$prompt_short_id" short_ids_input_str; final_short_id_placeholder=${short_ids_input_str:-${current_short_id_for_link:-"AUTO_GENERATE"}} # Placeholder
        echo -e "${GREEN}Short ID 行为设置为: ${final_short_id_placeholder}${NC}"
        # 实际的short_id_for_config_array和short_id_for_link将在环境安装阶段处理

        echo -e $'\n'"5. 请选择客户端 TLS 指纹 (Fingerprint/fp):" # (指纹选择逻辑同前)
        local fp_to_display_default="${current_fingerprint:-$DEFAULT_FP_OPTION}"
        for i in "${!AVAILABLE_FPS[@]}"; do local opt_num=$((i+1)); local opt_name="${AVAILABLE_FPS[$i]}"; if [[ "$opt_name" == "$fp_to_display_default" ]]; then echo -e "   $opt_num) $opt_name (当前/默认)"; else echo -e "   $opt_num) $opt_name"; fi; done
        read -rp "   请输入选项 [1-${#AVAILABLE_FPS[@]}] (直接回车默认使用 ${fp_to_display_default}): " fp_choice
        if [[ -z "$fp_choice" ]]; then final_fingerprint="$fp_to_display_default"
        elif [[ "$fp_choice" =~ ^[0-9]+$ ]] && [ "$fp_choice" -ge 1 ] && [ "$fp_choice" -le ${#AVAILABLE_FPS[@]} ]; then final_fingerprint="${AVAILABLE_FPS[$((fp_choice - 1))]}"
        else echo -e "${YELLOW}   无效的选择...将使用指纹 ${fp_to_display_default}.${NC}"; final_fingerprint="$fp_to_display_default"; fi
        echo -e "${GREEN}客户端指纹设置为: ${final_fingerprint}${NC}"
        return 0
    }
    # --- End of get_user_input_no_xray_deps ---

    load_install_details # 为get_user_input_no_xray_deps提供current_*值
    if ! get_user_input_no_xray_deps; then # 获取用户所有选择 (不依赖Xray)
        echo -e "${RED}参数输入有误或被取消, 中止安装.${NC}"; return
    fi

    echo -e "\n${BLUE}--- 请确认以下配置参数 ---${NC}"
    echo -e "SNI: ${GREEN}${final_sni}${NC}"
    echo -e "监听端口: ${GREEN}${final_listen_port}${NC}"
    echo -e "UUID (行为): ${GREEN}${final_user_uuid_placeholder}${NC}" # 显示占位符
    echo -e "Short ID (行为): ${GREEN}${final_short_id_placeholder}${NC}" # 显示占位符
    echo -e "客户端指纹: ${GREEN}${final_fingerprint}${NC}"
    echo -e "目标服务器 (dest - 自动设置): ${GREEN}${final_dest_server}${NC}"
    echo -e "-------------------------------------"
    echo -n -e "${YELLOW}以上参数是否正确并开始安装环境和配置服务? [Y/n]: ${NC}"
    read -r confirm_params
    if [[ "$confirm_params" =~ ^[Nn]$ ]]; then # 仅当输入 'n' 或 'N' 时取消
        echo -e "${BLUE}参数确认取消. 返回主菜单.${NC}"; return
    fi # 其他任何输入或直接回车都视为确认

    echo -e "\n${BLUE}阶段 2: 开始安装环境和配置服务...${NC}"
    check_os_compatibility || { return; } # 先检查OS
    install_dependencies || { echo -e "${RED}依赖安装失败, 中止安装.${NC}"; return; }
    install_xray_core || { echo -e "${RED}Xray核心安装失败, 中止安装.${NC}"; return; }

    # 处理UUID (现在Xray已安装)
    if [[ "$final_user_uuid_placeholder" == "AUTO_GENERATE" ]]; then
        final_user_uuid=$($XRAY_INSTALL_PATH uuid); echo -e "${GREEN}已自动生成 UUID: $final_user_uuid${NC}"
    else
        final_user_uuid=$final_user_uuid_placeholder; echo -e "${GREEN}UUID 设置为: $final_user_uuid${NC}"
    fi
    if [[ -z "$final_user_uuid" ]]; then echo -e "${RED}UUID 处理失败.${NC}"; return 1; fi

    # 处理ShortID (现在openssl可用, Xray核心也可用)
    if [[ "$final_short_id_placeholder" == "AUTO_GENERATE" ]]; then
        local gen_hex; gen_hex=$(openssl rand -hex 4)
        final_short_id_for_config_array="\"${gen_hex}\""; final_short_id_for_link="${gen_hex}"
        echo -e "${GREEN}已自动生成 Short ID: ${gen_hex}${NC}"
    else # 用户输入了值
        final_short_id_for_config_array=$(echo "$final_short_id_placeholder" | awk -F, '{for(i=1;i<=NF;i++) {gsub(/^[ \t]+|[ \t]+$/, "", $i); printf "\"%s\"%s", $i, (i==NF?"":",")}}')
        final_short_id_for_link=$(echo "$final_short_id_placeholder" | cut -d',' -f1 | sed 's/^[ \t]*//;s/[ \t]*$//')
        echo -e "${GREEN}Short ID(s) 设置为: ${final_short_id_placeholder} (客户端链接将使用: ${final_short_id_for_link})${NC}"
    fi
     if [[ -z "$final_short_id_for_link" ]]; then echo -e "${RED}Short ID 处理失败.${NC}"; return 1; fi


    generate_reality_keys_interactive || { echo -e "${RED}密钥生成失败, 中止安装.${NC}"; return; }
    create_xray_config_interactive || { echo -e "${RED}配置文件创建失败, 中止安装.${NC}"; return; }
    setup_systemd_service_interactive || { echo -e "${RED}服务设置失败, 中止安装.${NC}"; return; }

    save_install_details "$final_sni" "$final_listen_port" "$final_user_uuid" "$final_short_id_for_link" "$final_public_key" "$final_fingerprint" "$final_dest_server"

    local public_ip_addr; public_ip_addr=$(curl -s --max-time 5 ip.sb || curl -s --max-time 5 ifconfig.me || curl -s --max-time 5 api.ipify.org || echo "YOUR_SERVER_IP")
    display_client_config_info "$public_ip_addr" "$final_listen_port" "$final_user_uuid" "$final_sni" "$final_fingerprint" "$final_public_key" "$final_short_id_for_link" "$final_dest_server"
    echo -e "\n${GREEN}Reality 代理节点安装/配置完成!${NC}"
}

view_configuration() {
    echo -e "\n${BLUE}--- 查看当前 Reality 配置 ---${NC}"
    if ! is_managed_install; then echo -e "${YELLOW}未找到由本脚本管理的 Reality 安装信息. 请先安装.${NC}"; return; fi
    if ! load_install_details; then echo -e "${RED}无法加载安装详情.${NC}"; return; fi
    local stored_sni; stored_sni=$(jq -r '.sni' "$STATE_FILE"); # ... (其他stored_变量同之前)
    local stored_listen_port=$(jq -r '.listen_port' "$STATE_FILE"); local stored_uuid=$(jq -r '.uuid' "$STATE_FILE")
    local stored_short_id=$(jq -r '.short_id_for_link' "$STATE_FILE"); local stored_public_key=$(jq -r '.public_key' "$STATE_FILE")
    local stored_fingerprint=$(jq -r '.fingerprint' "$STATE_FILE"); local stored_dest_server=$(jq -r '.dest_server' "$STATE_FILE")

    if [[ -z "$stored_sni" || -z "$stored_listen_port" || -z "$stored_uuid" || -z "$stored_public_key" ]]; then echo -e "${RED}错误: 存储的配置信息不完整. 可能需要重新配置.${NC}"; return; fi
    local public_ip_addr; public_ip_addr=$(curl -s --max-time 5 ip.sb || curl -s --max-time 5 ifconfig.me || curl -s --max-time 5 api.ipify.org || echo "YOUR_SERVER_IP")
    display_client_config_info "$public_ip_addr" "$stored_listen_port" "$stored_uuid" "$stored_sni" "$stored_fingerprint" "$stored_public_key" "$stored_short_id" "$stored_dest_server"
}

modify_configuration() {
    echo -e "\n${BLUE}--- 修改 Reality 配置 ---${NC}"
    if ! is_managed_install; then echo -e "${YELLOW}未找到由本脚本管理的 Reality 安装信息. 请先安装.${NC}"; return; fi
    echo -e "${YELLOW}这将重新配置 Reality 服务, 但不会重装依赖或 Xray 核心 (除非Xray核心需要更新).${NC}"
    echo -e "${YELLOW}当前的 Reality 密钥对将会被重新生成.${NC}"

    load_install_details # 为 get_user_input_no_xray_deps 提供 current_*

    # 阶段1: 参数收集
    if ! get_user_input_no_xray_deps; then # 使用不依赖Xray的参数获取函数
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
    read -r confirm_mods
    if [[ "$confirm_mods" =~ ^[Nn]$ ]]; then echo -e "${BLUE}修改取消. 返回主菜单.${NC}"; return; fi

    echo -e "\n${BLUE}正在应用修改...${NC}"
    # 确保Xray核心是最新的, 因为修改配置时可能也想更新它
    install_xray_core || { echo -e "${RED}Xray核心更新失败, 中止修改.${NC}"; return; }

    # 处理UUID (现在Xray已安装/更新)
    if [[ "$final_user_uuid_placeholder" == "AUTO_GENERATE" ]]; then
        final_user_uuid=$($XRAY_INSTALL_PATH uuid); echo -e "${GREEN}已自动生成 UUID: $final_user_uuid${NC}"
    else
        final_user_uuid=$final_user_uuid_placeholder; echo -e "${GREEN}UUID 设置为: $final_user_uuid${NC}"
    fi
    if [[ -z "$final_user_uuid" ]]; then echo -e "${RED}UUID 处理失败.${NC}"; return 1; fi


    # 处理ShortID (现在openssl可用, Xray核心也可用)
    if [[ "$final_short_id_placeholder" == "AUTO_GENERATE" ]]; then
        local gen_hex; gen_hex=$(openssl rand -hex 4)
        final_short_id_for_config_array="\"${gen_hex}\""; final_short_id_for_link="${gen_hex}"
        echo -e "${GREEN}已自动生成 Short ID: ${gen_hex}${NC}"
    else # 用户输入了值
        final_short_id_for_config_array=$(echo "$final_short_id_placeholder" | awk -F, '{for(i=1;i<=NF;i++) {gsub(/^[ \t]+|[ \t]+$/, "", $i); printf "\"%s\"%s", $i, (i==NF?"":",")}}')
        final_short_id_for_link=$(echo "$final_short_id_placeholder" | cut -d',' -f1 | sed 's/^[ \t]*//;s/[ \t]*$//')
        echo -e "${GREEN}Short ID(s) 设置为: ${final_short_id_placeholder} (客户端链接将使用: ${final_short_id_for_link})${NC}"
    fi
    if [[ -z "$final_short_id_for_link" ]]; then echo -e "${RED}Short ID 处理失败.${NC}"; return 1; fi

    generate_reality_keys_interactive || { echo -e "${RED}密钥生成失败, 中止修改.${NC}"; return; }
    create_xray_config_interactive || { echo -e "${RED}配置文件创建失败, 中止修改.${NC}"; return; }
    setup_systemd_service_interactive || { echo -e "${RED}服务设置失败, 中止修改.${NC}"; return; }
    save_install_details "$final_sni" "$final_listen_port" "$final_user_uuid" "$final_short_id_for_link" "$final_public_key" "$final_fingerprint" "$final_dest_server"
    local public_ip_addr; public_ip_addr=$(curl -s --max-time 5 ip.sb || curl -s --max-time 5 ifconfig.me || curl -s --max-time 5 api.ipify.org || echo "YOUR_SERVER_IP")
    display_client_config_info "$public_ip_addr" "$final_listen_port" "$final_user_uuid" "$final_sni" "$final_fingerprint" "$final_public_key" "$final_short_id_for_link" "$final_dest_server"
    echo -e "\n${GREEN}Reality 配置修改完成!${NC}"
}

uninstall_reality() {
    echo -e "\n${BLUE}--- 卸载 Reality 代理 ---${NC}"
    if ! is_managed_install && ! systemctl list-unit-files | grep -q "xray.service"; then echo -e "${YELLOW}未检测到 Reality 安装 (通过本脚本或独立的 Xray 服务).${NC}"; return; fi
    echo -n -e "${RED}警告: 这将停止并移除 Xray 服务, 配置文件及本脚本存储的信息. 确定要卸载吗? [y/N]: ${NC}"
    read -r confirm_uninstall
    if [[ ! "$confirm_uninstall" =~ ^[Yy]$ ]]; then echo -e "${BLUE}卸载取消.${NC}"; return; fi

    if systemctl is-active --quiet xray; then echo -e "${YELLOW}正在停止 Xray 服务...${NC}"; systemctl stop xray; else echo -e "${BLUE}Xray 服务未在运行.${NC}"; fi
    if systemctl is-enabled --quiet xray; then echo -e "${YELLOW}正在禁用 Xray 服务...${NC}"; systemctl disable xray; else echo -e "${BLUE}Xray 服务未设置为开机自启.${NC}"; fi
    if [ -f "$XRAY_SERVICE_FILE" ]; then echo -e "${YELLOW}正在移除 systemd 服务文件 ($XRAY_SERVICE_FILE)...${NC}"; rm -f "$XRAY_SERVICE_FILE"; systemctl daemon-reload; else echo -e "${BLUE}Systemd 服务文件 ($XRAY_SERVICE_FILE) 不存在.${NC}"; fi

    echo -e "${YELLOW}正在尝试使用 Xray 官方脚本卸载 Xray 核心...${NC}"
    local xray_uninstalled_successfully=false
    if [ -f "/usr/local/bin/xray-uninstall.sh" ]; then # 优先使用本地卸载脚本
        if bash /usr/local/bin/xray-uninstall.sh remove --purge &>/dev/null; then xray_uninstalled_successfully=true; fi
    fi
    if ! $xray_uninstalled_successfully ; then # 如果本地卸载脚本失败或不存在，则重新下载执行
        if bash -c "$(curl -L ${XRAY_OFFICIAL_INSTALLER_URL})" @ remove --purge &>/dev/null; then xray_uninstalled_successfully=true; fi
    fi
    if $xray_uninstalled_successfully; then echo -e "${GREEN}Xray 核心卸载命令执行成功 (不代表所有文件都已清除).${NC}"; else echo -e "${YELLOW}Xray 核心卸载命令执行失败或未找到卸载脚本. 可能需要手动清理.${NC}"; fi
    # 强制清理，以防官方脚本不彻底或执行失败
    echo -e "${YELLOW}正在强制清理 Xray 相关目录和文件...${NC}"
    rm -rf "$XRAY_CONFIG_PATH"; rm -f "$XRAY_INSTALL_PATH"; rm -rf "/usr/local/share/xray"; rm -rf "/var/log/xray"
    echo -e "${YELLOW}正在移除本脚本存储的安装信息...${NC}"; rm -rf "$STATE_FILE_DIR"
    echo -e "${GREEN}Reality 代理及相关组件卸载完成.${NC}"
    echo -n -e "${YELLOW}是否删除此管理脚本 (${0}) 本身? [y/N]: ${NC}"; read -r delete_script_choice
    if [[ "$delete_script_choice" =~ ^[Yy]$ ]]; then echo -e "${YELLOW}正在删除管理脚本...${NC}"; rm -- "$0"; echo -e "${GREEN}管理脚本已删除. 再见!${NC}"; fi
}

# --- 主菜单 ---
main_menu() {
    clear
    echo -e "${BLUE}=============================================${NC}"
    echo -e "${GREEN}    Xray Reality 代理管理脚本 v${SCRIPT_VERSION}${NC}"
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
    echo -e "   ${RED}4)${NC} 卸载 Reality 代理"
    echo -e "---------------------------------------------"
    echo -e "   ${YELLOW}0)${NC} 退出脚本"
    echo -e "---------------------------------------------"
    read -rp "请输入选项 [0-4]: " choice

    case $choice in
        1) install_reality ;; 2) view_configuration ;; 3) modify_configuration ;;
        4) uninstall_reality ;; 0) echo -e "${GREEN}感谢使用, 正在退出...${NC}"; exit 0 ;;
        *) echo -e "${RED}无效选项! 请重新输入.${NC}"; sleep 2 ;;
    esac
    echo; read -rp "按任意键返回主菜单..." -n 1 -s
    main_menu
}

# --- 脚本开始执行 ---
trap 'echo -e "\n${YELLOW}操作被用户中断.${NC}"; exit 130' INT QUIT TERM # 捕获Ctrl+C等中断信号
check_root
main_menu
