#!/usr/bin/env bash
# =============================================================================
# mock 认证服务统一启停脚本(Git Bash / MSYS2 on Windows)
#
# 服务清单:
#   ldap           13890   ldap/mock_ldap_auth.py
#   oidc            8111   oidc/mock_oidc_auth.py
#   http_callback   8112   http_callback/mock_http_callback_auth.py
#   proxy_header    8113   proxy_header/mock_proxy_header_auth.py  (被保护应用示例)
#   gateway         8114   proxy_header/mock_proxy_gateway.py      (→ 注入身份头到 dbx)
#
# 用法:
#   bash mocks.sh start    [服务名...]        # 启动(缺省全部; 已在运行则跳过)
#   bash mocks.sh stop     [服务名...]        # 停止(缺省全部)
#   bash mocks.sh restart  [服务名...]        # 重启 = 先停后起(批量重启所有进程用这个)
#   bash mocks.sh status   [服务名...]        # 查看运行状态
#   bash mocks.sh logs     <服务名> [行数]    # 查看服务日志(默认 40 行)
#
# 实现说明:
#   - Windows 下 bash 的 kill 对 exe 子进程不可靠(曾出现残留进程占用端口),
#     本脚本统一按端口定位 Windows PID(netstat -ano)后用 taskkill //F 终止, 跨会话可靠。
#   - 仅当端口占用者是 python 进程时才终止; 被其他程序占用时只提示不强杀。
#   - 环境变量按调用方继承, 例如:
#       MOCK_CB_REQUIRE_SECRET=1 bash mocks.sh restart http_callback
#       PROXY_UPSTREAM=http://127.0.0.1:4224 bash mocks.sh restart gateway
#       MOCK_USERS_JSON='{"erin":{"groups":["ops-admin"]}}' bash mocks.sh restart
#   - 日志: logs/<服务名>.log(每次 start 清空重写)
# =============================================================================

set -u
cd "$(dirname "$0")"

PY=".venv/Scripts/python.exe"
LOG_DIR="logs"

SERVICES=(ldap oidc http_callback proxy_header gateway)

declare -A PORT=(
  [ldap]=13890
  [oidc]=8111
  [http_callback]=8112
  [proxy_header]=8113
  [gateway]=8114
)
declare -A SCRIPT=(
  [ldap]="ldap/mock_ldap_auth.py"
  [oidc]="oidc/mock_oidc_auth.py"
  [http_callback]="http_callback/mock_http_callback_auth.py"
  [proxy_header]="proxy_header/mock_proxy_header_auth.py"
  [gateway]="proxy_header/mock_proxy_gateway.py"
)
declare -A ENDPOINT=(
  [ldap]="ldap://127.0.0.1:13890"
  [oidc]="http://127.0.0.1:8111/.well-known/openid-configuration"
  [http_callback]="http://127.0.0.1:8112/auth/callback"
  [proxy_header]="http://127.0.0.1:8113/me"
  [gateway]="http://127.0.0.1:8114  ->  ${PROXY_UPSTREAM:-http://127.0.0.1:4224}"
)

# ---------------------------------------------------------------- 基础工具

pids_on_port() {
  # 输出: 监听指定端口的 Windows PID 列表(去重)
  netstat -ano 2>/dev/null | awk -v p=":$1" '$4 == "LISTENING" && $2 ~ p"$" {print $5}' | sort -u
}

port_listening() { [ -n "$(pids_on_port "$1")" ]; }

process_name() {
  # tasklist 偶发返回空(WMI 查询抖动): 重试 3 次, 仍失败则用 PowerShell 兜底
  local pid="$1" name="" i
  for i in 1 2 3; do
    name="$(tasklist //FI "PID eq $pid" //FO CSV //NH 2>/dev/null | head -1 | cut -d'"' -f2)"
    [ -n "$name" ] && { echo "$name"; return 0; }
    sleep 0.3
  done
  name="$(powershell -NoProfile -Command "(Get-Process -Id $pid -ErrorAction SilentlyContinue).ProcessName" 2>/dev/null | tr -d '\r' | head -1)"
  [ -n "$name" ] && echo "$name"
  return 0
}

wait_for() {  # wait_for <端口> <超时秒> — 等待端口开始监听
  local deadline=$(( $(date +%s) + $2 ))
  while [ "$(date +%s)" -le "$deadline" ]; do
    port_listening "$1" && return 0
    sleep 0.3
  done
  return 1
}

wait_free() {  # wait_free <端口> <超时秒> — 等待端口释放
  local deadline=$(( $(date +%s) + $2 ))
  while [ "$(date +%s)" -le "$deadline" ]; do
    port_listening "$1" || return 0
    sleep 0.3
  done
  return 1
}

resolve_targets() {  # 校验服务名, 无参数时取全部; 结果写入全局数组 targets
  targets=()
  if [ "$#" -gt 0 ]; then
    local t
    for t in "$@"; do
      if [ -z "${PORT[$t]+x}" ]; then
        echo "未知服务: $t (可用: ${SERVICES[*]})" >&2
        return 1
      fi
      targets+=("$t")
    done
  else
    targets=("${SERVICES[@]}")
  fi
}

# ---------------------------------------------------------------- 启动/停止/状态

start_one() {
  local name="$1"
  local port=${PORT[$name]}
  if port_listening "$port"; then
    echo "[$name] 端口 $port 已有监听, 跳过启动(强制重启: bash mocks.sh restart $name)"
    return 0
  fi
  if [ ! -f "$PY" ]; then
    echo "[$name] 未找到 $PY — 请先在项目根目录执行: uv sync" >&2
    return 1
  fi
  mkdir -p "$LOG_DIR"
  local extra=()
  if [ "$name" = "gateway" ]; then
    extra=(--upstream "${PROXY_UPSTREAM:-http://127.0.0.1:4224}")
  fi
  : > "$LOG_DIR/$name.log"
  PYTHONUNBUFFERED=1 PYTHONUTF8=1 "$PY" "${SCRIPT[$name]}" ${extra[@]+"${extra[@]}"} \
    >> "$LOG_DIR/$name.log" 2>&1 &
  local pid=$!
  if wait_for "$port" 20; then
    echo "[$name] 已启动   ${ENDPOINT[$name]}   (日志: $LOG_DIR/$name.log)"
  else
    echo "[$name] 启动超时/失败 — 最近日志:"
    tail -n 8 "$LOG_DIR/$name.log" | sed 's/^/    /'
    return 1
  fi
}

stop_one() {
  local name="$1"
  local port=${PORT[$name]}
  local pids
  pids="$(pids_on_port "$port")"
  if [ -z "$pids" ]; then
    echo "[$name] 未运行(端口 $port 无监听)"
    return 0
  fi

  local skipped="" p pname err
  for p in $pids; do
    pname="$(process_name "$p")"
    if [ -z "$pname" ]; then
      continue  # 进程已不存在(正在退出), 交给 wait_free 判断
    fi
    case "$pname" in
      python*|Python*)
        err="$(taskkill //F //PID "$p" 2>&1)"
        if [ $? -eq 0 ]; then
          echo "[$name] 已终止 pid=$p"
        else
          echo "[$name] 终止 pid=$p 失败: $err"
          echo "[$name] 提示: 该进程可能由管理员权限的终端启动 — 请在管理员终端执行 stop, 或手动 taskkill /F /PID $p"
        fi
        ;;
      *)
        skipped="$skipped  pid=$p($pname)"
        ;;
    esac
  done

  if [ -n "$skipped" ]; then
    echo "[$name] 端口 $port 被非 python 进程占用, 未强制终止:$skipped"
    echo "[$name] 如确认无误请手动执行: taskkill //F //PID <pid>"
  fi

  if wait_free "$port" 8; then
    echo "[$name] 端口 $port 已释放"
    return 0
  fi
  echo "[$name] 端口 $port 仍被占用 — 请以管理员身份运行 Git Bash 后重试 stop"
  return 1
}

status_one() {
  local name="$1"
  local port=${PORT[$name]}
  local pids
  pids="$(pids_on_port "$port")"
  if [ -n "$pids" ]; then
    local first
    first="$(echo "$pids" | head -1)"
    echo "[$name] 运行中   ${ENDPOINT[$name]}   (pid: $(echo "$pids" | tr '\n' ' ')$(process_name "$first"))"
  else
    echo "[$name] 未运行   ${ENDPOINT[$name]}"
  fi
}

cmd_logs() {
  local name="${1:-}" lines="${2:-40}"
  if [ -z "$name" ]; then
    echo "用法: bash mocks.sh logs <服务名> [行数]   (服务名: ${SERVICES[*]})"
    return 1
  fi
  [ -z "${PORT[$name]+x}" ] && { echo "未知服务: $name (可用: ${SERVICES[*]})"; return 1; }
  local f="$LOG_DIR/$name.log"
  if [ ! -f "$f" ]; then
    echo "日志不存在: $f(服务尚未通过本脚本启动过)"
    return 1
  fi
  tail -n "$lines" "$f"
}

usage() {
  sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
}

# ---------------------------------------------------------------- 入口

cmd="${1:-help}"
[ "$#" -gt 0 ] && shift

case "$cmd" in
  start | stop | restart | status)
    resolve_targets "$@" || exit 1
    if [ "$cmd" = "restart" ]; then
      echo "=== restart: 先停止 ${targets[*]} ==="
      for t in "${targets[@]}"; do stop_one "$t"; done
      echo "=== restart: 重新启动 ${targets[*]} ==="
    fi
    rc=0
    for t in "${targets[@]}"; do
      case "$cmd" in
        start | restart) start_one "$t" || rc=1 ;;
        stop)            stop_one "$t" || rc=1 ;;
        status)          status_one "$t" ;;
      esac
    done
    exit $rc
    ;;
  logs)
    cmd_logs "$@"
    ;;
  help | -h | --help)
    usage
    ;;
  *)
    echo "未知命令: $cmd"
    usage
    exit 1
    ;;
esac
