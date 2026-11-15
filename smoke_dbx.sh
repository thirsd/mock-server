#!/usr/bin/env bash
# 多用户联调冒烟脚本: 以独立进程启动全部 mock 服务, 验证 dbx 集成新增能力。
# 用法: bash smoke_dbx.sh   (在项目根目录执行; 结束时自动清理后台进程)

set -u
cd "$(dirname "$0")"
PY=".venv/Scripts/python.exe"
JAR_O="$(mktemp -u).jar" ; JAR_G="$(mktemp -u).jar"
ECHO_PORT=18999

# 预清理: 杀掉仍占用本脚本端口的残留进程(Windows 下 bash kill 杀不死 exe 子进程)
for PORT in 13890 8111 8112 8113 8114 $ECHO_PORT; do
  for PID in $(netstat -ano | grep ":$PORT " | grep LISTENING | awk '{print $NF}' | sort -u); do
    taskkill //F //PID "$PID" > /dev/null 2>&1 || true
  done
done
sleep 1

echo "=== 启动服务(ldap:13890 / oidc:8111 / callback:8112 / proxy-app:8113 / gateway:8114 / echo:$ECHO_PORT) ==="
"$PY" ldap/mock_ldap_auth.py --port 13890 & PID_LDAP=$!
"$PY" oidc/mock_oidc_auth.py --port 8111 & PID_OIDC=$!
"$PY" http_callback/mock_http_callback_auth.py --port 8112 & PID_CB=$!
"$PY" proxy_header/mock_proxy_header_auth.py --port 8113 & PID_PX=$!
PROXY_UPSTREAM="http://127.0.0.1:$ECHO_PORT" "$PY" proxy_header/mock_proxy_gateway.py --port 8114 --upstream "http://127.0.0.1:$ECHO_PORT" & PID_GW=$!
"$PY" -c "
import uvicorn
from fastapi import FastAPI, Request
app = FastAPI()
@app.api_route('/{path:path}', methods=['GET','POST'])
async def echo(request: Request, path: str):
    return {'user': request.headers.get('x-forwarded-user'),
            'groups': request.headers.get('x-forwarded-groups'),
            'path': request.url.path}
uvicorn.run(app, host='127.0.0.1', port=$ECHO_PORT, log_level='error')
" & PID_ECHO=$!
sleep 6

echo
echo "=== 1) OIDC 登录页(无会话 GET /authorize → HTML) ==="
curl -s "http://127.0.0.1:8111/authorize?response_type=code&client_id=demo-client&redirect_uri=http://127.0.0.1:4224/api/auth/oidc/sso/callback&scope=openid&state=s1" | grep -o "<title>[^<]*</title>"
echo "=== 2) OIDC 登录页提交 carol → 302 + 会话 cookie ==="
LOC=$(curl -s -o /dev/null -w "%{redirect_url}" -c "$JAR_O" -X POST http://127.0.0.1:8111/authorize \
  -d "response_type=code&client_id=demo-client&redirect_uri=http://127.0.0.1:4224/api/auth/oidc/sso/callback&scope=openid&state=s1&username=carol&password=carol-password")
echo "redirect: $LOC"
echo "=== 3) OIDC IdP 会话 SSO(同浏览器再次 authorize 免登录直接发 code) ==="
LOC2=$(curl -s -o /dev/null -w "%{redirect_url}" -b "$JAR_O" \
  "http://127.0.0.1:8111/authorize?response_type=code&client_id=demo-client&redirect_uri=http://127.0.0.1:4224/api/auth/oidc/sso/callback&scope=openid&state=s1")
echo "redirect: $LOC2"
echo "=== 4) OIDC /logout 清会话 ==="
curl -s -b "$JAR_O" -o /dev/null -w "logout HTTP %{http_code}\n" http://127.0.0.1:8111/logout
echo "=== 5) OIDC id_token claims(carol 密码模式换取后解码) ==="
TOKENS=$(curl -s -u demo-client:demo-secret -d "grant_type=password&username=carol&password=carol-password" http://127.0.0.1:8111/token)
echo "$TOKENS" | "$PY" -c "
import sys, json, urllib.request, jwt
t = json.load(sys.stdin)
jwks = json.load(urllib.request.urlopen('http://127.0.0.1:8111/.well-known/jwks.json'))
key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwks['keys'][0]))
claims = jwt.decode(t['id_token'], key, algorithms=['RS256'], audience='demo-client', issuer='http://127.0.0.1:8111')
print('preferred_username =', claims['preferred_username'], '| groups =', claims['groups'])
"

echo
echo "=== 6) HTTP Callback dbx 原生契约 /auth/callback ==="
curl -s -X POST http://127.0.0.1:8112/auth/callback -H "Content-Type: application/json" \
  -d '{"username":"carol","password":"carol-password"}'; echo
curl -s -o /dev/null -w "wrong-password -> HTTP %{http_code}\n" -X POST http://127.0.0.1:8112/auth/callback \
  -H "Content-Type: application/json" -d '{"username":"alice","password":"bad"}'
curl -s -X POST http://127.0.0.1:8112/auth/callback -H "Content-Type: application/json" -d '{"ping":true}'; echo

echo
echo "=== 7) LDAP carol 登录 + memberOf ==="
"$PY" -c "
import ldap3
s = ldap3.Server('127.0.0.1', port=13890, get_info=ldap3.NONE)
c = ldap3.Connection(s, 'uid=carol,ou=people,dc=example,dc=org', 'carol-password')
print('carol bind ok:', c.bind())
c.search('ou=people,dc=example,dc=org', '(uid=carol)', attributes=['memberOf','displayName'])
e = c.entries[0]
print('displayName:', e.displayName.value, '| memberOf:', sorted(e.memberOf.values))
"

echo
echo "=== 8) 网关: 未认证 → 登录页; 登录 alice → 注入 X-Forwarded-User 到上游 echo ==="
curl -s -o /dev/null -w "unauthenticated /echo -> HTTP %{http_code}(登录页)\n" "http://127.0.0.1:8114/echo"
curl -s -o /dev/null -w "login alice -> HTTP %{http_code}\n" -c "$JAR_G" -X POST "http://127.0.0.1:8114/__gw/login" \
  -d "username=alice&password=alice-password&next=/echo"
curl -s -b "$JAR_G" "http://127.0.0.1:8114/echo"; echo "  <- 上游 echo 收到的身份头"
curl -s -b "$JAR_G" -H "X-Forwarded-User: mallory" "http://127.0.0.1:8114/echo"; echo "  <- 伪造头被剥离"
curl -s -b "$JAR_G" -o /dev/null -w "logout -> HTTP %{http_code}\n" "http://127.0.0.1:8114/logout"

echo
for PID in $PID_LDAP $PID_OIDC $PID_CB $PID_PX $PID_GW $PID_ECHO; do
  taskkill //F //PID "$PID" > /dev/null 2>&1 || kill "$PID" 2>/dev/null || true
done
rm -f "$JAR_O" "$JAR_G"
echo "=== smoke done ==="
