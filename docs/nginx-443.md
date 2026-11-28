# 443 被 nginx 占着，让 Reality 也走 443

机器上已经有 nginx 在跑网站时，dun 装 Reality 会发现 443 被占用，自动换一个随机端口。节点照样能用，只是链接里带着这个端口，别人直接打开 `https://节点域名` 也看不到伪装站。

想让 Reality 也用 443，可以让 nginx 在 443 门口看一眼访问的是哪个域名：节点域名的连接原样转给 Reality，其他的照旧交给你的网站。dun 不会自动改你的 nginx，下面是手动的做法，按顺序来。

## 原理

TLS 握手的第一个包里写着要访问的域名，也就是 SNI。nginx 的 stream 模块配上 `ssl_preread`，可以只读这个域名，不解密，然后把整条连接原封不动转出去。Reality 收到的握手和客户端直连时一模一样。

```
客户端 ──443──▶ nginx stream
                 ├─ SNI 是节点域名 ──▶ 127.0.0.1:8444 ──▶ Reality
                 └─ 其他 ───────────▶ 127.0.0.1:8443 ──▶ 你原来的网站
```

网站从 443 挪到本机的 8443，对外还是 443，访客感觉不到。中间多了一跳，网站看到的来源会变成 127.0.0.1，所以要用 proxy_protocol 把访客的真实 IP 带过去。去 Reality 的那一跳要再经过 8444 把这个头摘掉，因为 sing-box 不认它。

8443、8444 只是例子，换成机器上空着的端口都行。

## 准备

先记下两样东西。

```bash
dun links | grep vless
```

`sni=` 后面是节点域名。Reality 的监听端口在 `/etc/dun/state.json` 里 `"reality"` 那段的 `"port"`，装的时候屏幕上也显示过。

改之前把 nginx 配置整个备份一份：

```bash
cp -a /etc/nginx /etc/nginx.bak-dun
```

## 第一步：装 stream 模块

```bash
nginx -V 2>&1 | tr ' ' '\n' | grep -E -- '^--with-stream(=dynamic)?$'
```

- 输出 `--with-stream`：模块已经编进去了，跳过这一步
- 输出 `--with-stream=dynamic`：模块要另外装，装过的再装一次也没事。Debian、Ubuntu 用 `apt install libnginx-mod-stream`，CentOS、Rocky、Alma 用 `dnf install nginx-mod-stream`，Alpine 用 `apk add nginx-mod-stream`
- 什么都没有：这个 nginx 不带 stream，没法这样做，Reality 就留在随机端口

nginx 官方源的包自带 stream。

## 第二步：网站挪到 8443

找出所有监听 443 的地方：

```bash
grep -rn 'listen.*443' /etc/nginx/
```

每个 `server` 里 TCP 的 443 都这样改：

```nginx
# 改前
listen 443 ssl;
listen [::]:443 ssl;

# 改后
listen 127.0.0.1:8443 ssl proxy_protocol;
```

- IPv6 那行删掉。对外的 IPv4、IPv6 都由下一步的 stream 接，网站只需要监听本机
- 原来带 `default_server`、`reuseport` 的，参数照抄到新的那行
- `listen 443 quic` 这类 HTTP/3 的行不用改，那是 UDP，和这里不冲突
- `http2 on;`、证书这些都不动

然后在 http 里加三行。Debian、Ubuntu、CentOS 可以新建 `/etc/nginx/conf.d/dun-443.conf`，Alpine 放在 `/etc/nginx/http.d/` 下：

```nginx
set_real_ip_from 127.0.0.1;
real_ip_header proxy_protocol;
port_in_redirect off;
```

前两行把访客的真实 IP 还原回 `$remote_addr`，日志、限流、fail2ban 照常工作。第三行不能省：网站现在监听的是 8443，nginx 自己发的跳转会把端口带出去，比如打开 `/docs` 会被跳到 `https://你的站:8443/docs/`。

## 第三步：在 443 上分流

新建 `/etc/nginx/dun-stream.conf`，把节点域名和 Reality 端口换成你自己的：

```nginx
stream {
    map $ssl_preread_server_name $dun_upstream {
        节点域名    127.0.0.1:8444;
        default     127.0.0.1:8443;
    }

    server {
        listen 443;
        listen [::]:443;
        ssl_preread on;
        proxy_protocol on;
        proxy_pass $dun_upstream;
    }

    # 去 Reality 的这一跳把 proxy_protocol 头摘掉
    server {
        listen 127.0.0.1:8444 proxy_protocol;
        proxy_pass 127.0.0.1:Reality端口;
    }
}
```

stream 要和 http 平级，不能写进 conf.d，那里面的文件是在 http 里引入的。在 `/etc/nginx/nginx.conf` 的最后一行加上：

```nginx
include /etc/nginx/dun-stream.conf;
```

机器没有 IPv6 的，把 `listen [::]:443;` 删掉。

检查并生效：

```bash
nginx -t && systemctl reload nginx
```

`nginx -t` 报错就别 reload，照报错改，改不明白就按最后一节还原。最常见的是 `unknown directive "stream"`，说明模块装了但没加载。Debian、Ubuntu 看 `/etc/nginx/modules-enabled/` 里有没有 stream，没有就补一个链接：

```bash
ln -s /usr/share/nginx/modules-available/mod-stream.conf /etc/nginx/modules-enabled/50-mod-stream.conf
```

## 第四步：让 dun 的链接写 443

打开 `/etc/dun/state.json`，在 `"reality"` 那段里把 `"pub_port"` 改成 `443`，`"port"` 不要动。然后：

```bash
dun apply
dun links
```

现在链接里 Reality 的端口是 443，订阅地址也不带端口了。客户端重新导入一次订阅。旧的订阅地址还能用，因为 Reality 的随机端口还开着。

## 验证

- 打开你原来的网站，一切照常；看一眼 access.log，来源是访客的真实 IP，不是 127.0.0.1
- 浏览器打开 `https://节点域名`，能看到登录页，证书有效
- 客户端用新订阅连 Reality，能上网

## 以后要注意

- 你的程序或配置里用到 `$server_port` 的，现在拿到的是 8443。常见的是 `proxy_set_header X-Forwarded-Port $server_port`，改成写死 443
- 网站前面本来就套了 CDN、自己配过 `real_ip_header` 的，第二步那三行要和原来的配置合并，别直接叠加，同一层只能有一个 `real_ip_header`
- 用面板管理 nginx 的，面板重新生成配置时可能会把第二步改掉，改之前先看看面板支不支持自定义监听
- AnyTLS 和 Reality 用的是同一个节点域名，nginx 分不出来，所以 AnyTLS 只能留在自己的端口
- 以后在 dun 里改了 Reality 端口，`dun-stream.conf` 里的端口要跟着改，`pub_port` 也要再改回 443

## 还原

```bash
rm -rf /etc/nginx && mv /etc/nginx.bak-dun /etc/nginx
nginx -t && systemctl restart nginx
```

再把 `/etc/dun/state.json` 里 Reality 的 `pub_port` 改回和 `port` 一样，执行 `dun apply`，客户端重新导入订阅。
