# Github 代理样例

本样例展示搭建一个 Github 专用的 SSH 代理的功能。

在一个可访问 Github 的服务器上执行该样例的 SRP 服务：

```bash
go run ./examples/github/main.go
```

随后在本地添加以下 SSH 配置到 `~/.ssh/config` 文件中：

```
Host github.com
    ProxyJump your_server_ip:8022
```

然后 git 工具就可以通过该代理服务器访问 Github 了。
