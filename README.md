# FastApiBackend

FastApiBackend 是一个使用 FastAPI 构建的后端项目。

## 主要特性

- 使用 FastAPI，一个现代的，快速的 (高性能)，基于标准 Python 类型提示的 Web 框架。
- 使用 SQLAlchemy 作为 ORM。
- 使用 JWT 进行身份验证。
- 包含用户管理和令牌管理路由。
- 使用验证码进行安全验证。
- 使用 Loguru 进行日志管理。

## 安装

首先，你需要安装 Python 和 pdm。

```bash
pip install pdm
```

然后，你可以使用以下命令安装项目依赖：

```bash
pdm install
``` 

## 运行

你可以使用以下命令运行项目：

```bash
pdm run start
```

## 贡献

欢迎任何形式的贡献。如果你发现了任何问题，或者有任何改进的建议，欢迎提交 issue 或 pull request。

## 许可证

此项目遵循 MIT 许可证。详情请参见 [LICENSE](LICENSE) 文件。