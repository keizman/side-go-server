# side-go-server

Go 后端服务（实验阶段），用于浏览器扩展认证与业务接口验证，支持 `AUTH` / `BUSINESS` 双模式。

## 关键内容

- 运行模式：
  - `AUTH`：签发与校验 Token（`/auth_token`、`/check_token`、`/api/register`）
  - `BUSINESS`：业务接口与签名校验（`/api/login`、`/api/logout`、`/api/logout_all`、`/api/translate`、`/api/user/profile`）
- 关键模块：
  - `auth/`：token 生命周期、nonce、防重放、限流
  - `middleware/`：请求签名验证
  - `api/`：注册/登录/登出等处理器
  - `repository/`：用户数据访问（PostgreSQL）
  - `internal/redis`、`internal/database`：基础设施连接
- 当前已补充失败路径详细日志，便于实验阶段定位问题。

## 启动要求

- Go `1.21+`
- PostgreSQL
- Redis
- 环境变量参考 `.env.example`

## 测试策略（当前）

- 单元 + BDD 场景测试（`Given/When/Then` 命名）：
  - `api/`、`auth/`、`middleware/`、`config/`、`internal/*`
- 集成测试：
  - `repository/user_repository_integration_test.go` 连接真实 PostgreSQL 验证 CRUD/密码校验/管理员创建逻辑
- Redis 相关测试使用 `miniredis`，避免依赖外部服务
- 回归要求包含普通测试、竞态检测和覆盖率

## 测试命令

```bash
go test -count=1 ./...
go test -race -count=1 ./...
go test -cover -count=1 ./...
```

如需跑仓储集成测试，请提供 DB 连接（任选其一）：

```bash
SIDE_GO_SERVER_TEST_DATABASE_URL=postgresql://... go test -count=1 ./repository
# 或使用
DATABASE_URL=postgresql://... go test -count=1 ./repository
```

## 开发与提交流程（强制）

新增或修改功能时，必须同时完成以下事项：

1. 在对应模块补充或更新测试用例。
2. 测试用例必须覆盖：
   - 正常路径
   - 常见异常路径（参数错误、依赖失败、权限/签名失败、边界条件）
3. 用例命名建议采用 BDD 风格：`Given...When...Then...`。
4. 修改完成后必须执行：
   - `go test -count=1 ./...`
   - `go test -race -count=1 ./...`
5. 测试不通过不得提交。

## 说明

- 本项目处于实验阶段，日志与测试优先级高于“快速上线”。
- 禁止在日志中打印敏感信息（密码、token、secret、salt）。
