# 凭证读取与网页应用配置

## 凭证读取

```bash
dws devapp credentials get --unified-app-id UNIFIED_APP_ID --format json
dws devapp credentials get --agent-id 123456 --format json
```

MCP tool: `get_open_dev_app_credentials`

后端 facade: `OpenInnerAppQueryFacade.getCredentials`。

**规则：**
- CLI 只传应用定位字段，不传 `showSecret`/`confirmSecret`。
- 返回可能包含 `clientSecret/appSecret`，输出按敏感凭证处理。
- 不能用 `devapp get` 代替，即使 get 偶尔返回 secret。

关键返回字段：

| 字段 | 说明 |
|------|------|
| `clientId` / `appKey` | 非密钥标识 |
| `clientSecret` / `appSecret` | 敏感凭证 |
| `currentSecretStatus` | 当前密钥状态 |
| `pendingExpireTask` | 密钥过期任务信息 |

## 网页应用查询

```bash
dws devapp webapp get --agent-id 123456 --format json
dws devapp webapp get --unified-app-id UNIFIED_APP_ID --format json
```

MCP tool: `get_webapp_config`

未配置网页应用前可能只返回 `agentId`。

## 网页应用配置

```bash
dws devapp webapp config --agent-id 123456 --homepage-link https://example.com/mobile --dry-run --format json
dws devapp webapp config --agent-id 123456 --homepage-link https://example.com/mobile --pc-homepage-link https://example.com/pc --yes --format json
```

MCP tool: `set_webapp_config`

| CLI | MCP | 说明 |
|-----|-----|------|
| `--h5-page-type` | `h5PageType` | 网页应用生效端 |
| `--homepage-link` | `homepageLink` | 移动端首页地址 |
| `--pc-homepage-link` | `pcHomepageLink` | PC 端首页地址 |
| `--omp-link` | `ompLink` | 管理后台地址 |

至少提供一个配置字段。`h5PageType` 未传入时后端默认返回 `all`。
