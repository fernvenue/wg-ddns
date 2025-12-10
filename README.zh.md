# WireGuard DDNS

[![wg-ddns](https://img.shields.io/badge/LICENSE-GPLv3%20Liscense-blue?style=flat-square)](./LICENSE)
[![wg-ddns](https://img.shields.io/badge/GitHub-WireGuard%20DDNS-blueviolet?style=flat-square&logo=github)](https://github.com/fernvenue/wg-ddns)

為 WireGuard 提供 DDNS 動態域名解析支援的輕量級工具.

## 功能

- [x] 支援自動發現當前活躍的 WireGuard 接口並檢查 `wg-quick` 配置;
- [x] 支援自定義 DNS 解析檢查間隔;
- [x] 支援單接口模式, 可指定 WireGuard 接口名稱;
- [x] 提供 API 接口, 可通過 Webhook 觸發 WireGuard 接口重啟;
- [x] API 接口提供基於 Header 的身份認證;
- [x] API 接口提供 Swagger 文檔支援;
- [x] 豐富的日志輸出, 支援 INFO, DEBUG 等級別;
- [x] 環境變量支援;
- [x] 提供 systemd service 模板;
- [x] 通過 Nix 進行打包和部署.

## 參數說明

- `--single-interface`: 指定單一的 WireGuard 接口進行監控, 如果不指定則自動發現所有活躍接口;
- `--listen-address`: 啟用 API 服務時的監聽地址, 支援 IPv4 和 IPv6 地址;
- `--listen-port`: 啟用 API 服務時的監聽端口;
- `--api-key`: 啟用 API 服務時的身份認證密鑰;
- `--log-level`: 日志輸出等級, 可選值為 `debug`, `info`, `warn`, `error`, 默認值為 `info`;
- `--check-interval`: DNS 解析檢查間隔, 支援時間單位如 `s`, `m`, `h`, 默認值為 `10s`;
- `--check-only`: 檢查活躍的 WireGuard 接口並退出 (不啟動監控);
- `--version`: 顯示版本信息;
- `--help`: 顯示幫助信息.

## 環境變量

除了命令行參數外, 所有配置選項都支援通過環境變量設置:

- `WG_DDNS_SINGLE_INTERFACE`: 對應 `--single-interface`
- `WG_DDNS_LISTEN_ADDRESS`: 對應 `--listen-address`
- `WG_DDNS_LISTEN_PORT`: 對應 `--listen-port`
- `WG_DDNS_API_KEY`: 對應 `--api-key`
- `WG_DDNS_LOG_LEVEL`: 對應 `--log-level`
- `WG_DDNS_CHECK_INTERVAL`: 對應 `--check-interval`

**注意**: 命令行參數優先於環境變量.

## 安装

### Nix 包管理器

通過 Nix 包管理器，你可以輕鬆安装 wg-ddns:

- 從 nixpkgs 安装

```bash
nix profile install nixpkgs#wg-ddns
```

- 從 GitHub 倉庫安装

```bash
nix profile install github:fernvenue/wg-ddns
```

- 從本地源碼構建

```bash
git clone https://github.com/fernvenue/wg-ddns.git
cd wg-ddns
nix build
./result/bin/wg-ddns --help
```

## 使用示例

- 自動發現

```
wg-ddns
```

- 指定接口

```
wg-ddns --single-interface wg0
```

- 指定檢查間隔

```
wg-ddns --check-interval 5m
```

- 啟用調試日志

```
wg-ddns --log-level debug
```

- 啟用 API 服務

```
wg-ddns --listen-address "[::1]" --listen-port 8080 --api-key "your_api_key"
```

- 單接口模式下啟用 API 服務

```
wg-ddns --single-interface wg0 --listen-address "[::1]" --listen-port 8080 --api-key "your_api_key"
```

- 快速檢查活躍接口

```
wg-ddns --check-only
```

- 檢查指定接口

```
wg-ddns --check-only --single-interface wg0
```
