# 簡易 Layer-3 路由器模擬系統

以純 C 語言實作的輕量級 **Layer-3 路由引擎**，模擬工業級網路路由器的核心功能：靜態路由（最長前綴匹配）、ARP 快取、ACL 封包過濾，以及每介面流量統計。

> 作為嵌入式網路職位（如 Moxa 交換器／路由器韌體）的作品集專案。

---

## 功能特色

| 模組 | 說明 |
|------|------|
| **靜態路由** | 32 筆路由表的最長前綴匹配（LPM） |
| **ARP 快取** | IP→MAC 解析，模擬快取命中／未命中流程 |
| **ACL 過濾** | 依來源 IP、目的 IP、協定進行 permit/deny 規則比對 |
| **TTL 處理** | 遞減並在過期時丟棄（預留 ICMP Time Exceeded 回應） |
| **介面統計** | 每介面 RX/TX 封包數、位元組數、丟棄計數器 |
| **預設路由** | 支援 0.0.0.0/0 fallback gateway |

---

## 專案架構

```
router_sim/
├── Makefile
├── include/
│   └── router.h          # 所有型別、結構體與函式宣告
└── src/
    ├── utils.c           # IP checksum、字串轉換工具
    ├── router_init.c     # 路由器與介面初始化
    ├── route.c           # 靜態路由表 + LPM 查詢
    ├── arp.c             # ARP 快取新增／查詢／列印
    ├── acl.c             # ACL 規則新增／比對／列印
    ├── forward.c         # 封包轉發核心邏輯
    └── main.c            # 示範：拓樸建立 + 5 個測試情境
```

### 封包轉發流程

```
進入封包 (ip_packet_t)
        │
        ▼
 ┌─────────────┐   TTL <= 1
 │  TTL 檢查  │ ──────────────► DROP（TTL 過期）
 └─────────────┘
        │ 正常
        ▼
 ┌─────────────┐   規則命中 DENY
 │  ACL 過濾  │ ──────────────► DROP（ACL 拒絕）
 └─────────────┘
        │ PERMIT
        ▼
 ┌──────────────────┐  無符合路由
 │   路由查詢       │ ─────────► DROP（No Route to Host）
 │   （LPM）        │
 └──────────────────┘
        │ 命中
        ▼
 ┌─────────────┐
 │  ARP 解析  │  快取命中 → 使用已知 MAC
 │ （下一跳） │  快取未命中 → 模擬送出 ARP Request
 └─────────────┘
        │
        ▼
 TTL-- ／ 重新計算 Checksum ／ 更新統計
        │
        ▼
     轉發成功 ✓
```

---

## 編譯與執行

### 環境需求

- Linux（建議 Ubuntu 20.04 以上）
- GCC ≥ 9
- GNU Make

### 編譯

```bash
git clone https://github.com/<你的帳號>/router_sim.git
cd router_sim
make
```

### 執行

```bash
./router_sim
```

### 清除

```bash
make clean
```

---

## 執行結果

程式建立一個 3 介面路由器，並執行 5 個轉發測試情境：

```
=========================================
   Simple Layer-3 Router Simulator
=========================================

--- 介面設定 ---
[IFACE] Added eth0  192.168.1.1/255.255.255.0
[IFACE] Added eth1  10.0.0.1/255.255.255.0
[IFACE] Added eth2  172.16.0.1/255.255.0.0

=== 路由表（4 筆） ===
Destination        Mask             Gateway          Iface    Metric
192.168.1.0        255.255.255.0    0.0.0.0          eth0     0
10.0.0.0           255.255.255.0    0.0.0.0          eth1     0
172.16.0.0         255.255.0.0      0.0.0.0          eth2     0
0.0.0.0            0.0.0.0          10.0.0.254       eth1     10

=== ACL 規則（2 筆） ===
block-tcp-172    DENY    192.168.1.0/255.255.255.0  172.16.0.0/255.255.0.0  TCP
permit-icmp-10   PERMIT  0.0.0.0/0.0.0.0            10.0.0.0/255.255.255.0  ICMP
```

### 測試情境

| # | 情境 | 來源 | 目的 | 結果 |
|---|------|------|------|------|
| 1 | 正常轉發 | 192.168.1.100 | 10.0.0.100（ICMP） | ✅ 轉發 via eth1，TTL 64→63 |
| 2 | ACL 阻擋 | 192.168.1.100 | 172.16.1.50（TCP） | ❌ 丟棄 – ACL 拒絕 |
| 3 | 預設路由 | 10.0.0.100 | 8.8.8.8（UDP） | ✅ 轉發 via eth1 → GW 10.0.0.254 |
| 4 | TTL 過期 | 192.168.1.100 | 10.0.0.100（ICMP，TTL=1） | ❌ 丟棄 – TTL 過期 |
| 5 | 無路由 | 10.0.0.100 | 8.8.8.8（預設路由已刪） | ❌ 丟棄 – No Route to Host |

```
=== 路由器統計 ===
總計轉發：2
總計丟棄：3

介面      RX 封包  TX 封包  RX 位元組  TX 位元組  丟棄
eth0           1        0         40          0      1
eth1           1        2         40         80      0
eth2           0        0          0          0      0
```

---

## 核心資料結構

```c
/* 靜態路由條目 */
typedef struct {
    ip_addr_t network;   /* 目的網路           */
    ip_addr_t mask;      /* 子網路遮罩         */
    ip_addr_t gateway;   /* 下一跳（0=直連）   */
    char      iface[16]; /* 出口介面           */
    int       metric;
} route_entry_t;

/* ACL 規則 */
typedef struct {
    ip_addr_t src_net, src_mask;
    ip_addr_t dst_net, dst_mask;
    uint8_t   protocol;   /* TCP=6, UDP=17, ICMP=1, ANY=0xFF */
    uint16_t  src_port, dst_port;
    int       action;     /* ACL_PERMIT / ACL_DENY */
    char      name[32];
} acl_entry_t;

/* 轉發結果 */
typedef struct {
    bool      forwarded, acl_dropped, ttl_expired, no_route, arp_hit;
    char      out_iface[16];
    ip_addr_t next_hop;
    char      reason[128];
} forward_result_t;
```

---

## 技術能力對應

| 技術 | 對應實作 |
|------|----------|
| **C 語言** | 原始結構體操作、位元運算 IP 處理、手動 Checksum 計算 |
| **Linux 網路** | Layer-3 轉發概念、ARP 解析、路由表查詢 |
| **嵌入式系統** | 固定大小陣列、無動態記憶體配置、零外部依賴 |
| **網路安全** | 有狀態 ACL 設計，支援協定感知過濾 |
| **軟體設計** | 模組化單一職責原則，清晰的標頭檔 API |

---

## 未來擴充方向

- [ ] 互動式 CLI 介面（`route add`、`show arp`、`show interface`）
- [ ] TTL 過期時送出 ICMP Time Exceeded 回應封包
- [ ] ARP 未命中時模擬完整 Request／Reply 交握流程
- [ ] TUN/TAP 介面接入 — 轉發真實 Linux kernel 封包
- [ ] 多執行緒每介面封包佇列處理

---

## 授權

MIT License — 可自由使用、修改與散布。
