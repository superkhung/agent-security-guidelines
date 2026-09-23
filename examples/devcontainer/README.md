# Devcontainer có proxy allowlist

Container của agent nằm trên một Docker network `internal`, không có đường ra nào. Đường ra duy nhất là container `proxy` (Squid), chỉ cho CONNECT tới cổng 443 của các domain trong `allowlist.txt`.

Vì đường ra bị cắt ở cấu trúc mạng chứ không bằng rule firewall trong container, IPv4, IPv6 và UDP đều bị chặn mà không cần cấp `NET_ADMIN` cho container của agent (NET-01). Container của agent cũng không tự phân giải được tên miền bên ngoài; proxy phân giải thay (NET-02).

```
.devcontainer/
  devcontainer.json   Dev Containers (VS Code, Cursor, devcontainer CLI) dùng compose.yaml
  compose.yaml        agent (network internal) + proxy (internal và egress)
  Dockerfile          image của agent: user không phải root, ghim theo digest
  squid.conf          chỉ CONNECT :443 tới domain trong allowlist; mọi quyết định được ghi log
  allowlist.txt       danh sách domain được phép
```

## Dùng

Chép thư mục `.devcontainer/` vào gốc dự án, rồi:

- Mở dự án bằng VS Code hoặc Cursor và chọn *Reopen in Container*, hoặc
- Chạy tay: `cd .devcontainer && docker compose up -d --build && docker compose exec agent bash`.

Cài client agent vào image ở chỗ đã đánh dấu trong `Dockerfile`, ghim phiên bản đã xem (SC-03). Nếu chạy chế độ bỏ qua phê duyệt, chỉ chạy bên trong container này (ISO-04).

Sửa `allowlist.txt` cho đúng việc của mình. Một tuần đầu, xem log để thu danh sách thật trước khi thêm domain:

```bash
docker compose exec proxy tail -f /var/log/squid/access.log
```

Đừng thêm wildcard rộng, và đọc NET-03 trước khi thêm những domain ghi được dữ liệu như `github.com`.

## Cấu hình này chặn gì

| Thiết lập | Tác dụng | Control |
| :--- | :--- | :--- |
| `networks.sandbox.internal: true` | Không có route ra ngoài; chỉ tới được proxy | NET-01, NET-02 |
| Chỉ mount thư mục dự án | Không có home, SSH key, cloud credential, Docker socket của host | ISO-03, ISO-04 |
| `user` không phải root, `cap_drop: [ALL]`, `no-new-privileges` | Không lên được root, không có capability | ISO-01, ISO-04 |
| `read_only: true`, home và `/tmp` là tmpfs | Không cài được persistence vào image; mọi thứ ngoài workspace mất khi dừng | ISO-04 |
| Squid `http_access deny !CONNECT`, chỉ `CONNECT` :443 tới allowlist | Không có HTTP thường, không có cổng lạ, không có domain ngoài danh sách | NET-01 |

Cấu hình này **không** chặn exfil qua domain đã được phép (NET-03), và không kiểm soát những gì agent làm với chính workspace của nó.

## Kết quả kiểm thử

Docker Desktop 29.6.2 trên macOS, image `debian:bookworm-slim` và `ubuntu/squid` (Squid 6.13) ghim theo digest trong `compose.yaml`. Chạy `checks/asal_check.py probe` bên trong container `agent`:

| Phép thử | Kết quả |
| :--- | :--- |
| ISO-01: không root, không có sudo | Đạt |
| ISO-03: home là tmpfs của container, không phải home của host; không tới được SSH agent, Docker socket, D-Bus | Đạt |
| ISO-04: không có CAP_SYS_ADMIN, no-new-privileges bật, seccomp bật, không mount được, không tới được 169.254.169.254 | Đạt |
| NET-01: TCP thẳng tới domain, IPv4, IPv6; UDP qua IPv4 và IPv6 | Đạt: *Network is unreachable* |
| NET-01: proxy cho CONNECT tới `example.org` | Đạt: 403 |
| NET-02: DNS thẳng qua UDP, TCP, DoT; tự phân giải tên miền ngoài | Đạt |

Log của Squid cho thấy `api.anthropic.com` đi qua (`TCP_TUNNEL/200`) và `example.org` bị chặn (`TCP_DENIED/403`, `HIER_NONE`: không được chuyển tiếp). Chưa kiểm bằng log DNS rằng Squid không phân giải tên miền bị chặn (NET-02); nếu bạn kiểm được, hãy báo lại.

Để so sánh, cùng image chạy với `--privileged` và home bind-mount từ host thì script báo *Chưa đạt* ở ISO-03 (ghi được vào home) và ISO-04 (CAP_SYS_ADMIN trong bounding set, seccomp tắt, no-new-privileges tắt).

Chưa thử trên Linux thật, Podman, hay Docker với IPv6 bật cho daemon.
