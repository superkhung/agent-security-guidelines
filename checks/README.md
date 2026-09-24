# Chạy phép kiểm chứng tự động

`asal_check.py` chạy tự động một phần phép kiểm chứng trong các thẻ control của guideline: phần bắt buộc ở ASAL-0 và phần máy trạm của ASAL-1. Mỗi kết quả gắn với một mã control và mang một trong các trạng thái: **Đạt**, **Chưa đạt**, **Cần xem** (dấu hiệu cần người xem lại), **Chưa kiểm được**, **Không áp dụng**.

Script chỉ dùng thư viện chuẩn của Python (3.9 trở lên), không cần cài gì thêm.

Hướng phát triển thành công cụ đánh giá cho cả tổ chức (gom kết quả nhiều máy, policy, xác nhận tay, báo cáo theo cấp ASAL) được mô tả trong [DESIGN.md](DESIGN.md).

## Hai nhóm phép thử

| Nhóm | Chạy ở đâu | Thử gì |
| :--- | :--- | :--- |
| `config` | Ngoài sandbox, như người dùng bình thường | Danh mục MCP server (SC-01); cấu hình cấp project (SC-02); `npx -y`, `uvx`, `@latest`, image không ghim digest (SC-03); remote MCP không dùng HTTPS (NET-04). Với Claude Code: `bypassPermissions` ở settings có hiệu lực (ACT-03), `sandbox.enabled` (ISO-02), deny rule `Read(...)` cho vị trí credential (ISO-03) |
| `probe` | **Bên trong** môi trường của agent | Quyền root, sudo không mật khẩu (ISO-01); đọc credential ngoài workspace, đọc qua symlink, ghi ra ngoài workspace, SSH/GPG agent, Docker socket, Keychain, D-Bus (ISO-03); capability, seccomp, no-new-privileges, mount, metadata endpoint khi chạy trong container (ISO-04); kết nối thẳng tới domain, IPv4, IPv6, UDP ra ngoài, proxy có chặn domain lạ không (NET-01); DNS thẳng ra ngoài qua UDP, TCP, DoT (NET-02); biến môi trường giống secret, file `.env` (CRED-01) |

Phần `probe` chỉ có ý nghĩa khi chạy đúng chỗ agent chạy, vì thứ cần đo là tiến trình của agent làm được gì, không phải tài khoản của bạn làm được gì. Chạy `probe` ngoài sandbox thì gần như mọi dòng đều là *Chưa đạt*, và như vậy là đúng.

## Cách chạy

```bash
python3 checks/asal_check.py config
```

Chạy phần `probe` trong môi trường của agent:

- **Coding agent có sandbox (Claude Code, Codex CLI):** yêu cầu chính agent chạy `python3 checks/asal_check.py probe` trong phiên làm việc bình thường, với sandbox đang bật. Lệnh chạy qua tool shell của agent, tức là đúng ranh giới cần đo.
- **Devcontainer hoặc container:** chạy lệnh trên bên trong container, từ thư mục dự án đã mount.
- **`srt` hay sandbox tự dựng:** bọc lệnh trên bằng đúng cấu hình bạn dùng cho agent.
- **Windows Sandbox:** map thư mục repo vào sandbox (có thể `ReadOnly`, trừ workspace thử) và chạy lệnh trên trong sandbox, hoặc qua `LogonCommand`.

Các tham số hay dùng:

| Tham số | Khi nào cần |
| :--- | :--- |
| `--workspace DIR` | Thư mục dự án không phải thư mục hiện tại |
| `--probe-host DOMAIN` | `example.org` đang nằm trong allowlist của bạn; đổi sang một domain chắc chắn không được phép |
| `--keychain-item TÊN` | macOS: thử ISO-03 với Keychain; truyền tên một item có thật. Script chỉ hỏi item có tồn tại không, không đọc mật khẩu |
| `--host-home DIR` | Agent chạy dưới user riêng (ISO-01); thử thêm thư mục home của user chính |
| `--no-network` | Không muốn script mở kết nối mạng nào |
| `--json` | Lưu kết quả để so sánh hoặc gom từ nhiều máy (SC-01) |

Mã thoát là 1 nếu có ít nhất một kết quả *Chưa đạt*.

## Script làm gì với máy của bạn

- **Đọc file:** chỉ đọc một byte hoặc liệt kê thư mục để biết có đọc được không, rồi bỏ đi. Không in, không lưu nội dung. Biến môi trường chỉ được in tên, không in giá trị.
- **Ghi file:** tạo một thư mục tạm có symlink trong workspace, và thử tạo file `~/.asal-check-write-test`. Cả hai được xóa ngay.
- **Socket:** chỉ mở kết nối tới SSH agent, GPG agent, Docker socket rồi đóng, không gửi yêu cầu nào.
- **Lệnh ngoài:** `sudo -n true`, `mount -t tmpfs` vào một thư mục tạm (chỉ trong container; nếu thành công thì `umount` ngay), `security find-generic-password` (chỉ khi có `--keychain-item`), `cmdkey /list` (Windows).
- **Mạng:** mở kết nối TCP tới `example.org:443`, `1.1.1.1:443`, `[2606:4700:4700::1111]:443`, `8.8.8.8:53` và `:853`, `169.254.169.254:80`; gửi một truy vấn DNS cho `example.org` qua UDP tới `1.1.1.1`, `2606:4700:4700::1111` và `8.8.8.8`; gửi một yêu cầu CONNECT tới proxy trong `HTTPS_PROXY` nếu có. Không gửi dữ liệu nào khác. Đổi các địa chỉ này bằng tham số, hoặc tắt hẳn bằng `--no-network`.

## Giới hạn

Kết quả chỉ nói về những đường đi mà script đã thử (guideline, Mục 0.5). *Đạt* không chứng minh hệ thống an toàn; *Chưa đạt* thì chắc chắn có đường hở.

Những gì script **không** thử được, phải kiểm tay theo thẻ control: xác thực OAuth của remote MCP (NET-04); tool poisoning (SC-04, dùng máy quét); annotations và fingerprint (SC-05); hạn mức chi tiêu (RES-01); dừng agent và dọn tiến trình con (OBS-04); client có hỏi lại khi cấu hình cấp project thay đổi không (SC-02); UDP 443 (QUIC) riêng lẻ, vì cần một máy nhận để xác nhận. Script coi UDP tới cổng 53 bị chặn là dấu hiệu UDP ra ngoài bị chặn nói chung, nhưng rule firewall theo cổng có thể khác nhau.

**Tool built-in nằm ngoài sandbox.** Theo [tài liệu của Claude Code](https://code.claude.com/docs/en/sandboxing.md), sandbox chỉ bọc các lệnh Bash, PowerShell, Monitor và tiến trình con của chúng; các tool Read, Edit, Write, WebFetch chịu permission rule, không chịu sandbox. Phần `probe` chạy qua shell nên chỉ đo được đường đi của shell. Việc tool Read có đọc được `~/.ssh` hay không được kiểm ở phần `config`, bằng cách xem đã có deny rule `Read(~/.ssh/**)` chưa. Đây là kiểm cấu hình, không phải phép thử. Nếu cả client chạy trong container, `srt` hay VM thì mọi tool đều nằm trong ranh giới đó, và `probe` chạy trong môi trường ấy đo được cả hai.

`bypassPermissions` đặt trong `.claude/settings.json` hay `.claude/settings.local.json` của project không có hiệu lực theo [tài liệu](https://code.claude.com/docs/en/permission-modes.md); script chỉ tính nó là *Chưa đạt* khi nằm trong managed settings hoặc `~/.claude/settings.json`. Cờ dòng lệnh `--dangerously-skip-permissions` không để lại dấu trong settings, nên script không thấy được.

Phát hiện biến môi trường giống secret là heuristic theo tên. Với secret trong file, chạy thêm `gitleaks`. Một số sandbox tự đặt biến có tên giống secret cho proxy của chính nó (ví dụ `srt` đặt `CLOUDSDK_PROXY_PASSWORD`); đó là credential của proxy trong phiên, không phải secret của bạn.

Khi `HTTPS_PROXY` có kèm user và mật khẩu, script gửi chúng trong yêu cầu CONNECT để câu trả lời phản ánh allowlist chứ không phải bước xác thực. Chúng không bao giờ được in ra.

## Đã thử trên đâu

| Nền tảng | Trạng thái |
| :--- | :--- |
| macOS, Python 3.9, ngoài sandbox và trong `sandbox-exec` với profile chặn và profile lỏng | Đã thử: kết quả đổi đúng theo profile |
| macOS, `srt` 0.0.77 với hai cấu hình trong `examples/srt/` | Đã thử: mọi phép thử ISO-03, NET-01, NET-02 đạt; proxy của `srt` trả 403 cho domain ngoài allowlist |
| macOS, Claude Code 2.1.273, sandbox bật với `denyRead: ["~/.ssh"]`, probe qua tool Bash | Đã thử: NET-01, NET-02, `~/.ssh`, ghi vào home, SSH agent đều bị chặn. **Nhưng vẫn đọc được `~/.config/gh/hosts.yml`, `~/.docker/config.json` và lịch sử shell**, vì sandbox mặc định cho đọc mọi nơi trừ `denyRead` (ISO-03) |
| macOS, Claude Code 2.1.273, cùng probe qua hook `SessionStart` | Đã thử: mọi dòng ISO-03, NET-01, NET-02 *Chưa đạt*. Hook chạy ngoài sandbox, đúng như [tài liệu](https://code.claude.com/docs/en/hooks.md); không dùng hook để chạy `probe` |
| Linux (bubblewrap, `srt`, Landlock) | Chưa thử |
| Container Linux trên Docker Desktop 29.6 (Debian bookworm) | Đã thử ba cấu hình: `examples/devcontainer` (mọi dòng đạt), container mặc định (bắt được no-new-privileges chưa bật), `--privileged` với bind-mount home (bắt được bounding set có CAP_SYS_ADMIN, seccomp tắt, ghi được vào home) |
| Windows, WSL2, Windows Sandbox | Chưa thử |

Nếu bạn chạy script trên một nền tảng chưa thử, hoặc thấy một phép thử cho kết quả sai (báo *Đạt* khi thật ra đường vẫn hở, hoặc ngược lại), mở Issue theo mẫu "Góp ý nội dung guideline", chọn loại "Phép kiểm chứng không đạt dù đã làm đúng hướng dẫn", và dán kết quả `--json` (xem lại trước khi dán: kết quả có đường dẫn trên máy bạn).

## Test

```bash
python3 -m unittest discover -s checks
```
