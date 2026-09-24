# asal: đánh giá tư thế agent theo ASAL

`asal.py` chạy tự động phép kiểm chứng trong các thẻ control của guideline, gom kết quả từ nhiều máy, và cho biết từng máy đang thật sự đạt cấp ASAL nào. Một file, chỉ dùng thư viện chuẩn của Python 3.9 trở lên. Thiết kế: [DESIGN.md](DESIGN.md).

Mỗi kết quả gắn với một mã control và một mã probe ổn định (ví dụ `iso03.read.credentials`), mang một trong các trạng thái: **Đạt**, **Chưa đạt**, **Cần xem** (máy thấy dấu hiệu nhưng không tự kết luận được), **Chưa kiểm được**, **Không áp dụng**.

## Ba lệnh

| Lệnh | Chạy ở đâu | Làm gì |
| :--- | :--- | :--- |
| `collect` | Ngoài sandbox, như người dùng bình thường | Danh mục MCP server và danh tính của chúng (SC-01); cấu hình cấp project (SC-02); `npx -y`, `uvx`, `@latest`, image không ghim digest (SC-03); remote MCP không dùng HTTPS (NET-04). Với Claude Code: `bypassPermissions` ở settings có hiệu lực (ACT-03), `sandbox.enabled` (ISO-02), việc chặn tool file built-in đọc ngoài thư mục làm việc (ISO-03) |
| `probe` | **Bên trong** môi trường của agent | Quyền root, sudo không mật khẩu (ISO-01); đọc credential ngoài workspace, đọc qua symlink, ghi ra ngoài workspace, SSH/GPG agent, Docker socket, Keychain, D-Bus (ISO-03); capability, seccomp, no-new-privileges, mount, metadata endpoint trong container (ISO-04); kết nối thẳng tới domain, IPv4, IPv6, UDP, proxy có chặn domain lạ không (NET-01); DNS thẳng qua UDP, TCP, DoT (NET-02); biến môi trường giống secret, file `.env` (CRED-01) |
| `report` | Máy của người đọc báo cáo | Gom file JSON của `collect` và `probe`, đối chiếu với policy và xác nhận tay, xuất báo cáo Markdown hoặc CSV theo cấp ASAL |

Phần `probe` chỉ có ý nghĩa khi chạy đúng chỗ agent chạy, vì thứ cần đo là tiến trình của agent làm được gì, không phải tài khoản của bạn làm được gì. Chạy `probe` ngoài sandbox thì gần như mọi dòng đều là *Chưa đạt*, và như vậy là đúng.

## Dùng cho một máy

```bash
python3 checks/asal.py collect
```

Chạy `probe` trong môi trường của agent:

- **Claude Code có sandbox:** yêu cầu agent chạy `python3 checks/asal.py probe --context claude-code-bash` qua tool Bash. Lệnh chạy trong sandbox, tức là đúng ranh giới cần đo. **Đừng chạy qua hook:** hook của Claude Code chạy ngoài sandbox, theo [tài liệu](https://code.claude.com/docs/en/hooks.md) và theo phép thử ghi ở bảng cuối trang.
- **Devcontainer hoặc container:** chạy lệnh trên bên trong container, với `--context devcontainer`.
- **`srt` hay sandbox tự dựng:** bọc lệnh bằng đúng cấu hình bạn dùng cho agent, với `--context srt`.
- **Windows Sandbox:** map thư mục repo vào sandbox và chạy lệnh trên trong sandbox, hoặc qua `LogonCommand`.

Mã thoát là 1 nếu có ít nhất một kết quả *Chưa đạt*.

## Dùng cho cả tổ chức

1. Trên mỗi máy, chạy `collect` như người dùng và `probe` trong môi trường của agent, mỗi lệnh ghi một file JSON:

   ```bash
   python3 checks/asal.py collect --use-case coding-agent-internal -o collect.json
   ```

   ```bash
   python3 checks/asal.py probe --use-case coding-agent-internal --context devcontainer -o probe.json
   ```

   Hai file của cùng một máy được ghép với nhau theo mã máy. Mã máy mặc định là băm SHA-256 của hostname. Đặt `ASAL_PSEUDONYM_KEY` (hoặc `--pseudonym-key`) là một khóa do tổ chức giữ để dùng HMAC thay cho SHA-256, vì hostname đoán được thì băm SHA-256 của nó cũng đoán được.

2. Gom các file JSON về một chỗ: script MDM, artifact của CI, thư mục chung. `asal` không tự gửi dữ liệu đi đâu.

3. Viết policy (mẫu: [policy.example.json](policy.example.json)) cho biết use case nào cam kết cấp nào, chạy ở context nào, và MCP server nào được duyệt. Danh tính server là chuỗi mà `collect` ghi trong `inventory`, ví dụ `pkg:npm:@scope/server@1.2.3` hay `oci:repo@sha256:…`.

4. Ghi xác nhận tay (mẫu: [attestation.example.json](attestation.example.json)) cho những control máy không tự kiểm được, như RES-01 hay OBS-04, và cho những dòng *Cần xem* sau khi đã có người xem.

5. Xuất báo cáo:

   ```bash
   python3 checks/asal.py report reports/ --policy policy.json --attest attestations.json -o report.md
   ```

Quy tắc tính cấp, theo Mục 0.5 của guideline:
- Một cấp chỉ đạt khi mọi control *bắt buộc* ở cấp đó là *Đạt* hoặc *Không áp dụng*.
- *Chưa kiểm được* và *Cần xem* đều chặn việc đạt cấp, cho tới khi có một xác nhận tay hợp lệ.
- Xác nhận tay không bao giờ đè lên kết quả *Chưa đạt* của máy.
- Miễn trừ một control bắt buộc nghĩa là không đạt cấp đó, kể cả khi đã có người chấp nhận rủi ro.
- Xác nhận quá hạn không được tính.

Ma trận control mà `report` dùng là [asal_matrix.json](asal_matrix.json), được sinh từ bảng 3.4 của guideline bằng `scripts/export_matrix.py`. CI báo lỗi nếu hai bên lệch nhau.

## Tham số hay dùng của `probe`

| Tham số | Khi nào cần |
| :--- | :--- |
| `--workspace DIR` | Thư mục dự án không phải thư mục hiện tại |
| `--probe-host DOMAIN` | `example.org` đang nằm trong allowlist của bạn; đổi sang một domain chắc chắn không được phép |
| `--keychain-item TÊN` | macOS: thử ISO-03 với Keychain; truyền tên một item có thật. Script chỉ hỏi item có tồn tại không, không đọc mật khẩu |
| `--host-home DIR` | Agent chạy dưới user riêng (ISO-01); thử thêm thư mục home của user chính |
| `--no-network` | Không muốn script mở kết nối mạng nào |
| `--json`, `-o FILE` | In JSON ra stdout, hoặc ghi vào file |

`checks/asal_check.py` là tên cũ, vẫn chạy được: `config` tương ứng `collect`, `probe` vẫn là `probe`.

## Script làm gì với máy của bạn

- **Đọc file:** chỉ đọc một byte hoặc liệt kê thư mục để biết có đọc được không, rồi bỏ đi. Không in, không lưu nội dung. Biến môi trường chỉ được in tên, không in giá trị. Đường dẫn trong home được thay bằng `~`.
- **Ghi file:** tạo một thư mục tạm có symlink trong workspace, và thử tạo file `~/.asal-write-test`. Cả hai được xóa ngay.
- **Socket:** chỉ mở kết nối tới SSH agent, GPG agent, Docker socket rồi đóng, không gửi yêu cầu nào.
- **Lệnh ngoài:** `sudo -n true`, `mount -t tmpfs` vào một thư mục tạm (chỉ trong container; nếu thành công thì `umount` ngay), `security find-generic-password` (chỉ khi có `--keychain-item`), `cmdkey /list` (Windows).
- **Mạng:** mở kết nối TCP tới `example.org:443`, `1.1.1.1:443`, `[2606:4700:4700::1111]:443`, `8.8.8.8:53` và `:853`, `169.254.169.254:80` (chỉ trong container); gửi một truy vấn DNS cho `example.org` qua UDP tới `1.1.1.1`, `2606:4700:4700::1111` và `8.8.8.8`; gửi một yêu cầu CONNECT tới proxy trong `HTTPS_PROXY` nếu có, kèm user và mật khẩu có trong URL đó để câu trả lời phản ánh allowlist chứ không phải bước xác thực (không bao giờ in ra). Đổi các địa chỉ bằng tham số, hoặc tắt hẳn bằng `--no-network`.

## Giới hạn

Kết quả chỉ nói về những đường đi đã thử (guideline, Mục 0.5). *Đạt* không chứng minh hệ thống an toàn; *Chưa đạt* thì chắc chắn có đường hở.

**Tool built-in nằm ngoài sandbox.** Theo [tài liệu của Claude Code](https://code.claude.com/docs/en/sandboxing.md), sandbox chỉ bọc các lệnh Bash, PowerShell, Monitor và tiến trình con của chúng; tool Read, Edit, Write, WebFetch chịu permission rule. `probe` chạy qua shell nên chỉ đo được đường của shell. Tool file built-in được kiểm ở `collect`, bằng cách đọc settings: `permissions.blockReadsOutsideWorkingDirectories`, hoặc deny rule `Read(...)` cho vị trí credential. Đó là kiểm cấu hình, không phải phép thử. Nếu cả client chạy trong container, `srt` hay VM thì mọi tool đều nằm trong ranh giới đó, và `probe` trong môi trường ấy đo được cả hai.

Những gì không kiểm tự động được, phải xác nhận tay: xác thực OAuth của remote MCP (NET-04); tool poisoning (SC-04, dùng máy quét); fingerprint tool (SC-05); hạn mức chi tiêu (RES-01); dừng agent và dọn tiến trình con (OBS-04); client có hỏi lại khi cấu hình cấp project thay đổi không (SC-02); UDP 443 (QUIC) riêng lẻ. `probe` coi UDP tới cổng 53 bị chặn là dấu hiệu UDP ra ngoài bị chặn nói chung, nhưng rule firewall theo cổng có thể khác nhau.

Phát hiện biến môi trường giống secret là heuristic theo tên. Một số sandbox tự đặt biến có tên giống secret cho proxy của chính nó, ví dụ `srt` đặt `CLOUDSDK_PROXY_PASSWORD`.

## Môi trường cố ý cấu hình sai

Mỗi probe được chạy trong CI trong những môi trường mà kết quả phải là *Đạt*, và những môi trường mà kết quả phải là *Chưa đạt*. Kết quả kỳ vọng nằm ở [fixtures/expected/](fixtures/expected/). Một probe báo *Đạt* ở nơi đường vẫn hở sẽ làm CI đỏ.

| Fixture | Môi trường | Chạy ở |
| :--- | :--- | :--- |
| `devcontainer-strict` | `examples/devcontainer`: network internal sau Squid, không root, `cap_drop: ALL`, no-new-privileges | CI Linux |
| `container-default` | Cùng image, `docker run` mặc định | CI Linux |
| `container-privileged-home` | `--privileged`, home bind-mount có credential giả | CI Linux |
| `container-network-host` | `--network host` | CI Linux |
| `macos-sandbox-exec-strict`, `macos-sandbox-exec-weak` | `sandbox-exec` chặn đọc, ghi và mạng; và chỉ chặn ghi | CI macOS |
| `macos-srt-workspace-only`, `macos-srt-no-denyread` | `srt` với `examples/srt/srt-workspace-only.json`; và không có `denyRead` | CI macOS |

Chạy trên máy mình: `checks/fixtures/run-macos.sh` (macOS) và `checks/fixtures/run-linux-containers.sh` (máy có Docker).

## Đã thử trên đâu

| Nền tảng | Trạng thái |
| :--- | :--- |
| macOS, `sandbox-exec` và `srt` 0.0.77 | Bốn fixture macOS đạt |
| Container Linux trên Docker Desktop 29 (Debian bookworm) | Bốn fixture container đạt |
| macOS, Claude Code 2.1.273, sandbox bật, probe qua tool Bash | Đã thử: với `denyRead: ["~/.ssh"]`, `~/.ssh`, mạng thẳng, ghi vào home và SSH agent đều bị chặn, **nhưng `~/.config/gh/hosts.yml`, `~/.docker/config.json` và lịch sử shell vẫn đọc được**, vì sandbox mặc định cho đọc mọi nơi trừ `denyRead`. Với [`examples/claude-code`](../examples/claude-code/README.md) thì mọi phép thử đạt |
| macOS, Claude Code 2.1.273, probe qua hook `SessionStart` | Đã thử: mọi dòng ISO-03, NET-01, NET-02 *Chưa đạt*. Hook chạy ngoài sandbox; không dùng hook để chạy `probe` |
| Linux với bubblewrap, `srt` hay Landlock trên máy thật | Chưa thử |
| Windows, WSL2, Windows Sandbox | Chưa thử |

Nếu bạn chạy `asal` trên một nền tảng chưa thử, hoặc thấy một phép thử cho kết quả sai (báo *Đạt* khi đường vẫn hở, hoặc ngược lại), mở Issue theo mẫu "Góp ý nội dung guideline", chọn loại "Phép kiểm chứng không đạt dù đã làm đúng hướng dẫn", và dán kết quả `--json`. Xem lại trước khi dán: kết quả có tên client và đường dẫn đã rút gọn, nhưng không có nội dung secret.

## Test

```bash
python3 -m unittest discover -s checks
```
