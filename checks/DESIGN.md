# Thiết kế: công cụ đánh giá tư thế agent cho cả tổ chức (`asal` v0.1)

Trạng thái: bản nháp thiết kế, mở góp ý. Mã hiện có (`asal_check.py`) là điểm xuất phát; tài liệu này mô tả nó sẽ trở thành gì.

## 1. Mục tiêu

Trả lời được, cho cả tổ chức chứ không chỉ một máy: *những máy và use case nào đang thật sự đạt cấp ASAL đã cam kết, control nào đang hở, và control nào vừa bị tắt đi so với lần đo trước.*

Ba nguyên tắc lấy thẳng từ guideline:

1. **Đo bằng phép thử, không bằng cấu hình** (Mục 0.5, Phụ lục B). Chỗ nào chỉ kiểm được cấu hình thì kết quả ghi rõ là kiểm cấu hình.
2. **Probe chạy đúng chỗ agent chạy.** Thứ cần đo là tiến trình của agent làm được gì.
3. **Không báo *Đạt* sai.** Một lần báo *Đạt* sai tệ hơn không có công cụ. Mọi probe phải có môi trường cấu hình sai tương ứng trong CI (Mục 7).

**Không làm:** dashboard web, server thu thập, agent chạy nền, tự sửa cấu hình trên máy người dùng. Đó là việc của MDM, SIEM và của tổ chức.

## 2. Người dùng và câu hỏi của họ

| Người dùng | Câu hỏi |
| :--- | :--- |
| Dev | Máy mình đã đạt Phụ lục A chưa, còn thiếu gì? |
| Người sở hữu danh mục (SC-01) | Trong tổ chức có những client và MCP server nào, server nào chưa được duyệt? |
| Security, platform | Use case X cam kết ASAL-1: bao nhiêu máy đạt thật, control nào hở nhiều nhất, tuần này có gì bị tắt? |
| Kiểm toán | Bằng chứng cho từng control bắt buộc ở Phụ lục C, cả phần máy kiểm được lẫn phần xác nhận tay |

## 3. Lệnh

| Lệnh | Chạy ở đâu | Làm gì |
| :--- | :--- | :--- |
| `asal collect` | Trên máy, như người dùng thường | Danh mục client và MCP server, cách khởi động server, settings của client (SC-01, SC-02, SC-03, NET-04, ACT-03; với Claude Code thêm ISO-02 và deny rule cho tool file built-in) |
| `asal probe` | Bên trong môi trường của agent | Phép thử ISO-01, ISO-03, ISO-04, NET-01, NET-02, CRED-01 |
| `asal report` | Máy của người đọc báo cáo | Gom nhiều file JSON, đối chiếu với policy và xác nhận tay, xuất báo cáo |

`collect` và `probe` chỉ ghi ra một file JSON. Không lệnh nào tự gửi dữ liệu đi đâu.

## 4. Chạy probe đúng chỗ

Đây là phần khó nhất. Bảng dưới ghi rõ điều gì đã xác minh và điều gì chưa.

| Môi trường | Cách chạy `asal probe` | Probe đo được | Trạng thái |
| :--- | :--- | :--- | :--- |
| Devcontainer, container | `postStartCommand`, hoặc lệnh trong container | Mọi tool của agent, vì cả client chạy trong container | Đã thử (`examples/devcontainer`) |
| `srt` bọc cả client | `asal probe --via srt --settings <file>`, dùng đúng cấu hình của agent | Mọi tool của agent | Đã thử trên macOS; chưa thử Linux |
| Runner CI chạy agent | Một bước trong job, cùng môi trường với agent | Mọi tool của agent | Chưa thử |
| Claude Code với sandbox của chính nó | Yêu cầu agent chạy `asal probe` qua tool Bash | **Chỉ đường đi của shell.** Sandbox của Claude Code chỉ bọc Bash, PowerShell, Monitor và tiến trình con; Read, Edit, Write, WebFetch chịu permission rule ([sandboxing](https://code.claude.com/docs/en/sandboxing.md)). Tool file built-in được kiểm bằng `collect` (deny rule `Read(...)`) | Theo tài liệu |
| Claude Code, chạy probe qua hook | Hook `SessionStart` | **Chưa biết.** Tài liệu không nói hook chạy trong hay ngoài sandbox. Chưa được dùng cho tới khi thử thật | Cần thử |
| MCP server local | Không áp dụng: MCP server của Claude Code không được nói là chạy trong sandbox | Phải bọc riêng (ISO-02) và probe trong môi trường bọc đó | Theo tài liệu |
| Windows Sandbox | `LogonCommand` | Mọi thứ chạy trong sandbox | Chưa thử |

Mỗi báo cáo `probe` ghi `context`: người chạy khai báo (`--context devcontainer`), script bổ sung những gì tự phát hiện được (đang trong container, có proxy của `srt`). Báo cáo tổng hợp tách riêng kết quả theo context, để không trộn "đo qua Bash của Claude Code" với "đo trong container".

## 5. Định dạng dữ liệu

Mọi file đều là JSON. Không dùng YAML hay TOML, để giữ yêu cầu chỉ dùng thư viện chuẩn của Python 3.9.

### 5.1. Báo cáo của một lần chạy

```json
{
  "schema": "asal-report/1",
  "tool": { "name": "asal", "version": "0.1.0" },
  "run": { "id": "<uuid>", "time": "2026-10-01T09:00:00Z", "command": "probe", "context": "devcontainer" },
  "host": { "id": "<HMAC của hostname>", "os": "Linux 6.8", "user": "<HMAC của user>" },
  "use_case": "coding-agent-internal",
  "results": [
    {
      "probe": "iso03.read.credentials",
      "control": "ISO-03",
      "kind": "test",
      "status": "fail",
      "message": "đọc được 2 vị trí credential ngoài workspace",
      "evidence": ["~/.ssh", "~/.aws"]
    }
  ]
}
```

- `probe` là mã ổn định của từng phép thử, không đổi giữa các phiên bản. Báo cáo drift và bộ môi trường cấu hình sai dựa vào mã này.
- `kind` là `test` (phép thử thật) hoặc `config` (chỉ đọc cấu hình). Báo cáo tổng hợp hiển thị hai loại khác nhau.
- `status` dùng mã tiếng Anh cố định: `pass`, `fail`, `review`, `untested`, `na`. Phần hiển thị dịch sang *Đạt*, *Chưa đạt*, *Cần xem*, *Chưa kiểm được*, *Không áp dụng*.
- Đường dẫn trong home được thay bằng `~`. Hostname và tên người dùng được băm bằng HMAC với một khóa do tổ chức giữ (`--pseudonym-key`); không có khóa thì hai trường này bỏ trống.

### 5.2. Policy

```json
{
  "schema": "asal-policy/1",
  "use_cases": [
    { "id": "coding-agent-internal", "level": "ASAL-1", "contexts": ["devcontainer", "claude-code-bash"] }
  ],
  "approved_mcp_servers": [
    { "identity": "oci:registry.example.internal/mcp/github@sha256:…", "note": "chỉ đọc" }
  ],
  "probe": { "probe_host": "blocked.example.net" }
}
```

Server được duyệt khai báo theo danh tính (digest image, package kèm phiên bản và hash, URL chuẩn hóa), không theo tên (SC-02).

### 5.3. Xác nhận tay

Control máy không tự kiểm được (ví dụ RES-01, OBS-04 diễn tập, OBS-06, SC-04 khi quét bằng công cụ ngoài) được ghi trong một file riêng:

```json
{
  "schema": "asal-attestation/1",
  "items": [
    { "control": "RES-01", "use_case": "coding-agent-internal", "status": "pass",
      "by": "<người xác nhận>", "date": "2026-10-01", "expires": "2027-01-01", "evidence": "<link>" },
    { "control": "CRED-04", "use_case": "coding-agent-internal", "status": "waived",
      "by": "<người xác nhận>", "date": "2026-10-01", "expires": "2027-01-01", "reason": "…" }
  ]
}
```

Theo Mục 0.5: `waived` chỉ dùng được cho control mức *Nên*. Với control *Bắt buộc*, `waived` nghĩa là use case không đạt cấp đó, và báo cáo chỉ ghi nhận nếu có `risk_accepted_by` là người phía nghiệp vụ. Xác nhận quá hạn được coi như chưa có.

### 5.4. Ma trận control

Công cụ cần biết control nào bắt buộc ở cấp nào để tính "use case đạt cấp nào". Ma trận này không được chép tay vào code. `scripts/export_matrix.py` sinh `checks/asal_matrix.json` từ bảng 3.4 của guideline (dùng lại phần parse của `scripts/lint.py`), và CI kiểm hai bên khớp nhau.

## 6. Báo cáo tổng hợp

`asal report reports/ --policy policy.json --attest attestations.json --previous reports-last-week/` xuất ra:

- **Theo use case:** cấp cam kết; số máy đạt cấp đó; với mỗi control bắt buộc, tỷ lệ máy đạt; control hở nhiều nhất.
- **Theo control:** máy nào chưa đạt, bằng chứng.
- **Danh mục (SC-01):** mọi client và MCP server thấy được, đánh dấu server chưa được duyệt.
- **Drift so với lần trước:** probe nào chuyển từ `pass` sang `fail`. Đây là cách đo các chỉ số ở Mục 3.6, như số người đã tắt sandbox, hay số phiên bỏ qua phê duyệt ngoài container.
- **Định dạng:** Markdown và CSV cho người đọc; JSON lines cho SIEM (OBS-03).

Mỗi báo cáo kết thúc bằng câu của Mục 0.5: kết quả chỉ nói về những đường đi đã thử.

## 7. Bộ môi trường cấu hình sai

Đây là cơ chế giữ cho công cụ không báo *Đạt* sai. Mỗi môi trường có một file kết quả kỳ vọng theo mã probe, và CI chạy `asal probe` trong môi trường đó rồi so sánh.

| Môi trường | Chạy ở đâu trong CI | Kỳ vọng |
| :--- | :--- | :--- |
| `examples/devcontainer` | Runner Linux, Docker | Mọi probe `pass` |
| Container mặc định (không `cap_drop`, không `no-new-privileges`) | Runner Linux, Docker | `iso04.*` `fail` |
| `--privileged`, home bind-mount | Runner Linux, Docker | `iso04.capbnd`, `iso03.write.home` `fail` |
| `--network host` | Runner Linux, Docker | `net01.*` `fail` |
| Network Docker có IPv6, rule chỉ chặn IPv4 | Runner Linux, Docker | `net01.ipv6` `fail` |
| `srt` với `examples/srt/srt-workspace-only.json` | Runner Linux | Mọi probe `pass` |
| `srt` không có `denyRead` | Runner Linux | `iso03.read.*` `fail` |
| `sandbox-exec` profile chặn và profile lỏng | Runner macOS | Như đã thử trên máy |

Quy tắc: một probe mới chỉ được phát hành khi có ít nhất một môi trường mà nó phải `fail` và một môi trường mà nó phải `pass`, cả hai đều chạy trong CI.

## 8. Quyền riêng tư và an toàn của chính công cụ

- **Không bao giờ thu thập nội dung file hay giá trị biến môi trường.** Chỉ thu tên, đường dẫn đã thay home bằng `~`, và kết quả phép thử.
- **Hostname và tên người dùng chỉ lưu dạng HMAC,** với khóa do tổ chức giữ.
- **Tổ chức cần thông báo cho nhân viên và hỏi pháp chế** trước khi thu thập trên diện rộng. Hướng dẫn triển khai ghi điều này ở đầu.
- **Công cụ được MDM đẩy xuống mọi máy dev, nên chính nó là mục tiêu supply chain (D1).** Chỉ dùng thư viện chuẩn, một file, phát hành có ký bằng Sigstore, ghim phiên bản khi triển khai. Không tự cập nhật.

## 9. Lộ trình

| Bản | Nội dung |
| :--- | :--- |
| v0.1 | CLI `asal` gồm `collect`, `probe` (mã probe ổn định), `report`; schema `asal-report/1`, `asal-policy/1`, `asal-attestation/1`; ma trận sinh từ guideline; báo cáo Markdown và CSV; bộ môi trường cấu hình sai cho container Linux, `srt` trên Linux và `sandbox-exec` trên macOS; hướng dẫn chạy qua devcontainer, CI, `srt` và Bash của Claude Code |
| v0.2 | Windows, WSL2, Windows Sandbox; drift; JSON lines cho SIEM; thử và ghi kết quả việc chạy probe qua hook |
| v0.3 | Fingerprint tool (SC-05) bằng thư viện của bản cài đặt tham chiếu `aab`; nhận output của `mcp-scanner` và Snyk Agent Scan cho SC-04 |

## 10. Câu hỏi mở

1. Hook của Claude Code (`SessionStart`) chạy trong hay ngoài sandbox? Tài liệu không nói; cần thử trên máy có Claude Code.
2. Client khác (Codex CLI, Cursor) lưu trạng thái sandbox và chế độ phê duyệt ở đâu, và sandbox của chúng bọc những tool nào?
3. Có nên cho `collect` đọc thêm log vi phạm sandbox của client, nếu client ghi ra file, để đếm "vi phạm sandbox theo loại" ở Mục 3.6?
4. Mã probe nên có không gian tên theo control (`iso03.read.credentials`) hay theo kỹ thuật (`fs.read.credentials`)? Bản nháp dùng theo control.
