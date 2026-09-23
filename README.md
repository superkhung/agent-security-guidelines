# Agent Security Technical Guidelines

**Hướng dẫn kỹ thuật an ninh cho AI Agent** · phiên bản 0.1.0 · public draft, mở góp ý

Tài liệu trả lời mấy câu cụ thể cho một đội đang dùng hoặc đang dựng agent: cần làm gì, theo thứ tự nào, khó cỡ nào, cần ai và cần tổ chức có sẵn những gì, công cụ mã nguồn mở nào dùng được liền, và chỗ nào hiện chưa có công cụ.

Tác giả: superkhung · VNSecurity

**Đọc:** [bản markdown](guideline/agent-security-guidelines.md) · bản PDF ở trang [Releases](../../releases)

## Trong repo có gì

```
guideline/        Guideline, bản gốc (tiếng Việt)
TOOLS.md          Bản sống của bảng công cụ ở Mục 5.1; khi lệch với guideline, tin file này
playbooks/        Playbook sự cố, break-glass và kịch bản diễn tập cho OBS-06
checks/           Script chạy tự động phép kiểm chứng của ASAL-0 và phần máy trạm của ASAL-1
examples/         Cấu hình mẫu đã kiểm thử: devcontainer có proxy allowlist, cấu hình srt
companion-spec/   Agent Action Binding: Wire Format and Test Vectors (tiếng Anh, bản nháp aab-00)
pdf/              Công cụ xuất PDF
```

`companion-spec/` là đặc tả wire format và test vectors cho SC-05, ACT-04, ACT-06 và OBS-02. Bản `aab-00` mới có cấu trúc spec và danh mục test vectors, **chưa dùng để cài đặt được**. Xem Phụ lục E của guideline.

## Bắt đầu từ đâu

- Dev dùng Claude Code, Cursor, Codex: Phụ lục A (quick start ASAL-0 trong một buổi), rồi Mục 3.1 để chọn cấp cho use case.
- Security engineer, platform: Mục 1, Mục 2, rồi toàn bộ Mục 4.
- Trưởng nhóm, CISO: Mục 1.2 và Mục 3, nhất là 3.3.

Đã áp Phụ lục A hay các control của ASAL-1 rồi? Chạy [`checks/asal_check.py`](checks/README.md) bên trong môi trường của agent để xem phép kiểm chứng có đạt thật không.

## Góp ý

Góp ý qua Issue hoặc Pull Request, xem [CONTRIBUTING.md](CONTRIBUTING.md). Phản biện về threat model, về độ khó thực tế, và về công cụ còn thiếu trong Mục 5 là những góp ý có giá trị nhất.

**Bản 0.1.0 đã đóng băng nội dung để nhận góp ý.** Vòng góp ý đầu kéo dài đến hết 31/12/2026. Trong thời gian này, guideline và bản nháp `aab-00` không đổi nội dung; góp ý được gom theo mã control và xử lý ở bản 0.2.0, dự kiến quý 1/2027. Chỉ lỗi chính tả, link hỏng và lỗi build được sửa trong các bản 0.1.x. `TOOLS.md` là bản sống nên vẫn được cập nhật qua Pull Request.

Sau vòng này, chu kỳ cập nhật dự kiến là mỗi quý, cộng thêm một lần mỗi khi MCP ra bản spec mới. Thay đổi giữa các phiên bản ghi ở [CHANGELOG.md](CHANGELOG.md).

## Xuất PDF

Cần `pandoc`, WeasyPrint, và hai font Be Vietnam Pro, JetBrains Mono (đều miễn phí trên Google Fonts). Trên macOS:

```bash
brew install pandoc weasyprint && brew install --cask font-be-vietnam-pro font-jetbrains-mono
```

```bash
python3 pdf/build.py
```

PDF được ghi vào `dist/agent-security-guidelines-v<phiên-bản>.pdf`. Thư mục `dist/` không được commit. Khi push tag `vX.Y.Z`, CI tự build PDF và đính kèm vào trang Releases.

## Giấy phép

- Guideline, `TOOLS.md`, playbook và companion spec: [CC BY 4.0](LICENSE).
- Mã nguồn (`pdf/`, và mã tham chiếu, test vectors của companion spec khi có): [Apache 2.0](LICENSE-CODE).

Copyright 2026 superkhung.
