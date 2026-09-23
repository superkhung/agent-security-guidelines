# Bản đồ công cụ mã nguồn mở

Đây là bản sống của bảng ở Mục 5.1 trong *Hướng dẫn kỹ thuật an ninh cho AI Agent*. Guideline là ảnh chụp tại thời điểm phát hành; file này được cập nhật qua Pull Request. Khi hai bản lệch nhau, tin bản này.

Việc có mặt trong bảng không phải là khuyến nghị sản phẩm, và bảng không xếp hạng. Kiểm lại trạng thái dự án, giấy phép và phiên bản trước khi dùng.

**Cập nhật lần cuối:** 23/09/2026 · khớp với guideline 0.1.0

Quy ước độ trưởng thành: **Ổn định** (dùng rộng rãi, API ít đổi) · **Dùng được** (đã có người chạy thật, còn thay đổi) · **Thử nghiệm** (research preview, beta, hoặc tính năng đánh dấu experimental).

---

## Bảng công cụ

### Quét cấu hình và mô tả tool · SC-01, SC-04, SC-05

| Công cụ | Nền tảng | Độ trưởng thành | Ghi chú | Nguồn |
| :--- | :--- | :--- | :--- | :--- |
| Cisco `mcp-scanner` | Đa nền tảng | Dùng được | Apache 2.0; quét tĩnh không cần key, các bộ phân tích dùng LLM là tùy chọn | [github.com/cisco-ai-defense/mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) |
| Snyk Agent Scan (trước là Invariant `mcp-scan`) | Đa nền tảng | Dùng được | Cần tài khoản Snyk và `SNYK_TOKEN`; có tool pinning | [github.com/snyk/agent-scan](https://github.com/snyk/agent-scan) |

### Gateway MCP · SC-02, ACT-02, OBS-01, NET-05

| Công cụ | Nền tảng | Độ trưởng thành | Ghi chú | Nguồn |
| :--- | :--- | :--- | :--- | :--- |
| agentgateway | Linux, container | Dùng được | Rust, Apache 2.0; policy bằng CEL | [github.com/agentgateway/agentgateway](https://github.com/agentgateway/agentgateway) |
| ToolHive | Container | Dùng được | Go, Apache 2.0; mỗi server một container | [github.com/stacklok/toolhive](https://github.com/stacklok/toolhive) |
| Docker MCP Gateway | Docker | Dùng được | Chạy server dưới dạng image | [github.com/docker/mcp-gateway](https://github.com/docker/mcp-gateway) |
| Bifrost | Đa nền tảng | Dùng được | Gộp cả gateway LLM và gateway MCP | [github.com/maximhq/bifrost](https://github.com/maximhq/bifrost) |
| IBM ContextForge | Container, Kubernetes | Dùng được | Gateway và registry MCP | [github.com/IBM/mcp-context-forge](https://github.com/IBM/mcp-context-forge) |
| Obot | Container, Kubernetes | Dùng được | Thiên về catalog và quản trị tập trung | [github.com/obot-platform/obot](https://github.com/obot-platform/obot) |
| Microsoft MCP Gateway | Kubernetes | Dùng được | Reverse proxy và quản lý vòng đời server trên Kubernetes | [github.com/microsoft/mcp-gateway](https://github.com/microsoft/mcp-gateway) |

### Sandbox tiến trình trên máy trạm · ISO-02, ISO-03, NET-01

| Công cụ | Nền tảng | Độ trưởng thành | Ghi chú | Nguồn |
| :--- | :--- | :--- | :--- | :--- |
| Anthropic Sandbox Runtime (`srt`) | macOS, Linux; Windows đang phát triển | Thử nghiệm | Bọc được cả agent, MCP server local và lệnh tùy ý; có proxy lọc mạng. Mặc định cho đọc ở mọi nơi trừ đường dẫn bị cấm | [github.com/anthropics/sandbox-runtime](https://github.com/anthropics/sandbox-runtime) |
| bubblewrap | Linux | Ổn định | Nền của nhiều sandbox khác | [github.com/containers/bubblewrap](https://github.com/containers/bubblewrap) |
| Landlock (kernel), `landrun` | Linux ≥ 5.13 (mạng TCP từ 6.7) | Ổn định (kernel) | Không cần root | [github.com/Zouuup/landrun](https://github.com/Zouuup/landrun) |
| `sandbox-exec` | macOS | Ổn định nhưng deprecated | Apple vẫn dùng nội bộ; chưa có thay thế công khai tương đương | Có sẵn trong macOS |

### Container và microVM · ISO-04

| Công cụ | Nền tảng | Độ trưởng thành | Ghi chú | Nguồn |
| :--- | :--- | :--- | :--- | :--- |
| Podman / Docker rootless | Linux, macOS (qua VM) | Ổn định | | [github.com/podman-container-tools/podman](https://github.com/podman-container-tools/podman) |
| gVisor | Linux | Ổn định | Kernel ở user space, cô lập mạnh hơn container thường | [github.com/google/gvisor](https://github.com/google/gvisor) |
| Kata Containers | Linux | Ổn định | Mỗi container một VM nhẹ | [github.com/kata-containers/kata-containers](https://github.com/kata-containers/kata-containers) |
| Firecracker | Linux | Ổn định | microVM | [github.com/firecracker-microvm/firecracker](https://github.com/firecracker-microvm/firecracker) |
| E2B | Linux/cloud | Dùng được | Nền tảng sandbox cho agent dựng trên Firecracker | [github.com/e2b-dev/E2B](https://github.com/e2b-dev/E2B) |
| `kubernetes-sigs/agent-sandbox` | Kubernetes | Dùng được | CRD `Sandbox`, giao cô lập cho gVisor/Kata qua RuntimeClass | [github.com/kubernetes-sigs/agent-sandbox](https://github.com/kubernetes-sigs/agent-sandbox) |

### Egress · NET-01, NET-02, NET-03

| Công cụ | Nền tảng | Độ trưởng thành | Ghi chú | Nguồn |
| :--- | :--- | :--- | :--- | :--- |
| Squid | Đa nền tảng | Ổn định | Proxy allowlist theo tên miền | [github.com/squid-cache/squid](https://github.com/squid-cache/squid) |
| Envoy | Đa nền tảng | Ổn định | Proxy allowlist theo tên miền; dùng làm egress gateway | [github.com/envoyproxy/envoy](https://github.com/envoyproxy/envoy) |
| Cilium (FQDN policy) | Kubernetes | Ổn định | | [github.com/cilium/cilium](https://github.com/cilium/cilium) |
| LuLu | macOS | Ổn định | Firewall theo ứng dụng dựa trên Network Extension | [github.com/objective-see/LuLu](https://github.com/objective-see/LuLu) |

### Mirror package nội bộ · NET-01

| Công cụ | Nền tảng | Độ trưởng thành | Ghi chú | Nguồn |
| :--- | :--- | :--- | :--- | :--- |
| Verdaccio | Đa nền tảng | Ổn định | Mirror npm. Dựng trước khi bật chặn egress | [github.com/verdaccio/verdaccio](https://github.com/verdaccio/verdaccio) |
| devpi | Đa nền tảng | Ổn định | Mirror PyPI | [github.com/devpi/devpi](https://github.com/devpi/devpi) |
| Nexus Repository Community Edition | Đa nền tảng | Ổn định | Nhiều loại registry trong một chỗ; bản community có giới hạn mức sử dụng. Artifactory OSS không hỗ trợ npm và PyPI nên không dùng được cho mục này | Trang của nhà phát hành |

### Secret và danh tính workload · CRED-01, CRED-03

| Công cụ | Nền tảng | Độ trưởng thành | Ghi chú | Nguồn |
| :--- | :--- | :--- | :--- | :--- |
| OpenBao | Đa nền tảng | Ổn định | Nhánh mã nguồn mở của Vault (Vault hiện dùng giấy phép BSL) | [github.com/openbao/openbao](https://github.com/openbao/openbao) |
| SOPS | Đa nền tảng | Ổn định | Mã hóa file secret | [github.com/getsops/sops](https://github.com/getsops/sops) |
| `gitleaks` | Đa nền tảng | Ổn định | Quét secret; dùng lại rule cho CRED-04 | [github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) |
| `trufflehog` | Đa nền tảng | Ổn định | Quét secret, có kiểm secret còn sống | [github.com/trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) |
| SPIFFE/SPIRE | Linux, Kubernetes | Ổn định | Workload identity | [github.com/spiffe/spire](https://github.com/spiffe/spire) |

### Gateway LLM, chi phí · RES-01

| Công cụ | Nền tảng | Độ trưởng thành | Ghi chú | Nguồn |
| :--- | :--- | :--- | :--- | :--- |
| LiteLLM | Đa nền tảng | Dùng được | Khóa ảo, quota | [github.com/BerriAI/litellm](https://github.com/BerriAI/litellm) |
| Bifrost | Đa nền tảng | Dùng được | Khóa ảo, quota | [github.com/maximhq/bifrost](https://github.com/maximhq/bifrost) |
| Portkey gateway | Đa nền tảng | Dùng được | Khóa ảo, quota | [github.com/Portkey-AI/gateway](https://github.com/Portkey-AI/gateway) |

### Lọc prompt injection (lớp xác suất) · bổ trợ D5

Không phải ranh giới kiểm soát (guideline, Mục 1.5).

| Công cụ | Nền tảng | Độ trưởng thành | Ghi chú | Nguồn |
| :--- | :--- | :--- | :--- | :--- |
| LlamaFirewall (PromptGuard 2, AlignmentCheck, CodeShield) | Python | Dùng được; AlignmentCheck còn experimental | Nằm trong repo PurpleLlama | [github.com/meta-llama/PurpleLlama](https://github.com/meta-llama/PurpleLlama) |
| NeMo Guardrails | Python | Dùng được | | [github.com/NVIDIA-NeMo/Guardrails](https://github.com/NVIDIA-NeMo/Guardrails) |

### Supply chain · SC-03, SC-06, SC-07

| Công cụ | Nền tảng | Độ trưởng thành | Ghi chú | Nguồn |
| :--- | :--- | :--- | :--- | :--- |
| Sigstore `cosign` | Đa nền tảng | Ổn định | Ký và kiểm image | [github.com/sigstore/cosign](https://github.com/sigstore/cosign) |
| OpenSSF model signing | Đa nền tảng | Dùng được | Ký và kiểm model weights | [github.com/sigstore/model-transparency](https://github.com/sigstore/model-transparency) |

### Thu hồi theo sự kiện · CRED-03, OBS-04

| Công cụ | Nền tảng | Độ trưởng thành | Ghi chú | Nguồn |
| :--- | :--- | :--- | :--- | :--- |
| Các bản cài đặt OpenID Shared Signals Framework (CAEP, RISC) | Khác nhau | Dùng được | Cần cả IdP lẫn hệ thống đích hỗ trợ | openid.net, nhóm Shared Signals |

### Log, phát hiện · OBS-01, OBS-03

| Công cụ | Nền tảng | Độ trưởng thành | Ghi chú | Nguồn |
| :--- | :--- | :--- | :--- | :--- |
| OpenTelemetry (GenAI semantic conventions) | Đa nền tảng | Dùng được | Semantic conventions cho GenAI còn đang hoàn thiện | [github.com/open-telemetry/semantic-conventions](https://github.com/open-telemetry/semantic-conventions) |
| Falco | Linux | Ổn định | Tín hiệu cấp kernel | [github.com/falcosecurity/falco](https://github.com/falcosecurity/falco) |
| Tetragon | Linux | Ổn định | Tín hiệu cấp kernel dựa trên eBPF, chặn được tại chỗ | [github.com/cilium/tetragon](https://github.com/cilium/tetragon) |

### Log chống sửa · OBS-02

| Công cụ | Nền tảng | Độ trưởng thành | Ghi chú | Nguồn |
| :--- | :--- | :--- | :--- | :--- |
| Trillian Tessera | Đa nền tảng | Dùng được | Transparency log | [github.com/transparency-dev/tessera](https://github.com/transparency-dev/tessera) |

### Forensics · OBS-05

| Công cụ | Nền tảng | Độ trưởng thành | Ghi chú | Nguồn |
| :--- | :--- | :--- | :--- | :--- |
| CRIU | Linux | Ổn định | Không checkpoint được mọi workload (GPU, kết nối TCP đang mở); thử trước | [github.com/checkpoint-restore/criu](https://github.com/checkpoint-restore/criu) |

### Dữ liệu cá nhân · MEM-05

| Công cụ | Nền tảng | Độ trưởng thành | Ghi chú | Nguồn |
| :--- | :--- | :--- | :--- | :--- |
| Presidio | Python | Ổn định | Ban đầu do Microsoft phát triển. Chất lượng với tiếng Việt cần tự đánh giá | [github.com/data-privacy-stack/presidio](https://github.com/data-privacy-stack/presidio) |

### Ủy quyền giữa agent · MA-02

| Công cụ | Nền tảng | Độ trưởng thành | Ghi chú | Nguồn |
| :--- | :--- | :--- | :--- | :--- |
| Biscuit | Đa nền tảng | Dùng được | Token cho phép thu hẹp offline | [github.com/eclipse-biscuit/biscuit](https://github.com/eclipse-biscuit/biscuit) |

### FIDO2 / WebAuthn · ACT-06

Là khối xây dựng, chưa phải giải pháp phê duyệt cho agent (guideline, Mục 5.2).

| Công cụ | Nền tảng | Độ trưởng thành | Ghi chú | Nguồn |
| :--- | :--- | :--- | :--- | :--- |
| libfido2 | Đa nền tảng | Ổn định | Thư viện C phía client | [github.com/Yubico/libfido2](https://github.com/Yubico/libfido2) |
| python-fido2 | Đa nền tảng | Ổn định | Có cả phía client và phía server | [github.com/Yubico/python-fido2](https://github.com/Yubico/python-fido2) |
| Các thư viện WebAuthn server | Khác nhau | Ổn định | Chọn theo ngôn ngữ của proxy | |

---

## Khoảng trống

Những nhu cầu dưới đây chưa có công cụ mã nguồn mở trưởng thành trong những gì đã khảo sát. Mô tả đầy đủ ở Mục 5.2 của guideline. Nếu bạn biết công cụ lấp được một dòng, mở PR thêm nó vào bảng phía trên, và ghi tên công cụ vào cột "Công cụ đã biết" của dòng tương ứng ở đây.

| Khoảng trống | Control | Công cụ đã biết (nếu có) |
| :--- | :--- | :--- |
| Egress biết đang phục vụ phiên agent nào | NET-03 | |
| Sandbox cho tiến trình tùy ý trên Windows | ISO-02, ISO-03 | `srt` (phần Windows đang phát triển) |
| Phê duyệt có màn hình tin cậy và ràng buộc với tham số | ACT-05, ACT-06 | |
| Capability lease có ngân sách | ACT-04 | |
| Định dạng chung cho fingerprint tool và bản ghi hành động | SC-05, OBS-02 | Companion spec (Phụ lục E), bản nháp `aab-00` trong `companion-spec/` |
| Information-flow control dùng được trong sản xuất | NET-03, Nguyên lý 3 | CaMeL (nghiên cứu) |
| Bộ test và dữ liệu red team tiếng Việt | Bổ trợ D5, MEM-05 | |

---

## Cách đề xuất thay đổi

Mở một Pull Request sửa đúng một dòng hoặc một nhóm dòng liên quan. Mô tả PR cần có:

1. **Nhu cầu và control** mà công cụ phục vụ, theo mã control của guideline.
2. **Nguồn**: link tới mã nguồn, và giấy phép.
3. **Độ trưởng thành** theo quy ước ở đầu file, kèm lý do. "Dùng được" cần ít nhất một bằng chứng có người chạy thật (bài viết, issue, hoặc chính bạn).
4. **Phép kiểm chứng của control** mà bạn đã chạy với công cụ này, nếu có. Đây là thông tin có giá trị nhất.

Tiêu chí để có mặt trong bảng: có bản mã nguồn mở dùng được mà không cần mua; phục vụ trực tiếp một control; còn được duy trì.

Tiêu chí để bị gỡ hoặc hạ độ trưởng thành: repo bị archive; không có bản phát hành mới trong 12 tháng mà còn issue bảo mật mở; đổi giấy phép sang dạng không còn là mã nguồn mở (ghi lại lịch sử ở cột Ghi chú thay vì xóa ngay).

PR không được chấp nhận nếu chủ yếu là quảng bá sản phẩm, hoặc đề nghị xếp hạng công cụ.
