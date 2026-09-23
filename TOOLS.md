# Bản đồ công cụ mã nguồn mở

Đây là bản sống của bảng ở Mục 5.1 trong *Hướng dẫn kỹ thuật an ninh cho AI Agent*. Guideline là ảnh chụp tại thời điểm phát hành; file này được cập nhật qua Pull Request. Khi hai bản lệch nhau, tin bản này.

Việc có mặt trong bảng không phải là khuyến nghị sản phẩm, và bảng không xếp hạng. Kiểm lại trạng thái dự án, giấy phép và phiên bản trước khi dùng.

**Cập nhật lần cuối:** 23/09/2026 · khớp với guideline 0.1.0

Sau bảng công cụ là phần [Công cụ đóng boundary nào](#công-cụ-đóng-boundary-nào): mỗi công cụ chặn hay chỉ phát hiện, ở tầng nào, và đường đi nào nằm ngoài nó.

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
| Windows Sandbox | Windows 10/11 Pro, Enterprise, Education | Ổn định | Có sẵn trong OS, không phải mã nguồn mở. VM dùng một lần trên Hyper-V, cấu hình bằng file `.wsb` (thư mục map, `ReadOnly`, tắt mạng, tắt clipboard). Mạng chỉ bật hoặc tắt, không có allowlist, nên không thay được NET-01 | [learn.microsoft.com/…/windows-sandbox](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/) |
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

## Công cụ đóng boundary nào

Bảng công cụ phía trên trả lời "có công cụ gì". Bảng này trả lời câu mà người làm security cần hơn: công cụ đó thật sự chặn được gì, ở tầng nào, lúc nào, và đường đi nào nằm ngoài nó.

Theo Nguyên lý 2 của guideline, một control chỉ tất định trên những đường đi mà nó bao phủ. Công cụ ở tầng MCP không thấy tool built-in như Bash, Edit, WebFetch hay tiến trình con. Công cụ ở tầng mạng không biết kết nối thuộc phiên agent nào. Cột "Không bao được" là chỗ để đọc trước khi tin một công cụ đã đóng một control.

Quy ước:

- **Kiểu.** *Chặn*: ngăn hành động xảy ra. *Phát hiện*: chỉ báo sau khi thấy, không ngăn. *Nền*: không tự chặn gì, nhưng control khác cần nó mới chạy được. *Xác suất*: có thể chặn, có thể không (guideline, Mục 1.5); không phải ranh giới kiểm soát.
- **Lúc.** *Trước khi chạy*: lúc duyệt, lúc build, trong CI. *Lúc chạy*: trên đường đi của từng hành động. *Sau sự việc*: khi điều tra.
- **Tầng.** *OS* (filesystem, tiến trình), *Mạng*, *Credential*, *MCP* (tool call có ngữ nghĩa), *LLM* (lời gọi model), *Log*, *Dữ liệu*.

Đây là đánh giá tại 09/2026, dựa trên tài liệu công khai của từng công cụ và trên guideline, không phải kết quả kiểm thử từng công cụ. Công cụ thay đổi nhanh. Nếu một dòng sai, hoặc một giới hạn đã được công cụ khắc phục, đó là góp ý có giá trị: sửa dòng đó qua Pull Request và ghi nguồn.

| Công cụ | Control | Kiểu | Lúc | Tầng | Không bao được |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Cisco `mcp-scanner`, Snyk Agent Scan | SC-01, SC-04 | Phát hiện | Trước khi chạy | MCP | Không ngăn tool chạy; chỉ thấy mô tả và cấu hình, không thấy code server làm gì khác mô tả; có false negative (SC-04) |
| Snyk Agent Scan (tool pinning) | SC-05 | Phát hiện | Trước khi chạy, và khi quét lại | MCP | Dùng ở chế độ quét thì chỉ phát hiện thay đổi khi được chạy lại, không chặn `tools/list` mà mô hình đã nhận; kiểm tra bản đang dùng có chế độ chạy trên đường đi hay không trước khi coi nó là điểm so sánh của SC-05 |
| Gateway MCP (agentgateway, ToolHive, Docker MCP Gateway, Bifrost, ContextForge, Obot, Microsoft MCP Gateway) | SC-02, ACT-02, OBS-01, NET-05 | Chặn | Lúc chạy | MCP | Không thấy tool built-in của client (Bash, Edit, WebFetch) và tiến trình con (Nguyên lý 2); phần lớn chưa pin đủ các trường của fingerprint (SC-05); không ràng buộc phê duyệt với tham số (ACT-06) |
| ToolHive, Docker MCP Gateway (chạy server trong container) | SC-03, ISO-04 cho MCP server | Chặn | Lúc chạy | OS | Cô lập MCP server, không cô lập chính agent và tool built-in; server vẫn làm được mọi thứ trong phạm vi container và mạng được cấp |
| Anthropic Sandbox Runtime (`srt`) | ISO-02, ISO-03, NET-01 | Chặn | Lúc chạy | OS, Mạng | Mặc định cho đọc mọi nơi trừ đường dẫn trong `denyRead`, nên danh sách phải đủ (ISO-03); allowlist theo tên miền, không chặn exfil qua domain đã được phép (NET-03) và không biết phiên agent đã đọc gì; trên Linux, chặn UNIX socket bằng seccomp chỉ trên x64/arm64; Windows còn alpha |
| bubblewrap | ISO-02, ISO-03 | Chặn | Lúc chạy | OS | Chỉ là cơ chế namespace: chính sách do người gọi viết; không tự lọc mạng theo tên miền, cần proxy đi kèm (NET-01) |
| Landlock, `landrun` | ISO-03 | Chặn | Lúc chạy | OS | Lọc mạng TCP chỉ theo cổng (kernel 6.7+), không theo tên miền; việc chặn kết nối UNIX socket phụ thuộc phiên bản ABI (ISO-03) |
| `sandbox-exec` | ISO-02, ISO-03, NET-01 | Chặn | Lúc chạy | OS, Mạng | Deprecated, không có tài liệu chính thức cho ngôn ngữ profile; không lọc mạng theo tên miền nếu không có proxy |
| Podman / Docker rootless | ISO-04 | Chặn | Lúc chạy | OS | Chung kernel với host; bảo vệ chỉ đúng bằng những gì không được mount và không được mở mạng (ISO-04) |
| gVisor | ISO-04 | Chặn | Lúc chạy | OS | Kernel ở user space, chưa được coi là đạt mức microVM của ASAL-3b (ISO-04); egress vẫn phải kiểm soát riêng |
| Kata Containers, Firecracker, E2B, `agent-sandbox` | ISO-04 (mức microVM) | Chặn | Lúc chạy | OS | Cô lập kernel, không kiểm soát egress hay credential được đưa vào; tác động qua workspace được mount vẫn nguyên |
| Windows Sandbox | ISO-04 | Chặn | Lúc chạy | OS | Mạng chỉ bật hoặc tắt, không có allowlist: bật mạng thì NET-01 chưa đạt; bọc cả VM, không theo tiến trình |
| Squid, Envoy (egress proxy) | NET-01, NET-02 | Chặn | Lúc chạy | Mạng | Không chặn exfil qua domain đã được phép (NET-03) nếu không có TLS inspection; không biết kết nối thuộc phiên agent nào (Mục 5.2); chỉ có tác dụng khi sandbox không còn đường ra nào khác, kể cả IPv6 và UDP |
| Cilium (FQDN policy) | NET-01 | Chặn | Lúc chạy | Mạng | Như egress proxy: theo tên miền, không theo phiên agent; chỉ trong Kubernetes |
| LuLu | NET-01 | Chặn | Lúc chạy | Mạng | Theo ứng dụng, không theo phiên agent: agent và mọi tiến trình con cùng chương trình dùng chung một rule |
| Verdaccio, devpi, Nexus Community | NET-01 | Nền | Lúc chạy | Mạng | Không tự chặn gì; giúp allowlist khỏi phải mở registry công cộng. Không quét package độc nếu không cấu hình thêm |
| OpenBao | CRED-01, CRED-03 | Nền | Lúc chạy | Credential | Rút ngắn đời credential, không giới hạn việc agent làm trong cửa sổ hiệu lực; token đã cấp vẫn sống tới lúc hết hạn ở hệ thống không kiểm lại trạng thái (CRED-03) |
| SOPS | CRED-01 | Nền | Trước khi chạy | Credential | Bảo vệ secret khi lưu; tiến trình nào có khóa giải mã thì đọc được hết |
| `gitleaks`, `trufflehog` | CRED-01, CRED-04 | Phát hiện | Trước khi chạy; lúc chạy khi dùng cho CRED-04 | Credential | Dựa trên mẫu, bỏ sót secret có định dạng lạ hoặc đã bị mã hóa (CRED-04) |
| SPIFFE/SPIRE | MA-01, CRED-02 | Nền | Lúc chạy | Credential | Cho mỗi workload một danh tính; không giới hạn danh tính đó được làm gì |
| LiteLLM, Bifrost, Portkey (gateway LLM) | RES-01, RES-02 | Chặn | Lúc chạy | LLM | Chỉ thấy lời gọi model, không thấy tool call gọi ra hệ thống khác (RES-02) |
| LlamaFirewall, NeMo Guardrails | Bổ trợ D5 | Xác suất | Lúc chạy | LLM | Không phải ranh giới kiểm soát (Mục 1.5); chưa có đánh giá công khai với nội dung tiếng Việt (Mục 5.2) |
| Sigstore `cosign`, OpenSSF model signing | SC-03, SC-06, SC-07 | Chặn khi bật kiểm chữ ký lúc chạy; nếu không thì chỉ là Nền | Trước khi chạy | OS | Chứng minh nguồn gốc, không chứng minh bản đã ký an toàn; vô dụng nếu không bật kiểm tra lúc chạy (SC-06) |
| OpenID Shared Signals (CAEP, RISC) | CRED-03, OBS-04 | Nền | Lúc chạy | Credential | Chỉ có tác dụng ở hệ thống thật sự nhận và xử lý sự kiện; không thay TTL ngắn (CRED-03) |
| OpenTelemetry (GenAI) | OBS-01, MA-04 | Phát hiện | Lúc chạy, Sau sự việc | Log | Chỉ ghi những gì được instrument; không tự chống sửa (OBS-02) |
| Falco | OBS-03 | Phát hiện | Lúc chạy | OS | Báo động, không ngăn; chỉ Linux |
| Tetragon | OBS-03 | Phát hiện; có thể Chặn khi bật policy enforcement | Lúc chạy | OS | Chỉ Linux; policy chặn phải tự viết và thử kỹ |
| Trillian Tessera | OBS-02 | Phát hiện | Sau sự việc | Log | Phát hiện sửa log sau khi ghi; không ngăn thành phần ghi log bị chiếm ghi sai từ đầu (OBS-02) |
| CRIU | OBS-05 | Nền | Sau sự việc | OS | Không checkpoint được mọi workload (GPU, kết nối TCP đang mở) (OBS-05) |
| Presidio | MEM-05 | Phát hiện | Trước khi chạy, định kỳ | Dữ liệu | Chất lượng với định dạng dữ liệu Việt Nam chưa được đánh giá (Mục 5.2) |
| Biscuit | MA-02 | Chặn | Lúc chạy | Credential | Chỉ có tác dụng khi service đích kiểm token và các ràng buộc của nó |
| libfido2, python-fido2, thư viện WebAuthn server | ACT-06 | Nền | Lúc chạy | Credential | Khối xây dựng; security key không có màn hình, nên không chứng minh người duyệt đã thấy tham số nào (ACT-05) |

Đọc bảng theo control thay vì theo công cụ thì thấy ngay chỗ trống: không có dòng nào *Chặn* ở tầng mạng mà biết phiên agent (NET-03 theo ngữ cảnh), không có dòng nào *Chặn* cho ACT-04 hay ACT-05, và ACT-06 chỉ có *Nền*. Đó cũng là các dòng trong bảng Khoảng trống dưới đây.

## Khoảng trống

Những nhu cầu dưới đây chưa có công cụ mã nguồn mở trưởng thành trong những gì đã khảo sát. Mô tả đầy đủ ở Mục 5.2 của guideline. Nếu bạn biết công cụ lấp được một dòng, mở PR thêm nó vào bảng phía trên, và ghi tên công cụ vào cột "Công cụ đã biết" của dòng tương ứng ở đây.

| Khoảng trống | Control | Công cụ đã biết (nếu có) |
| :--- | :--- | :--- |
| Egress biết đang phục vụ phiên agent nào | NET-03 | |
| Sandbox cho tiến trình tùy ý trên Windows | ISO-02, ISO-03 | `srt` (phần Windows đang phát triển); Windows Sandbox bọc cả VM, không theo tiến trình |
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
5. **Một dòng cho bảng "Công cụ đóng boundary nào"**: kiểu (Chặn, Phát hiện, Nền, Xác suất), lúc, tầng, và những gì công cụ không bao được. Đừng bỏ trống cột cuối; công cụ nào cũng có đường đi nằm ngoài nó.

Tiêu chí để có mặt trong bảng: có bản mã nguồn mở dùng được mà không cần mua, hoặc là tính năng có sẵn của hệ điều hành (như `sandbox-exec`, Windows Sandbox; ghi rõ ở cột Ghi chú); phục vụ trực tiếp một control; còn được duy trì.

Tiêu chí để bị gỡ hoặc hạ độ trưởng thành: repo bị archive; không có bản phát hành mới trong 12 tháng mà còn issue bảo mật mở; đổi giấy phép sang dạng không còn là mã nguồn mở (ghi lại lịch sử ở cột Ghi chú thay vì xóa ngay).

PR không được chấp nhận nếu chủ yếu là quảng bá sản phẩm, hoặc đề nghị xếp hạng công cụ.
