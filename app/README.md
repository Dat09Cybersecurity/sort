# 🔐 Bài thực hành: Kênh liên lạc an toàn
## Diffie–Hellman + Chữ ký số + mini-PKI + AEAD

Ứng dụng web mô phỏng kênh liên lạc an toàn giữa Alice và Bob qua máy chủ trung gian không tin cậy (Eve), minh họa đầy đủ chuỗi:
**Tạo khóa → Cấp chứng thư → Thỏa thuận khóa → Mã hóa lai có xác thực → Ký số**, kèm mô phỏng tấn công MITM và ví dụ số nhỏ kiểm chứng lý thuyết.

---

## 📋 Yêu cầu hệ thống

- **Python** ≥ 3.9 (khuyến nghị 3.10 hoặc 3.11)
- **pip** (đi kèm Python)
- Trình duyệt hiện đại (Chrome, Firefox, Edge)
- Hệ điều hành: Windows / macOS / Linux đều được

Kiểm tra Python:
```bash
python --version
# hoặc
python3 --version