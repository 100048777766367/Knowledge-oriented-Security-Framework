# Knowledge-oriented-Security-Framework
## Hệ thống Phân tích Bảo mật Thông minh cho SMB (Tích hợp Wazuh SIEM)

KOS là một hệ thống tinh gọn, được thiết kế để hỗ trợ các doanh nghiệp vừa và nhỏ (SMB) quy trình phân tích và ứng phó sự cố bảo mật từ log của Wazuh.

### 🚀 Tính năng chính
- **Perception Layer:** Giám sát real-time file `alerts.json` của Wazuh.
- **Logic Engine:** Phân tầng nguy cơ (Layer A-E) và chấm điểm uy tín IP (IP Reputation).
- **Operation Center:** Tự động sinh báo cáo sự cố (.md) và kịch bản chặn IP (.sh).
- **Knowledge Base:** Lưu trữ tri thức tấn công để đối soát lâu dài.

### 🛠 Kiến trúc hệ thống
Hệ thống gồm 3 tầng xử lý chính:
1. **Perception (Cảm nhận):** Thu thập dữ liệu thô.
2. **Logic (Tư duy):** Phân tích và đánh giá mức độ nguy hiểm.
3. **Operation (Vận hành):** Đề xuất kịch bản ứng phó.

### 📖 Hướng dẫn sử dụng
1. Cài đặt thư viện: `pip install watchdog`
2. Chạy hệ thống với quyền quản trị: `sudo python3 main.py`
3. Xem báo cáo tổng hợp: `python3 main.py --knowledge-report`

---
