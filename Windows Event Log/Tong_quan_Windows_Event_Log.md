# TỔNG QUAN WINDOWS EVENT LOG THEO BLUETEAM



Đánh giá các event log trong Windows theo các fields: ID, description, ý nghĩa thực tế, tác động tiềm tàng hỗ trợ trong SOC.<br>
(Chủ yếu từ Security log, một số từ System Log và Application Log)


----------------------------------------------------------------------------------

## 1. Hoạt động đăng nhập/đăng xuất (Logon/Logoff)

**Log source:** Security.

| **Event ID(s)** | **Description** |
|-----------------|-----------------|
| 4624 | Successful Logon | 
| 4625 | Failed Logon |
| 4634/4637 | Logoff |
| 4672 | Special Logon (Tài khoản có quyền admin/tương đương) |

**Description:** Ghi lại các phiên đăng nhập và đăng xuất trên hệ thống. Event 4624 chứa thông tin chi tiết về loại đăng nhập (interactive, remoteinteractive, network, batch, service,...), tài khoản nào, từ đâu (source IP),...

**Ý nghĩa cho SOC:** 
- *Phát hiện đăng nhập trái phép:* Số lượng lớn log **4625** từ một nguồn IP/trên nhiều tài khoản có thể là dấu hiệu chính của các cuộc tấn công brute-force or dò mật khẩu.
- *Theo dõi hoạt động người dùng:* **4624** giúp xác định ai đã đăng nhập vào hệ thống nào, khi nào, bằng cách nào. **4672** cảnh báo về các phiên đăng nhập có đặc quyền cao.
- *Theo dõi các đăng nhập bất thường:* Đăng nhập vào khoảng thời gian lạ, địa điểm lạ, loại đăng nhập bất thường (VD: tài khoản người dùng thông thường đăng nhập loại Service, Batch).

**Tác động tiềm tàng:** 
- Truy cập trái phép vào hệ thống/dữ liệu.
- Thiết lập initial access.
- Privilege escalation nếu phát hiện đăng nhập đặc quyền bất thường.
- Phát hiện các attempt to attack.

<img width="1848" height="875" alt="image" src="https://github.com/user-attachments/assets/f0213615-dc1d-4d19-8436-c6317ce4ccca" />


----------------------------------------------------------------------------------

## 2. Quản lý tài khoản người dùng, nhóm (Account Management)

**Log source:** Security.

| **Event ID(s)** | **Description** |
|-----------------|-----------------|
| 4720 | A user account was created. |
| 4726 | A user account was deleted. |
| 4722 | A user account was enabled. |
| 4723 | An attempt was made to change an account's password. |
| 4724 | An attempt was made to reset an account's password. |
| 4738 | A user account was changed. *(Kiểm tra các thay đổi về tên, trạng thái, mô tả,...)* |
| 4756 | A member was added to a security-enabled global group. *(VD: added to Administrators group)* |
| 4757 | A member was removed from a security-enabled group. |
| 4767 | A user account was unlocked. |

**Description:** Ghi lại các thay đổi đối với tài khoản người dùng và nhóm bảo mật trong AD, trên máy local.

**Ý nghĩa cho SOC:** 
- *Phát hiện tài khoản giả mạo/backdoor:* Tạo/kích hoạt tài khoản mới, đặc biệt là acc có tên đáng ngờ, added vào các nhóm có đặc quyền cao.
- *Theo dõi thay đổi quyền hạn:* Thêm user vào các nhóm quản trị (Administrators, Domain Admins) -> dấu hiệu privilege escalation.
- *Giám sát hoạt động quản trị:* Đảm bảo các thay đổi tài khoản được thực hiện bởi đúng người, có ủy quyền.

**Tác động tiềm tàng:**
- Tạo tài khoản tồn tại lâu dài, duy trì kiểm soát (Persistence)
- Leo thang đặc quyền (Privilege escalation)
- Che giấu hoạt động bằng tài khoản mới (Defense evasion)


<img width="1694" height="895" alt="image" src="https://github.com/user-attachments/assets/e81ea3cc-2332-4344-9e2c-d0d0297dd34e" />


----------------------------------------------------------------------------------

## 3. Thực thi tiến trình (Process Creation)

**Log Source:** Security.

| **Event ID(s)** | **Description** |
|-----------------|-----------------|
| 4688 | A new process has been created. *(VERY IMPORTANT: Yêu cầu cấu hình Audit Process Creation)* |
| 4689 | A process has exited. |

**Description:** 4688 ghi lại thông tin về tiến trình mới được tạo, gồm tên tiến trình cha, tên tiến trình con, full path của exe, command line used + arguments, ID process.

**Ý nghĩa cho SOC:** 
- *Phát hiện hoạt động của malware/exploit:* malware thường tạo ra các tiến trình đáng ngờ, chạy từ các vị trí bất thường (VD: Temp folder), hoặc sử dụng các dòng lệnh lạ.
- *Phát hiện kỹ thuật tấn công:* Các techni như "living off the land binaries" (LOLBAS - sử dụng các file nhị phân hệ thống hợp pháp cho mục đích độc hại, vd: powershell.exe, cmd.exe, certutil.exe), thực thi mã từ bộ nhớ, hoặc sử dụng các script độc hại sẽ được ghi lại trong command line.
- *Truy vết hoạt động:* Giúp xây dựng chuỗi sự kiện dẫn tới một sự cố (vd: 1 file độc hại được tải xuống bởi browser, sau đó browser tạo 1 process cmd/powershell, process này sẽ tạo ra 1 malware).

**Tác động tiềm tàng:**
- Execution (run malware)
- Discovery
- Actions on Objectives
- Persistence


----------------------------------------------------------------------------------

## 4. Thay đổi Chính sách Kiểm tra/Bảo mật (Audit Policy/Security Policy Changes)

**Log source:** Security.

| **Event ID(s)** | **Description** |
|-----------------|-----------------|
| 4719 | System audit policy was changed. |
| 4816 | The Security object logon cache was cleared. *(Có thể liên quan đến Kerberoasting hoặc tấn công vé)* |

**Description:** Ghi lại khi cấu hình Audit Policy của hệ thống bị thay đổi.

**Ý nghĩa cho SOC:** 
- *Phát hiện attacker che giấu dấu vết:* Attacker attempt to tắt/change audit policy để ngăn việc bị ghi lại hoạt động.


**Tác động tiềm tàng:**
- Tạo điều kiện cho các hoạt động độc hại khác diễn ra mà không bị ghi log.
- Che giấu bằng chứng về cuộc tấn công.



----------------------------------------------------------------------------------

## 5. Xóa log bảo mật (Security Log Clearing)

**Log Source:** Security.

| **Event ID(s)** | **Description** |
|-----------------|-----------------|
| 1102 | The audit log was cleared. |

**Description:** Ghi lại khi Security log bị xóa.

**Ý nghĩa cho SOC:** 
- *Dấu hiệu rõ của nỗ lực che giấu dấu vết:* Xóa log là một techni phổ biến được dùng bởi attacker để xóa bỏ bằng chứng về hoạt động của chúng.

**Tác động tiềm tàng:**
- Mất bằng chứng quan trọng về các sự cố bảo mật.
- Khó khăn/không thể thực hiện digital forensics.



----------------------------------------------------------------------------------

## 6. Thay đổi cấu hình hệ thống quan trọng

**Log source:** System, Security.

| **Event ID(s)** | **Description** |
|-----------------|-----------------|
| 7036 | The service entered the running state/stopped state. *(State service thay đổi -> monitor các service quan trọng/service mới được tạo/chạy)* |
| 7045 | A service was installed in the system. *(Dấu hiệu persistence)* |
| 1074 | The process ... has initiated the shutdown/restart of the computer. |

| **Event ID(s)** | **Description** |
|-----------------|-----------------|
