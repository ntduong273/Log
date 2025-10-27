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



----------------------------------------------------------------------------

## 6. Thay đổi cấu hình hệ thống quan trọng

**Log source:** System, Security.

| **Event ID(s)** | **Description** |
|-----------------|-----------------|
| 7036 | The service entered the running state/stopped state. *(State service thay đổi -> monitor các service quan trọng/service mới được tạo/chạy)* |
| 7045 | A service was installed in the system. *(Dấu hiệu persistence)* |
| 1074 | The process ... has initiated the shutdown/restart of the computer. |

| **Event ID(s)** | **Description** |
|-----------------|-----------------|
| 4697 | A service was installed in the system. *(Phiên bản Security Log của 7045 - Yêu cầu Audit Policy)* |
| 4698 | A scheduled task was created. *(Dấu hiệu Persistence - Yêu cầu Audit Policy)* |
| 4702 | A scheduled task was updated. |
| 4896 | A scheduled task was deleted. |
| 4946 | A rule has been added to the Windows Firewall exception list. *(Hoặc thay đổi rule).* |
| 4947 | A rule has been deleted from the Windows Firewall exception list. |


**Description:** Ghi lại các sự kiện liên quan đến trạng thái dịch vụ, cài đặt dịch vụ mới, tạo/thay đổi tác vụ theo lịch, và thay đổi cấu hình tường lửa Windows.

**Ý nghĩa cho SOC:**
- *Phát hiện kỹ thuật Persistence:* Attacker thường cài đặt dịch vụ hoặc tạo tác vụ theo lịch để đảm bảo mã độc chạy lại sau khi hệ thống khởi động lại.
- *Phát hiện thay đổi cấu hình phòng thủ:* Thay đổi tường lửa có thể cho phép attacker giao tiếp ra bên ngoài hoặc di chuyển ngang trong mạng.
- *Giám sát hoạt động bất thường:* Dịch vụ quan trọng bị dừng hoặc khởi động lại bất thường, hệ thống tự động tắt/khởi động lại không theo kế hoạch.

**Tác động tiềm tàng:**
- Persistence.
- Làm suy yếu các biện pháp phòng thủ (tường lửa).
- Gây gián đoạn dịch vụ (DoS) thông qua tắt dịch vụ quan trọng.



----------------------------------------------------------------------------

## 7. Truy cập đối tượng (Object Access: File, Registry,...)

**Log Source:** Security.

| **Event ID(s)** | **Description** |
|-----------------|-----------------|
| 4656 | A handle to an object was requested. *(Khi một đối tượng được truy cập)* |
| 4663 | An attempt was made to access an object. *(Khi quyền truy cập cụ thể (đọc, ghi, xóa) được sử dụng - RẤT QUAN TRỌNG - Yêu cầu cấu hình SACLs trên các file/registry key cụ thể và Audit Policy)* |

**Description:** Ghi lại các nỗ lực truy cập (đọc, ghi, xóa) vào các đối tượng hệ thống như file, thư mục, registry key, máy in, v.v.

**Ý nghĩa cho SOC:**
- *Phát hiện truy cập dữ liệu nhạy cảm trái phép:* Theo dõi ai đang cố gắng đọc, ghi hoặc xóa các file/thư mục chứa dữ liệu quan trọng.
- *Phát hiện thay đổi Registry độc hại:* Giám sát các thay đổi đối với các Registry key liên quan đến Persistence (Run keys), thay đổi cấu hình bảo mật, hoặc các cài đặt hệ thống quan trọng khác.
- *Truy vết hoạt động sau khi xâm nhập:* Xác định những file/registry key nào đã bị truy cập hoặc sửa đổi bởi kẻ tấn công.

**Tác động tiềm tàng:**
- Data Exfiltration.
- Phá hoại dữ liệu (Tampering).
- Persistence hoặc thay đổi cấu hình độc hại thông qua Registry.



----------------------------------------------------------------------------

## 8. Hoạt động của các thiết bị bên ngoài (External Device Usage)

**Log Source:** Security.

| **Event ID(s)** | **Description** |
|-----------------|-----------------|
| 4660 | An object was deleted. *(Có thể liên quan đến việc ngắt kết nối thiết bị USB sau khi dữ liệu bị sao chép - Yêu cầu cấu hình Audit Policy)* |

*(Các Event ID khác tùy thuộc vào cấu hình cụ thể cho việc cắm/tháo thiết bị USB)*

**Description:** Ghi lại các sự kiện liên quan đến việc kết nối và ngắt kết nối các thiết bị lưu trữ di động (USB drive).

**Ý nghĩa cho SOC:**
- *Phát hiện đánh cắp dữ liệu (Data Exfiltration):* Theo dõi việc cắm USB drive vào các máy chủ hoặc máy trạm nhạy cảm có thể là dấu hiệu của việc sao chép dữ liệu trái phép.
- *Phát hiện lây nhiễm mã độc qua USB:* Theo dõi việc cắm các thiết bị không được phê duyệt.

**Tác động tiềm tàng:**
- Đánh cắp dữ liệu.
- Lây nhiễm mã độc vào mạng nội bộ.



----------------------------------------------------------------------------

## 9. Các lỗi và cảnh báo hệ thống quan trọng

**Log source:** System.

**Event ID(s):** *(Các Event ID này rất đa dạng tùy thuộc vào nguyên nhân)*
- Bugcheck events: Các Event ID liên quan đến Blue Screen of Death (BSOD).
- Disk/Hardware errors: Các cảnh báo hoặc lỗi liên quan đến ổ cứng, bộ nhớ RAM, nguồn điện, v.v.
- Service Control Manager Errors: Lỗi khi khởi động hoặc chạy dịch vụ quan trọng.

**Description:** Ghi lại các lỗi nghiêm trọng, cảnh báo hoặc sự cố phần cứng/phần mềm gây ảnh hưởng đến hoạt động của hệ thống.

**Ý nghĩa cho SOC:**
- *Phát hiện sự cố ổn định hệ thống:* Các lỗi phần cứng/phần mềm liên tục có thể chỉ ra vấn đề cần khắc phục hoặc là kết quả của một cuộc tấn công *(vd: tấn công DoS).*
- *Manh mối về hoạt động độc hại:* Một số mã độc hoặc kỹ thuật tấn công có thể gây ra lỗi hệ thống hoặc làm sập dịch vụ.

**Tác động tiềm tàng:**
- Gián đoạn dịch vụ (DoS).
- Mất dữ liệu (trong trường hợp lỗi đĩa).
- Hệ thống không khả dụng.



----------------------------------------------------------------------------

## 10. Lỗi ứng dụng (Application Errors)

**Log source:** Application.

**Event ID(s):** *(Rất đa dạng, phụ thuộc vào ứng dụng)*

| **Event ID(s)** | **Description** |
|-----------------|-----------------|
| 1000 | Application Error *(Lỗi ứng dụng chung, thường là ứng dụng bị crash)* |

*Các Event ID khác từ các ứng dụng cụ thể: VD: Lỗi từ cơ sở dữ liệu, web server (IIS), phần mềm diệt virus, v.v.*

**Description:** Ghi lại các lỗi xảy ra trong quá trình hoạt động của các ứng dụng.

**Ý nghĩa cho SOC:**
- *Phát hiện tấn công khai thác lỗ hổng:* Một số cuộc tấn công (ví dụ: Buffer Overflow) có thể gây ra lỗi ứng dụng crash.
- *Theo dõi hoạt động của phần mềm bảo mật:* Log từ phần mềm diệt virus hoặc EDR (Endpoint Detection and Response) thường nằm trong Application Log và cung cấp cảnh báo quan trọng về việc phát hiện/chặn mã độc.
- *Phát hiện các vấn đề cấu hình/tương thích:* Giúp chẩn đoán các vấn đề gây ra lỗi ứng dụng có thể làm gián đoạn hoạt động kinh doanh.

**Tác động tiềm tàng:**
- Gián đoạn dịch vụ ứng dụng.
- Có thể là dấu hiệu của nỗ lực khai thác lỗ hổng.
