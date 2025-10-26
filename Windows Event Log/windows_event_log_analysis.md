# Windows Event Log Analysis

## Format của Windows Event Log

- Mặc định lưu ở: **<code>%SystemRoot%\System32\winevt\logs</code>**
- Định dạng mặc định: **dạng binary XML**, được thiết kế bởi extension: **.evtx**
- Có thể lưu trữ ở xa, sử dụng các log subscriptions, truyền dữ liệu diễn ra qua HTTPS trên cổng 5986 bằng WinRM.<br><br>
- 3 trường log quan trọng: **Security, System, Application**, ngoài ra còn có các loại log khác như: Setup, Forwared Logs,...
- Event log thường có các trường phổ biến như:
  <br>
  | Trường | Nội dung |
  |--------|----------|
  | 1. **Name** | Tên/nơi lưu trữ sự kiện <br>|
  | 2. **Source** | Service, application, Windows component tạo ra <br>|
  | 3. **Event ID** | Mã cho từng loại log <br>|
  | 4. **Level** | Mức độ nghiêm trọng <br>|
  | 5. **User** | Tài khoản liên quan/ngữ cảnh user khi log được ghi (chú ý: SYSTEM) <br>|
  | 6. **Opcode** | Mã do nguồn tạo log gán, ý nghĩa phụ thuộc nguồn <br>|
  | 7. **Logged** | Time và ngày hệ thống ghi sự kiện. <br>|
  | 8. **Task Category** | Danh mục nhiệm vụ do nguồn gán, ý nghĩa phụ thuộc nguồn <br>|
  | 9. **Keyword** | Do nguồn gán, dùng để nhóm/sắp xếp sự kiện. <br>|
  | 10. **Computer** | Tên máy ghi lại <br>|
  | 11. **Description** | Mô tả |

  <br><br><br>



 ## 1. Event quản lí tài khoản (Dải 4720 -> 4799)

- Ghi các event khi một account được created/modified.
- Ở local system nếu là local account, ở domain controller nếu là domain account.<br><br>



- Tài khoản người dùng:

| Event ID | Description |
|----------|-------------|
| 4720 | A user account was created. |
| 4722 | A user account was enabled. |
| 4723 | A user attempted to change an account’s password. |
| 4724 | An attempt was made to reset an account’s password. |
| 4725 | A user account was disabled. |
| 4726 | A user account was deleted. |
| 4738 | A user account was changed. |



- Tài khoản máy:

| Event ID | Description |
|----------|-------------|
| 4741 | A computer account was created. |
| 4742 | A computer account was changed. |
| 4743 | A computer account was deleted. |



- Còn lại là các event quản lí nhóm:

<img width="555" height="457" alt="image" src="https://github.com/user-attachments/assets/82b3011f-bac2-49e4-80ff-e1d534baad77" />

Trong Active Directory, có 3 loại nhóm chính:
- **Local Group:** Quản lý quyền cục bộ, tạo trên 1 máy tính(standalone) or domain controller, không phụ thuộc vào AD trừ khi tạo trên DC.
- **Global Group:** Quản lý quyền trong domain, tạo trong một domain cụ thể, đồng bộ qua AD.
- **Universal Group:** Quản lý quyền toàn rừng, tạo trong một domain thuộc rừng AD, đồng bộ qua toàn bộ rừng.


Mỗi loại nhóm này có thể được cấu hình với 2 kiểu nhóm:
- **Security Group:** Nhóm bảo mật, cho phép gán quyền truy cập vào tài nguyên (như tệp, thư mục, máy in) thông qua ACLs.
- **Distribution Group:** Nhóm phân phối, dùng chủ yếu cho email (như trong Exchange).


Security-enabled Local Group:

| Event ID | Description |
|----------|-------------|
| 4731 | created |
| 4732 | add a member |
| 4733 | remove a member |
| 4734 | deleted |
| 4735 | changed |



Security-enabled Global Group:

| Event ID | Description |
|----------|-------------|
| 4727 | created |
| 4728 | add member |
| 4729 | remove member |
| 4730 | deleted |
| 4737 | changed |



Security-enabled Universal Group:

| Event ID | Description |
|----------|-------------|
| 4754 | created |
| 4755 | changed |
| 4756 | add member |
| 4757 | remove member |
| 4758 | deleted |

<br>

2 log liệt kê:

| Event ID | Description |
|----------|-------------|
| 4798 | Khi 1 process/user cố gắng liệt kê (enumerated) các local groups mà 1 user account cụ thể là thành viên. Large numbers of these events may be account enumeration, để thu thập thông tin về tài khoản và nhóm, nhằm xác định mục tiêu tấn công |
| 4799 | Khi 1 process/user cố gắng liệt kê thành viên của 1 security-enabled local group. Large numbers of these events may be adversary group enumeration. |

<br>

-----------------------------------------------------------------------------------------------------------------------------

## 2. Event logon tài khoản (Giao thức xác thực Kerberos)


- Nằm ở **<code>Security event log</code>**, thiết lập thông qua Group Policy.
- Logon = an account gain access to a resource.
- Domain accounts được xác thực bởi domain controller trong một mạng Windows.
- Local accounts được xác thực bởi hệ thống cục bộ nơi chúng tồn tại.<br><br><br>

| Event ID | Description |
|----------|-------------|
| 4768 | Cấp phát thành công một TGT (Ticket Granting Ticket) | 
<br>
=> 1 user account đã được xác thực bởi DC. Phần Network Information trong mô tả sự kiện chứa thông tin bổ sung về máy chủ từ xa trong trường hợp có nỗ lực đăng nhập từ xa. Trường Keywords chỉ ra liệu nỗ lực xác thực có thành công hay thất bại. 

**Result code:**
- 6 (0x6): Username không có hiệu lực.
- 12 (0xC): Chính sách hạn chế (Policy restriction) cấm đăng nhập (hạn chế về tên máy, time đăng nhập trong ngày).
- 18 (0x12): Account bị khóa, vô hiệu hóa, hết hạn.
- 23 (0x17): Password của account hết hạn.
- 24 (0x18): Password sai.
- 32 (0x20): Ticket hết hạn (common on computer accounts).
- 37 (0x25): Độ lệch time của đồng hồ quá lớn.



| Event ID | Description |
|----------|-------------|
| 4769 | A service ticket được request by 1 user account cho 1 resource cụ thể (gồm source IP máy req, user account, service to be accessed)| 
| 4770 | A service ticket được renew (account name, service name, client IP address, encrypt type) |
| 4771 | Tùy lí do logon Kerberos failed, mà tạo ra event 4768 hay 4771 (result code: in4 failed) |
| 4776 | Các xác thực NTLM. 
- Nhiều event 4776 thất bại, error code: C000006A(mật khẩu không hợp lệ) + C0000234 (tài khoản bị khóa) -> dấu hiệu attack đoán mật khẩu thất bại (or đơn giản 1 user quên password).
- Nhiều event 4776 thất bại, theo sau là event 4776 thành công -> attack đoán mật khẩu thành công. |




Trên các hệ thống đã được truy cập, một số Event IDs cần chú ý:


| Event ID | Description |
|----------|-------------|
| 4624 | Một lần logon đã diễn ra. |

***Phân tích:*** 
- Type 2: đăng nhập Interactive (đăng nhập cục bộ).
- Type 3: đăng nhập từ xa hoặc Network.<br>
(*Event description field chứa thông tin liên quan, tập trung vào Network Information để lấy thông tin về máy chủ từ xa.<br>=> so sánh (correlation) với các event:4768, 4769,4776 có thể cung cấp thêm chi tiết về máy chủ từ xa. <br>Nếu tên máy chủ và địa chỉ IP được gán khác nhau, có thể là dấu hiệu của tấn công SMB relay, khi 1 attacker chuyển tiếp 1 req từ một hệ thống sử dụng địa chỉ IP không liên quan đến hệ thống đó.*)
(*Trường Caller Process Name, Caller Process ID trong Process Information cung cấp thêm chi tiết về tiến trình khởi tạo đăng nhập.<br>Các kết nối thành công qua RDP thường được ghi lại với Logon Type 10 trong Event ID 4624.<br>Các đăng nhập RDP thất bại thường dẫn đến Logon Type 3.*)
- Type 4: Batch (hàng loạt, scheduled task)
- Type 5: Service (Service Control Manager tạo 1 service)
- Type 7: Unlock 
- Type 8: NetworkCleartext
- Type 9: NewCredentials
- Type 10: RemoteInteractive
- Type 11: CachedInteractive



| Event ID | Description |
|----------|-------------|
| 4625 | Một lần logon đã thất bại. |

***Phân tích:*** Có nhiều event này trên toàn mạng -> có thể là dấu hiệu tấn công đoán mật khẩu/password spraying. Network Information trong Event Description cung cấp thông tin giá trị về máy chủ từ xa đang cố gắng đăng nhập. Lý do thất bại có trong Failure Information trong Event Description.

VD status code:

0xC000006A: User logon with misspelled or bad password.



| Event ID | Description |
|----------|-------------|
| 4634/4647 | User logoff. |
| 4648 | A logon cố dùng explicit credentials |
| 4672 | Khi một số đặc quyền liên quan đến quyền truy cập nâng cao (elevated) hoặc quyền quản trị viên được cấp cho một lần đăng nhập. |
| 4778 | Khi a session is reconnected to a Windows station |
| 4779 | Khi a session is disconnected |



*Thông tin thêm về RDP Sessions ở file log:* %SystemRoot%\System32\winevt\Logs\Microsoft-Windows-TerminalServicesLocalSessionManager%4Operational

Event ID 21 chỉ ra session logon events, both local and remote, including the IP from which the connection was made if remote. 

Event ID 24 chỉ ra session disconnection, including the IP from which the connection was made if remote


<br>

-----------------------------------------------------------------------------------------------------------------------------

## 3. Access to shared objects (Dải từ 5140 -> 5145)

Attacker bên ngoài thường tận dụng các valid credential để truy cập từ xa vào các dữ liệu được create/administrative share. Ngoài việc tạo ra các event log account logon & logon bên trên thì nó còn tạo ra các log access to shared object này. (enabled  trong Group Policy Management Console).

| Event ID | Description |
|----------|-------------|
| 5140 | A network share object đc accessed. Gồm các account name, source address của account đã accessed object, nhưng không chỉ rõ đã access những file nào. Nếu có nhiều event này từ 1 single acc -> dấu hiệu của harvest/map data |
| 5142 | A network share object đc added. | 
| 5143 |  A nso đc modified. |
| 5144 | A nso bị deleted. |
| 5145 | A nso bị checked để xem nếu client có thể được cấp quyền mong muốn. Ghi log failed nếu bị từ chối ở mức File Share, còn không ghi nếu ở NTFS level. |


<br>

-----------------------------------------------------------------------------------------------------------------------------

## 4. Scheduled task logging

Nếu trong Task Scheduler app có bật history thông qua Event Viewer/wevtutil thì %SystemRoot%\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational sẽ log các event scheduled task:

| Event ID | Description |
|----------|-------------|
| 106 | Scheduled Task được tạo. Chỉ ra user acc đã tạo, tên user được gán, date/time task được scheduled. |
| 140 | ST được updated. Chỉ ra user acc đã update task, tên task, date/time task được update. |
|141 | ST bị xóa. Chỉ ra user acc đã xóa + tên task. |
| 200 | ST được executed. Chỉ ra tên task, full path tới file thực thi on disk đã run. Kết hợp với Event ID 106 để tìm user acc đã tạo task. |
| 201 | ST hoàn thành. Chỉ ra tên task, full path tới file thực thi on disk đã run. Kết hợp với Event ID 106 để tìm user acc đã tạo task. |

<br>

-----------------------------------------------------------------------------------------------------------------------------

## 5. Object Access Auditing

Lưu trong Security log.

Mặc định không bật, nên bật trong sys nhạy cảm. 

Sử dụng Local Security Policy để bật (*Security Settings -> Local Policies -> Audit Policy -> Audit object access to Enabled for Success and Failure*). Một số hoạt động mặc định được log nhưng 1 số khác cần cấu hình rõ ràng, vì ghi log chi tiết nên tránh bật hết -> quá tải)

Nếu object access auditing bật thì scheduled task cũng có 1 số log bổ sung:


| Event ID | Description |
|----------|-------------|
| 4698 | A scheduled task được created. Trong ED có user acc đã tạo, chi tiết XML ở mục Task Description, gồm các task name, tag thông tin: <date>, <author>,.. |
| 4699 | A ST bị xóa.  |
| 4700 | A ST được kích hoạt. |
| 4701 | A ST bị vô hiệu hóa. |
| 4702 | A ST được updated, gồm chi tiết các task sau khi sửa đổi, liệt kê trong XML. |


Muốn sử dụng 1 sys object (như là file, ..) thì phải gồm 1 handle cho object đó.  

| Event ID | Description |
|----------|-------------|
| 4656 | 1 handle to 1 object được request. Khi 1 process cố gắng lấy 1 handle cho 1 audited object, event này sẽ được tạo, gồm chi tiết object này, handle ID được gán, success/failed, account used to req + Logon ID, … |
| 4657 | 1 giá trị registry được chỉnh sửa. Gồm: user account, process được mở cho handle, các chỉnh sửa chi tiết như: object name, full path, name registry key mà value được sửa,.. | 
| 4658 | Handle to 1 object bị closed. Gồm: user account, process được mở cho handle. |
| 4660 | 1 object bị xóa. Gồm: user account, process được mở cho handle. |
| 4663 | 1 nỗ lực đã được tạo để access 1 object, được log khi 1 process cố gắng tương tác với 1 object, hơn là chỉ lấy 1 handle cho 1 object -> sử dụng để xác định hành động đã được thực hiện trên 1 object |



<br>

-----------------------------------------------------------------------------------------------------------------------------

## 6. Audit Policy changes

Khi thay đổi audit policy dù là độc hại do attacker hay hợp pháp do admin thì vẫn có ảnh hưởng tới các bằng chứng sẵn có cho các nhà điều tra, ứng phó với sự cố. Tuy nhiên, Windows có ghi lại log đó:


| Event ID | Description |
|----------|-------------|
| 4719 | System audit policy đã được changed. Toàn bộ thay đổi được ghi trong section Audit Policy Change, account tạo thay đổi, tên của local system,… |
| 1102 | Bất kể các thiết lập trong Audit Policy, nếu security event log bị xóa, event 1102 sẽ được ghi lại như mục nhập đầu tiên trong log mới và trống, có thể xác định tên user account đã xóa log,.. |


<br>

-----------------------------------------------------------------------------------------------------------------------------

## 7. 
