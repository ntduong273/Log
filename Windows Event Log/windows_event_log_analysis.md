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

## 7. Auditing Windows  Service

Nhiều cuộc attack phụ thuộc vào Windows service nhờ vào execute command remotely hoặc maintain persistence trên system. Trong khi hầu hết các event mà chúng ta đề cập cho tới nay thì mới chỉ được tìm thấy trong Security Event Log, Windows cũng đã ghi nhận các log có liên quan để bắt đầu và dừng dịch vụ trên System Event Log.

| Event ID | Description |
|----------|-------------|
| 6005 | Event log service được bắt đầu. Xảy ra ở giai đoạn system boot & whenever sys khởi động thủ công. Bởi vì event log service quan trọng cho security nên nó có Event ID riêng. |
| 6006 | Event log service bị dừng lại. Xảy ra khi tắt hoặc khởi động lại sys, còn nếu ở các time khác thì cũng đáng ngờ. |
| 7034 | Một dịch vụ chấm dứt đột ngột. Event description hiển thị tên các dịch vụ, số lần service crashed. |
| 7036 | Một dịch vụ đã bị dừng hoặc bắt đầu. Event description cung cấp tên service, nhưng không chi tiết user account nào requested dừng service, chỉ ra service nhập vào running state khi nó được start/enter the stopped state khi nó bị dừng.  | 
| 7040 | Một loại khởi động cho một 1 dịch vụ đã thay đổi. Event description hiển thị tên service đã được thay đổi, mô tả thay đổi. |
| 7045 | Một dịch vụ đã được cài đặt bởi hệ thống. Tên service, full path tới exe,… Khá quan trọng, vì nhiều tools tạo 1 service trên remote sys để exe command, or tạo service có tên ngẫu nhiên (bất thường), chạy tệp từ các folder khác,…Trùng hợp thằng Windows Defender cũng hay có cái kiểu đặt tên random -> cần check kĩ để phát hiện dấu hiệu độc hại |

<br>

-----------------------------------------------------------------------------------------------------------------------------

## 8. Wireless LAN Auditing

Windows duy trì 1 event log dành riêng cho các LAN activities, và với các điểm truy cập giả mạo là kiểu tấn công mã độc/mitm thì nên check các kết nối bất thường trên các thiết bị có khả năng dùng Wifi, cụ thể là những cái cho phép rời khỏi environment của mình. 

Log này được đặt ở %SystemRoot%\System32\winevt\Logs\Microsoft-Windows-WLAN-AutoConfig%4Operational.evtx.

| Event ID | Description |
|----------|-------------|
| 8001 |  WLAN service success connect to 1 wireless network. Event description chứa connection mode:automatic connect dựa vào configured pro5 hay thủ công, SSID của access point, cơ chế xác thực, cơ chế mã hóa |
| 8002 | WLAN service failed to connect to a wireless network. Tương tự như 8001, nhưng có failure reason field. |

<br>

-----------------------------------------------------------------------------------------------------------------------------

## 9. Process Tracking

Cmd.exe không lưu history command run by users -> khó cho incident handlers để điều tra hành động của attacker trên 1 máy bị xâm phạm. 
Các hệ thống Windows sau này đã cải thiện, log full command lines trong các event create process để loại bỏ sự mù quáng khỏi incident handlers, cung cấp dấu vết để tìm ra attacker.
 Cần bật 2 thành phần:
Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Audit Policy -> Audit process tracking.
Computer Configuration -> Administrative Templates -> System -> Audit Process Creation -> Include command line in process creation events.

| Event ID | Description |
|----------|-------------|
| 4688 | A new process created. ED có Process ID, Process name, creator process ID, creator process name, process command line. Creator Subject liệt kê các user context mà Creator Process đã đang chạy. Target Subject liệt kê user context mà các tiến trình mới tạo đang chạy. |


<br><br>

Windows Filtering Platform events IDs:
| Event ID | Description |
|----------|-------------|
| 5031 | Windows Firewall Service đã blocked 1 app khỏi việc chấp nhận các connect incoming trong mạng |
| 5152 | WFP đã chặn 1 gói tin |
| 5154 | WFP đã cho phép 1 app/service nghe trên 1 cổng cho các connect đến. |
| 5156 | WFP đã cho phép 1 kết nôi |
| 5157 | WFP đã chặn 1 kết nối |
| 5158 | WFP đã cho phép liên kết tới 1 local port. |
| 5159 | WFP đã chặn 1 liên kết tới 1 local port. |

<br>

-----------------------------------------------------------------------------------------------------------------------------

## 10. Additional Program Execution logging

AppLocker: tạo log sự kiện tại C:\Windows\System32\winevt\Logs cho các tệp thực thi, DLL, MSI, script và ứng dụng đóng gói, tùy chế độ (audit-only or blocking).
Windows Defender: ghi log tại C:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%4Operational.evtx và %4WHC.evtx, theo dõi malware và script đáng ngờ qua AMSI.

Windows Defender suspicious events IDs:

| Event ID | Description |
|----------|-------------|
| 1006 | Antimalware engine tìm được malware/phần mềm độc hại không mong muốn khác |
| 1007 | Antimalware platform tạo 1 hành động để protect ur sys khỏi malware/phần mềm độc hại |
|1008 | AP cố tạo 1 hành động để bảo vệ ur sys khỏi malware/pm độc hại khác nhưng failed |
| 1013 | AP xóa history của malware |
| 1015 | AP phát hiện hành vi đáng ngờ |
| 1116 | AP phát hiện malware |
| 1117 | Antimalware platform tạo 1 hành động để protect ur sys khỏi malware/phần mềm độc hại |
| 1118 | AP cố tạo 1 hành động để bảo vệ ur sys khỏi malware/pm độc hại khác nhưng failed |
| 1119 | AP gặp 1 lỗi nghiêm trọng khi cố hành động với malware/pm khả nghi |
| 5001 | Bảo vệ real-time bị vô hiệu hóa |
| 5004 | Cấu hình bảo vệ real-time bị thay đổi |
| 5007 | Cấu hình antimalware platform bị thay đổi |
| 5010 | Scan malware/pm khả khi khác bị vô hiệu hóa |
| 5012 | Scan virus bị vô hiệu hóa |


Windows exploit protection cung cấp khả năng phòng thủ, bảo vệ OS, app cá nhân khỏi common attack vectors. Khi bật, các tính năng này ghi lại hoạt động của mình trong các tệp log C:\Windows\System32\winevt\Logs\Microsoft-Windows-SecurityMitigations%4KernelMode.evtx và Microsoft-Windows-Security-Mitigations%4UserMode.evtx.

Có thể sử dụng Sysmon – 1 tiện ích free của Sysinternals, cài dưới dạng dịch vụ hệ thống và trình điều khiển -> tạo các event logs tiến trình, kết nối mạng, thay đổi thời gian tạo tệp,… Nó tạo ra một danh mục log mới, được hiển thị trong Event Viewer dưới mục Applications and Services Logs\Microsoft\Windows\Sysmon\Operational và được lưu trữ tại C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx.

| Event ID | Description |
|----------|-------------|
| 1 | Process creation: process ID, path to exe, hash exe, command line use,… |
| 2 | A process changed a file creation time. |
| 3 | Network connection |
| 4 | Sysmon service state changed. |
| 5 | Process terminated |
| 6 | Driver loaded |
| … | …… |
| 255 | Sysmon error |


<br>

-----------------------------------------------------------------------------------------------------------------------------

## 11. Auditing Powershell use

Bật thông qua Group Policy, ở Computer Configuration -> Policies -> Administrative Templates -> Windows Components -> Windows PowerShell.

Có 3 loại log, phụ thuộc ver Windows:
-	Module Logging: log các event execution theo pipeline, event log.
-	Script Block Logging: capture các command giải rối gửi tới powershell, capture chỉ command, không có result output, log tới event log.
-	Transciption: capture input/output powershell, text files trong user specified location.
Powershell event log có 2 nơi lưu chính:


%SystemRoot%\System32\winevt\ Logs\Microsoft-Windows-PowerShell%4Operational.evtx

| Event ID | Description |
|----------|-------------|
| 4103 | show cái pipeline exe từ module logging facility, gồm các user context được used to run command.  |
| 4104 | show script block logging entries. Captures các commands đã gửi tới powershell, nhưng không có output |



%SystemRoot%\System32\winevt\Logs\Windows PowerShell.evtx

| Event ID | Description |
|----------|-------------|
| 400 | chỉ ra việc bắt đầu execution command hoặc session. |
| 800 | shows chi tiết pipeline execution. Trường hostname sẽ chỉ ra nếu Console or remote session. |

