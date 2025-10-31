# BÀI TẬP THỰC HÀNH PHÂN TÍCH, TRACE LOG CƠ BẢN (NCS)



## Sysmon_1.evtx

3 event đầu tiên đều bình thường, legit. Event ID = 1 new process, chạy cscript với memdump.vps và notepad.exe, tạo tiếp ra 2 event ID = 7: Image loaded là chạy scrobj.exe và wmiutils.dll. Tuy nhiên ở event thứ 3 có được phát hiện bất thường bởi rule: *Execution - Suspicious WMI module load.*
<br>
<img width="1195" height="889" alt="image" src="https://github.com/user-attachments/assets/09c70a02-0c19-401f-8a88-b286eee2df8f" />

<br>Kiểm tra tiếp event ID = 1 New process thì có tiến trình cha wmiprvse.exe mà lại tạo 1 tiến trình con là chạy rundll32 có tạo notepad.bin (Event ID = 11)<br>
=> Nghi ngờ tạo file notepad.bin giả mạo notepad.exe

<img width="1192" height="866" alt="image" src="https://github.com/user-attachments/assets/b80f1b17-4379-4029-853f-3e4d115d6e3b" />

Tạo file xong thì thực hiện truy cập vào process khác (Event ID = 10) với TargetImage là notepad.exe, GrantedAccess 0x1fffff (Full access).<br>
Tuy nhiên log này còn khớp với 1 rule có RuleName là CredAccess - Memdump.

<img width="1194" height="882" alt="image" src="https://github.com/user-attachments/assets/3009726b-498c-4932-ae4e-b1fcc50ec8d4" />

***=> Tóm lại: Nghi ngờ hành vi tạo 1 file có tên giống với notepad.exe, sau đó thực hiện access process khác nhằm credential access - memory dump nội dung vào file notepad.bin vừa tạo đó.***
<br>
- **T1059 Command and Scripting Interpreter:** Chạy cscript.
- **T1003 Credential Dumping:** Sử dụng 1 script là memdump.vbs, nhằm lấy nội dung tiến trình notepad.exe.


 
-----------------------------------------------

## Sysmon_2.evtx

**Event ID 11: FileCreate:** procdump.exe tạo 1 file lsass.exe_190317_120941.dmp, taskmgr.exe tạo 1 file lsass (2).DMP.
=> Nghi ngờ tạo 1 file .dmp để dump nội dung file lsass vào.

<img width="1191" height="754" alt="image" src="https://github.com/user-attachments/assets/119bd1ee-751d-46b7-99e3-6ce5ddc06cde" />

<img width="1182" height="687" alt="image" src="https://github.com/user-attachments/assets/13ef9638-0ff8-4b7d-b16d-ca901558e826" />


**Event ID 10: ProcessAccess:** procdump.exe truy cập bộ nhớ, handle của tiến trình lsass.exe với GrantedAccess = 0x1fffff (full access) bằng danh sách Calltrace là module/hàm được use để access tới tiến trình lsass.exe.
<br>=> Tiến trình procdump.exe thực hiện truy cập tới tiến trình lsass.exe.
<br>(taskmgr.exe thực hiện tương tự)

<img width="1191" height="854" alt="image" src="https://github.com/user-attachments/assets/c51e1822-569a-46f7-8cca-9c85a7e83225" />

<img width="1192" height="879" alt="image" src="https://github.com/user-attachments/assets/cb4e88cb-e6e0-4149-9f4f-fd5f929dbe35" />

***=> Tóm lại: Hành vi Credential Dumping.***
- **T1003.001 OS Credential Dumping - LSASS Memory:** procdump.exe, taskmgr.exe dumping bộ nhớ của tiến trình lsass.exe vào 2 file lsass.exe_190317_120941.dmp và lsass (2).DMP



-----------------------------------------------

## Sysmon_3.evtx

Một loạt các event có ID sysmon là 1: New process.

<img width="1197" height="850" alt="image" src="https://github.com/user-attachments/assets/e9f7bc14-5282-45ff-a943-c6c16b6ed76d" />

Kiểm tra thằng đầu tiên thì thấy tiến trình cha là w3wp.exe (Dịch vụ web) mà lại gọi thằng tiến trình con là powershell.exe, lại còn thực hiện 1 command line có tham số là -enc (encrypt) rồi đi kèm 1 đoạn payload đã được obfuscated = base64 ở thư mục Temp.
<br>
Khả năng attacker khai thác dịch vụ web để mở powershell chạy script, vì khi deobfuscated cái payload kia thì được script:

<img width="1536" height="830" alt="image" src="https://github.com/user-attachments/assets/9305bec6-0272-4706-bb55-48e422627b2d" />

Theo sau event log này là các event log ID = 1 khác đều là tiến trình con của tiến trình powershell.exe chạy script kia, thực hiện chạy file appcmd.exe trên directory của IIS, chỉ thay mỗi tham số truyền vào, đặc biệt luôn có 1 trong 2 tham số này /text:userName hoặc /text:password.<br>
=> Có lẽ là thực thi tools/mã độc để khai thác thông tin đăng nhập.

<img width="1190" height="856" alt="image" src="https://github.com/user-attachments/assets/77ff621e-7ea6-4ca7-b9e7-97082e8af68a" />

***=> Tóm lại: Hành vi T1059.001: Command and Scripting Interpreter - Powershell trong phase Execution có thể kết hợp các techni đánh cắp credential infor trong các phase Credential Access, Discovery,...***
<br>
- **T1059.001: Command and Scripting Interpreter - Powershell:** Lợi dụng w3wp.exe để gọi powershell.exe chạy script khai thác.
- **T1555.003: Credentials from Password Stores: Credentials from Web Browsers** powershell.exe thực hiện chạy file appcmd.exe trên IIS nhằm khai thác username, password.



-----------------------------------------------

## Sysmon_4.evtx

**Event ID 18 = Pipe Connected** kết nối tới named pipe: \ntsvcs (NT Service).
**Event ID 13 = Registry value set** tạo/thay đổi 1 giá trị registry.
- Log 1:<br>
 ProcessId 460<br> 
  Image C:\Windows\system32\services.exe <br> 
  TargetObject HKLM\System\CurrentControlSet\services\hello\Start <br> 
  Details DWORD (0x00000003) <br> <br> 
=> Sửa giá trị Start (điều khiển cách service khởi động) của một service Windows có tên hello = 0x3 = Manual (khởi động thủ công).

- Log 2:<br>
<img width="1144" height="519" alt="image" src="https://github.com/user-attachments/assets/df87e175-806e-49ca-880e-4281f046e30e" />

=> Tác động đến ImagePath là đường dẫn tới file thực thi (binary) của service hello.<br>
Ở đây là nội dung Details trông như một command line đã được obfuscated có sử dụng powershell.exe, chạy hidden,....

<img width="1200" height="715" alt="image" src="https://github.com/user-attachments/assets/3b1164c5-622b-478d-9e92-e51a34053c35" />

Theo sau đó là các log có Event ID = 1 là new process, tiến trình cha là services.exe mở tiến trình con là cmd.exe để chạy command line kia, cmd.exe này lại gọi tiếp powershell.exe để thực thi tiếp command line.

**Event ID 10 – ProcessAccess** powershell.exe này truy cập sâu vào tiến trình powershell.exe khác với quyền 0x1fffff (Full access) <br>
=> Mục đích: ??? leo thang đặc quyền ??? 

<img width="1177" height="641" alt="image" src="https://github.com/user-attachments/assets/0806d03d-8fb6-489a-8053-db37d989fadf" />

Tiếp theo là các log có **Event ID = 3 Network connection** có source IP, destination IP cùng 1 dải mạng.

<img width="1183" height="670" alt="image" src="https://github.com/user-attachments/assets/20bd3a55-1f12-4916-a25a-b0ede951ae69" />

Rồi lại có 1 log event ID = 13, set value cho registry:

ProcessId 460 
  Image C:\Windows\system32\services.exe 
  TargetObject HKLM\System\CurrentControlSet\services\hello\Start 
  Details DWORD (0x00000004) 

=> Details = 4 (Disabled – service)

Cuối cùng là lại là 1 log event ID = 3, src IP, dstIP tương tự tuy nhiên có 1 chút thay đổi:

<img width="1198" height="670" alt="image" src="https://github.com/user-attachments/assets/741c834d-1a59-418e-9d9e-9a7047885978" />

Khác nhau giữa 2 log:
- Image: full path tới tiến trình thực hiện kết nối mạng. *Cái trước là của System, cái này là của powershell.exe*
- Initiated: Cho biết ai khởi tạo kết nối mạng. *Trước đó System là false, giờ powershell.exe là true*
- Ngoài ra thì ProcessId là 2484 - tiến trình powershell mà bị 1 tiến trình powershell khác truy cập vào với full access.

***=> Kết luận: có khả năng là hành vi Lateral Movement giữa các máy trong hệ thống, lợi dụng tiến trình powershell.exe, chạy scripts, leo thang đặc quyền nhằm có quyền tạo kết nối***
<br>
- **T1059.001: Command and Scripting Interpreter - Powershell:** Chạy powershell.exe.
- **T1059.003: Command and Scripting Interpreter - Windows Command Shell:** Chạy cmd.exe.
- **T1112: Modify Registry:** Sửa ImagePath: thành command line đã được obfuscated có sử dụng powershell.exe.



-----------------------------------------------

## Sysmon_6.evtx

**Event ID = 1 New process**

<img width="1192" height="910" alt="image" src="https://github.com/user-attachments/assets/b492066d-e1eb-4bd4-97ab-cea4df67cff3" />

Điểm đáng chú ý nhất là Command Line, trông giống như bị obfuscated. <br>
Mặc dù không hiểu được ý nghĩa, nhưng nếu khả nghi thì cứ nên báo cho Tier 2 cho chắc =)))) vì nếu câu lệnh bình thường, chả ai obfuscated làm gì<br>
Từ đó check thêm các log trước và sau log này để có thêm thông tin => đưa ra kết luận chính xác hơn. 

- **T1059.001 Command and Scripting Interpreter: PowerShell**



-----------------------------------------------

## System.evtx

Nhiều log quá nhưng chỉ xoay quanh 3 event ID là 7000, 7009, 7045 theo thứ tự:

**Event ID: 7045 – A Service Was Installed** Một dịch vụ mới được tạo
**Event ID: 7009 – Service Timeout** Windows thử khởi động dịch vụ đó
**Event ID: 7000 – Service Failed to Start** Cuối cùng dịch vụ thất bại khi khởi động

Filter lấy các log có ID là 7045 thì thấy nội dung các log là gần như giống hệt nhau, chỉ có điểm khác là trong ImagePath, tên service tăng dần, từ 1 cho tới tận 245. 

<img width="1193" height="814" alt="image" src="https://github.com/user-attachments/assets/c4c5cea6-c3ea-4c36-986d-593eee3cbef5" />

Đi kèm với mỗi "segxxx" là nội dung servicename khác nhau, và rất dài, chẳng có đuôi gì cả.

VD với seg1: IyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIw0KIyBUaGlzIFBvd2Vyc2 

Xem xét kĩ trường imagepath, chatgpt thì đây khả năng là hành vi:
- Tạo nhiều service, mỗi cái chứa một mảnh dữ liệu ở DisplayName (có thể là malicious code, data nhạy cảm, giời bể gì đó mà attacker muốn lấy)
- Chạy PowerShell để đọc trường DisplayName của mỗi service segxxx đó và append đoạn đấy vào file tmp_payload.txt.
- Dĩ nhiên các service này là không hợp lệ nên chẳng thể nào chạy thành công được.
- Miễn sao chạy hết 245 lần thì tmp_payload.txt này đã có đầy đủ nội dung, chắc là nhằm lẩn trốn, tránh các tools def phát hiện hành vi mà vẫn tải dữ liệu qua lại được.
<br>
- **T1059.001 Command and Scripting Interpreter: PowerShell**



-----------------------------------------------

## Security_1.evtx


Toàn các log có event ID là 4624 - success logon. 

Hầu hết các log đều có SubjectUserName là PC02$, tuy nhiên thì phần TargetUserName lại thay đổi nhiều (Từ SYSTEM -> NETWORK SERVICE -> LOCAL SERVICE, sshd server, IEUser).

<img width="584" height="668" alt="image" src="https://github.com/user-attachments/assets/6bf5773a-3be8-444c-9391-4d9d8936beaf" />

<img width="1212" height="856" alt="image" src="https://github.com/user-attachments/assets/50e246eb-dae5-4a45-aa94-5436be7e6813" />


Khác nhau ở chỗ, sử dụng ProcessName khác nhau, ban đầu thì là services.exe, về sau thì là winlogon.exe. <br>
LogonType cũng thay đổi theo các kiểu từ 2 - interactive, 10 - remoteinteractive, 3 - network.<br>
Các địa chỉ IP là localhost và LAN nội bộ.

Bước cuối là có kết nối mạng (LogonType 3) được mở tới máy PC01 bởi tài khoản ANONYMOUS LOGON, sử dụng NTLM/NtLmSsp từ địa chỉ 10.0.2.17:49169

<img width="548" height="679" alt="image" src="https://github.com/user-attachments/assets/96104432-6f4b-4c9a-a8dd-9b0c8dc2a1fe" />


=> Trông giống như hành vi lateral movement, khi attacker cố gắng đăng nhập tới các targetusername khác nhau rồi khi đã chạm tới IEUser, đủ khả năng thì sẽ tạo kết nối mạng sang các máy khác trong LAN.

- **T1078 Valid Accounts:** attacker cố gắng tìm tới username hợp lệ để tiến hành kết nối mạng sang các máy khác.
- **T1021 — Remote Services (Lateral Movement):** Khi đã có quyền trên host, attacker mở kết nối tới các máy khác.
