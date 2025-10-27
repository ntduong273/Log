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



-----------------------------------------------

## Sysmon_4.evtx

