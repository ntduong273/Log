# BÀI TẬP THỰC HÀNH PHÂN TÍCH, TRACE LOG CƠ BẢN (NCS) - WIN_01



## Kiểm tra sysmon log:

- Vị trí: Microsoft-Windows-Sysmon%4Operational.evtx
- Số lượng event: 1179

<img width="1170" height="836" alt="image" src="https://github.com/user-attachments/assets/4b09704b-c1f6-4461-8887-30dd0302001f" />

Ban đầu, tài khoản BLUE.admin.hue liên tục thực hiện các câu lệnh xóa logs cũ bằng công cụ wevtutil.exe với options là "cl". Hành động này sinh ra một loạt các event có sysmon event ID = 1: New process/windows event log id = 1102: Log clear, 4688: Process Creation.

**_=> T1070.001: Indicator Removal: Clear Windows Event Logs_**

<br>
Kết thúc chuỗi các event xóa log này là một event ID = 1, mở một phần log có đường dẫn là <code>C:\inetpub\logs\LogFiles\W3SVC1\u_ex250711.log</code> trong công cụ notepad.exe.

<img width="1155" height="847" alt="image" src="https://github.com/user-attachments/assets/cf016270-7262-40eb-902d-6723b8b2ddf0" />



## Kiểm tra nội dung file u_ex250711.log:

Tiến hành phân tích nội dung log trong file u_ex250711.log này thì nó là log của dịch vụ web IIS được triển khai trên các Windows Server.

<img width="1715" height="827" alt="image" src="https://github.com/user-attachments/assets/23022367-525b-47a6-b233-700cb2cc21c5" />

Toàn bộ lưu lượng xảy ra trong khoảng 15h26 -> 18h41 (hơn 3 tiếng) với hơn 37k bản ghi (khá nhiều) đều xuất phát từ 1 src IP duy nhất (10.11.121.24) tới nhiều dst IP (10.11.121.23, 10.11.121.200,…).

Phân tích sơ bộ ban đầu thì:
- Ban đầu với nhiều request_method là GET với path rất đa dạng, status cho req toàn nhận về là 404 (File not found) => Đánh giá: giống như hành vi recon, kiểm tra xem hệ thống target đang public những thành phần nào.

Ctrl + F tìm theo status code 200 thì có khoảng 684 bản ghi trùng khớp:

<img width="1625" height="81" alt="image" src="https://github.com/user-attachments/assets/1b61a54a-4e59-4ec6-986b-a5c65ce2f3cb" />

Đầu tiên là /index.html: maybe default web page của target.

<img width="1731" height="145" alt="image" src="https://github.com/user-attachments/assets/43a34fd7-f91e-4839-9ebd-6c1459d1ccd4" />

Tiếp theo là cụm /uploads/robots.aspx. Sau khi thấy request GET trả về 200 thì có POST thử 2 lần lên, cũng nhận status code là 200.

<img width="1350" height="75" alt="image" src="https://github.com/user-attachments/assets/592ecea5-c6db-413e-ac54-5a5a9d74b8b3" />
<img width="1369" height="72" alt="image" src="https://github.com/user-attachments/assets/9e08fd57-ba2f-40d5-8edf-d1e64505d373" />
<img width="1425" height="64" alt="image" src="https://github.com/user-attachments/assets/233d0afa-292c-4fe0-b10a-a1919fbd61d1" />
<img width="1454" height="73" alt="image" src="https://github.com/user-attachments/assets/af9e5407-9d60-4777-a144-ede6c7ba4531" />


Các phần râu ria khác như /1.aspx, /2.aspx, /test.aspx, /upload.aspx cũng trả về 200.

<img width="1715" height="625" alt="image" src="https://github.com/user-attachments/assets/7d16fdbe-7426-43ed-971d-8361785a76b7" />


Ngoài /uploads/robots.aspx ra thì còn /uploads/tunnel.aspx cũng đang mở. Attacker tiến hành POST lên dữ liệu.

=> Tóm lại, ghi nhận hành vi nghi là recon nội bộ (cùng dải mạng 10.11.121.x).

Có thể attacker chiếm được máy 10.11.121.24 rồi tiến hành recon sang các máy khác nhằm thực hiện phase lateral movements bằng cách sử dụng tool gửi 1 loạt các request với các path phổ biến trong 1 khoảng thời gian rất ngắn (cỡ 1489 gói tin trong 1s thì chắc không phải là người rồi :v), xem cái nào trả về 200 thì gửi tiếp các gói tin POST tới path đó.

Ở đây em thấy thì phần /uploads/tunnel.aspx được tận dụng nhiều nhất, gửi tới đây cỡ khoảng 672 gói tin POST.

**_=> T1595: Active Scanning_**

## Quay lại với sysmon log:

Sau khi mà mở cái file log bằng notepad, thì máy 10.11.121.24 (hostname: WEB-APP.blue.lab) kết nối đến máy 10.11.121.25 (hostname: BLUE-COLLECTOR), gọi thằng winlogbeat.exe - agent để thu log máy host windows. 

Tiếp theo đó ghi nhận 1 tiến trình mới được tạo, event ID = 1 chạy command line ipconfig.
<img width="1188" height="623" alt="image" src="https://github.com/user-attachments/assets/570d764c-13db-43ad-898d-f34572115dcb" />

Gửi truy vấn DNS: Tiến trình mmc.exe (chạy dưới account BLUE\admin.hue) đã thực hiện các truy vấn DNS nội bộ để resolve tên WEB-APP, WEB-APP.blue.lab và nhận về địa chỉ nội bộ 10.11.121.24

<img width="679" height="498" alt="image" src="https://github.com/user-attachments/assets/4e94c322-a3e2-43f7-807f-14d6f5228f8e" />

<img width="677" height="510" alt="image" src="https://github.com/user-attachments/assets/ff1b09e9-d0d3-4be7-98e8-75949eda0b9c" />

Resolve tên WIN-DC.blue.lab ra được địa chỉ IP 10.11.121.21:

<img width="670" height="503" alt="image" src="https://github.com/user-attachments/assets/3e62d421-d926-4dba-9a41-fde4a8983d27" />

Đi kèm phía sau là các log event id=10: ProcessAccess, tiến trình <code>C:\Windows\system32\svchost.exe </code> truy cập đến bộ nhớ của <code>C:\Windows\system32\lsass.exe </code> nhưng chỉ với mức quyền là 0x1400 - chỉ cho phép tra cứu thông tin. Nên cũng chưa thể kết luận là hành vi độc hại, lsass dumping hay không, có thể là hoạt động hợp lệ của các tiến trình hệ thống, cần xác thực, giúp giảm việc chờ user đăng nhập.

<img width="1134" height="647" alt="image" src="https://github.com/user-attachments/assets/2ef4658d-939e-4781-8a1b-e89450101fba" />

Đối chiếu với Security trong Windows Event Log:

Sau khi thực hiện clear log, mở file u_ex250711.log thì 1 tiến trình svchost.exe tạo 1 tiến trình mới sử dụng cmd.exe để chạy ClipUp.bat.

<img width="732" height="614" alt="image" src="https://github.com/user-attachments/assets/83c01ac7-7167-4191-8d42-81c9508a7d18" />

Sau đó thì gọi đến các tiến trình mới như: conhost.exe, ipconfig, dllhost.exe, mmc.exe, WmiPrvSE.exe (cả domain: WEB-APP$ và local: LOCAL SERVICE).
Thằng WmiPrvSE.exe của WEB-APP$ này lại tiếp tục cố truy cập hoặc chiếm quyền sở hữu một đối tượng hệ thống (LOADPERF_MUTEX) trong kernel namespace. (PrivilegeList SeTakeOwnershipPrivilege).


<img width="745" height="549" alt="image" src="https://github.com/user-attachments/assets/c69b3622-fbfb-4788-a57d-f8695011807c" />

 4673: “A privileged service was called” – Một tiến trình gọi dịch vụ đặc quyền thuộc Local Security Authority (LSA).
lsass.exe đang thực thi lời gọi LsaRegisterLogonProcess() với quyền SeTcbPrivilege (Quyền này cho phép tiến trình đăng ký như một phần của Hệ điều hành, tức có thể xác thực người dùng hoặc can thiệp vào quá trình đăng nhập). Tài khoản thực hiện WEB-APP$ (thành viên trong domain) đang tương tác hợp lệ với LSA, có thể là khi một dịch vụ hệ thống hoặc ứng dụng web domain-based gọi đến LSA để xác thực.

<img width="763" height="475" alt="image" src="https://github.com/user-attachments/assets/dc59942f-6905-48c5-acad-22b2e2d8bf67" />

Tiếp theo, windows event log ghi nhận các tiến trình w3wp.exe chạy command line: ipconfig, net user, net localgroup administrator, net netstat -ano, tasklist, schtasks, ...

<img width="885" height="599" alt="image" src="https://github.com/user-attachments/assets/54af60de-0e82-4f6d-a68e-8a34a4a3bdbd" />
<img width="887" height="604" alt="image" src="https://github.com/user-attachments/assets/e6ab6274-0fe5-44c2-b508-c2417f508845" />
<img width="892" height="602" alt="image" src="https://github.com/user-attachments/assets/5d26fb9c-1138-47a3-8497-8393c8d33e17" />
<img width="894" height="604" alt="image" src="https://github.com/user-attachments/assets/6f468abd-1b6a-45ea-bf47-02508e9d561a" />
<img width="892" height="605" alt="image" src="https://github.com/user-attachments/assets/78cd5c12-65f6-4bc2-aad6-a05900c95d97" />
<img width="887" height="604" alt="image" src="https://github.com/user-attachments/assets/7689d375-2f1f-4100-9ad5-66a1874a1e22" />
<img width="1007" height="607" alt="image" src="https://github.com/user-attachments/assets/590400d2-4f4d-459e-b0e7-dfc33c71548d" />

w3wp.exe dùng powershell để kết nối, download string gì đó ở http://10.11.121.23:9999/mini-reverse.ps1 vào thằng clipup.bat.

<img width="968" height="602" alt="image" src="https://github.com/user-attachments/assets/4b15c802-04f6-46e1-9ae8-02b20469d5d4" />

Dùng rundll32.exe, dump gì đó vào ls.tmp

<img width="919" height="601" alt="image" src="https://github.com/user-attachments/assets/95cb638f-1e79-425a-93ef-f6457f9f51d0" />

w3wp.exe chạy csc.exe - trình biên dịch C# của .NET Framework (C# Compiler) không rõ lý do.

<img width="1080" height="604" alt="image" src="https://github.com/user-attachments/assets/2bc8963c-186f-4527-b645-56434acd64b9" />


<img width="1205" height="519" alt="image" src="https://github.com/user-attachments/assets/5c27537a-61da-48a6-9fb9-4202b1822e41" />

Thực hiện đăng nhập với đặc quyền cao.


<img width="648" height="620" alt="image" src="https://github.com/user-attachments/assets/12c5dd4d-c3c5-4f73-9fd0-56709193e46c" />


Logon vào 10.11.31.200



**=> Tóm lại: Theo như em thấy các hành vi này đều chưa critial cho lắm, nhưng vì được thực hiện ở các khoảng thời gian muộn (từ nửa đêm tới sáng) với các hành vi:**
- **T1070.001: Indicator Removal: Clear Windows Event Logs:** Xóa log
- **T1595: Active Scanning:** Quét mạng tới các máy nội bộ, GET, POST.
- **T1059.001: Command and Scripting Interpreter: Powershell:** Chạy powershell để thực thi câu lệnh
- Thực hiện đăng nhập với đặc quyền cao
- Dùng rundll32.exe, dump gì đó vào ls.tmp
- w3wp.exe chạy csc.exe - trình biên dịch C# của .NET Framework (C# Compiler) không rõ lý do.




