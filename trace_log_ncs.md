# BÀI TẬP THỰC HÀNH PHÂN TÍCH, TRACE LOG CƠ BẢN (NCS) - WIN_01



## Kiểm tra sysmon log:

- Vị trí: Microsoft-Windows-Sysmon%4Operational.evtx
- Số lượng event: 1179

<img width="1170" height="836" alt="image" src="https://github.com/user-attachments/assets/4b09704b-c1f6-4461-8887-30dd0302001f" />

Ban đầu, tài khoản BLUE.admin.hue liên tục thực hiện các câu lệnh xóa logs cũ bằng công cụ wevtutil.exe với options là "cl". Hành động này sinh ra một loạt các event có sysmon event ID = 1: New process. 
<br>
Kết thúc chuỗi các event xóa log này là một event ID = 1, mở một phần log có đường dẫn là <code>C:\inetpub\logs\LogFiles\W3SVC1\u_ex250711.log</code> trong công cụ notepad.exe.

<img width="1155" height="847" alt="image" src="https://github.com/user-attachments/assets/cf016270-7262-40eb-902d-6723b8b2ddf0" />



## Kiểm tra nội dung file u_ex250711.log:

Tiến hành phân tích nội dung log trong file u_ex250711.log này thì nó là log của dịch vụ web IIS được triển khai trên các Windows Server.

<img width="975" height="532" alt="image" src="https://github.com/user-attachments/assets/73e85bb5-f195-4e24-9049-af4fd6bfea89" />

Toàn bộ lưu lượng xảy ra trong khoảng 15h26 -> 18h41 (hơn 3 tiếng) với hơn 37k bản ghi (khá nhiều) đều xuất phát từ 1 src IP duy nhất (10.11.121.24) tới nhiều dst IP (10.11.121.23, 10.11.121.200,…).

Phân tích sơ bộ ban đầu thì:
- Ban đầu với nhiều request_method là GET với path rất đa dạng, status cho req toàn nhận về là 404 (File not found) => Đánh giá: giống như hành vi recon, kiểm tra xem hệ thống target đang public những thành phần nào.

Ctrl + F tìm theo status code 200 thì có khoảng 684 bản ghi trùng khớp:

<img width="975" height="102" alt="image" src="https://github.com/user-attachments/assets/7078da25-52e4-498d-82bf-b05e586776c1" />

Đầu tiên là /index.html: maybe default web page của target.

<img width="975" height="68" alt="image" src="https://github.com/user-attachments/assets/45aa7c02-bc62-4709-b235-bad0f896e7aa" />

Tiếp theo là cụm /uploads/robots.aspx. Sau khi thấy request GET trả về 200 thì có POST thử 2 lần lên, cũng nhận status code là 200.

<img width="975" height="54" alt="image" src="https://github.com/user-attachments/assets/4a02e38e-02be-4ee1-862a-23279f1161df" />
<img width="975" height="51" alt="image" src="https://github.com/user-attachments/assets/e74b5601-a47c-45aa-b1f2-b241352f0146" />
<img width="975" height="44" alt="image" src="https://github.com/user-attachments/assets/90767dfd-e0b1-4dfb-b320-3d9a81f4e20c" />
<img width="975" height="49" alt="image" src="https://github.com/user-attachments/assets/f26db340-87d4-4e00-885a-33ce3721941a" />

Các phần râu ria khác như /1.aspx, /2.aspx, /test.aspx, /upload.aspx cũng trả về 200.

<img width="975" height="355" alt="image" src="https://github.com/user-attachments/assets/ac46c45a-0ebe-468f-9c72-83948c426e2e" />

Ngoài /uploads/robots.aspx ra thì còn /uploads/tunnel.aspx cũng đang mở. Attacker tiến hành POST lên dữ liệu.

=> Tóm lại, ghi nhận hành vi nghi là recon nội bộ (cùng dải mạng 10.11.121.x).

Có thể attacker chiếm được máy 10.11.121.24 rồi tiến hành recon sang các máy khác nhằm thực hiện phase lateral movements bằng cách sử dụng tool gửi 1 loạt các request với các path phổ biến trong 1 khoảng thời gian rất ngắn (cỡ 1489 gói tin trong 1s thì chắc không phải là người rồi :v), xem cái nào trả về 200 thì gửi tiếp các gói tin POST tới path đó.

Ở đây em thấy thì phần /uploads/tunnel.aspx được tận dụng nhiều nhất, gửi tới đây cỡ khoảng 672 gói tin POST.
