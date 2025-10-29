# SYSMON



Sysmon là một công cụ trong bộ công cụ Sysinternal của do Microsoft cung cấp, hỗ trợ ghi thêm một số loại log mà Event log bình thường không lưu trữ mặc định. Sysmon sẽ chạy dưới dạng một Window Service và tùy theo cấu hình sẽ tạo ra các log trong folder “Application and Services Logs\Microsoft\Windows\Sysmon\Operation”


## Event ID 1: ProcessCreate

**Process creation:** Cung cấp thông tin về các tiến trình mới được tạo.

Trong số các trường dữ liệu này có rất nhiều các thông tin quan trọng trong quá trình giám sát như:
- **ProcessId:** Id của tiến trình được tạo ra
- **Image:** file thực thi để chạy tiến trình
- **CommandLine:** cho biết các câu lệnh kèm tham số, tùy chọn được dùng để chạy tiến trình.
- **User:** tài khoản người dùng chạy tiến trình
- **ParentProcessId, ParentImage và ParentCommandLine:** cho biết các thông tin về tiến trình cha của tiến trình hiện tại.
- ***Đặc biệt ProcessGUID:*** là giá trị định danh duy nhất của tiến trình trong môi trường có Domain để giúp việc giám sát và phân tích sự kiện dễ hơn tránh trùng lặp.

<img width="752" height="422" alt="image" src="https://github.com/user-attachments/assets/4ce18ef2-f2f8-4fde-a9f6-40f8a8846e05" />



## Event ID 2: FileCreateTime

**A process changed a file creation time:** ghi nhận một tiến trình thực hiện thay đổi thời gian tạo một file trên thiết bị.

Trên thực tế các kẻ tấn công có thể thay đổi thời gian tạo file để làm rối quá trình điều tra, sự kiện này sẽ ghi nhận thời gian tạo file thực tế đã bị thay đổi trước đó thông qua trường dữ liệu “PreviousCreationUtcTime”.

Case: gây rối quá trình điều tra. VD:
- Trong thư mục quản trị của 1 web app, có các file cấu hình, xử lí.
- Attacker có quyền truy cập, sửa nội dung, thực thi các file này.
- Chúng sẽ sửa nội dung, chèn vào các payload độc hại và thực thi.
- Tuy nhiên, khi thực thi sẽ ghi lại log, cập nhật lại time tạo, chạy, biên dịch của file.<br>
=> Attacker phải sửa time về khoảng hợp lí, khoảng mà các file khác cũng đang có. Kiểu giữa 1 đống file có time chạy lần cuối từ 2022 mà có 1 cái file có time chạy là mới hôm qua (2025) thì kiểu gì cũng bị admin nghi ngờ.

<img width="752" height="193" alt="image" src="https://github.com/user-attachments/assets/2180494b-645a-4d58-93f8-8b5561fd5ed3" />



## Event ID 3: NetworkConnect		

**Network connection:** ghi nhận một kết nối TCP/UDP, cung cấp các thông tin về process ID, port nguồn/đích, IP nguồn/đích 





## Event ID 4: Sysmon service state change (cannot be filtered)	
## Event ID 5: ProcessTerminate	
## Event ID 6: DriverLoad		
## Event ID 7: ImageLoad		
## Event ID 8: CreateRemoteThread	
## Event ID 9: RawAccessRead		
## Event ID 10: ProcessAccess	
11 FileCreate	File created	
12 RegistryEvent	Registry object added or deleted	
13 RegistryEvent	Registry value set	
14 RegistryEvent	Registry object renamed	
15 FileCreateStreamHash	File stream created	
16 n/a	Sysmon configuration change (cannot be filtered)	
17 PipeEvent	Named pipe created	
18 PipeEvent	Named pipe connected	
19 WmiEvent	WMI filter	
20 WmiEvent	WMI consumer	
21 WmiEvent	WMI consumer filter	
22 DNSQuery	DNS query
