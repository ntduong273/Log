# SYSMON



Sysmon là một công cụ trong bộ công cụ Sysinternal của do Microsoft cung cấp, hỗ trợ ghi thêm một số loại log mà Event log bình thường không lưu trữ mặc định. Sysmon sẽ chạy dưới dạng một Window Service và tùy theo cấu hình sẽ tạo ra các log trong folder “Application and Services Logs\Microsoft\Windows\Sysmon\Operation”


## Event ID 1: ProcessCreate

Cung cấp thông tin về các tiến trình mới được tạo.

Trong số các trường dữ liệu này có rất nhiều các thông tin quan trọng trong quá trình giám sát như:
- **ProcessId:** Id của tiến trình được tạo ra
- **Image:** file thực thi để chạy tiến trình
- **CommandLine:** cho biết các câu lệnh kèm tham số, tùy chọn được dùng để chạy tiến trình.
- **User:** tài khoản người dùng chạy tiến trình
- **ParentProcessId, ParentImage và ParentCommandLine:** cho biết các thông tin về tiến trình cha của tiến trình hiện tại.
- ***Đặc biệt ProcessGUID:*** là giá trị định danh duy nhất của tiến trình trong môi trường có Domain để giúp việc giám sát và phân tích sự kiện dễ hơn tránh trùng lặp.

<img width="752" height="422" alt="image" src="https://github.com/user-attachments/assets/4ce18ef2-f2f8-4fde-a9f6-40f8a8846e05" />



## Event ID 2: FileCreateTime
## Event ID 3: NetworkConnect		
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
