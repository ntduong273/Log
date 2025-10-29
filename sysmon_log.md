# SYSMON



Sysmon là một công cụ trong bộ công cụ Sysinternal của do Microsoft cung cấp, hỗ trợ ghi thêm một số loại log mà Event log bình thường không lưu trữ mặc định. Sysmon sẽ chạy dưới dạng một Window Service và tùy theo cấu hình sẽ tạo ra các log trong folder “Application and Services Logs\Microsoft\Windows\Sysmon\Operation”


## Event ID 1: ProcessCreate



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
