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



 ## Event quản lí tài khoản

- Ghi các event khi một account được created/modified.
- Ở local system nếu là local account, ở domain controller nếu là domain account.<br><br>
- Dải **<code>4720 -> 4799</code>**

| Event ID | Description |
|----------|-------------|
| 4720 | A user account was created. |
| 4722 | A user account was enabled. |
| 4723 | A user attempted to change an account’s password. |
| 4724 | An attempt was made to reset an account’s password. |
| 4725 | A user account was disabled. |
| 4726 | A user account was deleted. |
| 4738 | A user account was changed. |
