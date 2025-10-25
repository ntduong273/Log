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



 ## Event quản lí tài khoản (Dải 4720 -> 4799)

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

## Event đăng nhập tài khoản 
