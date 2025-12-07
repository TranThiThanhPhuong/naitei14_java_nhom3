document.addEventListener("DOMContentLoaded", function() {
        // Lấy tất cả các checkbox status
        const checkboxes = document.querySelectorAll(".status-checkbox");

        checkboxes.forEach(checkbox => {
            checkbox.addEventListener("change", function() {
                // Xác định hành động sắp làm để hiện thông báo cho đúng
                // Nếu hiện tại đang checked (sau khi bấm) -> Nghĩa là user muốn MỞ
                const actionName = this.checked ? "KÍCH HOẠT (ACTIVE)" : "KHÓA (BLOCK)";
                
                if (confirm(`Bạn có chắc chắn muốn ${actionName} người dùng này?`)) {
                    // Nếu đồng ý -> Submit form bao quanh nút này
                    this.closest("form").submit();
                } else {
                    // Nếu hủy -> Trả lại trạng thái cũ cho nút gạt
                    this.checked = !this.checked;
                }
            });
        });
    });