package org.example.framgiabookingtours.controller.admin;

import org.example.framgiabookingtours.entity.*;
import org.example.framgiabookingtours.enums.*;
import org.example.framgiabookingtours.service.UserService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Controller
@RequestMapping("/admin/users")
public class AdminUserController {

	private final List<User> mockUsers = new ArrayList<>();
	private final UserService userService;

	public AdminUserController(UserService userService) {
		this.userService = userService;
		initMockData();
	}

	// Tạo dữ liệu giả để test giao diện
	private void initMockData() {
		User u1 = new User();
		u1.setId(1L);
		u1.setEmail("nguyen.van.a@example.com");
		u1.setStatus(UserStatus.ACTIVE);
		u1.setProvider(Provider.LOCAL);
		u1.setRoles(List.of(new Role(1L, "USER", "Người dùng")));

		Profile p1 = new Profile();
		p1.setFullName("Nguyễn Văn A");
		p1.setPhone("0912345678");
		p1.setAddress("123 Lê Lợi, Q.1, TP.HCM");
		p1.setAvatarUrl("https://ui-avatars.com/api/?name=Nguyen+Van+A&background=1e40af&color=fff");
		p1.setBankName("Vietcombank");
		p1.setBankAccountNumber("001122334455");
		u1.setProfile(p1);

		Booking b1 = new Booking();
		b1.setId(1001L);
		b1.setStatus(BookingStatus.PAID);
		b1.setBookingDate(LocalDateTime.now().minusDays(10));
		b1.setStartDate(LocalDate.now().plusDays(5));
		b1.setTotalPrice(new BigDecimal("5500000"));
		b1.setTour(new Tour(1L, null, null, "Tour Đà Nẵng 3N2Đ", null, null, null, null, null, null, null, null, null));

		Payment pay1 = new Payment();
		pay1.setId(5001L);
		pay1.setAmount(new BigDecimal("5500000"));
		pay1.setPaymentDate(LocalDateTime.now().minusDays(10));
		pay1.setPaymentStatus(PaymentStatus.SUCCESS);
		pay1.setBankName("VCB");
		pay1.setAccountNumber("****8888");
		b1.setPayments(List.of(pay1));

		Booking b2 = new Booking();
		b2.setId(1002L);
		b2.setStatus(BookingStatus.PENDING);
		b2.setBookingDate(LocalDateTime.now().minusHours(2));
		b2.setStartDate(LocalDate.now().plusDays(20));
		b2.setTotalPrice(new BigDecimal("3200000"));
		b2.setTour(
				new Tour(2L, null, null, "Tour Đà Lạt Ngàn Hoa", null, null, null, null, null, null, null, null, null));
		b2.setPayments(new ArrayList<>()); // Chưa có payment

		// Lưu ý: Entity User của bạn chưa có field 'bookings', nên ta sẽ truyền list
		// này riêng vào model khi xem chi tiết
		// Để giả lập việc "User có booking", ta tạm lưu vào một map hoặc chỉ mock khi
		// gọi hàm detail.

		mockUsers.add(u1);

		// --- User 2: Admin ---
		User u2 = new User();
		u2.setId(2L);
		u2.setEmail("admin@framgia.com");
		u2.setStatus(UserStatus.ACTIVE);
		u2.setProvider(Provider.LOCAL);
		u2.setRoles(List.of(new Role(2L, "ADMIN", "Quản trị viên")));

		Profile p2 = new Profile();
		p2.setFullName("Admin System");
		p2.setAvatarUrl("https://ui-avatars.com/api/?name=Admin&background=ef4444&color=fff");
		u2.setProfile(p2);
		mockUsers.add(u2);
	}

	@GetMapping
	public String listUsers(Model model, @RequestParam(defaultValue = "1") int page,
			@RequestParam(defaultValue = "5") int size, @RequestParam(required = false) String status,
			@RequestParam(required = false) String role, @RequestParam(required = false) String keyword) {

		model.addAttribute("activeMenu", "users");

		Pageable pageable = PageRequest.of(page - 1, size, Sort.by("id").descending());

		Page<User> userPage = userService.getAllUsers(status, role, keyword, pageable);

		model.addAttribute("users", userPage.getContent());
		model.addAttribute("currentPage", page);
		model.addAttribute("totalPages", userPage.getTotalPages());
		model.addAttribute("totalItems", userPage.getTotalElements());
		model.addAttribute("pageSize", size);

		// Trả lại các giá trị lọc về View để giữ trạng thái trên Form
		model.addAttribute("currentStatus", status);
		model.addAttribute("currentRole", role);
		model.addAttribute("currentKeyword", keyword);

		return "admin/users";
	}

	@GetMapping("/{id}")
	public String viewUserDetail(@PathVariable Long id, Model model) {
		model.addAttribute("activeMenu", "users");

		User user = mockUsers.stream().filter(u -> u.getId().equals(id)).findFirst().orElse(null);

		if (user == null) {
			return "redirect:/admin/users"; // Không tìm thấy thì quay về list
		}

		model.addAttribute("user", user);
		model.addAttribute("pageTitle", "Chi tiết người dùng: "
				+ (user.getProfile() != null ? user.getProfile().getFullName() : user.getEmail()));

		// Mock Booking & Payment History cho trang chi tiết
		// (Sau này sẽ gọi BookingService.findByUserId(id))
		List<Booking> bookings = new ArrayList<>();
		if (id == 1L) {
			// Tái tạo lại booking data giống initMockData để gửi sang view
			Booking b1 = new Booking();
			b1.setId(1001L);
			b1.setStatus(BookingStatus.PAID);
			b1.setBookingDate(LocalDateTime.now().minusDays(10));
			b1.setTotalPrice(new BigDecimal("5500000"));
			b1.setTour(new Tour(1L, null, null, "Tour Đà Nẵng 3N2Đ", null, null, null, null, null, null, null, null,
					null));

			Payment pay1 = new Payment();
			pay1.setId(5001L);
			pay1.setAmount(new BigDecimal("5500000"));
			pay1.setPaymentStatus(PaymentStatus.SUCCESS);
			pay1.setPaymentDate(LocalDateTime.now().minusDays(10));
			pay1.setBankName("VCB");
			pay1.setAccountNumber("****8888");
			b1.setPayments(List.of(pay1));
			bookings.add(b1);

			Booking b2 = new Booking();
			b2.setId(1002L);
			b2.setStatus(BookingStatus.PENDING);
			b2.setBookingDate(LocalDateTime.now().minusHours(2));
			b2.setTotalPrice(new BigDecimal("3200000"));
			b2.setTour(new Tour(2L, null, null, "Tour Đà Lạt Ngàn Hoa", null, null, null, null, null, null, null, null,
					null));
			b2.setPayments(new ArrayList<>());
			bookings.add(b2);
		}
		model.addAttribute("bookings", bookings);

		return "admin/user-detail";
	}

	@PostMapping("/update-status")
	public String toggleUserStatus(@RequestParam Long id, @RequestParam String currentStatus,
			@RequestParam(defaultValue = "1") int page, @RequestParam(defaultValue = "5") int size,
			@RequestParam(required = false) String filterStatus, @RequestParam(required = false) String filterRole,
			@RequestParam(required = false) String filterKeyword, RedirectAttributes redirectAttributes) {
		// 1. Logic đổi trạng thái (Nếu đang ACTIVE -> BLOCKED, Ngược lại -> ACTIVE)
		// Lưu ý: Nếu user đang UNVERIFIED mà admin gạt nút -> Sẽ thành ACTIVE (Kích
		// hoạt)
		String newStatus = "ACTIVE".equals(currentStatus) ? "BLOCKED" : "ACTIVE";

		// 2. Gọi Service
		userService.updateUserStatus(id, newStatus);

		// 3. Gắn lại các tham số filter vào URL redirect
		redirectAttributes.addAttribute("page", page);
		redirectAttributes.addAttribute("size", size);

		if (filterStatus != null && !filterStatus.isEmpty()) {
			redirectAttributes.addAttribute("status", filterStatus);
		}
		if (filterRole != null && !filterRole.isEmpty()) {
			redirectAttributes.addAttribute("role", filterRole);
		}
		if (filterKeyword != null && !filterKeyword.isEmpty()) {
			redirectAttributes.addAttribute("keyword", filterKeyword);
		}

		// 4. Reload lại trang danh sách
		return "redirect:/admin/users";
	}
}