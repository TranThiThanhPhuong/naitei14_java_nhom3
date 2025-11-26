package org.example.framgiabookingtours.controller.admin;

import org.example.framgiabookingtours.entity.Profile;
import org.example.framgiabookingtours.entity.Role;
import org.example.framgiabookingtours.entity.User;
import org.example.framgiabookingtours.enums.Provider;
import org.example.framgiabookingtours.enums.UserStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.ArrayList;
import java.util.List;

@Controller
@RequestMapping("/admin/users")
public class AdminUserController {

    @GetMapping
    public String listUsers(Model model) {
        // 1. Setup dữ liệu cho Menu Sidebar active
        model.addAttribute("activeMenu", "users");

        // 2. Tạo dữ liệu giả (Mock Data) để test giao diện
        List<User> users = new ArrayList<>();
        
        // User 1
        User u1 = new User();
        u1.setId(1L);
        u1.setEmail("nguyen.van.a@example.com");
        u1.setStatus(UserStatus.ACTIVE);
        u1.setProvider(Provider.LOCAL);
        
        Role roleUser1 = new Role();
        roleUser1.setName("USER"); 
        u1.setRoles(List.of(roleUser1));
        
        Profile p1 = new Profile();
        p1.setFullName("Nguyễn Văn A");
        p1.setPhone("0912345678");
        p1.setAvatarUrl("https://ui-avatars.com/api/?name=Nguyen+Van+A&background=1e40af&color=fff");
        u1.setProfile(p1);
        users.add(u1);

        // User 2
        User u2 = new User();
        u2.setId(2L);
        u2.setEmail("admin@framgia.com");
        u2.setStatus(UserStatus.ACTIVE);
        u2.setProvider(Provider.LOCAL);
        
        Role roleUser2 = new Role();
        roleUser2.setName("ADMIN"); 
        u2.setRoles(List.of(roleUser2));
        
        Profile p2 = new Profile();
        p2.setFullName("Admin System");
        p2.setPhone("0900000000");
        p2.setAvatarUrl("https://ui-avatars.com/api/?name=Admin&background=1e40af&color=fff");
        u2.setProfile(p2);
        users.add(u2);

        model.addAttribute("users", users);

        return "admin/users";
    }
}