package org.example.framgiabookingtours.service;

import org.example.framgiabookingtours.entity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface UserService {
	Page<User> getAllUsers(String status, String role, String keyword, Pageable pageable);
}