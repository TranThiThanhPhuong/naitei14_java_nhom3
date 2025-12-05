package org.example.framgiabookingtours.service.impl;

import lombok.RequiredArgsConstructor;
import org.example.framgiabookingtours.entity.User;
import org.example.framgiabookingtours.repository.UserRepository;
import org.example.framgiabookingtours.repository.specification.UserSpecification;
import org.example.framgiabookingtours.service.UserService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

	private final UserRepository userRepository;

	@Override
	public Page<User> getAllUsers(String status, String role, String keyword, Pageable pageable) {
		Specification<User> spec = (root, query, criteriaBuilder) -> criteriaBuilder.conjunction();

        // Ghép điều kiện Status
        if (status != null && !status.isEmpty()) {
            spec = spec.and(UserSpecification.hasStatus(status));
        }

        // Ghép điều kiện Role
        if (role != null && !role.isEmpty()) {
            spec = spec.and(UserSpecification.hasRole(role));
        }

        // Ghép điều kiện Keyword (Tìm kiếm)
        if (keyword != null && !keyword.isEmpty()) {
            spec = spec.and(UserSpecification.hasKeyword(keyword));
        }

        // Gọi Repository
        return userRepository.findAll(spec, pageable);
	}
}