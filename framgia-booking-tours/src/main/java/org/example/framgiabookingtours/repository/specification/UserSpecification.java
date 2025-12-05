package org.example.framgiabookingtours.repository.specification;

import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.JoinType;
import org.example.framgiabookingtours.entity.Profile;
import org.example.framgiabookingtours.entity.Role;
import org.example.framgiabookingtours.entity.User;
import org.example.framgiabookingtours.enums.UserStatus;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.util.StringUtils;

public class UserSpecification {

	// 1. Lọc theo Status (Exact match)
	public static Specification<User> hasStatus(String status) {
		return (root, query, criteriaBuilder) -> {
			if (!StringUtils.hasText(status)) {
				return null;
			}
			return criteriaBuilder.equal(root.get("status"), UserStatus.valueOf(status));
		};
	}

	// 2. Lọc theo Role (Join bảng roles)
	public static Specification<User> hasRole(String roleName) {
		return (root, query, criteriaBuilder) -> {
			if (!StringUtils.hasText(roleName)) {
				return null;
			}
			// Join bảng User -> Roles
			Join<User, Role> roles = root.join("roles", JoinType.INNER);
			return criteriaBuilder.equal(roles.get("name"), roleName);
		};
	}

	// 3. Tìm kiếm theo Keyword (Email hoặc FullName)
	public static Specification<User> hasKeyword(String keyword) {
		return (root, query, criteriaBuilder) -> {
			if (!StringUtils.hasText(keyword)) {
				return null;
			}
			String likePattern = "%" + keyword.toLowerCase() + "%";

			// Join bảng User -> Profile (Left Join vì Profile có thể null)
			Join<User, Profile> profile = root.join("profile", JoinType.LEFT);

			// Tìm trong Email OR FullName
			return criteriaBuilder.or(criteriaBuilder.like(criteriaBuilder.lower(root.get("email")), likePattern),
					criteriaBuilder.like(criteriaBuilder.lower(profile.get("fullName")), likePattern));
		};
	}
}