package org.example.framgiabookingtours.service.impl;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.example.framgiabookingtours.dto.CustomUserDetails;
import org.example.framgiabookingtours.dto.response.AuthResponseDTO;
import org.example.framgiabookingtours.dto.response.ProfileResponseDTO;
import org.example.framgiabookingtours.entity.Profile;
import org.example.framgiabookingtours.entity.Role;
import org.example.framgiabookingtours.entity.User;
import org.example.framgiabookingtours.enums.Provider;
import org.example.framgiabookingtours.enums.UserStatus;
import org.example.framgiabookingtours.exception.AppException;
import org.example.framgiabookingtours.exception.ErrorCode;
import org.example.framgiabookingtours.repository.RoleRepository;
import org.example.framgiabookingtours.repository.UserRepository;
import org.example.framgiabookingtours.service.CustomUserDetailsService;
import org.example.framgiabookingtours.service.OAuth2Service;
import org.example.framgiabookingtours.util.JwtUtils;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Slf4j
public class OAuth2ServiceImpl implements OAuth2Service {
    UserRepository userRepository;
    RoleRepository roleRepository;
    CustomUserDetailsService userDetailsService;
    JwtUtils jwtUtils;
    RedisTemplate<String, String> redisTemplate;

    String REFRESH_TOKEN_PREFIX = "refreshtoken:";

    @Override
    @Transactional
    public AuthResponseDTO processOAuth2Login(OAuth2User oAuth2User) {
        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");
        String picture = oAuth2User.getAttribute("picture");
        String googleId = oAuth2User.getAttribute("sub");

        if (email == null || email.isEmpty()) {
            throw new AppException(ErrorCode.UNCATEGORIZED_EXCEPTION);
        }

        User user = userRepository.findByEmail(email)
                .orElseGet(() -> createNewGoogleUser(email, name, picture, googleId));

        if (user.getGoogleId() == null || user.getGoogleId().isEmpty()) {
            user.setGoogleId(googleId);
            user.setStatus(UserStatus.ACTIVE);
            userRepository.save(user);
        }

        CustomUserDetails userDetail = userDetailsService.loadUserByUsername(user.getEmail());
        return generateAuthResponse(user, userDetail);
    }

    private User createNewGoogleUser(String email, String name, String picture, String googleId) {
        Role role = roleRepository.findByName("USER")
                .orElseThrow(() -> new AppException(ErrorCode.ROLE_NOT_FOUND));

        String avatarUrl = (picture != null && !picture.isEmpty())
                ? picture
                : "https://ui-avatars.com/api/?name=" + (name != null ? name.replace(" ", "+") : "User") + "&background=random";

        User user = User.builder()
                .email(email)
                .password(null)
                .googleId(googleId)
                .provider(Provider.GOOGLE)
                .roles(Collections.singletonList(role))
                .status(UserStatus.ACTIVE)
                .build();

        Profile userProfile = Profile.builder()
                .fullName(name != null ? name : "Google User")
                .avatarUrl(avatarUrl)
                .build();

        user.setProfile(userProfile);
        userProfile.setUser(user);

        return userRepository.save(user);
    }

    private AuthResponseDTO generateAuthResponse(User user, CustomUserDetails userDetail) {
        String accessToken = jwtUtils.generateAccessToken(userDetail);
        String refreshToken = jwtUtils.generateRefreshToken(userDetail);

        String refreshRedisKey = REFRESH_TOKEN_PREFIX + userDetail.getUsername();
        redisTemplate.opsForValue().set(refreshRedisKey, refreshToken, 7, TimeUnit.DAYS);

        ProfileResponseDTO profileResponseDTO = buildProfileResponseDto(user);
        return AuthResponseDTO.builder()
                .user(profileResponseDTO)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    private ProfileResponseDTO buildProfileResponseDto(User user) {
        Profile profile = user.getProfile();
        if (profile == null) {
            return ProfileResponseDTO.builder()
                    .id(user.getId())
                    .email(user.getEmail())
                    .fullName("No Name")
                    .build();
        }

        return ProfileResponseDTO.builder()
                .id(user.getId())
                .email(user.getEmail())
                .fullName(profile.getFullName())
                .avatarUrl(profile.getAvatarUrl())
                .phone(profile.getPhone())
                .address(profile.getAddress())
                .bankName(profile.getBankName())
                .bankAccountNumber(profile.getBankAccountNumber())
                .build();
    }
}