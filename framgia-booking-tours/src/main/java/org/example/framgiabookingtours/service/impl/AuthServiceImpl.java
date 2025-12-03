package org.example.framgiabookingtours.service.impl;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.example.framgiabookingtours.dto.CustomUserDetails;
import org.example.framgiabookingtours.dto.request.LoginRequestDTO;
import org.example.framgiabookingtours.dto.request.RegisterRequestDTO;
import org.example.framgiabookingtours.dto.response.AuthResponseDTO;
import org.example.framgiabookingtours.dto.response.ProfileResponseDTO;
import org.example.framgiabookingtours.entity.Profile;
import org.example.framgiabookingtours.entity.Role;
import org.example.framgiabookingtours.entity.User;
import org.example.framgiabookingtours.enums.UserStatus;
import org.example.framgiabookingtours.exception.AppException;
import org.example.framgiabookingtours.exception.ErrorCode;
import org.example.framgiabookingtours.repository.RoleRepository;
import org.example.framgiabookingtours.repository.UserRepository;
import org.example.framgiabookingtours.service.AuthService;
import org.example.framgiabookingtours.service.CustomUserDetailsService;
import org.example.framgiabookingtours.util.JwtUtils;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AuthServiceImpl implements AuthService {
    AuthenticationManager authenticationManager;
    UserRepository userRepository;
    RoleRepository roleRepository;
    CustomUserDetailsService userDetailsService;
    PasswordEncoder passwordEncoder;
    JwtUtils jwtUtils;
    RedisTemplate<String, String> redisTemplate;

    String REFRESH_TOKEN_PREFIX = "refreshtoken:";

    @Override
    public AuthResponseDTO login(LoginRequestDTO loginRequestDTO) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequestDTO.getEmail(),
                        loginRequestDTO.getPassword())
        );

        var user = userRepository.findByEmail(loginRequestDTO.getEmail())
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        var userDetail = userDetailsService.loadUserByUsername(user.getEmail());

        return generateAuthResponse(user, userDetail);
    }

    @Override
    @Transactional
    public void register(RegisterRequestDTO registerRequestDTO) {
        if (userRepository.existsByEmail(registerRequestDTO.getEmail())) {
            throw new AppException(ErrorCode.USER_EXISTED);
        }

        Role role = roleRepository.findByName("USER")
                .orElseThrow(() -> new AppException(ErrorCode.UNCATEGORIZED_EXCEPTION));

        User user = User.builder()
                .email(registerRequestDTO.getEmail())
                .password(passwordEncoder.encode(registerRequestDTO.getPassword()))
                .roles(Collections.singletonList(role))
                .status(UserStatus.UNVERIFIED)
                .build();

        String defaultAvatarUrl = "https://ui-avatars.com/api/?name="
                + registerRequestDTO.getFullName().replace(" ", "+")
                + "&background=random";

        Profile userProfile = Profile.builder()
                .fullName(registerRequestDTO.getFullName())
                .avatarUrl(defaultAvatarUrl)
                .build();

        user.setProfile(userProfile);
        userProfile.setUser(user);
        User savedUser = userRepository.save(user);
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
