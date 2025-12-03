package org.example.framgiabookingtours.controller;

import io.swagger.v3.oas.annotations.Operation;
import jakarta.validation.Valid;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.example.framgiabookingtours.dto.ApiResponse;
import org.example.framgiabookingtours.dto.CustomUserDetails;
import org.example.framgiabookingtours.dto.request.LoginRequestDTO;
import org.example.framgiabookingtours.dto.request.RegisterRequestDTO;
import org.example.framgiabookingtours.dto.response.AuthResponseDTO;
import org.example.framgiabookingtours.service.AuthService;
import org.example.framgiabookingtours.service.CustomUserDetailsService;
import org.example.framgiabookingtours.util.JwtUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@RequestMapping("/api/auth")
public class AuthController {
    AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthResponseDTO>> login(
            @Valid @RequestBody LoginRequestDTO loginDto) {
        AuthResponseDTO result = authService.login(loginDto);
        ApiResponse<AuthResponseDTO> apiResponse = ApiResponse.<AuthResponseDTO>builder()
                .code(HttpStatus.OK.value())
                .result(result)
                .message("Đăng nhập thành công!")
                .build();

        return ResponseEntity.ok(apiResponse);
    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<Void>> register(
            @Valid @RequestBody RegisterRequestDTO registerDto) {
        authService.register(registerDto);

        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.<Void>builder()
                .code(HttpStatus.CREATED.value())
                .message("Đăng ký thành công. Vui lòng kiểm tra email để kích hoạt.")
                .build());
    }
}
