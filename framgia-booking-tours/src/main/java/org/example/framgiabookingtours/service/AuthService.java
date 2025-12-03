package org.example.framgiabookingtours.service;

import org.example.framgiabookingtours.dto.request.LoginRequestDTO;
import org.example.framgiabookingtours.dto.request.RegisterRequestDTO;
import org.example.framgiabookingtours.dto.request.ResendOtpRequestDTO;
import org.example.framgiabookingtours.dto.request.VerifyEmailRequestDTO;
import org.example.framgiabookingtours.dto.response.AuthResponseDTO;

public interface AuthService {
    AuthResponseDTO login(LoginRequestDTO loginRequestDTO);
    void register(RegisterRequestDTO registerRequestDTO);
    AuthResponseDTO verify(VerifyEmailRequestDTO verifyEmailRequestDTO);
    void resendVerificationCode(ResendOtpRequestDTO resendDTO);
}
