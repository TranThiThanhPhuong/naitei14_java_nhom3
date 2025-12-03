package org.example.framgiabookingtours.service;

import org.example.framgiabookingtours.dto.request.LoginRequestDTO;
import org.example.framgiabookingtours.dto.request.RegisterRequestDTO;
import org.example.framgiabookingtours.dto.response.AuthResponseDTO;

public interface AuthService {
    AuthResponseDTO login(LoginRequestDTO loginRequestDTO);
    void register(RegisterRequestDTO registerRequestDTO);
}
