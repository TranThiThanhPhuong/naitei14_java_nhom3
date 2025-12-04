package org.example.framgiabookingtours.service;

import org.example.framgiabookingtours.dto.response.AuthResponseDTO;
import org.springframework.security.oauth2.core.user.OAuth2User;

public interface OAuth2Service {
    AuthResponseDTO processOAuth2Login(OAuth2User oAuth2User);
}
