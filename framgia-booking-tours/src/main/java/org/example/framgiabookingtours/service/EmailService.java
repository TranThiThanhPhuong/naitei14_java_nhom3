package org.example.framgiabookingtours.service;

public interface EmailService {
    void sendVerificationEmail(String toEmail, String code);
}
