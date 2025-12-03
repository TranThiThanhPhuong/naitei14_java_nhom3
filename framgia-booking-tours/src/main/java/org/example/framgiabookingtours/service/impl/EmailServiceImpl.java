package org.example.framgiabookingtours.service.impl;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.framgiabookingtours.service.EmailService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.util.Random;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailServiceImpl implements EmailService {
    
    private final JavaMailSender mailSender;
    private final RedisTemplate<String, String> redisTemplate;

    @Value("${app.mail.from}")
    private String fromEmail;
    
    @Value("${app.mail.sender-name}")
    private String senderName;
    
    @Override
    @Async("taskExecutor")
    public void sendVerificationEmail(String toEmail, String code) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            
            helper.setFrom(fromEmail, senderName);
            helper.setTo(toEmail);
            helper.setSubject("Xác thực tài khoản - Framgia Booking Tours");
            
            String htmlContent = buildVerificationEmailContent(code);
            helper.setText(htmlContent, true);
            
            mailSender.send(message);
            log.info("Verification email sent successfully to: {}", toEmail);
            
        } catch (MessagingException e) {
            log.error("Failed to send verification email to: {}", toEmail, e);
            throw new RuntimeException("Could not send verification email", e);
        } catch (Exception e) {
            log.error("Unexpected error sending email to: {}", toEmail, e);
            throw new RuntimeException("Unexpected error sending email", e);
        }
    }

    private String buildVerificationEmailContent(String code) {
        return """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        line-height: 1.6;
                        color: #333;
                        max-width: 600px;
                        margin: 0 auto;
                        padding: 20px;
                    }
                    .container {
                        background-color: #f9f9f9;
                        border-radius: 10px;
                        padding: 30px;
                        box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                    }
                    .header {
                        text-align: center;
                        color: #2c3e50;
                        margin-bottom: 30px;
                    }
                    .code-box {
                        background-color: #fff;
                        border: 2px dashed #3498db;
                        border-radius: 8px;
                        padding: 20px;
                        text-align: center;
                        margin: 30px 0;
                    }
                    .code {
                        font-size: 32px;
                        font-weight: bold;
                        color: #3498db;
                        letter-spacing: 5px;
                        font-family: 'Courier New', monospace;
                    }
                    .footer {
                        text-align: center;
                        color: #7f8c8d;
                        font-size: 12px;
                        margin-top: 30px;
                        padding-top: 20px;
                        border-top: 1px solid #ddd;
                    }
                    .warning {
                        background-color: #fff3cd;
                        border-left: 4px solid #ffc107;
                        padding: 15px;
                        margin-top: 20px;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🎫 Framgia Booking Tours</h1>
                        <h2>Xác thực tài khoản của bạn</h2>
                    </div>
                    
                    <p>Xin chào,</p>
                    <p>Cảm ơn bạn đã đăng ký tài khoản tại Framgia Booking Tours. Để hoàn tất quá trình đăng ký, vui lòng sử dụng mã xác thực bên dưới:</p>
                    
                    <div class="code-box">
                        <p style="margin: 0; color: #7f8c8d; font-size: 14px;">MÃ XÁC THỰC CỦA BẠN</p>
                        <div class="code">%s</div>
                        <p style="margin: 10px 0 0 0; color: #7f8c8d; font-size: 12px;">Mã có hiệu lực trong 5 phút</p>
                    </div>
                    
                    <p>Nhập mã này vào trang xác thực để kích hoạt tài khoản của bạn.</p>
                    
                    <div class="warning">
                        <strong>⚠️ Lưu ý:</strong> Nếu bạn không yêu cầu mã này, vui lòng bỏ qua email này. Không chia sẻ mã xác thực với bất kỳ ai.
                    </div>
                    
                    <div class="footer">
                        <p>Email này được gửi tự động, vui lòng không trả lời.</p>
                        <p>&copy; 2024 Framgia Booking Tours. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
            """.formatted(code);
    }
}