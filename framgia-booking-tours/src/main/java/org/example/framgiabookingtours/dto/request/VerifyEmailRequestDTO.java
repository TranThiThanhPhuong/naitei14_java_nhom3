package org.example.framgiabookingtours.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class VerifyEmailRequestDTO {
    
    @NotBlank(message = "EMAIL_IS_REQUIRED")
    @Email(message = "INVALID_EMAIL")
    private String email;
    
    @NotBlank(message = "VERIFICATION_CODE_IS_REQUIRED")
    @Pattern(regexp = "^\\d{6}$", message = "VERIFICATION_CODE_INVALID")
    private String code;
}