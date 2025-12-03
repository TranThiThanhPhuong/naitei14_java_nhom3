package org.example.framgiabookingtours.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ResendOtpRequestDTO {
    @NotBlank(message = "EMAIL_IS_REQUIRED")
    @Email(message = "INVALID_EMAIL")
    private String email;
}
