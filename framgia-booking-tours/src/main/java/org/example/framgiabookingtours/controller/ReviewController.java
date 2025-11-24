package org.example.framgiabookingtours.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.example.framgiabookingtours.dto.ApiResponse;
import org.example.framgiabookingtours.dto.request.ReviewRequestDTO;
import org.example.framgiabookingtours.dto.response.ReviewResponseDTO;
import org.example.framgiabookingtours.service.ReviewService;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/reviews")
@RequiredArgsConstructor
public class ReviewController {

    private final ReviewService reviewService;

    @PostMapping
    public ApiResponse<ReviewResponseDTO> createReview(
            @Valid @RequestBody ReviewRequestDTO request,
            Authentication authentication) {
        
        String userEmail = authentication.getName();
        ReviewResponseDTO response = reviewService.createReview(request, userEmail);
        
        return ApiResponse.<ReviewResponseDTO>builder()
                .code(1000)
                .message("Review created successfully")
                .result(response)
                .build();
    }
}
