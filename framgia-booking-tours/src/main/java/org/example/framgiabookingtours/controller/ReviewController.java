package org.example.framgiabookingtours.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.example.framgiabookingtours.dto.ApiResponse;
import org.example.framgiabookingtours.dto.request.ReviewRequestDTO;
import org.example.framgiabookingtours.dto.request.UpdateReviewRequestDTO;
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
            @RequestHeader(value = "X-User-Email", required = false) String headerEmail,
            Authentication authentication) {

        String userEmail = (authentication != null) ? authentication.getName() : headerEmail;
        ReviewResponseDTO response = reviewService.createReview(request, userEmail);

        return ApiResponse.<ReviewResponseDTO>builder()
                .code(1000)
                .message("Review created successfully")
                .result(response)
                .build();
    }

    @PutMapping("/{reviewId}")
    public ApiResponse<ReviewResponseDTO> updateReview(
            @PathVariable Long reviewId,
            @Valid @RequestBody UpdateReviewRequestDTO request,
            @RequestHeader(value = "X-User-Email", required = false) String headerEmail,
            Authentication authentication) {

        String userEmail = (authentication != null) ? authentication.getName() : headerEmail;
        ReviewResponseDTO response = reviewService.updateReview(reviewId, request, userEmail);

        return ApiResponse.<ReviewResponseDTO>builder()
                .code(1000)
                .message("Review updated successfully")
                .result(response)
                .build();
    }

    @DeleteMapping("/{reviewId}")
    public ApiResponse<Void> deleteReview(
            @PathVariable Long reviewId,
            @RequestHeader(value = "X-User-Email", required = false) String headerEmail,
            Authentication authentication) {

        String userEmail = (authentication != null) ? authentication.getName() : headerEmail;
        reviewService.deleteReview(reviewId, userEmail);

        return ApiResponse.<Void>builder()
                .code(1000)
                .message("Review deleted successfully")
                .build();
    }
}
