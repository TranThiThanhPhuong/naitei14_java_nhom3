package org.example.framgiabookingtours.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.example.framgiabookingtours.dto.ApiResponse;
import org.example.framgiabookingtours.dto.request.ReviewRequestDTO;
import org.example.framgiabookingtours.dto.request.UpdateReviewRequestDTO;
import org.example.framgiabookingtours.dto.response.ReviewResponseDTO;
import org.example.framgiabookingtours.service.ReviewService;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/api/reviews")
@RequiredArgsConstructor
public class ReviewController {

    private final ReviewService reviewService;
    private final ObjectMapper objectMapper;

    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ApiResponse<ReviewResponseDTO> createReview(
            @RequestPart("data") @Valid String dataJson,
            @RequestPart(value = "images", required = false) List<MultipartFile> images,
            @RequestHeader(value = "X-User-Email", required = false) String headerEmail,
            Authentication authentication) {

        try {
            ReviewRequestDTO request = objectMapper.readValue(dataJson, ReviewRequestDTO.class);
            String userEmail = (authentication != null) ? authentication.getName() : headerEmail;
            ReviewResponseDTO response = reviewService.createReview(request, images != null ? images : new ArrayList<>(), userEmail);

            return ApiResponse.<ReviewResponseDTO>builder()
                    .code(1000)
                    .message("Review created successfully")
                    .result(response)
                    .build();
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse request data", e);
        }
    }

    @PutMapping(value = "/{reviewId}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ApiResponse<ReviewResponseDTO> updateReview(
            @PathVariable Long reviewId,
            @RequestPart("data") @Valid String dataJson,
            @RequestPart(value = "images", required = false) List<MultipartFile> images,
            @RequestHeader(value = "X-User-Email", required = false) String headerEmail,
            Authentication authentication) {

        try {
            UpdateReviewRequestDTO request = objectMapper.readValue(dataJson, UpdateReviewRequestDTO.class);
            String userEmail = (authentication != null) ? authentication.getName() : headerEmail;
            ReviewResponseDTO response = reviewService.updateReview(reviewId, request, images != null ? images : new ArrayList<>(), userEmail);

            return ApiResponse.<ReviewResponseDTO>builder()
                    .code(1000)
                    .message("Review updated successfully")
                    .result(response)
                    .build();
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse request data", e);
        }
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

    /**
     * Task 3.1 — Toggle Like / Unlike Review
     * POST /api/reviews/{reviewId}/like
     */
    @PostMapping("/{reviewId}/like")
    public ApiResponse<Void> toggleLikeReview(
            @PathVariable Long reviewId,
            @RequestHeader(value = "X-User-Email", required = false) String headerEmail,
            Authentication authentication) {

        String userEmail = (authentication != null) ? authentication.getName() : headerEmail;
        reviewService.toggleLikeReview(reviewId, userEmail);

        return ApiResponse.<Void>builder()
                .code(1000)
                .message("Toggle like review successfully")
                .build();
    }

    /**
     * Task 3.2 — Get Like Count
     * GET /api/reviews/{reviewId}/likes/count
     */
    @GetMapping("/{reviewId}/likes/count")
    public ApiResponse<Long> getLikeCount(
            @PathVariable Long reviewId) {

        long likeCount = reviewService.getLikeCountByReviewId(reviewId);

        return ApiResponse.<Long>builder()
                .code(1000)
                .message("Get like count successfully")
                .result(likeCount)
                .build();
    }
}
