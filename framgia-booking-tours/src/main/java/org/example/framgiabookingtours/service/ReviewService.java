package org.example.framgiabookingtours.service;

import org.example.framgiabookingtours.dto.request.ReviewRequestDTO;
import org.example.framgiabookingtours.dto.request.UpdateReviewRequestDTO;
import org.example.framgiabookingtours.dto.response.ReviewResponseDTO;

public interface ReviewService {

    ReviewResponseDTO createReview(ReviewRequestDTO request, String userEmail);

    ReviewResponseDTO updateReview(Long reviewId, UpdateReviewRequestDTO request, String userEmail);

    void deleteReview(Long reviewId, String userEmail);
}
