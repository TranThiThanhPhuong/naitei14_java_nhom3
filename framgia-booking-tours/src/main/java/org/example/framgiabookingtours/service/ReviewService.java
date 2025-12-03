package org.example.framgiabookingtours.service;

import org.example.framgiabookingtours.dto.request.ReviewRequestDTO;
import org.example.framgiabookingtours.dto.request.UpdateReviewRequestDTO;
import org.example.framgiabookingtours.dto.response.ReviewListItemDTO;
import org.example.framgiabookingtours.dto.response.ReviewResponseDTO;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface ReviewService {

    ReviewResponseDTO createReview(ReviewRequestDTO request, String userEmail);

    ReviewResponseDTO updateReview(Long reviewId, UpdateReviewRequestDTO request, String userEmail);

    void deleteReview(Long reviewId, String userEmail);

    Page<ReviewListItemDTO> getReviewsByTourId(Long tourId, Pageable pageable);

    /**
     * Task 3.1 — Toggle Like / Unlike Review
     */
    void toggleLikeReview(Long reviewId, String userEmail);

    /**
     * Task 3.2 — Get Like Count
     */
    long getLikeCountByReviewId(Long reviewId);
}
