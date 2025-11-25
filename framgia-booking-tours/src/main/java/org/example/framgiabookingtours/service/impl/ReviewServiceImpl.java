package org.example.framgiabookingtours.service.impl;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.framgiabookingtours.dto.request.ReviewRequestDTO;
import org.example.framgiabookingtours.dto.request.UpdateReviewRequestDTO;
import org.example.framgiabookingtours.dto.response.ReviewResponseDTO;
import org.example.framgiabookingtours.entity.Booking;
import org.example.framgiabookingtours.entity.Review;
import org.example.framgiabookingtours.entity.User;
import org.example.framgiabookingtours.enums.BookingStatus;
import org.example.framgiabookingtours.exception.AppException;
import org.example.framgiabookingtours.exception.ErrorCode;
import org.example.framgiabookingtours.repository.BookingRepository;
import org.example.framgiabookingtours.repository.ReviewRepository;
import org.example.framgiabookingtours.repository.UserRepository;
import org.example.framgiabookingtours.service.ReviewService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class ReviewServiceImpl implements ReviewService {

    private final ReviewRepository reviewRepository;
    private final BookingRepository bookingRepository;
    private final UserRepository userRepository;

    @Override
    @Transactional
    public ReviewResponseDTO createReview(ReviewRequestDTO request, String userEmail) {
        // Tìm user
        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        // Tìm booking
        Booking booking = bookingRepository.findById(request.getBookingId())
                .orElseThrow(() -> new AppException(ErrorCode.BOOKING_NOT_FOUND));

        // Kiểm tra booking thuộc về user
        if (!booking.getUser().getId().equals(user.getId())) {
            throw new AppException(ErrorCode.BOOKING_NOT_BELONG_TO_USER);
        }

        // Kiểm tra booking đã hoàn thành
        if (booking.getStatus() != BookingStatus.PAID) {
            throw new AppException(ErrorCode.BOOKING_NOT_COMPLETED);
        }

        // Kiểm tra đã có review chưa
        if (reviewRepository.existsByBookingId(request.getBookingId())) {
            throw new AppException(ErrorCode.REVIEW_ALREADY_EXISTS);
        }

        // Tạo review
        Review review = Review.builder()
                .booking(booking)
                .title(request.getTitle())
                .content(request.getContent())
                .rating(request.getRating())
                .isDeleted(false)
                .build();

        Review savedReview = reviewRepository.save(review);

        // Map sang DTO
        return ReviewResponseDTO.builder()
                .id(savedReview.getId())
                .bookingId(savedReview.getBooking().getId())
                .title(savedReview.getTitle())
                .content(savedReview.getContent())
                .rating(savedReview.getRating())
                .createdAt(savedReview.getCreatedAt())
                .updatedAt(savedReview.getUpdatedAt())
                .build();
    }

    @Override
    @Transactional
    public ReviewResponseDTO updateReview(Long reviewId, UpdateReviewRequestDTO request, String userEmail) {
        // Tìm user
        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        // Tìm review
        Review review = reviewRepository.findById(reviewId)
                .orElseThrow(() -> new AppException(ErrorCode.REVIEW_NOT_FOUND));

        // Kiểm tra review có bị xóa không
        if (review.getIsDeleted()) {
            throw new AppException(ErrorCode.REVIEW_NOT_FOUND);
        }

        // Kiểm tra review thuộc về user (thông qua booking)
        if (!review.getBooking().getUser().getId().equals(user.getId())) {
            throw new AppException(ErrorCode.REVIEW_NOT_BELONG_TO_USER);
        }

        // Cập nhật chỉ rating và content
        review.setRating(request.getRating());
        review.setContent(request.getContent());

        Review updatedReview = reviewRepository.save(review);

        // Map sang DTO
        return ReviewResponseDTO.builder()
                .id(updatedReview.getId())
                .bookingId(updatedReview.getBooking().getId())
                .title(updatedReview.getTitle())
                .content(updatedReview.getContent())
                .rating(updatedReview.getRating())
                .createdAt(updatedReview.getCreatedAt())
                .updatedAt(updatedReview.getUpdatedAt())
                .build();
    }

    @Override
    @Transactional
    public void deleteReview(Long reviewId, String userEmail) {
        // Tìm user
        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        // Tìm review
        Review review = reviewRepository.findById(reviewId)
                .orElseThrow(() -> new AppException(ErrorCode.REVIEW_NOT_FOUND));

        // Kiểm tra review có bị xóa không
        if (review.getIsDeleted()) {
            throw new AppException(ErrorCode.REVIEW_NOT_FOUND);
        }

        // Kiểm tra review thuộc về user (thông qua booking)
        if (!review.getBooking().getUser().getId().equals(user.getId())) {
            throw new AppException(ErrorCode.REVIEW_NOT_BELONG_TO_USER);
        }

        // Soft delete: đánh dấu là đã xóa
        review.setIsDeleted(true);
        reviewRepository.save(review);
    }
}
