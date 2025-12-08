package org.example.framgiabookingtours.service.impl;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.framgiabookingtours.dto.request.ReviewRequestDTO;
import org.example.framgiabookingtours.dto.request.UpdateReviewRequestDTO;
import org.example.framgiabookingtours.dto.response.ReviewListItemDTO;
import org.example.framgiabookingtours.dto.response.ReviewResponseDTO;
import org.example.framgiabookingtours.entity.Booking;
import org.example.framgiabookingtours.entity.Profile;
import org.example.framgiabookingtours.entity.Review;
import org.example.framgiabookingtours.entity.User;
import org.example.framgiabookingtours.entity.ReviewLike;
import org.example.framgiabookingtours.enums.BookingStatus;
import org.example.framgiabookingtours.exception.AppException;
import org.example.framgiabookingtours.exception.ErrorCode;
import org.example.framgiabookingtours.repository.BookingRepository;
import org.example.framgiabookingtours.repository.CommentRepository;
import org.example.framgiabookingtours.repository.ReviewLikeRepository;
import org.example.framgiabookingtours.repository.ReviewRepository;
import org.example.framgiabookingtours.repository.TourRepository;
import org.example.framgiabookingtours.repository.UserRepository;
import org.example.framgiabookingtours.service.ImageUploadService;
import org.example.framgiabookingtours.service.ReviewService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class ReviewServiceImpl implements ReviewService {

    private final ReviewRepository reviewRepository;
    private final BookingRepository bookingRepository;
    private final UserRepository userRepository;
    private final TourRepository tourRepository;
    private final ReviewLikeRepository reviewLikeRepository;
    private final CommentRepository commentRepository;
    private final ImageUploadService imageUploadService;
    private final ObjectMapper objectMapper;

    @Override
    @Transactional
    public ReviewResponseDTO createReview(ReviewRequestDTO request, List<MultipartFile> images, String userEmail) {
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

        // Upload images nếu có
        String imageUrlsJson = null;
        if (images != null && !images.isEmpty()) {
            List<String> imageUrls = new ArrayList<>();
            for (MultipartFile image : images) {
                if (image != null && !image.isEmpty()) {
                    try {
                        String fileName = "review-" + UUID.randomUUID().toString() + ".jpg";
                        String folder = "review_images";
                        String imageUrl = imageUploadService.uploadFile(image, fileName, folder);
                        imageUrls.add(imageUrl);
                    } catch (Exception e) {
                        log.error("Failed to upload image for review", e);
                        throw new AppException(ErrorCode.UPLOAD_FAILED);
                    }
                }
            }
            if (!imageUrls.isEmpty()) {
                try {
                    imageUrlsJson = objectMapper.writeValueAsString(imageUrls);
                } catch (Exception e) {
                    log.error("Failed to convert image URLs to JSON", e);
                    throw new AppException(ErrorCode.UNCATEGORIZED_EXCEPTION);
                }
            }
        }

        // Tạo review
        Review review = Review.builder()
                .booking(booking)
                .title(request.getTitle())
                .content(request.getContent())
                .rating(request.getRating())
                .imageUrls(imageUrlsJson)
                .isDeleted(false)
                .build();

        Review savedReview = reviewRepository.save(review);

        // Map sang DTO
        return mapToResponseDTO(savedReview);
    }

    @Override
    @Transactional
    public ReviewResponseDTO updateReview(Long reviewId, UpdateReviewRequestDTO request, List<MultipartFile> images, String userEmail) {
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

        // Upload images nếu có
        if (images != null && !images.isEmpty()) {
            List<String> imageUrls = new ArrayList<>();
            for (MultipartFile image : images) {
                if (image != null && !image.isEmpty()) {
                    try {
                        String fileName = "review-" + UUID.randomUUID().toString() + ".jpg";
                        String folder = "review_images";
                        String imageUrl = imageUploadService.uploadFile(image, fileName, folder);
                        imageUrls.add(imageUrl);
                    } catch (Exception e) {
                        log.error("Failed to upload image for review", e);
                        throw new AppException(ErrorCode.UPLOAD_FAILED);
                    }
                }
            }
            if (!imageUrls.isEmpty()) {
                try {
                    String imageUrlsJson = objectMapper.writeValueAsString(imageUrls);
                    review.setImageUrls(imageUrlsJson);
                } catch (Exception e) {
                    log.error("Failed to convert image URLs to JSON", e);
                    throw new AppException(ErrorCode.UNCATEGORIZED_EXCEPTION);
                }
            }
        }

        Review updatedReview = reviewRepository.save(review);

        // Map sang DTO
        return mapToResponseDTO(updatedReview);
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

    @Override
    @Transactional(readOnly = true)
    public Page<ReviewListItemDTO> getReviewsByTourId(Long tourId, Pageable pageable) {
        // Kiểm tra tour tồn tại
        if (!tourRepository.existsById(tourId)) {
            throw new AppException(ErrorCode.TOUR_NOT_FOUND);
        }

        // Lấy danh sách reviews theo tour
        Page<Review> reviews = reviewRepository.findByTourId(tourId, pageable);

        // Map sang DTO
        return reviews.map(review -> {
            User user = review.getBooking().getUser();
            Profile profile = user.getProfile();

            // Đếm likes và comments
            long likeCount = reviewLikeRepository.countByReviewIdAndIsDeletedFalse(review.getId());
            long commentCount = commentRepository.countByReviewIdAndIsDeletedFalse(review.getId());

            // Tạo user info DTO
            ReviewListItemDTO.UserInfoDTO userInfo = ReviewListItemDTO.UserInfoDTO.builder()
                    .id(user.getId())
                    .email(user.getEmail())
                    .fullName(profile != null ? profile.getFullName() : null)
                    .avatarUrl(profile != null ? profile.getAvatarUrl() : null)
                    .build();

            // Parse image URLs từ JSON string
            List<String> imageUrls = null;
            if (review.getImageUrls() != null && !review.getImageUrls().isEmpty()) {
                try {
                    imageUrls = objectMapper.readValue(review.getImageUrls(), new TypeReference<List<String>>() {});
                } catch (Exception e) {
                    log.error("Failed to parse image URLs from JSON", e);
                    imageUrls = new ArrayList<>();
                }
            }

            // Tạo review DTO
            return ReviewListItemDTO.builder()
                    .id(review.getId())
                    .title(review.getTitle())
                    .content(review.getContent())
                    .rating(review.getRating())
                    .imageUrls(imageUrls)
                    .createdAt(review.getCreatedAt())
                    .updatedAt(review.getUpdatedAt())
                    .user(userInfo)
                    .likeCount(likeCount)
                    .commentCount(commentCount)
                    .build();
        });
    }

    private ReviewResponseDTO mapToResponseDTO(Review review) {
        // Parse image URLs từ JSON string
        List<String> imageUrls = null;
        if (review.getImageUrls() != null && !review.getImageUrls().isEmpty()) {
            try {
                imageUrls = objectMapper.readValue(review.getImageUrls(), new TypeReference<List<String>>() {});
            } catch (Exception e) {
                log.error("Failed to parse image URLs from JSON", e);
                imageUrls = new ArrayList<>();
            }
        }

        return ReviewResponseDTO.builder()
                .id(review.getId())
                .bookingId(review.getBooking().getId())
                .title(review.getTitle())
                .content(review.getContent())
                .rating(review.getRating())
                .imageUrls(imageUrls)
                .createdAt(review.getCreatedAt())
                .updatedAt(review.getUpdatedAt())
                .build();
    }

    @Override
    @Transactional
    public void toggleLikeReview(Long reviewId, String userEmail) {
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

        // Kiểm tra đã like chưa (bản ghi chưa bị xóa)
        var existingLikeOpt = reviewLikeRepository
                .findByUserIdAndReviewIdAndIsDeletedFalse(user.getId(), reviewId);

        if (existingLikeOpt.isPresent()) {
            // Đã like -> unlike: soft delete bản ghi like
            ReviewLike existingLike = existingLikeOpt.get();
            existingLike.setIsDeleted(true);
            existingLike.setDeletedAt(LocalDateTime.now());
            reviewLikeRepository.save(existingLike);
        } else {
            // Chưa like -> tạo mới
            ReviewLike newLike = ReviewLike.builder()
                    .user(user)
                    .review(review)
                    .isDeleted(false)
                    .build();
            reviewLikeRepository.save(newLike);
        }
    }

    @Override
    @Transactional(readOnly = true)
    public long getLikeCountByReviewId(Long reviewId) {
        // Đảm bảo review tồn tại và chưa bị xóa
        Review review = reviewRepository.findById(reviewId)
                .orElseThrow(() -> new AppException(ErrorCode.REVIEW_NOT_FOUND));

        if (review.getIsDeleted()) {
            throw new AppException(ErrorCode.REVIEW_NOT_FOUND);
        }

        return reviewLikeRepository.countByReviewIdAndIsDeletedFalse(reviewId);
    }
}
