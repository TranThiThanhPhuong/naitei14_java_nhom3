package org.example.framgiabookingtours.service.impl;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.framgiabookingtours.dto.request.CommentRequestDTO;
import org.example.framgiabookingtours.dto.request.UpdateCommentRequestDTO;
import org.example.framgiabookingtours.dto.response.CommentResponseDTO;
import org.example.framgiabookingtours.entity.Comment;
import org.example.framgiabookingtours.entity.Profile;
import org.example.framgiabookingtours.entity.Review;
import org.example.framgiabookingtours.entity.User;
import org.example.framgiabookingtours.exception.AppException;
import org.example.framgiabookingtours.exception.ErrorCode;
import org.example.framgiabookingtours.repository.CommentRepository;
import org.example.framgiabookingtours.repository.ReviewRepository;
import org.example.framgiabookingtours.repository.UserRepository;
import org.example.framgiabookingtours.service.CommentService;
import org.example.framgiabookingtours.service.ImageUploadService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class CommentServiceImpl implements CommentService {

    private final CommentRepository commentRepository;
    private final ReviewRepository reviewRepository;
    private final UserRepository userRepository;
    private final ImageUploadService imageUploadService;
    private final ObjectMapper objectMapper;

    @Override
    @Transactional
    public CommentResponseDTO createComment(CommentRequestDTO request, List<MultipartFile> images, String userEmail) {
        // Tìm user
        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        // Tìm review
        Review review = reviewRepository.findById(request.getReviewId())
                .orElseThrow(() -> new AppException(ErrorCode.REVIEW_NOT_FOUND));

        // Kiểm tra review có bị xóa không
        if (review.getIsDeleted()) {
            throw new AppException(ErrorCode.REVIEW_NOT_FOUND);
        }

        // Xử lý parent comment nếu có
        Comment parentComment = null;
        if (request.getParentCommentId() != null) {
            parentComment = commentRepository.findByIdAndIsDeletedFalse(request.getParentCommentId())
                    .orElseThrow(() -> new AppException(ErrorCode.COMMENT_NOT_FOUND));

            // Kiểm tra parent comment phải thuộc về cùng review
            if (!parentComment.getReview().getId().equals(request.getReviewId())) {
                throw new AppException(ErrorCode.COMMENT_NOT_BELONG_TO_REVIEW);
            }
        }

        // Upload images nếu có
        String imageUrlsJson = null;
        if (images != null && !images.isEmpty()) {
            List<String> imageUrls = new ArrayList<>();
            for (MultipartFile image : images) {
                if (image != null && !image.isEmpty()) {
                    try {
                        String fileName = "comment-" + UUID.randomUUID().toString() + ".jpg";
                        String folder = "comment_images";
                        String imageUrl = imageUploadService.uploadFile(image, fileName, folder);
                        imageUrls.add(imageUrl);
                    } catch (Exception e) {
                        log.error("Failed to upload image for comment", e);
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

        // Tạo comment
        Comment comment = Comment.builder()
                .review(review)
                .user(user)
                .content(request.getContent())
                .parentComment(parentComment)
                .imageUrls(imageUrlsJson)
                .isDeleted(false)
                .build();

        Comment savedComment = commentRepository.save(comment);

        // Map sang DTO
        return mapToDTO(savedComment);
    }

    @Override
    @Transactional
    public CommentResponseDTO updateComment(Long commentId, UpdateCommentRequestDTO request, List<MultipartFile> images, String userEmail) {
        // Tìm user
        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        // Tìm comment
        Comment comment = commentRepository.findByIdAndIsDeletedFalse(commentId)
                .orElseThrow(() -> new AppException(ErrorCode.COMMENT_NOT_FOUND));

        // Kiểm tra comment thuộc về user
        if (!comment.getUser().getId().equals(user.getId())) {
            throw new AppException(ErrorCode.COMMENT_NOT_BELONG_TO_USER);
        }

        // Cập nhật content
        comment.setContent(request.getContent());

        // Upload images nếu có
        if (images != null && !images.isEmpty()) {
            List<String> imageUrls = new ArrayList<>();
            for (MultipartFile image : images) {
                if (image != null && !image.isEmpty()) {
                    try {
                        String fileName = "comment-" + UUID.randomUUID().toString() + ".jpg";
                        String folder = "comment_images";
                        String imageUrl = imageUploadService.uploadFile(image, fileName, folder);
                        imageUrls.add(imageUrl);
                    } catch (Exception e) {
                        log.error("Failed to upload image for comment", e);
                        throw new AppException(ErrorCode.UPLOAD_FAILED);
                    }
                }
            }
            if (!imageUrls.isEmpty()) {
                try {
                    String imageUrlsJson = objectMapper.writeValueAsString(imageUrls);
                    comment.setImageUrls(imageUrlsJson);
                } catch (Exception e) {
                    log.error("Failed to convert image URLs to JSON", e);
                    throw new AppException(ErrorCode.UNCATEGORIZED_EXCEPTION);
                }
            }
        }

        Comment updatedComment = commentRepository.save(comment);

        // Map sang DTO
        return mapToDTO(updatedComment);
    }

    @Override
    @Transactional
    public void deleteComment(Long commentId, String userEmail) {
        // Tìm user
        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        // Tìm comment
        Comment comment = commentRepository.findByIdAndIsDeletedFalse(commentId)
                .orElseThrow(() -> new AppException(ErrorCode.COMMENT_NOT_FOUND));

        // Kiểm tra comment thuộc về user
        if (!comment.getUser().getId().equals(user.getId())) {
            throw new AppException(ErrorCode.COMMENT_NOT_BELONG_TO_USER);
        }

        // Soft delete
        comment.setIsDeleted(true);
        comment.setDeletedAt(LocalDateTime.now());
        commentRepository.save(comment);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<CommentResponseDTO> getCommentsByReviewId(Long reviewId, Pageable pageable) {
        // Kiểm tra review tồn tại
        Review review = reviewRepository.findById(reviewId)
                .orElseThrow(() -> new AppException(ErrorCode.REVIEW_NOT_FOUND));

        // Kiểm tra review có bị xóa không
        if (review.getIsDeleted()) {
            throw new AppException(ErrorCode.REVIEW_NOT_FOUND);
        }

        // Lấy danh sách comments theo review
        Page<Comment> comments = commentRepository.findByReviewId(reviewId, pageable);

        // Map sang DTO
        return comments.map(this::mapToDTO);
    }

    @Override
    @Transactional(readOnly = true)
    public List<CommentResponseDTO> getCommentThreadByReviewId(Long reviewId) {
        // Kiểm tra review tồn tại và chưa bị xóa
        Review review = reviewRepository.findById(reviewId)
                .orElseThrow(() -> new AppException(ErrorCode.REVIEW_NOT_FOUND));

        if (review.getIsDeleted()) {
            throw new AppException(ErrorCode.REVIEW_NOT_FOUND);
        }

        // Lấy toàn bộ comments (chưa xóa) theo review
        List<Comment> comments = commentRepository
                .findAllByReviewIdAndIsDeletedFalseOrderByCreatedAtAsc(reviewId);

        // Map Comment -> DTO trước
        Map<Long, CommentResponseDTO> dtoMap = new HashMap<>();
        for (Comment comment : comments) {
            CommentResponseDTO dto = mapToDTO(comment);
            dto.setReplies(new ArrayList<>()); // chuẩn bị list rỗng cho replies
            dtoMap.put(dto.getId(), dto);
        }

        // Xây cây: gom các child vào replies của parent
        List<CommentResponseDTO> roots = new ArrayList<>();
        for (Comment comment : comments) {
            CommentResponseDTO dto = dtoMap.get(comment.getId());
            Long parentId = comment.getParentComment() != null
                    ? comment.getParentComment().getId()
                    : null;

            if (parentId == null) {
                // Comment gốc
                roots.add(dto);
            } else {
                CommentResponseDTO parentDto = dtoMap.get(parentId);
                if (parentDto != null) {
                    if (parentDto.getReplies() == null) {
                        parentDto.setReplies(new ArrayList<>());
                    }
                    parentDto.getReplies().add(dto);
                } else {
                    // Trong trường hợp hiếm hoi parent không tồn tại trong danh sách (an toàn)
                    roots.add(dto);
                }
            }
        }

        return roots;
    }

    private CommentResponseDTO mapToDTO(Comment comment) {
        User user = comment.getUser();
        Profile profile = user.getProfile();

        // Tạo user info DTO
        CommentResponseDTO.UserInfoDTO userInfo = CommentResponseDTO.UserInfoDTO.builder()
                .id(user.getId())
                .email(user.getEmail())
                .fullName(profile != null ? profile.getFullName() : null)
                .avatarUrl(profile != null ? profile.getAvatarUrl() : null)
                .build();

        // Parse image URLs từ JSON string
        List<String> imageUrls = null;
        if (comment.getImageUrls() != null && !comment.getImageUrls().isEmpty()) {
            try {
                imageUrls = objectMapper.readValue(comment.getImageUrls(), new TypeReference<List<String>>() {});
            } catch (Exception e) {
                log.error("Failed to parse image URLs from JSON", e);
                imageUrls = new ArrayList<>();
            }
        }

        // Tạo comment DTO
        return CommentResponseDTO.builder()
                .id(comment.getId())
                .reviewId(comment.getReview().getId())
                .content(comment.getContent())
                .imageUrls(imageUrls)
                .createdAt(comment.getCreatedAt())
                .parentCommentId(comment.getParentComment() != null ? comment.getParentComment().getId() : null)
                .user(userInfo)
                .build();
    }
}
