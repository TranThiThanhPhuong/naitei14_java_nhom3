package org.example.framgiabookingtours.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.example.framgiabookingtours.dto.ApiResponse;
import org.example.framgiabookingtours.dto.request.CommentRequestDTO;
import org.example.framgiabookingtours.dto.request.UpdateCommentRequestDTO;
import org.example.framgiabookingtours.dto.response.CommentResponseDTO;
import org.example.framgiabookingtours.service.CommentService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/api/comments")
@RequiredArgsConstructor
public class CommentController {

    private final CommentService commentService;
    private final ObjectMapper objectMapper;

    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ApiResponse<CommentResponseDTO> createComment(
            @RequestPart("data") @Valid String dataJson,
            @RequestPart(value = "images", required = false) List<MultipartFile> images,
            @RequestHeader(value = "X-User-Email", required = false) String headerEmail,
            Authentication authentication) {

        try {
            CommentRequestDTO request = objectMapper.readValue(dataJson, CommentRequestDTO.class);
            String userEmail = (authentication != null) ? authentication.getName() : headerEmail;
            CommentResponseDTO response = commentService.createComment(request, images != null ? images : new ArrayList<>(), userEmail);

            return ApiResponse.<CommentResponseDTO>builder()
                    .code(1000)
                    .message("Comment created successfully")
                    .result(response)
                    .build();
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse request data", e);
        }
    }

    @PutMapping(value = "/{commentId}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ApiResponse<CommentResponseDTO> updateComment(
            @PathVariable Long commentId,
            @RequestPart("data") @Valid String dataJson,
            @RequestPart(value = "images", required = false) List<MultipartFile> images,
            @RequestHeader(value = "X-User-Email", required = false) String headerEmail,
            Authentication authentication) {

        try {
            UpdateCommentRequestDTO request = objectMapper.readValue(dataJson, UpdateCommentRequestDTO.class);
            String userEmail = (authentication != null) ? authentication.getName() : headerEmail;
            CommentResponseDTO response = commentService.updateComment(commentId, request, images != null ? images : new ArrayList<>(), userEmail);

            return ApiResponse.<CommentResponseDTO>builder()
                    .code(1000)
                    .message("Comment updated successfully")
                    .result(response)
                    .build();
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse request data", e);
        }
    }

    @DeleteMapping("/{commentId}")
    public ApiResponse<Void> deleteComment(
            @PathVariable Long commentId,
            @RequestHeader(value = "X-User-Email", required = false) String headerEmail,
            Authentication authentication) {

        String userEmail = (authentication != null) ? authentication.getName() : headerEmail;
        commentService.deleteComment(commentId, userEmail);

        return ApiResponse.<Void>builder()
                .code(1000)
                .message("Comment deleted successfully")
                .build();
    }

    @GetMapping
    public ApiResponse<Page<CommentResponseDTO>> getCommentsByReviewId(
            @RequestParam Long reviewId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {

        Pageable pageable = PageRequest.of(page, size);
        Page<CommentResponseDTO> comments = commentService.getCommentsByReviewId(reviewId, pageable);

        return ApiResponse.<Page<CommentResponseDTO>>builder()
                .code(1000)
                .message("Get comments successfully")
                .result(comments)
                .build();
    }

    @GetMapping("/thread")
    public ApiResponse<List<CommentResponseDTO>> getCommentThreadByReviewId(
            @RequestParam Long reviewId) {

        List<CommentResponseDTO> thread = commentService.getCommentThreadByReviewId(reviewId);

        return ApiResponse.<List<CommentResponseDTO>>builder()
                .code(1000)
                .message("Get comment thread successfully")
                .result(thread)
                .build();
    }
}
