package org.example.framgiabookingtours.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CommentResponseDTO {

    private Long id;
    private Long reviewId;
    private String content;
    private java.util.List<String> imageUrls;
    private LocalDateTime createdAt;
    private Long parentCommentId;

    // User info
    private UserInfoDTO user;

    // Replies (children comments) for thread view.
    // This field can be null when not using thread API.
    private List<CommentResponseDTO> replies;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UserInfoDTO {
        private Long id;
        private String email;
        private String fullName;
        private String avatarUrl;
    }
}
