package org.example.framgiabookingtours.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ReviewListItemDTO {

    private Long id;
    private String title;
    private String content;
    private Integer rating;
    private java.util.List<String> imageUrls;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    // User info
    private UserInfoDTO user;

    // Counts
    private Long likeCount;
    private Long commentCount;

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
