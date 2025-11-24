package org.example.framgiabookingtours.dto.response;

import lombok.*;
import lombok.experimental.FieldDefaults;

import java.math.BigDecimal;
import java.time.Instant;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class TourResponseDTO {
    Long id;
    String name;
    String location;
    String description;
    String imageUrl;
    BigDecimal price;
    Integer durationDays;
    Integer availableSlots;
    
    CategoryInfo category;
    
    Instant createdAt;
    Instant updatedAt;
    
    Double averageRating; 

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @FieldDefaults(level = AccessLevel.PRIVATE)
    public static class CategoryInfo {
        Long id;
        String name;
    }
}