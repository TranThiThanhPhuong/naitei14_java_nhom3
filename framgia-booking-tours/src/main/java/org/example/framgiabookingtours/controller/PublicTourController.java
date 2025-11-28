package org.example.framgiabookingtours.controller;

import java.math.BigDecimal;

import org.example.framgiabookingtours.dto.ApiResponse;
import org.example.framgiabookingtours.dto.response.ReviewListItemDTO;
import org.example.framgiabookingtours.dto.response.TourResponseDTO;
import org.example.framgiabookingtours.service.ReviewService;
import org.example.framgiabookingtours.service.TourService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/tours")
@RequiredArgsConstructor
public class PublicTourController {

    private final TourService tourService;
    private final ReviewService reviewService;

    @GetMapping
    public ResponseEntity<ApiResponse<Page<TourResponseDTO>>> getTours(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "createdAt") String sortBy,
            @RequestParam(defaultValue = "DESC") String sortDirection,
            
            @RequestParam(value = "q", required = false) String keyword,
            @RequestParam(value = "category_id", required = false) Long categoryId,
            @RequestParam(value = "price_min", required = false) BigDecimal minPrice,
            @RequestParam(value = "price_max", required = false) BigDecimal maxPrice
    ) {
        Page<TourResponseDTO> tourPage = tourService.getAvailableTours(page, size, sortBy, sortDirection, 
                keyword, categoryId, minPrice, maxPrice);

        return ResponseEntity.ok(ApiResponse.<Page<TourResponseDTO>>builder()
                .code(1000)
                .message("Lấy danh sách tour thành công")
                .result(tourPage)
                .build());
    }
    
    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<TourResponseDTO>> getTourDetail(@PathVariable("id") Long tourId) {
        TourResponseDTO tourDetail = tourService.getTourDetail(tourId);

        return ResponseEntity.ok(ApiResponse.<TourResponseDTO>builder()
                .code(1000)
                .message("Lấy chi tiết tour thành công")
                .result(tourDetail)
                .build());
    }

    @GetMapping("/{tourId}/reviews")
    public ResponseEntity<ApiResponse<Page<ReviewListItemDTO>>> getReviewsByTourId(
            @PathVariable Long tourId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size
    ) {
        Pageable pageable = PageRequest.of(page, size);
        Page<ReviewListItemDTO> reviews = reviewService.getReviewsByTourId(tourId, pageable);

        return ResponseEntity.ok(ApiResponse.<Page<ReviewListItemDTO>>builder()
                .code(1000)
                .message("Lấy danh sách review thành công")
                .result(reviews)
                .build());
    }
}