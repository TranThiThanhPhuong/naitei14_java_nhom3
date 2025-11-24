package org.example.framgiabookingtours.controller;

import org.example.framgiabookingtours.dto.ApiResponse;
import org.example.framgiabookingtours.dto.response.TourResponseDTO;
import org.example.framgiabookingtours.service.TourService;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/tours") 
@RequiredArgsConstructor
public class PublicTourController {

    private final TourService tourService;

    @GetMapping
    public ResponseEntity<ApiResponse<Page<TourResponseDTO>>> getTours(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "createdAt") String sortBy,
            @RequestParam(defaultValue = "DESC") String sortDirection
    ) {
        Page<TourResponseDTO> tourPage = tourService.getAvailableTours(page, size, sortBy, sortDirection);
        
        return ResponseEntity.ok(ApiResponse.<Page<TourResponseDTO>>builder()
                .code(1000)
                .message("Lấy danh sách tour thành công")
                .result(tourPage)
                .build());
    }
    
}