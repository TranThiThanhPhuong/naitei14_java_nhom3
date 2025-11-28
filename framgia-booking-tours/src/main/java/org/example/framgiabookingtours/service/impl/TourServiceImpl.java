package org.example.framgiabookingtours.service.impl;

import org.example.framgiabookingtours.dto.response.TourResponseDTO;
import org.example.framgiabookingtours.entity.Tour;
import org.example.framgiabookingtours.enums.TourStatus;
import org.example.framgiabookingtours.exception.AppException;
import org.example.framgiabookingtours.exception.ErrorCode;
import org.example.framgiabookingtours.repository.TourRepository;
import org.example.framgiabookingtours.repository.TourSpecification;
import org.example.framgiabookingtours.service.TourService;
import org.springframework.data.domain.*;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import lombok.RequiredArgsConstructor;

import java.math.BigDecimal;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class TourServiceImpl implements TourService {

    private final TourRepository tourRepository;

    @Override
    public Page<TourResponseDTO> getAvailableTours(int page, int size, String sortBy, String sortDirection, 
            String keyword, Long categoryId, BigDecimal minPrice, BigDecimal maxPrice) {
        
        Sort.Direction direction = Sort.Direction.DESC;
        try {
            direction = Sort.Direction.fromString(sortDirection);
        } catch (IllegalArgumentException e) {
            
        }
        
        Specification<Tour> spec = Specification
                .where(TourSpecification.isAvailable())
                .and(TourSpecification.hasKeyword(keyword))
                .and(TourSpecification.hasCategoryId(categoryId))
                .and(TourSpecification.hasPriceRange(minPrice, maxPrice));

        Sort sort = Sort.by(direction, sortBy);
        
        Pageable pageable = PageRequest.of(page, size, sort);

        Page<Tour> tourPage = tourRepository.findAll(spec, pageable);

        return tourPage.map(this::convertToDto);
    }
    
    @Override
    public TourResponseDTO getTourDetail(Long tourId) {
        Tour tour = tourRepository.findById(tourId)
                .orElseThrow(() -> new AppException(ErrorCode.TOUR_NOT_FOUND));

        if (tour.getStatus() != TourStatus.AVAILABLE) {
            throw new AppException(ErrorCode.TOUR_NOT_AVAILABLE);
        }
        
        return convertToDto(tour);
    }
   
    private TourResponseDTO convertToDto(Tour tour) {
        Double avgRating = 0.0; 
        
        TourResponseDTO.CategoryInfo categoryInfo = Optional.ofNullable(tour.getCategory())
                .map(c -> TourResponseDTO.CategoryInfo.builder().id(c.getId()).name(c.getName()).build())
                .orElse(null);
        
        return TourResponseDTO.builder()
                .id(tour.getId())
                .name(tour.getName())
                .location(tour.getLocation())
                .description(tour.getDescription())
                .imageUrl(tour.getImageUrl())
                .price(tour.getPrice())
                .durationDays(tour.getDurationDays())
                .availableSlots(tour.getAvailableSlots())
                .createdAt(tour.getCreatedAt())
                .updatedAt(tour.getUpdatedAt())
                .averageRating(avgRating)
                .category(categoryInfo)
                .build();
    }
}