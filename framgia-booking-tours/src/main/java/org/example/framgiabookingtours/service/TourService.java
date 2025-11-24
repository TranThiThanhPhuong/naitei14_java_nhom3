package org.example.framgiabookingtours.service;

import org.example.framgiabookingtours.dto.response.TourResponseDTO;
import org.springframework.data.domain.Page;

public interface TourService {

	Page<TourResponseDTO> getAvailableTours(int page, int size, String sortBy, String sortDirection);
	
}
