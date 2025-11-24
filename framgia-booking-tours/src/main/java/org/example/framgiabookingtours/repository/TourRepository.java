package org.example.framgiabookingtours.repository;

import org.example.framgiabookingtours.entity.Tour;
import org.example.framgiabookingtours.enums.TourStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository

public interface TourRepository extends JpaRepository<Tour, Long>, JpaSpecificationExecutor<Tour> {
    
	Page<Tour> findByStatus(TourStatus status, Pageable pageable);
	
} //Kế thừa JpaSpecificationExecutor để hỗ trợ lọc phức tạp (sẽ dùng trong F2)