package org.example.framgiabookingtours.repository;

import org.example.framgiabookingtours.entity.Tour;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository

public interface TourRepository extends JpaRepository<Tour, Long>, JpaSpecificationExecutor<Tour> {
    
} //Kế thừa JpaSpecificationExecutor để hỗ trợ lọc phức tạp (sẽ dùng trong F2)