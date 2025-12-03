package org.example.framgiabookingtours.repository;

import org.example.framgiabookingtours.entity.ReviewLike;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ReviewLikeRepository extends JpaRepository<ReviewLike, Long> {

    long countByReviewIdAndIsDeletedFalse(Long reviewId);

    Optional<ReviewLike> findByUserIdAndReviewIdAndIsDeletedFalse(Long userId, Long reviewId);
}
