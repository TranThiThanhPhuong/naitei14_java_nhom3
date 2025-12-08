package org.example.framgiabookingtours.controller.admin;

import lombok.RequiredArgsConstructor;
import org.example.framgiabookingtours.entity.Comment;
import org.example.framgiabookingtours.entity.Review;
import org.example.framgiabookingtours.repository.CommentRepository;
import org.example.framgiabookingtours.repository.ReviewRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Controller
@RequestMapping("/admin/reviews")
@RequiredArgsConstructor
public class AdminReviewController {

    private final ReviewRepository reviewRepository;
    private final CommentRepository commentRepository;
    private final ObjectMapper objectMapper;

    @GetMapping
    public String listReviews(Model model,
                              @RequestParam(defaultValue = "1") int page,
                              @RequestParam(defaultValue = "10") int size) {

        model.addAttribute("activeMenu", "reviews");

        Pageable pageable = PageRequest.of(page - 1, size);
        Page<Review> reviewPage = reviewRepository.findAllActive(pageable);

        // Đếm số comment cho từng review (đơn giản, phù hợp cho admin)
        Map<Long, Long> commentCounts = new HashMap<>();
        for (Review review : reviewPage.getContent()) {
            long count = commentRepository.countByReviewIdAndIsDeletedFalse(review.getId());
            commentCounts.put(review.getId(), count);
        }

        model.addAttribute("reviews", reviewPage.getContent());
        model.addAttribute("currentPage", page);
        model.addAttribute("totalPages", reviewPage.getTotalPages());
        model.addAttribute("totalItems", reviewPage.getTotalElements());
        model.addAttribute("pageSize", size);
        model.addAttribute("commentCounts", commentCounts);

        // Parse imageUrls for each review
        Map<Long, List<String>> reviewImages = new HashMap<>();
        for (Review review : reviewPage.getContent()) {
            List<String> images = new ArrayList<>();
            if (review.getImageUrls() != null && !review.getImageUrls().isEmpty()) {
                try {
                    images = objectMapper.readValue(review.getImageUrls(), new TypeReference<List<String>>() {});
                } catch (Exception e) {
                    images = new ArrayList<>();
                }
            }
            reviewImages.put(review.getId(), images);
        }

        model.addAttribute("reviewImages", reviewImages);

        return "admin/reviews";
    }

    @GetMapping("/{id}")
    public String viewReviewDetail(@PathVariable Long id, Model model) {
        model.addAttribute("activeMenu", "reviews");

        Review review = reviewRepository.findById(id).orElse(null);
        if (review == null || Boolean.TRUE.equals(review.getIsDeleted())) {
            return "redirect:/admin/reviews";
        }

        List<Comment> comments = commentRepository
                .findAllByReviewIdAndIsDeletedFalseOrderByCreatedAtAsc(id);

        // Parse imageUrls for review
        List<String> reviewImages = new ArrayList<>();
        if (review.getImageUrls() != null && !review.getImageUrls().isEmpty()) {
            try {
                reviewImages = objectMapper.readValue(review.getImageUrls(), new TypeReference<List<String>>() {});
            } catch (Exception e) {
                reviewImages = new ArrayList<>();
            }
        }

        // Parse imageUrls for each comment
        Map<Long, List<String>> commentImages = new HashMap<>();
        for (Comment comment : comments) {
            List<String> images = new ArrayList<>();
            if (comment.getImageUrls() != null && !comment.getImageUrls().isEmpty()) {
                try {
                    images = objectMapper.readValue(comment.getImageUrls(), new TypeReference<List<String>>() {});
                } catch (Exception e) {
                    images = new ArrayList<>();
                }
            }
            commentImages.put(comment.getId(), images);
        }

        model.addAttribute("review", review);
        model.addAttribute("reviewImages", reviewImages);
        model.addAttribute("comments", comments);
        model.addAttribute("commentImages", commentImages);
        model.addAttribute("pageTitle", "Chi tiết review #" + review.getId());

        return "admin/review-detail";
    }

    @PostMapping("/{id}/delete")
    public String deleteReview(@PathVariable Long id) {
        reviewRepository.findById(id).ifPresent(review -> {
            review.setIsDeleted(true);
            review.setDeletedAt(LocalDateTime.now());
            reviewRepository.save(review);
        });

        return "redirect:/admin/reviews";
    }

    @PostMapping("/comments/{commentId}/delete")
    public String deleteComment(@PathVariable Long commentId) {
        Comment comment = commentRepository.findById(commentId).orElse(null);
        if (comment == null || Boolean.TRUE.equals(comment.getIsDeleted())) {
            return "redirect:/admin/reviews";
        }

        Long reviewId = comment.getReview().getId();

        comment.setIsDeleted(true);
        comment.setDeletedAt(LocalDateTime.now());
        commentRepository.save(comment);

        return "redirect:/admin/reviews/" + reviewId;
    }
}


