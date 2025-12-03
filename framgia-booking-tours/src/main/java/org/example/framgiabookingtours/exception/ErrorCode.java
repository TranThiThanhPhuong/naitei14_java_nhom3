package org.example.framgiabookingtours.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;

@Getter
public enum ErrorCode {
    UNCATEGORIZED_EXCEPTION(9999, "Uncategorized error", HttpStatus.INTERNAL_SERVER_ERROR),
    INVALID_KEY(1001, "Invalid key", HttpStatus.BAD_REQUEST),
    USER_EXISTED(1002, "User existed", HttpStatus.BAD_REQUEST),
    USERNAME_INVALID(1003, "Username must be at least 3 characters", HttpStatus.BAD_REQUEST),
    INVALID_PASSWORD(1004, "Password must be at least 8 characters", HttpStatus.BAD_REQUEST),
    USER_NOT_EXISTED(1005, "User not existed", HttpStatus.NOT_FOUND),
    UNAUTHENTICATED(1006, "Unauthenticated", HttpStatus.UNAUTHORIZED),
    UNAUTHORIZED(1007, "You do not have permission", HttpStatus.FORBIDDEN),
    INVALID_EMAIL(1008, "Email is not valid", HttpStatus.BAD_REQUEST),
    ROLE_EXISTED(1009, "Role existed", HttpStatus.BAD_REQUEST),
    ROLE_NOT_FOUND(1010, "Role not found", HttpStatus.NOT_FOUND),
    PERMISSION_NOT_FOUND(1011, "Permission not found", HttpStatus.NOT_FOUND),
    ACCOUNT_LOCKED(1012, "Account is locked", HttpStatus.FORBIDDEN),
    TOUR_NOT_ENOUGH_SLOTS(1013, "Tour does not have enough slots. Only %d slots available", HttpStatus.BAD_REQUEST),
    TOUR_NOT_FOUND(1014, "Tour not found", HttpStatus.NOT_FOUND),
    TOUR_NOT_AVAILABLE(1015, "Tour not available now", HttpStatus.NOT_FOUND),
    FULL_NAME_TOO_LONG(1201, "Full name must be less than 100 characters", HttpStatus.BAD_REQUEST),
    PHONE_TOO_LONG(1202, "Phone number must be less than 20 characters", HttpStatus.BAD_REQUEST),
    BANK_NAME_TOO_LONG(1203, "Bank name must be less than 100 characters", HttpStatus.BAD_REQUEST),
    BANK_ACCOUNT_TOO_LONG(1204, "Bank account number must be less than 50 characters", HttpStatus.BAD_REQUEST),
    PROFILE_UPDATE_FAILED(1205, "Update profile failed", HttpStatus.BAD_REQUEST),
    FILE_NULL(1301, "File is null or empty", HttpStatus.BAD_REQUEST),
    UPLOAD_FAILED(1302, "File upload failed", HttpStatus.INTERNAL_SERVER_ERROR),
    BOOKING_NOT_FOUND(1016, "Booking not found", HttpStatus.NOT_FOUND),
    BOOKING_NOT_COMPLETED(1017, "Booking is not completed, cannot create review", HttpStatus.BAD_REQUEST),
    REVIEW_ALREADY_EXISTS(1018, "Review already exists for this booking", HttpStatus.BAD_REQUEST),
    BOOKING_NOT_BELONG_TO_USER(1019, "Booking does not belong to this user", HttpStatus.FORBIDDEN),
    REVIEW_NOT_FOUND(1020, "Review not found", HttpStatus.NOT_FOUND),
    REVIEW_NOT_BELONG_TO_USER(1021, "Review does not belong to this user", HttpStatus.FORBIDDEN),
    BOOKING_INVALID_STATUS(1022, "Cannot cancel booking with status %s", HttpStatus.BAD_REQUEST),
    COMMENT_NOT_FOUND(1023, "Comment not found", HttpStatus.NOT_FOUND),
    COMMENT_NOT_BELONG_TO_USER(1024, "Comment does not belong to this user", HttpStatus.FORBIDDEN),
    COMMENT_NOT_BELONG_TO_REVIEW(1025, "Comment does not belong to this review", HttpStatus.BAD_REQUEST),
    BOOKING_COMPLETE(1026, "This booking is completed", HttpStatus.BAD_REQUEST),
    INVALID_CREDENTIALS(1027, "Incorrect email or password", HttpStatus.UNAUTHORIZED),
    UNVERIFIED_EMAIL(1028, "Your account is not verified. Please check your email and activate your account.", HttpStatus.FORBIDDEN),
    INVALID_INPUT(1029, "Invalid input data", HttpStatus.BAD_REQUEST),
    EMAIL_IS_REQUIRED(1030, "Email cannot be blank", HttpStatus.BAD_REQUEST),
    PASSWORD_IS_REQUIRED(1031, "Password cannot be blank", HttpStatus.BAD_REQUEST),
    NAME_IS_REQUIRED(1032, "Name cannot be blank", HttpStatus.BAD_REQUEST);

    ErrorCode(int code, String message, HttpStatusCode httpStatusCode) {
        this.code = code;
        this.message = message;
        this.httpStatusCode = httpStatusCode;
    }

    private int code;
    private String message;
    private HttpStatusCode httpStatusCode;
}
