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
    BOOKING_NOT_FOUND(1016, "Booking not found", HttpStatus.NOT_FOUND),
    BOOKING_NOT_COMPLETED(1017, "Booking is not completed, cannot create review", HttpStatus.BAD_REQUEST),
    REVIEW_ALREADY_EXISTS(1018, "Review already exists for this booking", HttpStatus.BAD_REQUEST),
    BOOKING_NOT_BELONG_TO_USER(1019, "Booking does not belong to this user", HttpStatus.FORBIDDEN);;

    ErrorCode(int code, String message, HttpStatusCode httpStatusCode) {
        this.code = code;
        this.message = message;
        this.httpStatusCode = httpStatusCode;
    }

    private int code;
    private String message;
    private HttpStatusCode httpStatusCode;
}
