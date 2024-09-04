package br.com.fiap.apicarsale.exception;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class ErrorHandler {

    record ErrorResponse(String message) {}

    @ExceptionHandler({CarNotFoundException.class, CommentNotFoundException.class})
    public ResponseEntity<?> handleCarNotFoundException(RuntimeException exception) {
        return ResponseEntity
                .status(404)
                .body(new ErrorResponse(exception.getMessage()));
    }

}
