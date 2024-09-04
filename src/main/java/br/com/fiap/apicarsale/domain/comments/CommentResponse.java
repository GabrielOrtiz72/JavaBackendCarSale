package br.com.fiap.apicarsale.domain.comments;

import com.fasterxml.jackson.annotation.JsonFormat;

import java.time.LocalDate;
import java.util.List;

public record CommentResponse(
        Long id,
        String name,
        String comment,
        @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "dd/MM/yyyy")
        LocalDate createdDate
) {


    public static CommentResponse fromModel(Comment comment) {
        return new CommentResponse(
                comment.getId(),
                comment.getUser().getName(),
                comment.getComment(),
                comment.getCreatedDate()
        );
    }

    public static List<CommentResponse> fromModelList(List<Comment> comments) {
        return comments.stream().map(CommentResponse::fromModel).toList();
    }
}