package br.com.fiap.apicarsale.domain.comments;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/comments")
public class CommentsController {

    private final CommentService commentService;

    public CommentsController(CommentService commentService) {
        this.commentService = commentService;
    }

    @GetMapping
    public List<CommentResponse> getAllComments() {
        return commentService.getAllComments().stream().map(CommentResponse::fromModel).toList();
    }

    @PostMapping
    public Comment createComment(@RequestBody CommentRequest commentRequest) {
        return commentService.createComment(commentRequest.toModel());
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteComment(@PathVariable Long id) {
        commentService.deleteComment(id);
    }

}
