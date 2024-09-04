package br.com.fiap.apicarsale.domain.comments;

import br.com.fiap.apicarsale.exception.CommentNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CommentService {

    private final CommentRepository commentRepository;

    public CommentService(CommentRepository commentRepository) {
        this.commentRepository = commentRepository;
    }

    public List<Comment> getAllComments() {
        return commentRepository.findAll();
    }

    public Comment createComment(Comment comment) {
        return commentRepository.save(comment);
    }

    public void deleteComment(Long id) {
        commentRepository.findById(id).orElseThrow(
                () -> new CommentNotFoundException(id)
        );
        commentRepository.deleteById(id);
    }
}
