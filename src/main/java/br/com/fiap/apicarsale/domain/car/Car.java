package br.com.fiap.apicarsale.domain.car;

import br.com.fiap.apicarsale.domain.comments.Comment;
import jakarta.persistence.*;
import lombok.Data;

import java.util.List;

@Entity
@Data
@Table(name = "cars")
public class Car {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String model;
    private String brand;
    private String description;
    private String imageUrl;
    @OneToMany(mappedBy = "car")
    private List<Comment> comments;

}
