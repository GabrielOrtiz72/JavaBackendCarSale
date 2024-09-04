package br.com.fiap.apicarsale.domain.car;

import br.com.fiap.apicarsale.domain.comments.Comment;
import br.com.fiap.apicarsale.domain.comments.CommentResponse;

import java.util.List;

public record CarResponse(
        Long id,
        String brand,
        String model,
        String imageUrl,
        String description,
        List<CommentResponse> comments
) {
    public static CarResponse fromModel(Car car) {
        return new CarResponse(
                car.getId(),
                car.getBrand(),
                car.getModel(),
                car.getImageUrl(),
                car.getDescription(),
                CommentResponse.fromModelList(car.getComments())
        );
    }
}
