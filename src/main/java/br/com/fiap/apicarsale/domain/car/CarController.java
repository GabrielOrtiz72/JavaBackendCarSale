package br.com.fiap.apicarsale.domain.car;

import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/cars")
public class CarController {

    private final CarService carService;

    public CarController(CarService carService) {
        this.carService = carService;
    }

    @GetMapping
    public List<CarResponse> getAllCars() {
        return carService.getAllCars().stream().map(CarResponse::fromModel).toList();
    }

    @GetMapping("{id}")
    public CarResponse getCarById(@PathVariable Long id) {
        return CarResponse.fromModel( carService.getCarById(id) );
    }

}
