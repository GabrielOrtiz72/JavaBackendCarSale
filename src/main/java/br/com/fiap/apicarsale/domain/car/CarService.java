package br.com.fiap.apicarsale.domain.car;

import br.com.fiap.apicarsale.exception.CarNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CarService {

    private final CarRepository carRepository;

    public CarService(CarRepository carRepository) {
        this.carRepository = carRepository;
    }

    public List<Car> getAllCars() {
        return carRepository.findAll();
    }

    public Car getCarById(Long id) {
        return carRepository.findById(id).orElseThrow(
                () -> new CarNotFoundException(id)
        );
    }
}
