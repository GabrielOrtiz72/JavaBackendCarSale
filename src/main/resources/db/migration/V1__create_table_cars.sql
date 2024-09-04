CREATE TABLE IF NOT EXISTS cars (
    id bigint NOT NULL AUTO_INCREMENT,
    brand VARCHAR(255) NOT NULL,
    model VARCHAR(255) NOT NULL,
    image_url VARCHAR(255) NOT NULL,
    description VARCHAR(255) NOT NULL,
    primary key (id)
);

INSERT INTO cars (brand, model, image_url, description) VALUES
('Toyota', 'Corolla', 'https://www.toyotacomunica.com.br/wp-content/uploads/2023/09/pagina-24_COROLLA-2024_GR-S_2.png', 'Reliable and fuel-efficient sedan'),
('Honda', 'Civic', 'https://production.autoforce.com/uploads/version/profile_image/2701/comprar-exl_414646a7fc.png', 'Sporty and compact sedan'),
('Ford', 'Mustang', 'https://estofariabrasil.com.br/wp-content/uploads/2020/03/Mustang-GT500.png', 'Iconic American muscle car'),
('Chevrolet', 'Camaro', 'https://www.riocarchevroletpetrolina.com.br/content/dam/chevrolet/sa/br/pt/master/home/performance/camaro/colorizer/chevrolet-camaro-coupe-laranja-sunset.png?imwidth=900', 'High-performance sports car'),
('Tesla', 'Model S', 'https://www.tesla.com/ownersmanual/images/GUID-752B0ED4-D0A1-46C4-A141-F6A339F786A3-online-en-US.png', 'Luxurious electric sedan with autopilot'),
('BMW', 'X5', 'https://grandbrasil.com.br/wp-content/uploads/2020/02/5c1b0-grupo-de-mc3a1scara-1.webp', 'Premium mid-size SUV with advanced features');


