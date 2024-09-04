package br.com.fiap.apicarsale.auth;

import br.com.fiap.apicarsale.domain.user.User;
import br.com.fiap.apicarsale.domain.user.UserRepository;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
public class TokenService {

    public Algorithm ALGORITHM;
    private final UserRepository userRepository;

    public TokenService(@Value("${jwt.secret}") String secret, UserRepository userRepository) {
        this.userRepository = userRepository;
        ALGORITHM = Algorithm.HMAC256(secret);
    }

    public Token create(User user){
        var expires = LocalDateTime.now().plusMinutes(10).toInstant(ZoneOffset.ofHours(-3));

        var token = JWT.create()
                .withSubject(user.getId().toString())
                .withClaim("username", user.getUsername())
                .withClaim("role", user.getRole())
                .withExpiresAt(expires)
                .sign(ALGORITHM);

        return new Token(token, user.getName(), user.getId().toString(), user.getRole());
    }

    public User getUserFromToken(String token) {
        var userId = JWT.require(ALGORITHM)
                .build()
                .verify(token)
                .getSubject();

        return userRepository.findById(Long.parseLong(userId))
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

}
