package br.ufpb.dcx.dsc.repositorios.config;

import br.ufpb.dcx.dsc.repositorios.models.User;
import br.ufpb.dcx.dsc.repositorios.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class DataLoader {

    @Bean
    CommandLineRunner initDatabase(UserRepository userRepository, PasswordEncoder encoder) {
        return args -> {
            if (userRepository.findByEmail("admin@admin.com").isEmpty()) {
                User admin = new User();
                admin.setNome("Administrador");
                admin.setEmail("admin@admin.com");
                admin.setPassword(encoder.encode("123456"));
                admin.setRole("ADMIN");
                userRepository.save(admin);
            }
        };
    }
}
