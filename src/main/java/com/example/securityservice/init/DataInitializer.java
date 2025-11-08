package com.example.securityservice.init;

import com.example.securityservice.entities.AppRole;
import com.example.securityservice.entities.AppUser;
import com.example.securityservice.repository.AppRoleRepository;
import com.example.securityservice.repository.AppUserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;

@Configuration
public class DataInitializer {

    @Bean
    CommandLineRunner initDatabase(AppUserRepository userRepo, AppRoleRepository roleRepo, PasswordEncoder passwordEncoder) {
        return args -> {
            // Create roles if not exist
            AppRole userRole = roleRepo.findByName("USER").orElseGet(() -> roleRepo.save(new AppRole(null, "USER", null)));
            AppRole adminRole = roleRepo.findByName("ADMIN").orElseGet(() -> roleRepo.save(new AppRole(null, "ADMIN", null)));

            // Create users if not exist
            if (userRepo.findByUsername("user1").isEmpty()) {
                AppUser user1 = new AppUser();
                user1.setUsername("user1");
                user1.setPassword(passwordEncoder.encode("1234"));
                user1.setEnabled(true);
                user1.setRoles(Set.of(userRole));
                userRepo.save(user1);
            }

            if (userRepo.findByUsername("admin1").isEmpty()) {
                AppUser admin1 = new AppUser();
                admin1.setUsername("admin1");
                admin1.setPassword(passwordEncoder.encode("1234"));
                admin1.setEnabled(true);
                admin1.setRoles(Set.of(userRole, adminRole));
                userRepo.save(admin1);
            }

            System.out.println("✅ Users and roles inserted successfully!");
        };
    }
}
