package com.youssfi.springsecurityjwt;

import com.youssfi.springsecurityjwt.entity.Role;
import com.youssfi.springsecurityjwt.entity.AppUser;
import com.youssfi.springsecurityjwt.service.UserSerivce;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@Slf4j
@SpringBootApplication
@EnableGlobalMethodSecurity(prePostEnabled = true,securedEnabled = true)
public class SpringSecurityJwtApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityJwtApplication.class, args);
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return  new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner start(UserSerivce userSerivce){
        return args -> {
            userSerivce.addRole(new Role(null,"USER"));
            userSerivce.addRole(new Role(null,"ADMIN"));
            userSerivce.addRole(new Role(null,"CUSTOMER_MANAGER"));
            userSerivce.addRole(new Role(null,"PRODUCT_MANAGER"));

            userSerivce.addUser(new AppUser(null,"user1","1234",new ArrayList<>()));
            userSerivce.addUser(new AppUser(null,"admin","1234",new ArrayList<>()));
            userSerivce.addUser(new AppUser(null,"user2","1234",new ArrayList<>()));
            userSerivce.addUser(new AppUser(null,"user3","1234",new ArrayList<>()));
            userSerivce.addUser(new AppUser(null,"user4","1234",new ArrayList<>()));



            userSerivce.addRoleToUser("user1","USER");
            userSerivce.addRoleToUser("admin","ADMIN");
            userSerivce.addRoleToUser("user2","CUSTOMER_MANAGER");
            userSerivce.addRoleToUser("user3","PRODUCT_MANAGER");
            userSerivce.addRoleToUser("user4","USER");











        };
    }

}
