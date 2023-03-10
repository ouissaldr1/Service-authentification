package com.youssfi.springsecurityjwt.repo;

import com.youssfi.springsecurityjwt.entity.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

public interface UserRepo extends JpaRepository<AppUser,Long> {
    AppUser findByUsername(String username);
}
