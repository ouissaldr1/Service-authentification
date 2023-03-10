package com.youssfi.springsecurityjwt.service;

import com.youssfi.springsecurityjwt.entity.Role;
import com.youssfi.springsecurityjwt.entity.AppUser;
import com.youssfi.springsecurityjwt.repo.RoleRepo;
import com.youssfi.springsecurityjwt.repo.UserRepo;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Transactional
@Service
public class UserServiceImpl implements UserSerivce {


    RoleRepo roleRepository;
    UserRepo userRepository;

    PasswordEncoder passwordEncoder;

    public UserServiceImpl(RoleRepo roleRepository, UserRepo userRepository,PasswordEncoder passwordEncoder){
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }
    @Override
    public AppUser addUser(AppUser user) {
        String pw = user.getPassword();
        user.setPassword(passwordEncoder.encode(pw));
        return userRepository.save(user);
    }

    @Override
    public Role addRole(Role role) {
        return roleRepository.save(role);
    }

    @Override
    public void addRoleToUser(String user, String role) {
        AppUser appUser = userRepository.findByUsername(user);
        Role appRole = roleRepository.findByRoleName(role);
        appUser.getRoles().add(appRole);


    }

    @Override
    public AppUser loadUserByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public List<AppUser> findAllUsers() {
        return userRepository.findAll();
    }
}
