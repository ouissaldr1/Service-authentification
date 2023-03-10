package com.youssfi.springsecurityjwt.service;


import com.youssfi.springsecurityjwt.entity.Role;
import com.youssfi.springsecurityjwt.entity.AppUser;

import java.util.List;

public interface UserSerivce {
    AppUser addUser(AppUser user);
    Role addRole(Role role);

    void addRoleToUser(String user,String role);
    AppUser loadUserByUsername(String username);
    List<AppUser> findAllUsers();

}
