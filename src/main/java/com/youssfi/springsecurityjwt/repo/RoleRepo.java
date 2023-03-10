package com.youssfi.springsecurityjwt.repo;

import com.youssfi.springsecurityjwt.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

public interface RoleRepo extends JpaRepository<Role,Long>{
    //@Query("SELECT r FROM Role r WHERE r.roleName =: RoleName")
    Role findByRoleName(String RoleName);
}
