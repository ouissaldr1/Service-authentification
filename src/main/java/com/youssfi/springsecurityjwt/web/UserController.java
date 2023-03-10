package com.youssfi.springsecurityjwt.web;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.youssfi.springsecurityjwt.entity.AppUser;
import com.youssfi.springsecurityjwt.entity.Role;
import com.youssfi.springsecurityjwt.service.UserSerivce;
import lombok.Data;
import org.apache.catalina.User;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

@RestController
public class UserController {
    private UserSerivce userSerivce;

    public UserController(UserSerivce userSerivce) {
        this.userSerivce = userSerivce;
    }


    @GetMapping("/users")
    @PostAuthorize("hasAuthority('USER')")
    public List<AppUser> getUsers(){
        return userSerivce.findAllUsers();
    }

    @PostMapping("/users")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppUser saveUser(@RequestBody AppUser appUser){
        return userSerivce.addUser(appUser);
    }

    @PostMapping("/roles")
    @PostAuthorize("hasAuthority('ADMIN')")
    public Role saveRole(@RequestBody Role role){
        return  userSerivce.addRole(role);
    }

    @PostMapping("/addRoleToUser")
    public void saveRoleToUser(@RequestBody RoleToUserForm roleToUserForm){
        userSerivce.addRoleToUser(roleToUserForm.getUsername(), roleToUserForm.getRoleName());
    }

    @GetMapping("/refreshToken")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authToken = request.getHeader(("Authorization"));
        if (authToken != null && authToken.startsWith("Bearer ")) {

            try {
                String jwt = authToken.substring(7);
                Algorithm algo = Algorithm.HMAC256("Secret1234");
                JWTVerifier verify = JWT.require(algo).build();
                DecodedJWT decode = verify.verify(jwt);
                String username = decode.getSubject();
                AppUser user = userSerivce.loadUserByUsername(username);
                String jwtAccessToken = JWT.create().withSubject(user.getUsername()).withExpiresAt(new Date(System.currentTimeMillis()+ 10*60*1000))
                        .withClaim("roles",user.getRoles().stream().map(ele->ele.getRoleName()).collect(Collectors.toList()))
                        .withIssuer(request.getRequestURL().toString())
                        .sign(algo);

                Map<String,String> IdToken = new HashMap<>();
                IdToken.put("access-token", jwtAccessToken);
                IdToken.put("refrech-token", jwt);
                response.setContentType("application/json");

                new ObjectMapper().writeValue(response.getOutputStream(),IdToken);


            } catch (Exception e) {
               throw e;
            }



        }
        else{
            throw new RuntimeException("Refrech Token required");

        }

    }

}

@Data
class RoleToUserForm{
    String username;
    String roleName;
}
