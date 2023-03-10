package com.youssfi.springsecurityjwt.filters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

public class JWtAuthorizationFiltrer extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorizationToken = request.getHeader("Authorization");

        if(request.getRequestURL().equals("/refreshToken")){
            filterChain.doFilter(request,response);
        }
        if (authorizationToken != null && authorizationToken.startsWith("Bearer ")) {

            try {
                String jwt = authorizationToken.substring(7);
                Algorithm algo = Algorithm.HMAC256("Secret1234");
                JWTVerifier verify = JWT.require(algo).build();
                DecodedJWT decode = verify.verify(jwt);
                String username = decode.getSubject();
                String[] roles = decode.getClaim("role").asArray(String.class);
                Collection<GrantedAuthority> authorities = new ArrayList<>();
                for (String r : roles) {
                    authorities.add(new SimpleGrantedAuthority(r));
                }
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                filterChain.doFilter(request,response);


            } catch (Exception e) {
                response.setHeader("error-message",e.getMessage());
                response.sendError(HttpServletResponse.SC_FORBIDDEN);
            }



        }
        else{
            filterChain.doFilter(request,response);

        }
    }
}
