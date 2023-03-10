package com.youssfi.springsecurityjwt.security;

import com.youssfi.springsecurityjwt.entity.AppUser;
import com.youssfi.springsecurityjwt.entity.Role;
import com.youssfi.springsecurityjwt.filters.JWtAuthorizationFiltrer;
import com.youssfi.springsecurityjwt.filters.JwtAuthenticationFilter;
import com.youssfi.springsecurityjwt.service.UserServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.ArrayList;
import java.util.Collection;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    UserServiceImpl userService;
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(new UserDetailsService() {

            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                AppUser appUser = userService.loadUserByUsername(username);
                Collection<GrantedAuthority> autorities= new ArrayList<>();
                appUser.getRoles().forEach(ele->{
                    autorities.add(new SimpleGrantedAuthority(ele.getRoleName()));
                });
                return new User(appUser.getUsername(),appUser.getPassword(),autorities);
            }
        });
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.headers().frameOptions().disable();
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        //http.formLogin();
        http.authorizeRequests().antMatchers("/h2-console/**","/refreshToken/**").permitAll();

        http.authorizeRequests().anyRequest().authenticated();
        http.addFilter(new JwtAuthenticationFilter(authenticationManagerBean()));
        http.addFilterBefore(new JWtAuthorizationFiltrer(), UsernamePasswordAuthenticationFilter.class);
    }


    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception{
   return  super.authenticationManager();
    }
}


