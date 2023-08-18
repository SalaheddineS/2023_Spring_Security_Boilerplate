package com.Ms.Security.Config;

import com.Ms.Security.Entities.User;
import com.Ms.Security.Repository.UserRepository;
import com.Ms.Security.Utilities.JwtUtilities;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.IOException;

import static org.springframework.security.config.Customizer.withDefaults;
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityMainConfig {

    private final JwtAuthFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;
    private final UserRepository userRepository;
    private final JwtUtilities jwtUtilities;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(
                        csrf -> csrf
                                .disable()
                )
                .httpBasic(withDefaults())
                .sessionManagement(
                        session -> session
                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authorizeHttpRequests(
                        auth -> auth
                                .requestMatchers("/login").permitAll()
                                .requestMatchers("/test").permitAll()
                                .anyRequest().authenticated()
                )
                .oauth2Login(login -> login
                        .successHandler(this::onAuthenticationSuccess)
                )
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    private String onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                         Authentication authentication) throws IOException, ServletException {
        if (authentication instanceof OAuth2AuthenticationToken) {
            OAuth2AuthenticationToken oauth2Authentication = (OAuth2AuthenticationToken) authentication;

            String email = oauth2Authentication.getPrincipal().getAttribute("email");
            if (email == null) {
                throw new UsernameNotFoundException("Email not found from OAuth2 provider");
            }
            User user = userRepository.findByUsername(email);
            System.out.println("user = " + user);
            if (user == null) {
                user = new User();
                user.setUsername(email);
                user.setPassword(new BCryptPasswordEncoder().encode("123456"));
                user.setRole("USER");
                userRepository.save(user);
            }
            String myToken=jwtUtilities.generateToken(user);
            response.sendRedirect("/test?token=" + myToken);
            return myToken;
        }
        return null;
    }
}
