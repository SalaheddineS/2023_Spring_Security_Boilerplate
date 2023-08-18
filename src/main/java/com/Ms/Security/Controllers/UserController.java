package com.Ms.Security.Controllers;

import com.Ms.Security.Entities.User;
import com.Ms.Security.Repository.UserRepository;
import com.Ms.Security.Utilities.JwtUtilities;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class UserController {
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtUtilities jwtUtilities;
    @Autowired
    public UserController(UserRepository userRepository, AuthenticationManager authenticationManager, JwtUtilities jwtUtilities) {
        this.userRepository = userRepository;
        this.authenticationManager = authenticationManager;
        this.jwtUtilities = jwtUtilities;
    }

    @GetMapping("/test")
    public String test()
    {
        return "test";
    }

    @GetMapping("getUsers")
    public List<User> getUsers()
    {
        return userRepository.findAll();
    }

    @PostMapping("addUser")
    public User addUser(@RequestBody User user)
    {
        user.setRole("USER");
        user.setPassword(new BCryptPasswordEncoder().encode(user.getPassword()));
        return this.userRepository.save(user);
    }
    @PostMapping("login")
    public String login(@RequestBody User user){
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(),user.getPassword()));
        return jwtUtilities.generateToken(user);
    }
}
