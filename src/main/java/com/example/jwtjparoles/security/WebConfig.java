package com.example.jwtjparoles.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/*
    We can enable CORS requests from different origins.
*/

@Configuration
@EnableWebMvc
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        // This will allow requests from any origin to any of our mapped endpoints
        registry.addMapping("/**").allowedOrigins("http:localhost:3525");

        /*
            This will allow requests from these different origins to any of our mapped endpoints
            registry.addMapping("/**").allowedOrigins("http://localhost:8080");

            // We can pass in an array to allowedOrigins() which is useful if we need to load this array from an external source at runtime
            registry.addMapping("/**").allowedOrigins("http://localhost:8080", "http://localhost:5000");

           // We can specify a pattern for our mapped endpoints
           registry.addMapping("/hello-world");

            There is a whole bunch of methods to customize our CORS policy. It follows the builder pattern so we can chain as many methods as we can to customize
            our policy
            registry.addMapping("/**").allowedOrigins("http://localhost:8080").allowedMethods("GET", "POST");
        */
    }
}