package com.example.jwtjparoles.security.jwt;

import com.example.jwtjparoles.security.services.UserDetailsServiceImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AuthTokenFilter extends OncePerRequestFilter {
    // This class is a custom filter we implement and throw in with the other chain of filters. This class extends the
    // OncePerRequestFilter class that only dispatches once per request, meaning the method below (doFilterInternal) is dispatched once
    // per request


    // We create this jwt utility file with some helper methods, such as getting the username from the jwt and generating a new jwt token
    @Autowired
    private JwtUtils jwtUtils;

    // We create an interface that implements the UserDetailsService interface and we override a method that loads a user by username from the database
    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    // This logger is not neccessary, it is only used to return a custom message when we catch an excepction
    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

    /*
        Remember that Spring Security works out of the box, with our particular case of wanting to use stateless authentication with JWT, we need to override certain methods that Spring
        Security provided us out of the box.

        The doFilterInternal takes three arguments, a request, a response, and a filterchain.
        The request and response should be normal to use by now but filterchains are something new that Spring Security provides. Remember, HTTP is stateless. It won't remember everything
        about requests, and in a functional programming kind of way, our HTTP requests go through filters that each return the request for the next filter.

        Filter 1
        Filter 2
        Filter 3

        We can define 3 filters and have our HTTP request go through the first filter and take a look at the request, modify it ect. If everything goes well then the request is passed
        into the second filter and so on. If something goes wrong, we don't pass to the next filter and stop right there.

    */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            String jwt = parseJwt(request); // The first thing we do is remove "Bearer" from the request header. This helper method is defined below
            if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
                // If the jwt is not null and we can validate that the key came from us (remember that we have helper methods from the JwtUtils class we defined) then we use another helper method to get the username
                String username = jwtUtils.getUserNameFromJwtToken(jwt);
                // We create a class that we can use to define the details of a user. Spring Security has a class called UserDetails so we implement our own. We do the same with UserDetailsService and override the method
                // loadByUsername(). This method isn't special, we use the userRepository to find a specific user from our database.
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                /*
                   UsernamePasswordAuthenticationToken is an Authentication implementation that is designed for simple presentation of a username and password provided by Spring Security.
                   This particular constructor takes three parameters, principal, credentials, and authorities.
                   The principal is the identity of the user being authenticated.
                   The credentials prove that the principal is correct
                   The authorities are roles used to give or restrict access to endpoints based on those roles a user has
                   In our particular case, we are passing 'null' for the credentials argument. The reason for that is we do no simply have to pass a username as the principle. We can pass something
                   more complex, such as a UserDetails object. A UserDetails object contains the details for a user, we implement our own version of UserDetails since our users have an email
                */

                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null,
                        userDetails.getAuthorities());

                /*
                    WebAuthenticationDetails contains HTTP details related to the current web authentication request. We instantiate a new object and call the buildDetails()
                    which takes in a context of type HtppServletRequest and returns the details of that request such as an IP address, certificate serial number etc. We are setting those details
                    in the authentication instance we created
                */
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                /*
                    The SecurityContext associates a given SecurityContext with the current execution thread.
                    The SecurityContext is the Interface defining the minimum security information associated with the current thread of execution. The getContext() method returns the current
                    SecurityContext and the setAuthentication() sets the currently authenticated principle. It has an 'authentication' parameter which is
                    the new Authentication token, or null if no further authentication information should be stored
                */
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e);
        }

        // Remember that if all goes well with the request in a filter, we pass the request and response to the next filter. This method doFilterInternal() that we override
        // takes in a filterChain. To pass the request and response to the next filter, call the doFilter() method on the filterChain passed in. If it is the last filterchain
        // then the resource at the end of the chain will be invoked.
        filterChain.doFilter(request, response);
    }

    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");

        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7, headerAuth.length());
        }

        return null;
    }
}