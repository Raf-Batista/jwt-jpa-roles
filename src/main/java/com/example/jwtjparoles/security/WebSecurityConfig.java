package com.example.jwtjparoles.security;

import com.example.jwtjparoles.security.jwt.AuthEntryPointJwt;
import com.example.jwtjparoles.security.jwt.AuthTokenFilter;
import com.example.jwtjparoles.security.services.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(
        // securedEnabled = true,
        // jsr250Enabled = true,
        prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    // Our implementation of the UsersDetailsService class. This class interacts with the database and
    // fetches a user to be authenticated on reqeusts
    UserDetailsServiceImpl userDetailsService;

    // This is the class that handles exceptions with a custom message, not necessary
    private final AuthEntryPointJwt unauthorizedHandler;

    public WebSecurityConfig(UserDetailsServiceImpl userDetailsService, AuthEntryPointJwt unauthorizedHandler) {
        this.userDetailsService = userDetailsService;
        this.unauthorizedHandler = unauthorizedHandler;
    }

    // This is our custom filter which we will add to the filter chain.
    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }

    /*
        The AuthenticationManagerBuilder allows for building in memory authentication, LDAP authentication and
        JDBC based authentication. Basically we can create users in memory to be used for authentication or grab users
        from a database and use it for authentication. We can also add an authentication provider. The authentication provider
        provider processes a specific Authentication implementation. The Authentication represents the jwt token that a user sends to
        authenticate a principle (user) with the credentials (password)

        In our case, we build an authentication manager and add the usersDetailsService
        (which takes care of fetching a user that will be authenticated) and specify how we encode password. If we do not provide
        one then the password will be plain text
    */
    @Override
    public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    // The AuthenticationManager attempts to authenticate the token in an authentication object which returns an authentication object along with the list of authorities
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    // This is how we will encrypt a user's password, in our case it's BCrypt
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        /*
            We enable CORS (Cross Origin Resource Sharing) because of the Same Origin Policy adopted by Browsers. to restrict access from on domain to another domain's resources. We bypass tge Same Origin Policy
            without decreasing security. CORS needs to be processed first or else Spring Security will reject the request before it reaches Spring MVC, Web, etc
        */
        http.cors().and().csrf().disable()
                // We can use this for exception handling instead of the using our custom 'unauthorizedHandler' which is implemented in src/main/java/com/example/jwtjparoles/AuthEntryPointJwt
                //.exceptionHandling().authenticationEntryPoint((req, rsp, e) -> rsp.sendError(HttpServletResponse.SC_UNAUTHORIZED)).and()
                .exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and()
                // Jwt is stateless so we want to make sure we don't use state here
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                // We authorize requests matching a certain ant pattern and we permit all requests
                .authorizeRequests().antMatchers("/api/auth/**").permitAll()
                .antMatchers("/api/test/**").permitAll()
                .anyRequest().authenticated();

        http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
    }
}