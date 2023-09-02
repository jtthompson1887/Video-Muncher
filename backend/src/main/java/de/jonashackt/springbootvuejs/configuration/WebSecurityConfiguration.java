package de.jonashackt.springbootvuejs.configuration;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
@EnableWebSecurity
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            // Session Management
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
            .and()

            // HTTP Basic Auth
            .httpBasic()
            .and()

            // Remember Me Config (if needed)
            .rememberMe()
            .key("uniqueAndSecret")  // Replace with your secret key
            .tokenValiditySeconds(86400)  // 24 hours validity
            .and()

            // Authorization Requests
            .authorizeRequests()
            .antMatchers("/api/hello").permitAll()
            .antMatchers("/api/user/**").permitAll()
            .antMatchers("/api/secured").authenticated()
            .and()

            // CSRF
            .csrf()
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()) // Storing CSRF tokens in cookies
            .and()

            // Setting HSTS Header, ensure HTTPS and set the session cookie as secure
            .headers()
            .httpStrictTransportSecurity()
            .includeSubDomains(true)
            .maxAgeInSeconds(31536000);  // HSTS for one year
    }


    //@Override
    //protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    //    auth.inMemoryAuthentication()
    //            .withUser("foo").password("{noop}bar").roles("USER");
    //}
}
