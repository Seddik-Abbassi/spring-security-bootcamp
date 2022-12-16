package sdk.amigoscode.springsecuritybootcamp.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import sdk.amigoscode.springsecuritybootcamp.auth.ApplicationUserService;
import sdk.amigoscode.springsecuritybootcamp.jwt.JwtUsernameAndPasswordAuthenticationFilter;

import java.util.concurrent.TimeUnit;

import static sdk.amigoscode.springsecuritybootcamp.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig {

    private final PasswordEncoder passwordEncoder;

    private final ApplicationUserService applicationUserService;

    @Autowired
    public ApplicationSecurityConfig ( PasswordEncoder passwordEncoder , ApplicationUserService applicationUserService ) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain( HttpSecurity http ,AuthenticationConfiguration authenticationConfiguration) throws Exception {
        http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(authenticationConfiguration)))
                .authorizeRequests()
                .antMatchers("/","index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
//                .antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
                .anyRequest()
                .authenticated();
//                .and()
//                .formLogin()
//                .loginPage("/login").permitAll()
//                .defaultSuccessUrl("/courses", true)
//                .and()
//                .rememberMe()
//                .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
//                .key("somethingverysecured")
//                .and()
//                .logout()
//                .logoutUrl("/logout")
//                .clearAuthentication(true)
//                .invalidateHttpSession(true)
//                .deleteCookies("JSESSIONID","remember-me")
//                .logoutSuccessUrl("/login"); // defaults to 2 weeks

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager( AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);

        return provider;
    }


//    @Bean
//    public UserDetailsService userDetailsService() {
//        UserDetails seddikUser = User.builder()
//                .username("seddik")
//                .password(passwordEncoder.encode("pwd"))
////                .roles(STUDENT.name()) // ROLE_STUDENT
//                .authorities(STUDENT.getGrantedAuthorities())
//                .build();
//
//        UserDetails mariemUser = User.builder()
//                .username("mariem")
//                .password(passwordEncoder.encode("pwd123"))
////                .roles(ADMIN.name()) // ROLE_ADMIN
//                .authorities(ADMIN.getGrantedAuthorities())
//                .build();
//
//        UserDetails ghasssenUser = User.builder()
//                .username("ghassen")
//                .password(passwordEncoder.encode("pwd123"))
////                .roles(ADMINTRAINEE.name()) // ROLE_ADMINTRAINEE
//                .authorities(ADMINTRAINEE.getGrantedAuthorities())
//                .build();
//
//        return new InMemoryUserDetailsManager(seddikUser, mariemUser, ghasssenUser);
//    }

}
