package sdk.amigoscode.springsecuritybootcamp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import sdk.amigoscode.springsecuritybootcamp.jwt.JwtConfig;

@SpringBootApplication
@EnableConfigurationProperties(JwtConfig.class)
public class SpringSecurityBootcampApplication {

    public static void main ( String[] args ) {
        SpringApplication.run(SpringSecurityBootcampApplication.class , args);
    }

}
