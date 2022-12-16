package sdk.amigoscode.springsecuritybootcamp.auth;

import com.google.common.collect.Lists;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;
import sdk.amigoscode.springsecuritybootcamp.security.ApplicationUserRole;

import java.util.List;
import java.util.Optional;

@Repository("fake")
@AllArgsConstructor
public class FakeApplicationUserDaoService implements ApplicationUserDao {

    @Autowired
    private final PasswordEncoder passwordEncoder;

    @Override
    public Optional < ApplicationUser > selectApplicationUserByUsername ( String username ) {
        return getApplicationUsers().stream()
                .filter(applicationUser -> applicationUser.getUsername().equals(username))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers() {
        return Lists.newArrayList(
                  new ApplicationUser(
                          "seddik",
                          passwordEncoder.encode("pwd"),
                          ApplicationUserRole.STUDENT.getGrantedAuthorities(),
                          true,
                          true,
                          true,
                          true
                  ),
                new ApplicationUser(
                        "mariem",
                        passwordEncoder.encode("pwd"),
                        ApplicationUserRole.ADMIN.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser(
                        "ghassen",
                        passwordEncoder.encode("pwd"),
                        ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true
                )
        );
    }
}
