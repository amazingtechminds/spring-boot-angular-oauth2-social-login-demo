# Spring Boot 2 + Angular 10: User Login, Registration using JWT Authentication and OAuth2 Social Login with Facebook, Google, LinkedIn, and Github using Spring Security 5

[Creating Backend - Spring REST API - Part 1](https://www.javachinna.com/2020/10/23/spring-boot-angular-10-user-registration-oauth2-social-login-part-1/)

[Creating Backend - Spring REST API - Part 2](https://www.javachinna.com/2020/10/23/spring-boot-angular-10-user-registration-oauth2-social-login-part-2/)

[Creating Angular 10 Client Application - Part 3](https://www.javachinna.com/2020/10/28/spring-boot-angular-10-user-registration-oauth2-social-login-part-3/)


How to Build Spring Boot Angular User Registration and OAuth2 Social Login with Facebook, Google, LinkedIn, and Github – Part 1

Post author:Chinna
Post published:October 23, 2020
Post category:Spring Boot
Post comments:8 Comments
Tweet
Share
Share
Pin
0SHARES
Welcome to the Spring Boot OAuth2 Social Login tutorial series. In this series, we are going to learn how to add Social as well as email and password based login to the Angular + Spring Boot application using Spring Security 5 OAuth2 features and JWT token authentication


Table of Contents	
What you’ll build
What you’ll need
Tech Stack
Social Login Configuration
Application Flow
Bootstrap your application
Project Structure
Project Dependencies
Creating JPA Entities
Creating Spring Data JPA Repositories
Creating Service Layer to Access the Repositories
Implementing Spring UserDetailsService
Creating Validators
Creating DTOs
Creating Utility Classes
Creating Custom Exceptions
Creating REST Exception Handler
What’s next?
What you’ll build
Spring Boot REST API with OAuth2 Social Login & JWT Authentication
Angular 10 Client Application to consume the REST API.
Login
Angular Login Page
Register
A
User Home
Angular user home page
Admin Home
Angular admin home page
Admin Profile
Angular Admin Profile Page
What you’ll need
Spring Tool Suite 4
JDK 11
MySQL Server 8
node.js
Tech Stack
Spring Boot 2 and Spring Security 5
Spring Data JPA and Hibernate 5
Angular 10 and Bootstrap 4
Social Login Configuration
You can follow the steps given in this article to configure Google, Facebook, Github, and LinkedIn for Social Login in Your Spring Boot Angular app.


Application Flow
Angular + Spring REST API User Registration, OAuth2 Social Login as well as Email and Password based Login Sequence Diagram
Bootstrap your application
First, we will develop the Spring Boot REST API backend application. You can create your spring boot application with the required dependencies and download it from here


Project Structure
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
44
45
46
47
48
49
50
51
52
53
54
55
56
57
58
59
60
61
62
63
64
65
66
67
68
69
70
71
72
73
74
75
76
77
78
79
80
81
82
83
84
+---pom.xml
|       
+---src
|   \---main
|       +---java
|       |   \---com
|       |       \---javachinna
|       |           |   DemoApplication.java
|       |           |   
|       |           +---config
|       |           |       WebConfig.java
|       |           |       AppProperties.java
|       |           |       CurrentUser.java
|       |           |       RestAuthenticationEntryPoint.java
|       |           |       SetupDataLoader.java
|       |           |       WebSecurityConfig.java
|       |           |       
|       |           +---controller
|       |           |       AuthController.java
|       |           |       UserController.java
|       |           |       
|       |           +---dto
|       |           |       ApiResponse.java
|       |           |       JwtAuthenticationResponse.java
|       |           |       LocalUser.java
|       |           |       LoginRequest.java
|       |           |       SignUpRequest.java
|       |           |       SocialProvider.java
|       |           |       UserInfo.java
|       |           |       
|       |           +---exception
|       |           |   |   BadRequestException.java
|       |           |   |   OAuth2AuthenticationProcessingException.java
|       |           |   |   ResourceNotFoundException.java
|       |           |   |   UserAlreadyExistAuthenticationException.java
|       |           |   |   
|       |           |   \---handler
|       |           |           RestResponseEntityExceptionHandler.java
|       |           |           
|       |           +---model
|       |           |       Role.java
|       |           |       User.java
|       |           |       
|       |           +---repo
|       |           |       RoleRepository.java
|       |           |       UserRepository.java
|       |           |       
|       |           +---security
|       |           |   +---jwt
|       |           |   |       TokenAuthenticationFilter.java
|       |           |   |       TokenProvider.java
|       |           |   |       
|       |           |   \---oauth2
|       |           |       |   CustomOAuth2UserService.java
|       |           |       |   CustomOidcUserService.java
|       |           |       |   HttpCookieOAuth2AuthorizationRequestRepository.java
|       |           |       |   OAuth2AccessTokenResponseConverterWithDefaults.java
|       |           |       |   OAuth2AuthenticationFailureHandler.java
|       |           |       |   OAuth2AuthenticationSuccessHandler.java
|       |           |       |   
|       |           |       \---user
|       |           |               FacebookOAuth2UserInfo.java
|       |           |               GithubOAuth2UserInfo.java
|       |           |               GoogleOAuth2UserInfo.java
|       |           |               LinkedinOAuth2UserInfo.java
|       |           |               OAuth2UserInfo.java
|       |           |               OAuth2UserInfoFactory.java
|       |           |               
|       |           +---service
|       |           |       LocalUserDetailService.java
|       |           |       UserService.java
|       |           |       UserServiceImpl.java
|       |           |       
|       |           +---util
|       |           |       CookieUtils.java
|       |           |       GeneralUtils.java
|       |           |       
|       |           \---validator
|       |                   PasswordMatches.java
|       |                   PasswordMatchesValidator.java
|       |                   
|       \---resources
|               application.properties
|               messages_en.properties

Project Dependencies
pom.xml
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
44
45
46
47
48
49
50
51
52
53
54
55
56
57
58
59
60
61
62
63
64
65
66
67
68
69
70
71
72
73
74
75
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.3.4.RELEASE</version>
        <relativePath /> <!-- lookup parent from repository -->
    </parent>
    <groupId>com.javachinna</groupId>
    <artifactId>demo</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    <name>demo</name>
    <description>Demo project for Spring Boot</description>
 
    <properties>
        <java.version>11</java.version>
    </properties>
 
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-oauth2-client</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-validation</artifactId>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt</artifactId>
            <version>0.9.1</version>
        </dependency>
        <!-- mysql driver -->
        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-devtools</artifactId>
        </dependency>
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-configuration-processor</artifactId>
            <optional>true</optional>
        </dependency>
    </dependencies>
    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>
</project>

Creating JPA Entities
User.java
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
44
45
46
47
48
49
50
51
52
53
54
55
56
57
58
59
60
61
62
63
64
65
66
67
68
69
70
71
package com.javachinna.model;
 
import java.io.Serializable;
import java.util.Date;
import java.util.Set;
 
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
 
import com.fasterxml.jackson.annotation.JsonIgnore;
 
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
 
/**
 * The persistent class for the user database table.
 * 
 */
@Entity
@NoArgsConstructor
@Getter
@Setter
public class User implements Serializable {
 
    /**
     * 
     */
    private static final long serialVersionUID = 65981149772133526L;
 
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "USER_ID")
    private Long id;
 
    @Column(name = "PROVIDER_USER_ID")
    private String providerUserId;
 
    private String email;
 
    @Column(name = "enabled", columnDefinition = "BIT", length = 1)
    private boolean enabled;
 
    @Column(name = "DISPLAY_NAME")
    private String displayName;
 
    @Column(name = "created_date", nullable = false, updatable = false)
    @Temporal(TemporalType.TIMESTAMP)
    protected Date createdDate;
 
    @Temporal(TemporalType.TIMESTAMP)
    protected Date modifiedDate;
 
    private String password;
 
    private String provider;
 
    // bi-directional many-to-many association to Role
    @JsonIgnore
    @ManyToMany
    @JoinTable(name = "user_role", joinColumns = { @JoinColumn(name = "USER_ID") }, inverseJoinColumns = { @JoinColumn(name = "ROLE_ID") })
    private Set<Role> roles;
}
Role.java
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
44
45
46
47
48
49
50
51
52
53
54
55
56
57
58
59
60
61
62
63
64
65
66
67
68
69
70
71
72
73
74
75
76
77
78
79
package com.javachinna.model;
 
import java.io.Serializable;
import java.util.Set;
 
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.ManyToMany;
 
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
 
/**
 * The persistent class for the role database table.
 * 
 */
@Entity
@Getter
@Setter
@NoArgsConstructor
public class Role implements Serializable {
    private static final long serialVersionUID = 1L;
    public static final String USER = "USER";
    public static final String ROLE_USER = "ROLE_USER";
    public static final String ROLE_ADMIN = "ROLE_ADMIN";
    public static final String ROLE_MODERATOR = "ROLE_MODERATOR";
 
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "ROLE_ID")
    private Long roleId;
 
    private String name;
 
    // bi-directional many-to-many association to User
    @ManyToMany(mappedBy = "roles")
    private Set<User> users;
 
    public Role(String name) {
        this.name = name;
    }
 
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        return result;
    }
 
    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final Role role = (Role) obj;
        if (!role.equals(role.name)) {
            return false;
        }
        return true;
    }
 
    @Override
    public String toString() {
        final StringBuilder builder = new StringBuilder();
        builder.append("Role [name=").append(name).append("]").append("[id=").append(roleId).append("]");
        return builder.toString();
    }
}

Creating Spring Data JPA Repositories
UserRepository.java
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
package com.javachinna.repo;
 
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
 
import com.javachinna.model.User;
 
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
 
    User findByEmail(String email);
 
    boolean existsByEmail(String email);
 
}
RoleRepository.java
1
2
3
4
5
6
7
8
9
10
11
12
package com.javachinna.repo;
 
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
 
import com.javachinna.model.Role;
 
@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
 
    Role findByName(String name);
}

Creating Service Layer to Access the Repositories
UserService.java
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
package com.javachinna.service;
 
import java.util.Map;
import java.util.Optional;
 
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
 
import com.javachinna.dto.LocalUser;
import com.javachinna.dto.SignUpRequest;
import com.javachinna.exception.UserAlreadyExistAuthenticationException;
import com.javachinna.model.User;
 
/**
 * @author Chinna
 * @since 26/3/18
 */
public interface UserService {
 
    public User registerNewUser(SignUpRequest signUpRequest) throws UserAlreadyExistAuthenticationException;
 
    User findUserByEmail(String email);
 
    Optional<User> findUserById(Long id);
 
    LocalUser processUserRegistration(String registrationId, Map<String, Object> attributes, OidcIdToken idToken, OidcUserInfo userInfo);
}
UserServiceImpl.java
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
44
45
46
47
48
49
50
51
52
53
54
55
56
57
58
59
60
61
62
63
64
65
66
67
68
69
70
71
72
73
74
75
76
77
78
79
80
81
82
83
84
85
86
87
88
89
90
91
92
93
94
95
96
97
98
99
100
101
102
103
104
105
106
107
108
109
110
111
112
113
114
115
116
117
118
119
120
package com.javachinna.service;
 
import java.util.Calendar;
import java.util.Date;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
 
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
 
import com.javachinna.dto.LocalUser;
import com.javachinna.dto.SignUpRequest;
import com.javachinna.dto.SocialProvider;
import com.javachinna.exception.OAuth2AuthenticationProcessingException;
import com.javachinna.exception.UserAlreadyExistAuthenticationException;
import com.javachinna.model.Role;
import com.javachinna.model.User;
import com.javachinna.repo.RoleRepository;
import com.javachinna.repo.UserRepository;
import com.javachinna.security.oauth2.user.OAuth2UserInfo;
import com.javachinna.security.oauth2.user.OAuth2UserInfoFactory;
import com.javachinna.util.GeneralUtils;
 
/**
 * @author Chinna
 * @since 26/3/18
 */
@Service
public class UserServiceImpl implements UserService {
 
    @Autowired
    private UserRepository userRepository;
 
    @Autowired
    private RoleRepository roleRepository;
 
    @Autowired
    private PasswordEncoder passwordEncoder;
 
    @Override
    @Transactional(value = "transactionManager")
    public User registerNewUser(final SignUpRequest signUpRequest) throws UserAlreadyExistAuthenticationException {
        if (signUpRequest.getUserID() != null && userRepository.existsById(signUpRequest.getUserID())) {
            throw new UserAlreadyExistAuthenticationException("User with User id " + signUpRequest.getUserID() + " already exist");
        } else if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            throw new UserAlreadyExistAuthenticationException("User with email id " + signUpRequest.getEmail() + " already exist");
        }
        User user = buildUser(signUpRequest);
        Date now = Calendar.getInstance().getTime();
        user.setCreatedDate(now);
        user.setModifiedDate(now);
        user = userRepository.save(user);
        userRepository.flush();
        return user;
    }
 
    private User buildUser(final SignUpRequest formDTO) {
        User user = new User();
        user.setDisplayName(formDTO.getDisplayName());
        user.setEmail(formDTO.getEmail());
        user.setPassword(passwordEncoder.encode(formDTO.getPassword()));
        final HashSet<Role> roles = new HashSet<Role>();
        roles.add(roleRepository.findByName(Role.ROLE_USER));
        user.setRoles(roles);
        user.setProvider(formDTO.getSocialProvider().getProviderType());
        user.setEnabled(true);
        user.setProviderUserId(formDTO.getProviderUserId());
        return user;
    }
 
    @Override
    public User findUserByEmail(final String email) {
        return userRepository.findByEmail(email);
    }
 
    @Override
    @Transactional
    public LocalUser processUserRegistration(String registrationId, Map<String, Object> attributes, OidcIdToken idToken, OidcUserInfo userInfo) {
        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(registrationId, attributes);
        if (StringUtils.isEmpty(oAuth2UserInfo.getName())) {
            throw new OAuth2AuthenticationProcessingException("Name not found from OAuth2 provider");
        } else if (StringUtils.isEmpty(oAuth2UserInfo.getEmail())) {
            throw new OAuth2AuthenticationProcessingException("Email not found from OAuth2 provider");
        }
        SignUpRequest userDetails = toUserRegistrationObject(registrationId, oAuth2UserInfo);
        User user = findUserByEmail(oAuth2UserInfo.getEmail());
        if (user != null) {
            if (!user.getProvider().equals(registrationId) && !user.getProvider().equals(SocialProvider.LOCAL.getProviderType())) {
                throw new OAuth2AuthenticationProcessingException(
                        "Looks like you're signed up with " + user.getProvider() + " account. Please use your " + user.getProvider() + " account to login.");
            }
            user = updateExistingUser(user, oAuth2UserInfo);
        } else {
            user = registerNewUser(userDetails);
        }
 
        return LocalUser.create(user, attributes, idToken, userInfo);
    }
 
    private User updateExistingUser(User existingUser, OAuth2UserInfo oAuth2UserInfo) {
        existingUser.setDisplayName(oAuth2UserInfo.getName());
        return userRepository.save(existingUser);
    }
 
    private SignUpRequest toUserRegistrationObject(String registrationId, OAuth2UserInfo oAuth2UserInfo) {
        return SignUpRequest.getBuilder().addProviderUserID(oAuth2UserInfo.getId()).addDisplayName(oAuth2UserInfo.getName()).addEmail(oAuth2UserInfo.getEmail())
                .addSocialProvider(GeneralUtils.toSocialProvider(registrationId)).addPassword("changeit").build();
    }
 
    @Override
    public Optional<User> findUserById(Long id) {
        return userRepository.findById(id);
    }
}
Note: For users who signed up using a social login provider, you can provide a link to reset the password once they logged in. This way they will be able to login using their credentials as well.


Implementing Spring UserDetailsService
LocalUserDetailService.java
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
44
45
46
47
48
package com.javachinna.service;
 
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
 
import com.javachinna.dto.LocalUser;
import com.javachinna.exception.ResourceNotFoundException;
import com.javachinna.model.User;
import com.javachinna.util.GeneralUtils;
 
/**
 * 
 * @author Chinna
 *
 */
@Service("localUserDetailService")
public class LocalUserDetailService implements UserDetailsService {
 
    @Autowired
    private UserService userService;
 
    @Override
    @Transactional
    public LocalUser loadUserByUsername(final String email) throws UsernameNotFoundException {
        User user = userService.findUserByEmail(email);
        if (user == null) {
            throw new UsernameNotFoundException("User " + email + " was not found in the database");
        }
        return createLocalUser(user);
    }
 
    @Transactional
    public LocalUser loadUserById(Long id) {
        User user = userService.findUserById(id).orElseThrow(() -> new ResourceNotFoundException("User", "id", id));
        return createLocalUser(user);
    }
 
    /**
     * @param user
     * @return
     */
    private LocalUser createLocalUser(User user) {
        return new LocalUser(user.getEmail(), user.getPassword(), user.isEnabled(), true, true, true, GeneralUtils.buildSimpleGrantedAuthorities(user.getRoles()), user);
    }
}
Creating Validators
PasswordMatches.java
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
package com.javachinna.validator;
 
import static java.lang.annotation.ElementType.ANNOTATION_TYPE;
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;
 
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;
 
import javax.validation.Constraint;
import javax.validation.Payload;
 
@Target({ TYPE, ANNOTATION_TYPE })
@Retention(RUNTIME)
@Constraint(validatedBy = PasswordMatchesValidator.class)
@Documented
public @interface PasswordMatches {
 
    String message() default "Passwords don't match";
 
    Class<?>[] groups() default {};
 
    Class<? extends Payload>[] payload() default {};
}
PasswordMatchesValidator.java
1
2
3
4
5
6
7
8
9
10
11
12
13
14
package com.javachinna.validator;
 
import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
 
import com.javachinna.dto.SignUpRequest;
 
public class PasswordMatchesValidator implements ConstraintValidator<PasswordMatches, SignUpRequest> {
 
    @Override
    public boolean isValid(final SignUpRequest user, final ConstraintValidatorContext context) {
        return user.getPassword().equals(user.getMatchingPassword());
    }
}

Creating DTOs
ApiResponse.java
1
2
3
4
5
6
7
8
9
package com.javachinna.dto;
 
import lombok.Value;
 
@Value
public class ApiResponse {
    private Boolean success;
    private String message;
}
JwtAuthenticationResponse.java
1
2
3
4
5
6
7
8
9
package com.javachinna.dto;
 
import lombok.Value;
 
@Value
public class JwtAuthenticationResponse {
    private String accessToken;
    private UserInfo user;
}
LocalUser.java
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
44
45
46
47
48
49
50
51
52
53
54
55
56
57
58
59
60
61
62
63
64
65
66
67
68
69
70
71
72
73
74
75
76
77
78
79
80
81
82
83
84
package com.javachinna.dto;
 
import java.util.Collection;
import java.util.Map;
 
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
 
import com.javachinna.util.GeneralUtils;
 
/**
 * 
 * @author Chinna
 *
 */
public class LocalUser extends User implements OAuth2User, OidcUser {
 
    /**
     * 
     */
    private static final long serialVersionUID = -2845160792248762779L;
    private final OidcIdToken idToken;
    private final OidcUserInfo userInfo;
    private Map<String, Object> attributes;
    private com.javachinna.model.User user;
 
    public LocalUser(final String userID, final String password, final boolean enabled, final boolean accountNonExpired, final boolean credentialsNonExpired,
            final boolean accountNonLocked, final Collection<? extends GrantedAuthority> authorities, final com.javachinna.model.User user) {
        this(userID, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities, user, null, null);
    }
 
    public LocalUser(final String userID, final String password, final boolean enabled, final boolean accountNonExpired, final boolean credentialsNonExpired,
            final boolean accountNonLocked, final Collection<? extends GrantedAuthority> authorities, final com.javachinna.model.User user, OidcIdToken idToken,
            OidcUserInfo userInfo) {
        super(userID, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
        this.user = user;
        this.idToken = idToken;
        this.userInfo = userInfo;
    }
 
    public static LocalUser create(com.javachinna.model.User user, Map<String, Object> attributes, OidcIdToken idToken, OidcUserInfo userInfo) {
        LocalUser localUser = new LocalUser(user.getEmail(), user.getPassword(), user.isEnabled(), true, true, true, GeneralUtils.buildSimpleGrantedAuthorities(user.getRoles()),
                user, idToken, userInfo);
        localUser.setAttributes(attributes);
        return localUser;
    }
 
    public void setAttributes(Map<String, Object> attributes) {
        this.attributes = attributes;
    }
 
    @Override
    public String getName() {
        return this.user.getDisplayName();
    }
 
    @Override
    public Map<String, Object> getAttributes() {
        return this.attributes;
    }
 
    @Override
    public Map<String, Object> getClaims() {
        return this.attributes;
    }
 
    @Override
    public OidcUserInfo getUserInfo() {
        return this.userInfo;
    }
 
    @Override
    public OidcIdToken getIdToken() {
        return this.idToken;
    }
 
    public com.javachinna.model.User getUser() {
        return user;
    }
}

LoginRequest.java
1
2
3
4
5
6
7
8
9
10
11
12
13
14
package com.javachinna.dto;
 
import javax.validation.constraints.NotBlank;
 
import lombok.Data;
 
@Data
public class LoginRequest {
    @NotBlank
    private String email;
 
    @NotBlank
    private String password;
}
SignUpRequest.java
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
44
45
46
47
48
49
50
51
52
53
54
55
56
57
58
59
60
61
62
63
64
65
66
67
68
69
70
71
72
73
74
75
76
77
78
79
80
81
82
83
84
package com.javachinna.dto;
 
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.Size;
 
import com.javachinna.validator.PasswordMatches;
 
import lombok.Data;
 
/**
 * @author Chinna
 * @since 26/3/18
 */
@Data
@PasswordMatches
public class SignUpRequest {
 
    private Long userID;
 
    private String providerUserId;
 
    @NotEmpty
    private String displayName;
 
    @NotEmpty
    private String email;
 
    private SocialProvider socialProvider;
 
    @Size(min = 6, message = "{Size.userDto.password}")
    private String password;
 
    @NotEmpty
    private String matchingPassword;
 
    public SignUpRequest(String providerUserId, String displayName, String email, String password, SocialProvider socialProvider) {
        this.providerUserId = providerUserId;
        this.displayName = displayName;
        this.email = email;
        this.password = password;
        this.socialProvider = socialProvider;
    }
 
    public static Builder getBuilder() {
        return new Builder();
    }
 
    public static class Builder {
        private String providerUserID;
        private String displayName;
        private String email;
        private String password;
        private SocialProvider socialProvider;
 
        public Builder addProviderUserID(final String userID) {
            this.providerUserID = userID;
            return this;
        }
 
        public Builder addDisplayName(final String displayName) {
            this.displayName = displayName;
            return this;
        }
 
        public Builder addEmail(final String email) {
            this.email = email;
            return this;
        }
 
        public Builder addPassword(final String password) {
            this.password = password;
            return this;
        }
 
        public Builder addSocialProvider(final SocialProvider socialProvider) {
            this.socialProvider = socialProvider;
            return this;
        }
 
        public SignUpRequest build() {
            return new SignUpRequest(providerUserID, displayName, email, password, socialProvider);
        }
    }
}

SocialProvider.java
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
package com.javachinna.dto;
 
/**
 * @author Chinna
 * @since 26/3/18
 */
public enum SocialProvider {
 
    FACEBOOK("facebook"), TWITTER("twitter"), LINKEDIN("linkedin"), GOOGLE("google"), GITHUB("github"), LOCAL("local");
 
    private String providerType;
 
    public String getProviderType() {
        return providerType;
    }
 
    SocialProvider(final String providerType) {
        this.providerType = providerType;
    }
}
UserInfo.java
1
2
3
4
5
6
7
8
9
10
11
package com.javachinna.dto;
 
import java.util.List;
 
import lombok.Value;
 
@Value
public class UserInfo {
    private String id, displayName, email;
    private List<String> roles;
}

Creating Utility Classes
GeneralUtils.java
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
44
45
package com.javachinna.util;
 
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
 
import org.springframework.security.core.authority.SimpleGrantedAuthority;
 
import com.javachinna.dto.LocalUser;
import com.javachinna.dto.SocialProvider;
import com.javachinna.dto.UserInfo;
import com.javachinna.model.Role;
import com.javachinna.model.User;
 
/**
 * 
 * @author Chinna
 *
 */
public class GeneralUtils {
 
    public static List<SimpleGrantedAuthority> buildSimpleGrantedAuthorities(final Set<Role> roles) {
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        for (Role role : roles) {
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        }
        return authorities;
    }
 
    public static SocialProvider toSocialProvider(String providerId) {
        for (SocialProvider socialProvider : SocialProvider.values()) {
            if (socialProvider.getProviderType().equals(providerId)) {
                return socialProvider;
            }
        }
        return SocialProvider.LOCAL;
    }
 
    public static UserInfo buildUserInfo(LocalUser localUser) {
        List<String> roles = localUser.getAuthorities().stream().map(item -> item.getAuthority()).collect(Collectors.toList());
        User user = localUser.getUser();
        return new UserInfo(user.getId().toString(), user.getDisplayName(), user.getEmail(), roles);
    }
}
CookieUtils.java
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
44
45
46
47
48
49
50
51
52
53
54
55
56
57
package com.javachinna.util;
 
import java.util.Base64;
import java.util.Optional;
 
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
 
import org.springframework.util.SerializationUtils;
 
public class CookieUtils {
 
    public static Optional<Cookie> getCookie(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
 
        if (cookies != null && cookies.length > 0) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(name)) {
                    return Optional.of(cookie);
                }
            }
        }
 
        return Optional.empty();
    }
 
    public static void addCookie(HttpServletResponse response, String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(maxAge);
        response.addCookie(cookie);
    }
 
    public static void deleteCookie(HttpServletRequest request, HttpServletResponse response, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null && cookies.length > 0) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(name)) {
                    cookie.setValue("");
                    cookie.setPath("/");
                    cookie.setMaxAge(0);
                    response.addCookie(cookie);
                }
            }
        }
    }
 
    public static String serialize(Object object) {
        return Base64.getUrlEncoder().encodeToString(SerializationUtils.serialize(object));
    }
 
    public static <T> T deserialize(Cookie cookie, Class<T> cls) {
        return cls.cast(SerializationUtils.deserialize(Base64.getUrlDecoder().decode(cookie.getValue())));
    }
}

Creating Custom Exceptions
BadRequestException.java
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
package com.javachinna.exception;
 
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;
 
@ResponseStatus(HttpStatus.BAD_REQUEST)
public class BadRequestException extends RuntimeException {
    private static final long serialVersionUID = 752858877580882829L;
 
    public BadRequestException(String message) {
        super(message);
    }
 
    public BadRequestException(String message, Throwable cause) {
        super(message, cause);
    }
}

OAuth2AuthenticationProcessingException.java
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
package com.javachinna.exception;
 
import org.springframework.security.core.AuthenticationException;
 
public class OAuth2AuthenticationProcessingException extends AuthenticationException {
    private static final long serialVersionUID = 3392450042101522832L;
 
    public OAuth2AuthenticationProcessingException(String msg, Throwable t) {
        super(msg, t);
    }
 
    public OAuth2AuthenticationProcessingException(String msg) {
        super(msg);
    }
}
ResourceNotFoundException.java
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
package com.javachinna.exception;
 
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;
 
import lombok.Getter;
 
@Getter
@ResponseStatus(HttpStatus.NOT_FOUND)
public class ResourceNotFoundException extends RuntimeException {
    private static final long serialVersionUID = 7004203416628447047L;
    private String resourceName;
    private String fieldName;
    private Object fieldValue;
 
    public ResourceNotFoundException(String resourceName, String fieldName, Object fieldValue) {
        super(String.format("%s not found with %s : '%s'", resourceName, fieldName, fieldValue));
        this.resourceName = resourceName;
        this.fieldName = fieldName;
        this.fieldValue = fieldValue;
    }
}
UserAlreadyExistAuthenticationException.java
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
package com.javachinna.exception;
 
import org.springframework.security.core.AuthenticationException;
 
/**
 * 
 * @author Chinna
 *
 */
public class UserAlreadyExistAuthenticationException extends AuthenticationException {
 
    private static final long serialVersionUID = 5570981880007077317L;
 
    public UserAlreadyExistAuthenticationException(final String msg) {
        super(msg);
    }
 
}

Creating REST Exception Handler
ResponseEntityExceptionHandler provides centralized exception handling across all @RequestMapping methods through @ExceptionHandler methods.

RestResponseEntityExceptionHandler extends ResponseEntityExceptionHandler and overrides handleMethodArgumentNotValid method to provide a detailed error message with all the validation errors in the response.

RestResponseEntityExceptionHandler.java
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
package com.javachinna.exception.handler;
 
import java.util.stream.Collectors;
 
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;
 
import com.javachinna.dto.ApiResponse;
 
@ControllerAdvice
public class RestResponseEntityExceptionHandler extends ResponseEntityExceptionHandler {
 
    public RestResponseEntityExceptionHandler() {
        super();
    }
 
    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(final MethodArgumentNotValidException ex, final HttpHeaders headers, final HttpStatus status,
            final WebRequest request) {
        logger.error("400 Status Code", ex);
        final BindingResult result = ex.getBindingResult();
 
        String error = result.getAllErrors().stream().map(e -> {
            if (e instanceof FieldError) {
                return ((FieldError) e).getField() + " : " + e.getDefaultMessage();
            } else {
                return e.getObjectName() + " : " + e.getDefaultMessage();
            }
        }).collect(Collectors.joining(", "));
        return handleExceptionInternal(ex, new ApiResponse(false, error), new HttpHeaders(), HttpStatus.BAD_REQUEST, request);
    }
}

What’s next?
In this article, we have created entities, repositories, services, validators, DTOs, custom exceptions, and exception handler. In the next article, we’ll configure Spring Security OAuth2 Social Login and JWT authentication
