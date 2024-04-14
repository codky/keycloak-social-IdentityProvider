![image](https://github.com/codky/keycloak-social-IdentityProvider/assets/61862366/110c0140-f3d8-40ed-a6e1-2cad833fbae6)


Keycloak 은 OIDC를 지원하는 다양한 소셜 로그인들을 지원합니다. (Configure - Identity Providers )

하지만 네이버, 카카오등 필요한 소셜 로그인을 지원하지 않기때문에 직접 연결해줘야합니다.

프로젝트 구조

![image](https://github.com/codky/keycloak-social-IdentityProvider/assets/61862366/54154c4a-c3e5-498e-b970-2f7988eb76aa)


Gradle Dependency

```
plugins{
id 'java'
    id 'war'
    id 'org.springframework.boot' version '2.7.5'
    id 'io.spring.dependency-management' version '1.0.15.RELEASE'
}

group = 'com.nexgrid'
version = '0.0.1-SNAPSHOT'
description = 'Identity Provider - Naver'
sourceCompatibility = '11'

repositories{
mavenCentral()
}

dependencies{
		compileOnly 'org.keycloak:keycloak-services:13.0.0'
    compileOnly 'org.keycloak:keycloak-server-spi:13.0.0'
    compileOnly 'org.keycloak:keycloak-server-spi-private:13.0.0'
}
```

NaverIdentityProvider.class

```java
public class NaverIdentityProvider extends AbstractOAuth2IdentityProvider implements SocialIdentityProvider {

    public static final StringAUTH_URL= "https://nid.naver.com/oauth2.0/authorize";
    public static final StringTOKEN_URL= "https://nid.naver.com/oauth2.0/token";
    public static final StringPROFILE_URL= "https://openapi.naver.com/v1/nid/me";
    public static final StringDEFAULT_SCOPE= "basic";

    public NaverIdentityProvider(KeycloakSession session, OAuth2IdentityProviderConfig config) {
        super(session, config);
        config.setAuthorizationUrl(AUTH_URL);
        config.setTokenUrl(TOKEN_URL);
        config.setUserInfoUrl(PROFILE_URL);
    }

    @Override
    protected boolean supportsExternalExchange() {
        return true;
    }

    @Override
    protected String getProfileEndpointForValidation(EventBuilder event) {
        returnPROFILE_URL;
    }

    @Override
    protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {
        BrokeredIdentityContext user = new BrokeredIdentityContext(profile.get("response").get("id").asText());

        String email = profile.get("response").get("email").asText();

        user.setIdpConfig(getConfig());
        user.setUsername(email);
        user.setEmail(email);
        user.setIdp(this);

        AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());

        return user;
    }

    @Override
    protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
        try {
            JsonNode profile = SimpleHttp.doGet(PROFILE_URL, session).param("access_token", accessToken).asJson();

            BrokeredIdentityContext user = extractIdentityFromProfile(null, profile);

            return user;
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not obtain user profile from naver.", e);
        }
    }

    @Override
    protected String getDefaultScopes() {
        return "";
    }
}
```

`getProfileEndpointForValidation` : `네이버 profile Endopoint 주소 반환`

`extractIdentityFromProfile` : `네이버 Profile 내용 반환`

`doGetFederatedIdentity` : `실제로 네이버에 인증 요청을 하고 토큰을 받아오는 역할, 토큰을 이용해 profile을 가져오는 역할을 수행하는 메소드`

`getDefaultScopes` : `네이버 개발가이드에도 나와있듯이 scope 값이 필요 없기 때문에 여기서는 빈 문자열을 반환`

NaverIdentityProviderFactory.class : `Id 값을 넣어주고 Provider를 생성해줍니다.`

```java
public class NaverIdentityProviderFactory extends AbstractIdentityProviderFactory<NaverIdentityProvider> implements SocialIdentityProviderFactory<NaverIdentityProvider> {

    public static final StringPROVIDER_ID= "naver";

    @Override
    public String getName() {
        return "Naver";
    }

    @Override
    public NaverIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new NaverIdentityProvider(session, new OAuth2IdentityProviderConfig(model));
    }

    @Override
    public OAuth2IdentityProviderConfig createConfig() {
        return new OAuth2IdentityProviderConfig();
    }

    @Override
    public String getId() {
        returnPROVIDER_ID;
    }
}
```

NaverUserAttributeMapper.class

```java
public class NaverUserAttributeMapper extends AbstractJsonUserAttributeMapper {

    private static final String[]cp= new String[] { NaverIdentityProviderFactory.PROVIDER_ID};

    @Override
    public String[] getCompatibleProviders() {
        returncp;
    }

    @Override
    public String getId() {
        return "naver-user-attribute-mapper";
    }
}
```

resources/META-INF/services

org.keycloak.broker.provider.IdentityProviderMapper

 `com.nexgrid.keycloaksocialnaver.NaverUserAttributeMapper`

org.keycloak.broker.social.SocialIdentityProviderFactory

 `com.nexgrid.keycloaksocialnaver.NaverIdentityProviderFactory`

jboss-deployment-structure.xml

```java
<?xml version="1.0" encoding="UTF-8"?>
<jboss-deployment-structure xmlns="urn:jboss:deployment-structure:1.2">
  <deployment>
    <dependencies>
      <module name="org.keycloak.keycloak-services"/>
      <module name="org.keycloak.keycloak-server-spi"/>
      <module name="org.keycloak.keycloak-server-spi-private"/>
    </dependencies>
  </deployment>
</jboss-deployment-structure>
```

src 와 같은 레벨에 resources/keycloak/themes/base/admin/resources/partials 디렉토리가 있습니다.

realm-identity-provider-naver.html

 `<div data-ng-include data-src="resourceUrl + '/partials/realm-identity-provider-social.html'"></div>`

realm-identity-provider-naver-ext.html(값없음)

위의 html 파일들은 아래의 Naver Identity Providers 의 Client 정보를 등록하는 화면입니다.

![image](https://github.com/codky/keycloak-social-IdentityProvider/assets/61862366/fd9d516e-5a1e-4dba-a617-3feee509ea96)



html 파일 두개를 {keycloak 설치경로}\themes\base\admin\resources\partials\ 에 넣어줘야합니다.

![image](https://github.com/codky/keycloak-social-IdentityProvider/assets/61862366/f0bf1583-4ad5-4eb8-80dc-17bd0eeca40a)



프로젝트 빌드를 하고(예제 프로젝트는 Gradle 입니다.) build 디렉토리 아래에 생성된 jar 를

{keyclaok 설치경로}\standalone\deployments\ 에 넣어줍니다.

![image](https://github.com/codky/keycloak-social-IdentityProvider/assets/61862366/66ffc4cb-973c-4794-ae93-254719d1c97d)



Keycloak 서버를 재실행하고 대시보드로 접속해서 Identity Provider를 보시면  Naver 가 생성된것을 볼 수 있습니다.

![image](https://github.com/codky/keycloak-social-IdentityProvider/assets/61862366/f22fed03-b1fb-4938-9a1d-848ddba81e09)



네이버 Client ID, Client Secret 을 입력해줍니다.

![image](https://github.com/codky/keycloak-social-IdentityProvider/assets/61862366/2aff8c85-8a9e-4c2b-a15d-f7f3ef4b7803)



네이버 개발자 콘솔에서 Callback URL 을 등록해줍니다.

![image](https://github.com/codky/keycloak-social-IdentityProvider/assets/61862366/f49574e7-3cc4-418c-81f1-3019c35ee6c3)



이제 정상적으로 네이버 로그인이 되는지 접속해보겠습니다.

인증된 사용자만 볼수있는 리소스에 접근해보겠습니다.

로그인창 하단에 Naver 가 생겼습니다.

![image](https://github.com/codky/keycloak-social-IdentityProvider/assets/61862366/67a65134-ed0f-44be-a0ca-fdac247bde99)

![image](https://github.com/codky/keycloak-social-IdentityProvider/assets/61862366/0701105a-eea8-4bf0-b615-528c6db30c97)



네이버 로그인을 하면  계정 정보 업데이트 폼이 뜹니다. 

처음 로그인하는 유저일 경우 가입절차입니다.

정보를 입력합니다.

![image](https://github.com/codky/keycloak-social-IdentityProvider/assets/61862366/402fa45f-f8fe-48fc-a45d-56fa5fe95b07)



인증이 정상적으로 처리되고 인증된 리소스를 확인할수 있습니다.

![image](https://github.com/codky/keycloak-social-IdentityProvider/assets/61862366/828dfd62-e07e-4389-8a28-c06cfde4939a)



데이터베이스에도 자동으로 등록된 것을 확인할 수 있습니다.

(gbc5011@naver.com, min-seok kyeon)


유저정보에도 등록되어있습니다. (Manage - Users)

![image](https://github.com/codky/keycloak-social-IdentityProvider/assets/61862366/9857c697-36ca-4dfe-8782-f6cc0b1cec47)


세션에서도 확인가능합니다. (Manage - Sessions)

![image](https://github.com/codky/keycloak-social-IdentityProvider/assets/61862366/c2113932-7f8d-4034-b6cf-f84a4a7cac48)


참고: https://github.com/danny8376/keycloak-social-baidu

참고: https://subji.github.io/posts/2020/07/24/keycloak4
