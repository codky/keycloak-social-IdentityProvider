package com.nexgrid.keycloaksocialnaver;

import com.fasterxml.jackson.databind.JsonNode;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;

public class NaverIdentityProvider extends AbstractOAuth2IdentityProvider implements SocialIdentityProvider {

    public static final String AUTH_URL = "https://nid.naver.com/oauth2.0/authorize";
    public static final String TOKEN_URL = "https://nid.naver.com/oauth2.0/token";
    public static final String PROFILE_URL = "https://openapi.naver.com/v1/nid/me";
    public static final String DEFAULT_SCOPE = "basic";

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
    protected String getProfileEndpointForValidation(EventBuilder event) { // 네이버 profile Endopoint 주소 반환
        return PROFILE_URL;
    }

    @Override
    protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) { // 네이버 Profile 내용 반환
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
    protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) { // 실제로 네이버에 인증 요청을 하고 토큰을 받아오는 역할, 토큰을 이용해 profile을 가져오는 역할을 수행하는 메소드
        try {
            JsonNode profile = SimpleHttp.doGet(PROFILE_URL, session).param("access_token", accessToken).asJson();

            BrokeredIdentityContext user = extractIdentityFromProfile(null, profile);

            return user;
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not obtain user profile from naver.", e);
        }
    }

    @Override
    protected String getDefaultScopes() { // 네이버 개발가이드에도 나와있듯이 scope 값이 필요 없기 때문에 여기서는 빈 문자열을 반환
        return "";
    }
}
