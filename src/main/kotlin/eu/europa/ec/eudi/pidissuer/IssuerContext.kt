/*
 * Copyright (c) 2023-2026 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.pidissuer

import arrow.core.*
import com.nimbusds.jose.CompressionAlgorithm
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.*
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.Base64
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPProtectedResourceRequestVerifier
import com.nimbusds.oauth2.sdk.dpop.verifiers.DefaultDPoPSingleUseChecker
import com.nimbusds.oauth2.sdk.id.Issuer
import com.nimbusds.oauth2.sdk.util.X509CertificateUtils
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import eu.europa.ec.eudi.pidissuer.adapter.input.web.IssuerApi
import eu.europa.ec.eudi.pidissuer.adapter.input.web.IssuerUi
import eu.europa.ec.eudi.pidissuer.adapter.input.web.MetaDataApi
import eu.europa.ec.eudi.pidissuer.adapter.input.web.WalletApi
import eu.europa.ec.eudi.pidissuer.adapter.input.web.security.*
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.credential.*
import eu.europa.ec.eudi.pidissuer.adapter.out.generalcredential.CredentialIssuanceOverrides
import eu.europa.ec.eudi.pidissuer.adapter.out.generalcredential.CredentialStyle
import eu.europa.ec.eudi.pidissuer.adapter.out.generalcredential.CredentialSchemaLoader
import eu.europa.ec.eudi.pidissuer.adapter.out.generalcredential.CredentialSchemaSource
import eu.europa.ec.eudi.pidissuer.adapter.out.generalcredential.ForestIssuanceBindingClient
import eu.europa.ec.eudi.pidissuer.adapter.out.generalcredential.GetGeneralCredentialFromBinding
import eu.europa.ec.eudi.pidissuer.adapter.out.generalcredential.IssueGeneralCredentialSdJwtVc
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.*
import eu.europa.ec.eudi.pidissuer.adapter.out.persistence.InMemoryDeferredCredentialRepository
import eu.europa.ec.eudi.pidissuer.adapter.out.persistence.InMemoryIssuedCredentialRepository
import eu.europa.ec.eudi.pidissuer.adapter.out.pid.*
import eu.europa.ec.eudi.pidissuer.adapter.out.qr.DefaultGenerateQrCode
import eu.europa.ec.eudi.pidissuer.adapter.out.status.GenerateStatusListTokenWithExternalService
import eu.europa.ec.eudi.pidissuer.adapter.out.trust.Ignored
import eu.europa.ec.eudi.pidissuer.adapter.out.trust.usingTrustValidatorService
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.*
import eu.europa.ec.eudi.pidissuer.port.out.asDeferred
import eu.europa.ec.eudi.pidissuer.port.out.jose.GenerateSignedMetadata
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateTransactionId
import eu.europa.ec.eudi.pidissuer.port.out.status.GenerateStatusListToken
import eu.europa.ec.eudi.pidissuer.port.out.trust.IsTrustedKeyAttestationIssuer
import eu.europa.ec.eudi.sdjwt.HashAlgorithm
import eu.europa.ec.eudi.sdjwt.vc.Vct
import io.ktor.http.*
import io.netty.handler.ssl.SslContextBuilder
import io.netty.handler.ssl.util.InsecureTrustManagerFactory
import kotlinx.coroutines.reactor.awaitSingle
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.BeanRegistrarDsl
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.http.codec.CodecCustomizer
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.OAuth2ResourceServerProperties
import org.springframework.core.env.Environment
import org.springframework.core.env.getProperty
import org.springframework.core.env.getRequiredProperty
import org.springframework.core.io.DefaultResourceLoader
import org.springframework.core.io.FileSystemResource
import org.springframework.core.io.Resource
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.client.reactive.ReactorClientHttpConnector
import org.springframework.http.codec.json.KotlinSerializationJsonDecoder
import org.springframework.http.codec.json.KotlinSerializationJsonEncoder
import org.springframework.security.config.web.server.SecurityWebFiltersOrder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.config.web.server.invoke
import org.springframework.security.oauth2.server.resource.authentication.OpaqueTokenReactiveAuthenticationManager
import org.springframework.security.oauth2.server.resource.introspection.SpringReactiveOpaqueTokenIntrospector
import org.springframework.security.oauth2.server.resource.web.access.server.BearerTokenServerAccessDeniedHandler
import org.springframework.security.oauth2.server.resource.web.server.BearerTokenServerAuthenticationEntryPoint
import org.springframework.security.oauth2.server.resource.web.server.authentication.ServerBearerTokenAuthenticationConverter
import org.springframework.security.web.server.DelegatingServerAuthenticationEntryPoint
import org.springframework.security.web.server.authentication.AuthenticationConverterServerWebExchangeMatcher
import org.springframework.security.web.server.authentication.AuthenticationWebFilter
import org.springframework.security.web.server.authentication.HttpStatusServerEntryPoint
import org.springframework.security.web.server.authentication.ServerAuthenticationEntryPointFailureHandler
import org.springframework.security.web.server.authorization.HttpStatusServerAccessDeniedHandler
import org.springframework.security.web.server.authorization.ServerWebExchangeDelegatingServerAccessDeniedHandler
import org.springframework.util.unit.DataSize
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.bodyToMono
import org.springframework.web.server.WebFilter
import org.springframework.web.util.UriComponentsBuilder
import reactor.netty.http.client.HttpClient
import reactor.netty.transport.ProxyProvider
import java.net.URI
import java.net.URL
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.*
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
import kotlin.time.toJavaDuration

private val log = LoggerFactory.getLogger(PidIssuerApplication::class.java)

/**
 * [WebClient] instances for usage within the application.
 */
internal object WebClients {

    /**
     * A [WebClient] with [Json] serialization enabled.
     */
    fun default(proxy: HttpProxy?): WebClient {
        val httpClient = httpClient(proxy)
        val connector = ReactorClientHttpConnector(httpClient)
        return WebClient
            .builder()
            .clientConnector(connector)
            .configureCodecs()
            .build()
    }

    /**
     * A [WebClient] with [Json] serialization enabled that trusts *all* certificates.
     */
    fun insecure(proxy: HttpProxy?): WebClient {
        log.warn("Using insecure WebClient trusting all certificates")
        val sslContext = SslContextBuilder.forClient()
            .trustManager(InsecureTrustManagerFactory.INSTANCE)
            .build()
        val httpClient = httpClient(proxy).secure { it.sslContext(sslContext) }
        val connector = ReactorClientHttpConnector(httpClient)
        return WebClient.builder()
            .clientConnector(connector)
            .configureCodecs()
            .build()
    }

    private fun httpClient(proxy: HttpProxy? = null): HttpClient {
        if (proxy == null) {
            return HttpClient.create()
        }
        return HttpClient.create().proxy { proxyProvider ->
            log.info("Using WebClient with proxy settings")
            proxyProvider.type(ProxyProvider.Proxy.HTTP)
                .host(proxy.url.host)
                .port(proxy.url.port)
                .apply {
                    proxy.username?.let {
                        username(it)
                        password { proxy.password ?: "" }
                    }
                }
        }
    }

    private fun WebClient.Builder.configureCodecs(): WebClient.Builder {
        val json = Json { ignoreUnknownKeys = true }

        return codecs {
            it.defaultCodecs().kotlinSerializationJsonDecoder(KotlinSerializationJsonDecoder(json))
            it.defaultCodecs().kotlinSerializationJsonEncoder(KotlinSerializationJsonEncoder(json))
            it.defaultCodecs().enableLoggingRequestDetails(true)
        }
    }
}

data class HttpProxy(
    val url: Url,
    val username: String? = null,
    val password: String? = null,
) {
    init {
        require(password == null || username != null) {
            "Password cannot be set if username is null"
        }
        require(url.protocol == URLProtocol.HTTP) {
            "Url should be Http"
        }
        require(url.encodedPathAndQuery.isBlank()) {
            "No path or query params should be present in the Url"
        }
        require(url.fragment.isEmpty()) {
            "No fragment should be present in the Url"
        }
    }
}

private const val keystoreDefaultLocation = "/keystore.jks"

fun beans(clock: Clock) = BeanRegistrarDsl {
    val issuerPublicUrl = env.readRequiredUrl("issuer.publicUrl", removeTrailingSlash = true)
    val enableMsoMdocPid = env.getProperty<Boolean>("issuer.pid.mso_mdoc.enabled") ?: true
    val enableSdJwtVcPid = env.getProperty<Boolean>("issuer.pid.sd_jwt_vc.enabled") ?: true
    val credentialsOfferUri = env.getRequiredProperty("issuer.credentialOffer.uri")
    val enableStatusList = env.getProperty<Boolean>("issuer.statusList.enabled") ?: false
    val trustValidatorServiceUrl = env.getProperty<String>("issuer.trust.service-url")

    val issuerKeystore: KeyStore by lazy {
        val keystoreLocation = env.getRequiredProperty("issuer.keystore.file")
        log.info("Will try to load Keystore from: '{}'", keystoreLocation)
        val keystoreResource = DefaultResourceLoader().getResource(keystoreLocation).some()
            .filter { it.exists() }
            .recover {
                log.warn(
                    "Could not find Keystore at '{}'. Fallback to '{}'",
                    keystoreLocation,
                    keystoreDefaultLocation,
                )
                FileSystemResource(keystoreDefaultLocation).some()
                    .filter { it.exists() }
                    .bind()
            }
            .getOrNull()
        checkNotNull(keystoreResource) { "Could not load Keystore either from '$keystoreLocation' or '$keystoreDefaultLocation'" }

        val keystoreType = env.getProperty("issuer.keystore.type", KeyStore.getDefaultType())
        val keystorePassword = env.getProperty("issuer.keystore.password")?.takeIf { it.isNotBlank() }

        keystoreResource.inputStream.use { inputStream ->
            val keystore = KeyStore.getInstance(keystoreType)
            keystore.load(inputStream, keystorePassword?.toCharArray())
            keystore
        }
    }

    fun getIssuerSigningKey(prefix: String): IssuerSigningKey {
        val signingKey = when (env.getProperty<KeyOption>(prefix)) {
            null, KeyOption.GenerateRandom -> {
                log.info("Generating random signing key and self-signed certificate for '$prefix'")
                val key = ECKeyGenerator(Curve.P_256).keyID("issuer-kid-$prefix").generate()
                val certificate = X509CertificateUtils.generateSelfSigned(
                    Issuer(issuerPublicUrl.value.host),
                    clock.now().toJavaDate(),
                    (clock.now() + 365.days).toJavaDate(),
                    key.toECPublicKey(),
                    key.toECPrivateKey(),
                )
                ECKey.Builder(key)
                    .x509CertChain(listOf(Base64.encode(certificate.encoded)))
                    .build()
            }

            KeyOption.LoadFromKeystore -> {
                log.info("Loading signing key and certificate for issuance from keystore for '$prefix'")
                issuerKeystore.loadJwk(env, prefix)
            }
        }
        require(signingKey is ECKey) { "Only ECKeys are supported for signing" }
        return IssuerSigningKey(signingKey)
    }

    fun credentialRequestEncryption(): CredentialRequestEncryption {
        val isSupported = env.getProperty<Boolean>("issuer.credentialRequestEncryption.supported") ?: false
        return if (!isSupported) {
            CredentialRequestEncryption.NotSupported
        } else {
            val key = when (env.getProperty<KeyOption>("issuer.credentialRequestEncryption.jwks")) {
                null, KeyOption.GenerateRandom -> {
                    log.info("Generating random encryption key for Credential Request Encryption")
                    ECKeyGenerator(Curve.P_256)
                        .keyID(UUID.randomUUID().toString())
                        .keyUse(KeyUse.ENCRYPTION)
                        .algorithm(JWEAlgorithm.ECDH_ES)
                        .generate()
                }
                KeyOption.LoadFromKeystore -> {
                    log.info("Loading encryption key for Credential Request Encryption from keystore")
                    val keyAlgorithm = env.getProperty<String>("issuer.credentialRequestEncryption.jwks.algorithm")?.let {
                        JWEAlgorithm.parse(it)
                    } ?: error("Missing or invalid 'issuer.credentialRequestEncryption.jwks.algorithm' property")

                    when (val loadedJwk = issuerKeystore.loadJwk(env, "issuer.credentialRequestEncryption.jwks")) {
                        is ECKey -> {
                            require(keyAlgorithm in loadedJwk.supportedJWEAlgorithms) {
                                "${keyAlgorithm.name} cannot be used with an ECKey"
                            }
                            ECKey.Builder(loadedJwk).algorithm(keyAlgorithm).build()
                        }
                        is RSAKey -> {
                            require(keyAlgorithm in loadedJwk.supportedJWEAlgorithms) {
                                "${keyAlgorithm.name} cannot be used with an RSAKey"
                            }
                            RSAKey.Builder(loadedJwk).algorithm(keyAlgorithm).build()
                        }
                        else -> error("unsupported key type '${loadedJwk.javaClass}'")
                    }
                }
            }

            val encryptionMethods = env.readNonEmptySet(
                "issuer.credentialRequestEncryption.encryptionMethods",
                EncryptionMethod::parse,
            )
            require(key.supportedEncryptionMethods.containsAll(encryptionMethods)) {
                "Encryption methods: ${encryptionMethods.joinToString { it.name }} cannot be used with the configured encryption key"
            }

            val parameters = CredentialRequestEncryptionSupportedParameters(
                encryptionKeys = JWKSet(key),
                methodsSupported = encryptionMethods,
                zipAlgorithmsSupported = env.readNullableNonEmptySet(
                    "issuer.credentialRequestEncryption.zipAlgorithmsSupported",
                ) { algorithm -> algorithm.takeIf { it.isNotBlank() }?.let { CompressionAlgorithm(it) } },
            )
            val isRequired = env.getProperty<Boolean>("issuer.credentialRequestEncryption.required") ?: false
            if (!isRequired) {
                CredentialRequestEncryption.Optional(parameters)
            } else {
                CredentialRequestEncryption.Required(parameters)
            }
        }
    }

    //
    // Nonce encryption key
    //
    val nonceEncryptionKey = run {
        val encryptionKey: ECKey = when (env.getProperty<KeyOption>("issuer.nonce.encryption-key")) {
            null, KeyOption.GenerateRandom -> {
                log.info("Generating random encryption key for Nonce")
                ECKeyGenerator(Curve.P_256).keyUse(KeyUse.ENCRYPTION).generate()
            }

            KeyOption.LoadFromKeystore -> {
                log.info("Loading Nonce encryption key from keystore")
                val nonceEncryptionKey = issuerKeystore.loadJwk(env, "issuer.nonce.encryption-key")
                require(nonceEncryptionKey is ECKey) { "Only ECKey are supported for encryption" }
                nonceEncryptionKey
            }
        }
        NonceEncryptionKey(encryptionKey)
    }

    //
    // Signed metadata signing key
    //
    registerBean(lazyInit = true) {
        val key = when (env.getProperty<KeyOption>("issuer.access-certificate")) {
            null, KeyOption.GenerateRandom -> {
                log.info("Generating random access certificate key for metadata signing")
                ECKeyGenerator(Curve.P_256)
                    .keyID("issuer-kid-1")
                    .keyUse(KeyUse.SIGNATURE)
                    .generate()
            }

            KeyOption.LoadFromKeystore -> {
                log.info("Loading access certificate for metadata signing from keystore")
                issuerKeystore.loadJwk(env, "issuer.access-certificate")
            }
        }

        AccessCertificate(key)
    }

    //
    // Adapters (out ports)
    //
    registerBean { clock }

    val proxy = env.getProperty("issuer.http.proxy.url")?.let {
        val url = Url(it)
        val username = env.getProperty("issuer.http.proxy.username")
        val password = env.getProperty("issuer.http.proxy.password")
        HttpProxy(url, username, password)
    }
    val webClient =
        if ("insecure" in env.activeProfiles) {
            WebClients.insecure(proxy = proxy)
        } else {
            WebClients.default(proxy = proxy)
        }
    registerBean { webClient }
    registerBean {
        KeycloakConfigurationProperties(
            env.getRequiredProperty<URL>("issuer.keycloak.server-url"),
            env.getRequiredProperty("issuer.keycloak.authentication-realm"),
            env.getRequiredProperty("issuer.keycloak.client-id"),
            env.getRequiredProperty("issuer.keycloak.username"),
            env.getRequiredProperty("issuer.keycloak.password"),
            env.getRequiredProperty("issuer.keycloak.user-realm"),
        )
    }
    registerBean {
        val keycloakProperties = bean<KeycloakConfigurationProperties>()
        GetPidDataFromKeyCloak(
            issuerCountry = env.getRequiredProperty("issuer.pid.issuingCountry").let(::IsoCountry),
            issuingJurisdiction = env.getProperty("issuer.pid.issuingJurisdiction"),
            clock = clock,
            webClient = bean(),
            keyCloak = Url(keycloakProperties.serverUrl.toExternalForm()),
            administrationClient = AdministrationClient(
                realm = Realm(keycloakProperties.authenticationRealm),
                client = Credentials(username = keycloakProperties.clientId, password = null),
                admin = Credentials(username = keycloakProperties.username, password = keycloakProperties.password),
            ),
            users = Realm(keycloakProperties.userRealm),
        )
    }
    registerBean {
        ForestIssuanceBindingClient(
            webClient = bean(),
            bindingsUrl = env.getRequiredProperty("issuer.forest.binding-url"),
            secret = env.getRequiredProperty("issuer.forest.binding-secret"),
        )
    }
    registerBean<EncodePidInCbor>(lazyInit = true) {
        DefaultEncodePidInCbor(getIssuerSigningKey("issuer.pid.mso_mdoc.signing-key"))
    }

    registerBean { DefaultGenerateQrCode() }
    registerBean { HandleNotificationRequest(bean()) }
    registerBean {
        val cNonceExpiresIn = env.duration("issuer.cnonce.expiration") ?: 5.minutes
        HandleNonceRequest(clock, cNonceExpiresIn, bean())
    }
    registerBean {
        val resolvers = buildMap<CredentialIdentifier, CredentialRequestFactory> {
            if (enableMsoMdocPid) {
                this[CredentialIdentifier(PidMsoMdocScope.value)] =
                    { identifier, unvalidatedProofs, requestedResponseEncryption ->
                        ResolvedCredentialRequest(
                            PidMsoMdocV1CredentialConfigurationId,
                            MsoMdocCredentialRequest(
                                unvalidatedProofs = unvalidatedProofs,
                                credentialResponseEncryption = requestedResponseEncryption,
                                docType = PidMsoMdocV1DocType,
                            ),
                            identifier,
                        )
                    }
            }

            if (enableSdJwtVcPid) {
                this[CredentialIdentifier(PidSdJwtVcScope.value)] =
                    { identifier, unvalidatedProofs, requestedResponseEncryption ->
                        ResolvedCredentialRequest(
                            SdJwtVcPidCredentialConfigurationId,
                            SdJwtVcCredentialRequest(
                                unvalidatedProofs = unvalidatedProofs,
                                credentialResponseEncryption = requestedResponseEncryption,
                                type = SdJwtVcPidVct,
                            ),
                            identifier,
                        )
                    }
            }
        }

        DefaultResolveCredentialRequestByCredentialIdentifier(resolvers)
    }
    registerBean(lazyInit = true) {
        val signedMetadataIssuer = env.getProperty("issuer.signed-metadata.issuer")
            ?.takeIf { it.isNotBlank() }
            ?.trim()
            ?.let { requireNotNull(HttpsUrl.of(it)) { "'issuer.signed-metadata.issuer' is not a valid HttpsUrl" } }
            ?: issuerPublicUrl

        GenerateSignedMetadataWithNimbus(
            clock = bean(),
            signedMetadataIssuer = signedMetadataIssuer,
            credentialIssuerId = bean<CredentialIssuerMetaData>().id,
            accessCertificate = bean(),
        )
    }
    if (enableStatusList) {
        registerBean<GenerateStatusListToken> {
            val serviceUrl = URL(env.getRequiredProperty("issuer.statusList.service.uri"))
            log.info("Token Status List support enabled. Service URL: ${serviceUrl.toExternalForm()}")
            GenerateStatusListTokenWithExternalService(
                webClient = bean(),
                serviceUrl = serviceUrl,
                apiKey = env.getRequiredProperty("issuer.statusList.service.apiKey"),
                clock = bean(),
            )
        }
    }

    //
    // Encryption of credential response
    //
    registerBean(lazyInit = true) {
        EncryptDeferredResponseNimbus(bean<CredentialIssuerMetaData>().id, clock)
    }
    registerBean(lazyInit = true) {
        EncryptCredentialResponseNimbus(bean<CredentialIssuerMetaData>().id, clock)
    }

    //
    // Nonce
    //
    registerBean { GenerateNonceAndEncryptWithNimbus(issuerPublicUrl, nonceEncryptionKey) }
    registerBean { DecryptNonceWithNimbusAndVerify(issuerPublicUrl, nonceEncryptionKey) }

    //
    // Credentials
    //
    with(InMemoryIssuedCredentialRepository()) {
        registerBean { GenerateNotificationId.Random }
        registerBean { storeIssuedCredentials }
        registerBean { loadIssuedCredentialsByNotificationId }
    }

    //
    // Deferred Credentials
    //
    with(InMemoryDeferredCredentialRepository(mutableMapOf(), clock)) {
        registerBean { GenerateTransactionId.Random }
        registerBean { storeDeferredCredential }
        registerBean { loadDeferredCredentialByTransactionId }
    }

    //
    // Specific Issuers
    //
    registerBean {
        if (trustValidatorServiceUrl.isNullOrBlank()) {
            log.warn("Trust Validator Service has not been configured. Trusting all Wallet Providers.")
            IsTrustedKeyAttestationIssuer.Ignored
        } else {
            log.info("Using Trust Validator Service '{}'", trustValidatorServiceUrl)
            IsTrustedKeyAttestationIssuer.usingTrustValidatorService(bean(), URI.create(trustValidatorServiceUrl))
        }
    }
    registerBean { VerifyKeyAttestation(isTrustedKeyAttestationIssuer = bean()) }
    registerBean { ValidateJwtProof(issuerPublicUrl, bean()) }
    registerBean { ValidateAttestationProof(bean()) }
    registerBean { DefaultExtractJwkFromCredentialKey }
    registerBean { ValidateProofs(bean(), bean(), bean(), bean()) }
    registerBean {
        CredentialIssuerMetaData(
            id = issuerPublicUrl,
            credentialEndPoint = issuerPublicUrl.appendPath(WalletApi.CREDENTIAL_ENDPOINT),
            deferredCredentialEndpoint = issuerPublicUrl.appendPath(WalletApi.DEFERRED_ENDPOINT),
            notificationEndpoint = issuerPublicUrl.appendPath(WalletApi.NOTIFICATION_ENDPOINT),
            nonceEndpoint = issuerPublicUrl.appendPath(WalletApi.NONCE_ENDPOINT),
            authorizationServers = listOf(env.readRequiredUrl("issuer.authorizationServer.publicUrl")),
            credentialRequestEncryption = credentialRequestEncryption(),
            credentialResponseEncryption = env.credentialResponseEncryption(),
            specificCredentialIssuers = buildList {
                if (enableMsoMdocPid) {
                    val duration = env.duration("issuer.pid.mso_mdoc.encoder.duration") ?: 30.days
                    val jwtProofsSupportedSigningAlgorithms = env.readNonEmptySet(
                        "issuer.pid.mso_mdoc.jwtProofs.supportedSigningAlgorithms",
                        JWSAlgorithm::parse,
                    )
                    val keyAttestationRequirement = this@BeanRegistrarDsl.keyAttestationRequirement("issuer.pid.mso_mdoc")
                    val pidMsoMdocReusePolicy = this@BeanRegistrarDsl.credentialReusePolicy("issuer.pid.mso_mdoc")
                    val issueMsoMdocPid = IssueMsoMdocPid(
                        getPidData = bean(),
                        encodePidInCbor = bean(),
                        notificationsEnabled = env.getProperty<Boolean>("issuer.pid.mso_mdoc.notifications.enabled")
                            ?: true,
                        generateNotificationId = bean(),
                        clock = clock,
                        validityDuration = duration,
                        storeIssuedCredentials = bean(),
                        validateProofs = bean(),
                        jwtProofsSupportedSigningAlgorithms = jwtProofsSupportedSigningAlgorithms,
                        keyAttestationRequirement = keyAttestationRequirement,
                        generateStatusListToken = beanProvider<GenerateStatusListToken>().ifAvailable,
                        credentialReusePolicy = pidMsoMdocReusePolicy,
                    )
                    add(issueMsoMdocPid)
                    add(issueMsoMdocPid.asDeferred(bean(), bean(), clock))
                }

                if (enableSdJwtVcPid) {
                    val expiresIn = env.duration("issuer.pid.sd_jwt_vc.duration") ?: 30.days
                    val notUseBefore = env.duration("issuer.pid.sd_jwt_vc.notUseBefore")
                    val keyAttestationRequirement = this@BeanRegistrarDsl.keyAttestationRequirement("issuer.pid.sd_jwt_vc")
                    val pidSdJwtVcReusePolicy = this@BeanRegistrarDsl.credentialReusePolicy("issuer.pid.sd_jwt_vc")

                    val digestsHashAlgorithm = env.getProperty<HashAlgorithm>(
                        "issuer.pid.sd_jwt_vc.digests.hashAlgorithm",
                    ) ?: HashAlgorithm.SHA_256
                    val jwtProofsSupportedSigningAlgorithms = env.readNonEmptySet(
                        "issuer.pid.sd_jwt_vc.jwtProofs.supportedSigningAlgorithms",
                        JWSAlgorithm::parse,
                    )

                    val issueSdJwtVcPid = IssueSdJwtVcPid(
                        hashAlgorithm = digestsHashAlgorithm,
                        issuerSigningKey = getIssuerSigningKey("issuer.pid.sd_jwt_vc.signing-key"),
                        getPidData = bean(),
                        clock = clock,
                        credentialIssuerId = issuerPublicUrl,
                        calculateExpiresAt = { iat -> iat + expiresIn },
                        calculateNotUseBefore = notUseBefore?.let { duration -> { iat -> iat + duration } },
                        notificationsEnabled = env.getProperty<Boolean>("issuer.pid.sd_jwt_vc.notifications.enabled") ?: true,
                        generateNotificationId = bean(),
                        storeIssuedCredentials = bean(),
                        validateProofs = bean(),
                        generateStatusListToken = beanProvider<GenerateStatusListToken>().ifAvailable,
                        jwtProofsSupportedSigningAlgorithms = jwtProofsSupportedSigningAlgorithms,
                        keyAttestationRequirement = keyAttestationRequirement,
                        credentialReusePolicy = pidSdJwtVcReusePolicy,
                    )

                    add(issueSdJwtVcPid)
                    add(issueSdJwtVcPid.asDeferred(bean(), bean(), clock))
                }

                // Every other credential type (Forest Owner Company and anything
                // added later) is schema-driven: each unmodified JSON Schema under
                // issuer.credential-schemas.location is one credential, instead of a
                // new Kotlin class. Issuance settings fall back to
                // issuer.credential-defaults.*. See adapter/out/generalcredential/.
                val defaultSigningKey by lazy { getIssuerSigningKey("$CREDENTIAL_DEFAULTS.signing-key") }
                val registeredConfigurationIds = mutableMapOf<CredentialConfigurationId, String>()
                env.generalCredentialSettings().forEach { settings ->
                    if (env.getPropertyOrEnvVariable<Boolean>(settings.keyFor("enabled")) ?: true) {
                        val schema = CredentialSchemaLoader.load(settings.source.resource, settings.overrides)
                        registeredConfigurationIds.put(schema.credentialConfigurationId, settings.source.name)?.let { other ->
                            error(
                                "Credential schemas '$other' and '${settings.source.name}' both resolve to " +
                                    "'${schema.credentialConfigurationId.value}'; override vct or credential-configuration-id for one",
                            )
                        }
                        log.info(
                            "Registering schema-driven credential '{}' (vct {}, scope {}) from {}",
                            schema.credentialConfigurationId.value,
                            schema.vct.value,
                            schema.scope.value,
                            settings.source.resource.description,
                        )
                        val issuerSigningKey =
                            if (settings.overrides("signing-key")) getIssuerSigningKey(settings.keyFor("signing-key"))
                            else defaultSigningKey
                        val jwtProofsSupportedSigningAlgorithms = env.readNonEmptySet(
                            settings.keyFor("jwtProofs.supportedSigningAlgorithms"),
                            JWSAlgorithm::parse,
                        )
                        val keyAttestationRequirement =
                            this@BeanRegistrarDsl.keyAttestationRequirement(settings.prefixFor("key_attestations.required"))
                        val reusePolicy = this@BeanRegistrarDsl.credentialReusePolicy(settings.prefixFor("reusePolicy.enabled"))
                        val validity = Duration.parse(env.getPropertyOrEnvVariable(settings.keyFor("validity")) ?: "P30D")
                        val digestHashAlgorithm = env.getPropertyOrEnvVariable<HashAlgorithm>(
                            settings.keyFor("sdJwtVc.encoder.digests.hashAlgorithm"),
                        ) ?: HashAlgorithm.SHA_256
                        val notificationsEnabled =
                            env.getPropertyOrEnvVariable<Boolean>(settings.keyFor("notifications.enabled")) ?: true

                        val generalCredentialIssuer = IssueGeneralCredentialSdJwtVc.sdJwtVcCompact(
                            schema = schema,
                            issuerSigningKey = issuerSigningKey,
                            proofsSupportedSigningAlgorithms = jwtProofsSupportedSigningAlgorithms,
                            keyAttestationRequirement = keyAttestationRequirement,
                            credentialIssuerId = issuerPublicUrl,
                            clock = bean(),
                            validateProofs = bean(),
                            getCredential = GetGeneralCredentialFromBinding(bean(), schema),
                            validity = validity,
                            digestsHashAlgorithm = digestHashAlgorithm,
                            generateNotificationId = if (notificationsEnabled) bean() else null,
                            storeIssuedCredentials = bean(),
                            completeBinding = bean(),
                            credentialReusePolicy = reusePolicy,
                            style = settings.style,
                        )
                        add(generalCredentialIssuer)
                        add(generalCredentialIssuer.asDeferred(bean(), bean(), bean()))
                    }
                }
            },
            batchCredentialIssuance = run {
                val enabled = env.getProperty<Boolean>("issuer.credentialEndpoint.batchIssuance.enabled") ?: true
                if (enabled) {
                    val batchSize = env.getProperty<Int>("issuer.credentialEndpoint.batchIssuance.batchSize") ?: 10
                    BatchCredentialIssuance.Supported(batchSize)
                } else {
                    BatchCredentialIssuance.NotSupported
                }
            },
            display = bean<IssuerMetadataProperties>().display
                .map { display ->
                    CredentialIssuerDisplay(
                        name = display.name,
                        locale = display.locale?.let { Locale.forLanguageTag(it) },
                        logo = display.logo?.let { ImageUri(it.uri, it.alternativeText) },
                    )
                },
        )
    }

    //
    // In Ports (use cases)
    //
    registerBean {
        val enableSignedMetadata = env.getProperty<Boolean>("issuer.metadata.signed-metadata.enabled") ?: true
        val generateSignedMetadata = if (enableSignedMetadata) bean<GenerateSignedMetadata>() else null
        GetCredentialIssuerMetaData(bean(), generateSignedMetadata)
    }
    registerBean {
        IssueCredential(
            credentialIssuerMetadata = bean(),
            resolveCredentialRequestByCredentialIdentifier = bean(),
            encryptCredentialResponse = bean(),
        )
    }
    registerBean {
        GetDeferredCredential(bean(), bean(), bean())
    }
    registerBean {
        CreateCredentialsOffer(bean(), credentialsOfferUri)
    }

    val accessTokenType = env.getProperty<AccessTokenType>("issuer.access-token.type") ?: AccessTokenType.DPoP
    val enableBearerTokenAuthentication =
        AccessTokenType.Bearer == accessTokenType ||
            AccessTokenType.BearerAndDPoPIfAvailable == accessTokenType

    if (AccessTokenType.DPoP == accessTokenType || AccessTokenType.BearerAndDPoPIfAvailable == accessTokenType) {
        val algorithms = runBlocking {
            val authorizationServerMetadata = URI.create(env.getRequiredProperty("issuer.authorizationServer.metadata"))
            webClient.authorizationServerSupportedDPoPJWSAlgorithms(authorizationServerMetadata)
        }
        if (AccessTokenType.DPoP == accessTokenType) {
            requireNotNull(algorithms) { "DPoP is required but Authorization Server does not support DPoP." }
        }

        algorithms?.let {
            log.info("DPoP support will be enabled. Supported algorithms: $it")

            val proofMaxAge = env.duration("issuer.dpop.proof-max-age") ?: 1.minutes
            val cachePurgeInterval = env.duration("issuer.dpop.cache-purge-interval") ?: 10.minutes
            val realm = env.getProperty("issuer.dpop.realm")?.takeIf { it.isNotBlank() }

            registerBean { DPoPConfigurationProperties(it, proofMaxAge, cachePurgeInterval, realm) }
        }
    }

    registerBean {
        GetProtectedResourceMetadata(
            bean(),
            enableBearerTokenAuthentication,
            beanProvider<DPoPConfigurationProperties>().ifAvailable,
        )
    }

    //
    // Routes
    //
    registerBean {
        val typeMetadata = bean<SdJwtVcProperties>().typeMetadata
            .associateBy { Vct(it.vct) }
            .mapValues { it.value.resource }
        val metaDataApi = MetaDataApi(bean(), bean(), typeMetadata, bean())
        val walletApi = WalletApi(bean(), bean(), bean(), bean(), bean())
        val issuerUi = IssuerUi(credentialsOfferUri, bean(), bean(), bean())
        val issuerApi = IssuerApi(bean(), bean())
        metaDataApi.route.and(walletApi.route).and(issuerUi.router).and(issuerApi.router)
    }

    //
    // Security
    //

    registerBean {
        /*
         * This is a Spring naming convention
         * A prefix of SCOPE_xyz will grant a SimpleAuthority(xyz)
         * if there is a scope xyz
         *
         * Note that on the OAUTH2 server we set xyz as the scope
         * and not SCOPE_xyz
         */
        fun Scope.springConvention() = "SCOPE_$value"
        val metaData = bean<CredentialIssuerMetaData>()
        val scopes = metaData.credentialConfigurationsSupported
            .map { it.scope.springConvention() }
            .distinct()
        val http = bean<ServerHttpSecurity>()
        http {
            authorizeExchange {
                authorize(WalletApi.CREDENTIAL_ENDPOINT, hasAnyAuthority(*scopes.toTypedArray()))
                authorize(WalletApi.DEFERRED_ENDPOINT, hasAnyAuthority(*scopes.toTypedArray()))
                authorize(WalletApi.NOTIFICATION_ENDPOINT, hasAnyAuthority(*scopes.toTypedArray()))
                authorize(WalletApi.NONCE_ENDPOINT, permitAll)
                authorize(MetaDataApi.WELL_KNOWN_OPENID_CREDENTIAL_ISSUER, permitAll)
                authorize(MetaDataApi.WELL_KNOWN_JWT_VC_ISSUER, permitAll)
                authorize(MetaDataApi.PUBLIC_KEYS, permitAll)
                authorize(MetaDataApi.TYPE_METADATA, permitAll)
                authorize(MetaDataApi.WELL_KNOWN_PROTECTED_RESOURCE_METADATA, permitAll)
                authorize(IssuerUi.GENERATE_CREDENTIALS_OFFER, permitAll)
                authorize(IssuerApi.CREATE_CREDENTIALS_OFFER, permitAll)
                authorize("", permitAll)
                authorize("/", permitAll)
                authorize(env.getRequiredProperty("spring.webflux.static-path-pattern"), permitAll)
                authorize(env.getRequiredProperty("spring.webflux.webjars-path-pattern"), permitAll)
                authorize(anyExchange, denyAll)
            }

            csrf {
                disable()
            }

            cors {
                disable()
            }

            val introspectionProperties = bean<OAuth2ResourceServerProperties>()
            val introspector = SpringReactiveOpaqueTokenIntrospector(
                introspectionProperties.opaquetoken.introspectionUri,
                webClient
                    .mutate()
                    .defaultHeaders {
                        it.setBasicAuth(
                            introspectionProperties.opaquetoken.clientId!!,
                            introspectionProperties.opaquetoken.clientSecret!!,
                        )
                    }
                    .build(),
            )

            val dpopConfigurationProperties = beanProvider<DPoPConfigurationProperties>().ifAvailable

            val entryPoints = mutableListOf<DelegatingServerAuthenticationEntryPoint.DelegateEntry>()
            val accessDeniedHandlers = mutableListOf<ServerWebExchangeDelegatingServerAccessDeniedHandler.DelegateEntry>()
            val filters = mutableListOf<Pair<SecurityWebFiltersOrder, WebFilter>>()

            if (null != dpopConfigurationProperties) {
                log.info("Enabling DPoP AccessToken support")

                val enableDPoPNonce = env.getProperty<Boolean>("issuer.dpop.nonce.enabled") ?: true
                val dpopNonce =
                    if (enableDPoPNonce) {
                        val dpopNonceExpiresIn = env.duration("issuer.dpop.nonce.expiration") ?: 5.minutes
                        DPoPNoncePolicy.Enforcing(bean(), bean(), dpopNonceExpiresIn)
                    } else {
                        DPoPNoncePolicy.Disabled
                    }

                val entryPoint = DPoPTokenServerAuthenticationEntryPoint(dpopConfigurationProperties.realm, dpopNonce, bean())
                val tokenConverter = ServerDPoPAuthenticationTokenAuthenticationConverter()

                entryPoints.add(
                    DelegatingServerAuthenticationEntryPoint.DelegateEntry(
                        AuthenticationConverterServerWebExchangeMatcher(tokenConverter),
                        entryPoint,
                    ),
                )

                accessDeniedHandlers.add(
                    ServerWebExchangeDelegatingServerAccessDeniedHandler.DelegateEntry(
                        AuthenticationConverterServerWebExchangeMatcher(tokenConverter),
                        DPoPTokenServerAccessDeniedHandler(dpopConfigurationProperties.realm),
                    ),
                )

                val dpopFilter = run {
                    val dPoPVerifier = DPoPProtectedResourceRequestVerifier(
                        dpopConfigurationProperties.algorithms.toMutableSet(),
                        dpopConfigurationProperties.proofMaxAge.inWholeSeconds,
                        DefaultDPoPSingleUseChecker(
                            dpopConfigurationProperties.proofMaxAge.inWholeSeconds,
                            dpopConfigurationProperties.cachePurgeInterval.inWholeSeconds,
                        ),
                    )

                    val authenticationManager =
                        DPoPTokenReactiveAuthenticationManager(introspector, dPoPVerifier, dpopNonce, bean())

                    AuthenticationWebFilter(authenticationManager).apply {
                        setServerAuthenticationConverter(tokenConverter)
                        setAuthenticationFailureHandler(ServerAuthenticationEntryPointFailureHandler(entryPoint))
                    }
                }
                filters.add(SecurityWebFiltersOrder.AUTHENTICATION to dpopFilter)

                if (dpopNonce is DPoPNoncePolicy.Enforcing) {
                    val dpopNonceFilter = DPoPNonceWebFilter(
                        dpopNonce,
                        bean(),
                        listOf(
                            WalletApi.CREDENTIAL_ENDPOINT,
                            WalletApi.DEFERRED_ENDPOINT,
                            WalletApi.NOTIFICATION_ENDPOINT,
                            WalletApi.NONCE_ENDPOINT,
                        ),
                    )
                    filters.add(SecurityWebFiltersOrder.LAST to dpopNonceFilter)
                }
            }

            if (enableBearerTokenAuthentication) {
                log.info("Enabled Bearer AccessToken support")

                val entryPoint = BearerTokenServerAuthenticationEntryPoint()
                val tokenConverter = ServerBearerTokenAuthenticationConverter()

                entryPoints.add(
                    DelegatingServerAuthenticationEntryPoint.DelegateEntry(
                        AuthenticationConverterServerWebExchangeMatcher(tokenConverter),
                        entryPoint,
                    ),
                )

                accessDeniedHandlers.add(
                    ServerWebExchangeDelegatingServerAccessDeniedHandler.DelegateEntry(
                        AuthenticationConverterServerWebExchangeMatcher(tokenConverter),
                        BearerTokenServerAccessDeniedHandler(),
                    ),
                )

                val filter = AuthenticationWebFilter(OpaqueTokenReactiveAuthenticationManager(introspector))
                    .apply {
                        setServerAuthenticationConverter(tokenConverter)
                        setAuthenticationFailureHandler(
                            ServerAuthenticationEntryPointFailureHandler(HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED)),
                        )
                    }

                filters.add(SecurityWebFiltersOrder.AUTHENTICATION to filter)
            }

            exceptionHandling {
                authenticationEntryPoint = DelegatingServerAuthenticationEntryPoint(entryPoints)
                    .apply {
                        setDefaultEntryPoint(HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED))
                    }

                accessDeniedHandler = ServerWebExchangeDelegatingServerAccessDeniedHandler(accessDeniedHandlers)
                    .apply {
                        setDefaultAccessDeniedHandler(HttpStatusServerAccessDeniedHandler(HttpStatus.FORBIDDEN))
                    }
            }

            filters.forEach { (order, filter) ->
                if (SecurityWebFiltersOrder.LAST == order) {
                    http.addFilterAt(filter, SecurityWebFiltersOrder.LAST)
                } else {
                    http.addFilterAfter(filter, order)
                }
            }
        }
    }

    //
    // Other
    //
    registerBean {
        CodecCustomizer {
            val json = Json {
                explicitNulls = false
                ignoreUnknownKeys = true
            }
            it.defaultCodecs().kotlinSerializationJsonDecoder(KotlinSerializationJsonDecoder(json))
            it.defaultCodecs().kotlinSerializationJsonEncoder(KotlinSerializationJsonEncoder(json))
            it.defaultCodecs().enableLoggingRequestDetails(true)

            val maxInMemorySize = DataSize.parse(env.getProperty("spring.webflux.codecs.max-in-memory-size", "1MB"))
            it.defaultCodecs().maxInMemorySize(maxInMemorySize.toBytes().toInt())
        }
    }
}

private fun BeanRegistrarDsl.credentialReusePolicy(prefix: String): CredentialReusePolicy {
    val enabled = env.getProperty<Boolean>("$prefix.reusePolicy.enabled") ?: false
    if (!enabled) return CredentialReusePolicy.None

    val type = env.getProperty("$prefix.reusePolicy.type") ?: "ArfAnnex2"
    return when (type) {
        "ArfAnnex2" -> {
            val options = mutableListOf<EudiReusePolicy>()
            var index = 0
            while (true) {
                val detailsStr = env.getPropertyOrEnvVariable("$prefix.reusePolicy.options[$index].details") ?: break
                val methods = detailsStr.split(",").map { it.trim() }.mapNotNull { EudiReusePolicyType.fromValue(it) }
                if (methods.isEmpty()) {
                    index++
                    continue
                }
                methods.mapTo(options) { method ->
                    when (method) {
                        EudiReusePolicyType.OnceOnly -> {
                            val batchSize = env.getRequiredPropertyOrEnvVariable<Int>("$prefix.reusePolicy.options[$index].batchSize")
                            val reissueTriggerUnused = env.getRequiredPropertyOrEnvVariable<Int>(
                                "$prefix.reusePolicy.options[$index].reissueTriggerUnused",
                            )
                            EudiReusePolicy.OnceOnly(batchSize, reissueTriggerUnused)
                        }

                        EudiReusePolicyType.LimitedTime -> {
                            val reissueTriggerLifetimeLeft = env.getRequiredPropertyOrEnvVariable<Long>(
                                "$prefix.reusePolicy.options[$index].reissueTriggerLifetimeLeft",
                            ).seconds
                            EudiReusePolicy.LimitedTime(reissueTriggerLifetimeLeft)
                        }

                        EudiReusePolicyType.RotatingBatch -> {
                            val batchSize = env.getRequiredPropertyOrEnvVariable<Int>("$prefix.reusePolicy.options[$index].batchSize")
                            val reissueTriggerLifetimeLeft = env.getRequiredPropertyOrEnvVariable<Long>(
                                "$prefix.reusePolicy.options[$index].reissueTriggerLifetimeLeft",
                            ).seconds
                            EudiReusePolicy.RotatingBatch(batchSize, reissueTriggerLifetimeLeft)
                        }

                        EudiReusePolicyType.PerRelyingParty -> {
                            val batchSize = env.getRequiredPropertyOrEnvVariable<Int>("$prefix.reusePolicy.options[$index].batchSize")
                            val reissueTriggerUnused = env.getRequiredPropertyOrEnvVariable<Int>(
                                "$prefix.reusePolicy.options[$index].reissueTriggerUnused",
                            )
                            val reissueTriggerLifetimeLeft = env.getRequiredPropertyOrEnvVariable<Long>(
                                "$prefix.reusePolicy.options[$index].reissueTriggerLifetimeLeft",
                            ).seconds
                            EudiReusePolicy.PerRelyingParty(
                                batchSize,
                                reissueTriggerLifetimeLeft,
                                reissueTriggerUnused,
                            )
                        }
                    }
                }
                index++
            }
            if (options.isEmpty()) CredentialReusePolicy.None
            else CredentialReusePolicy.EUDI(
                id = CredentialReusePolicy.EUDI.ARF_ANNEX_II_ID,
                options = options,
            )
        }

        else -> CredentialReusePolicy.None
    }
}

private fun BeanRegistrarDsl.keyAttestationRequirement(attestationPropertyPrefix: String): KeyAttestationRequirement {
    val keyAttestationRequired = env.getProperty<Boolean>("$attestationPropertyPrefix.key_attestations.required")
    val keyStorageConstraints = env.getProperty<List<String>>(
        "$attestationPropertyPrefix.key_attestations.constraints.key_storage",
    )
    val userAuthenticationConstraints = env.getProperty<List<String>>(
        "$attestationPropertyPrefix.key_attestations.constraints.user_authentication",
    )
    return if (keyAttestationRequired == null || !keyAttestationRequired)
        KeyAttestationRequirement.NotRequired
    else KeyAttestationRequirement.Required(
        keyStorage = keyStorageConstraints?.map {
            AttackPotentialResistance(it)
        }?.toNonEmptySetOrNull(),
        userAuthentication = userAuthenticationConstraints?.map {
            AttackPotentialResistance(it)
        }?.toNonEmptySetOrNull(),
    )
}

private fun Environment.credentialResponseEncryption(): CredentialResponseEncryption {
    val isSupported = getProperty<Boolean>("issuer.credentialResponseEncryption.supported") ?: false
    return if (!isSupported) {
        CredentialResponseEncryption.NotSupported
    } else {
        val parameters = CredentialResponseEncryptionSupportedParameters(
            algorithmsSupported = readNonEmptySet(
                "issuer.credentialResponseEncryption.algorithmsSupported",
                JWEAlgorithm::parse,
            ),
            methodsSupported = readNonEmptySet(
                "issuer.credentialResponseEncryption.encryptionMethods",
                EncryptionMethod::parse,
            ),
            zipAlgorithmsSupported = readNullableNonEmptySet(
                "issuer.credentialResponseEncryption.zipAlgorithmsSupported",
            ) { algorithm -> algorithm.takeIf { it.isNotBlank() }?.let { CompressionAlgorithm(it) } },
        )
        val isRequired = getProperty<Boolean>("issuer.credentialResponseEncryption.required") ?: false
        if (!isRequired) {
            CredentialResponseEncryption.Optional(parameters)
        } else {
            CredentialResponseEncryption.Required(parameters)
        }
    }
}

private fun Environment.readRequiredUrl(key: String, removeTrailingSlash: Boolean = false): HttpsUrl =
    getRequiredProperty(key)
        .let { url ->
            fun String.normalize() =
                if (removeTrailingSlash) {
                    this.removeSuffix("/")
                } else {
                    this
                }

            fun String.toHttpsUrl(): HttpsUrl = HttpsUrl.of(this) ?: HttpsUrl.unsafe(this)

            url.normalize().toHttpsUrl()
        }

private fun <T> Environment.readNonEmptySet(key: String, f: (String) -> T?): NonEmptySet<T> {
    val nonEmptySet = getRequiredProperty<MutableSet<String>>(key)
        .mapNotNull(f)
        .toNonEmptySetOrNull()
    return checkNotNull(nonEmptySet) { "Missing or incorrect values values for key `$key`" }
}

private fun <T> Environment.readNullableNonEmptySet(key: String, f: (String) -> T?): NonEmptySet<T>? {
    return getProperty<MutableSet<String>>(key)
        ?.mapNotNull(f)
        ?.toNonEmptySetOrNull()
}

private fun Environment.duration(key: String): Duration? =
    getProperty(key)?.let { Duration.parse(it) }?.takeIf { it.isPositive() }

internal fun HttpsUrl.appendPath(path: String): HttpsUrl =
    HttpsUrl.unsafe(
        UriComponentsBuilder.fromUriString(externalForm)
            .path(path)
            .build()
            .toUriString(),
    )

/**
 * Loads a key pair alongside its associated certificate chain as a JWK.
 *
 * This method expects to find the following properties in the provided [environment].
 * - [prefix].alias -> alias of the key pair to load
 * - [prefix].password -> password of the key pair
 *
 * @receiver the [KeyStore] from which to load the [JWK]
 */
@Suppress("SameParameterValue")
private fun KeyStore.loadJwk(environment: Environment, prefix: String): JWK {
    fun property(property: String): String =
        when {
            prefix.isBlank() -> property
            prefix.endsWith(".") -> "$prefix$property"
            else -> "$prefix.$property"
        }

    fun JWK.withCertificateChain(chain: List<X509Certificate>): JWK {
        require(this.parsedX509CertChain.isNotEmpty()) { "jwk must have a leaf certificate" }
        require(chain.isNotEmpty()) { "chain cannot be empty" }
        require(this.parsedX509CertChain.first() == chain.first()) {
            "leaf certificate of provided chain does not match leaf certificate of jwk"
        }

        val encodedChain = chain.map { Base64.encode(it.encoded) }
        return when (this) {
            is RSAKey -> RSAKey.Builder(this).x509CertChain(encodedChain).build()
            is ECKey -> ECKey.Builder(this).x509CertChain(encodedChain).build()
            is OctetKeyPair -> OctetKeyPair.Builder(this).x509CertChain(encodedChain).build()
            is OctetSequenceKey -> OctetSequenceKey.Builder(this).x509CertChain(encodedChain).build()
            else -> error("Unexpected JWK type '${this.keyType.value}'/'${this.javaClass}'")
        }
    }

    val keyAlias = environment.getRequiredProperty(property("alias"))
    val keyPassword = environment.getProperty(property("password"))?.takeIf { it.isNotBlank() }

    val jwk = JWK.load(this, keyAlias, keyPassword?.toCharArray())
    val chain = getCertificateChain(keyAlias).orEmpty()
        .map { certificate -> certificate as X509Certificate }
        .toList()

    return when {
        chain.isNotEmpty() -> jwk.withCertificateChain(chain)
        else -> jwk
    }
}

/**
 * Indicates whether a random key pairs should be generated, or a key pair should be loaded from a keystore.
 */
private enum class KeyOption {
    GenerateRandom,
    LoadFromKeystore,
}

enum class AccessTokenType {
    DPoP,
    Bearer,
    BearerAndDPoPIfAvailable,
}

/**
 * Configuration properties for Keycloak.
 */
data class KeycloakConfigurationProperties(
    val serverUrl: URL,
    val authenticationRealm: String,
    val clientId: String,
    val username: String,
    val password: String,
    val userRealm: String,
) {
    init {
        require(authenticationRealm.isNotBlank()) { "'authenticationRealm' cannot be blank" }
        require(clientId.isNotBlank()) { "'clientId' cannot be blank" }
        require(username.isNotBlank()) { "'username' cannot be blank" }
        require(password.isNotBlank()) { "'password' cannot be blank" }
        require(userRealm.isNotBlank()) { "'userRealm' cannot be blank" }
    }
}

/**
 * Configuration properties for Issuer metadata.
 */
@ConfigurationProperties("issuer.metadata")
internal data class IssuerMetadataProperties(
    val display: List<DisplayProperties> = emptyList(),
) {
    data class DisplayProperties(
        val name: String? = null,
        val locale: String? = null,
        val logo: LogoProperties? = null,
    )

    data class LogoProperties(
        val uri: URI,
        val alternativeText: String? = null,
    )
}

@ConfigurationProperties("issuer.sd-jwt-vc")
internal data class SdJwtVcProperties(
    val typeMetadata: List<TypeMetadataProperties>,
) {
    init {
        val vcts = typeMetadata.map { it.vct }
        require(vcts.size == vcts.distinct().size)
    }

    data class TypeMetadataProperties(
        val vct: String,
        val resource: Resource,
    ) {
        init {
            require(vct.isNotBlank()) { "'vct' cannot be blank" }
            require(resource.exists()) { "'resource' must exist" }
        }
    }
}

private suspend fun WebClient.authorizationServerSupportedDPoPJWSAlgorithms(authorizationServerMetadata: URI): NonEmptySet<JWSAlgorithm>? =
    Either.catch {
        val metadata = get()
            .uri(authorizationServerMetadata)
            .accept(MediaType.APPLICATION_JSON)
            .retrieve()
            .bodyToMono<String>()
            .timeout(5.seconds.toJavaDuration())
            .awaitSingle()
        // Keycloak also advertises RSA and EdDSA algorithms, which the DPoP proof
        // verifier refuses at start-up: only the EC ones (ES256/384/512) are used.
        OIDCProviderMetadata.parse(metadata).dPoPJWSAlgs
            ?.filter { it in JWSAlgorithm.Family.EC }
            ?.toNonEmptySetOrNull()
    }.getOrElse {
        log.warn("Unable to fetch Authorization Server metadata. DPoP support will be disabled.", it)
        null
    }

private const val CREDENTIAL_SCHEMAS_LOCATION = "issuer.credential-schemas.location"
private const val CREDENTIAL_DEFAULTS = "issuer.credential-defaults"

/**
 * Configuration of the schema-driven credential read from [source]. Nothing is
 * required: each setting is read from `issuer.credential-overrides[<file name
 * without .json>]` when that sets it, otherwise from [CREDENTIAL_DEFAULTS].
 */
private class GeneralCredentialSettings(private val env: Environment, val source: CredentialSchemaSource) {
    private val prefix = "issuer.credential-overrides[${source.name}]"

    val overrides = CredentialIssuanceOverrides(
        vct = property("vct"),
        credentialConfigurationId = property("credential-configuration-id"),
        scope = property("scope"),
        displayName = property("display-name"),
    )

    /**
     * Wallet card styling from `display.*` (logo, background colour and image,
     * text colour), each falling back to [CREDENTIAL_DEFAULTS] like any other key.
     */
    val style: CredentialStyle
        get() {
            fun display(key: String): String? = env.getPropertyOrEnvVariable(keyFor("display.$key"))?.takeIf(String::isNotBlank)
            return CredentialStyle(
                locales = display("locales")?.split(',')?.map { Locale.forLanguageTag(it.trim()) } ?: listOf(Locale.ENGLISH),
                logo = display("logo.uri")?.let { ImageUri(URI.create(it), display("logo.alternative-text")) },
                backgroundColor = display("background-color"),
                backgroundImage = display("background-image.uri")?.let {
                    BackgroundImage(URI.create(it), display("background-image.alternative-text"))
                },
                textColor = display("text-color"),
            )
        }

    /** Whether this entry sets [key] itself instead of inheriting it from the defaults. */
    fun overrides(key: String): Boolean = property(key) != null

    fun prefixFor(key: String): String = if (overrides(key)) prefix else CREDENTIAL_DEFAULTS

    fun keyFor(key: String): String = "${prefixFor(key)}.$key"

    private fun property(key: String): String? =
        env.getPropertyOrEnvVariable("$prefix.$key")?.takeIf(String::isNotBlank)
}

private fun Environment.generalCredentialSettings(): List<GeneralCredentialSettings> {
    val location = getProperty(CREDENTIAL_SCHEMAS_LOCATION) ?: "file:/schemas/"
    val sources = CredentialSchemaLoader.discover(location)
    if (sources.isEmpty()) log.warn("No credential schemas found under {} ({})", location, CREDENTIAL_SCHEMAS_LOCATION)
    return sources.map { GeneralCredentialSettings(this, it) }
}

private fun Environment.getPropertyOrEnvVariable(property: String): String? {
    return getProperty(property) ?: getProperty(toEnvironmentVariable(property))
}

private inline fun <reified T : Any> Environment.getPropertyOrEnvVariable(property: String): T? {
    return getProperty<T>(property) ?: getProperty<T>(toEnvironmentVariable(property))
}

private inline fun <reified T : Any> Environment.getRequiredPropertyOrEnvVariable(property: String): T {
    return getProperty<T>(property) ?: getProperty<T>(toEnvironmentVariable(property))
        ?: throw IllegalStateException("Property $property or environment variable ${toEnvironmentVariable(property)} not found")
}

private fun toEnvironmentVariable(property: String): String {
    return property.replace(".", "_")
        .replace("[", "_")
        .replace("]", "")
        .replace("-", "")
        .uppercase()
}
