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
package eu.europa.ec.eudi.pidissuer.adapter.out.forestowner

import arrow.core.Either
import arrow.core.NonEmptyList
import arrow.core.NonEmptySet
import arrow.core.nonEmptyListOf
import arrow.core.nonEmptySetOf
import arrow.core.raise.catch
import arrow.core.raise.either
import arrow.core.raise.ensureNotNull
import arrow.core.toNonEmptyListOrNull
import arrow.fx.coroutines.parMap
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.ValidateProofs
import eu.europa.ec.eudi.pidissuer.adapter.out.sdJwtVcIssuer
import eu.europa.ec.eudi.pidissuer.adapter.out.signingAlgorithm
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.out.IssueSpecificCredential
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreIssuedCredentials
import eu.europa.ec.eudi.sdjwt.*
import eu.europa.ec.eudi.sdjwt.dsl.values.sdJwt
import kotlinx.coroutines.Dispatchers
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import org.slf4j.LoggerFactory
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.awaitBody
import java.util.Locale
import kotlin.time.Duration
import kotlin.time.Instant
import kotlin.uuid.Uuid

val ForestOwnerCompanyVct = SdJwtVcType("urn:forest:owner-company:eaa:1")
val ForestOwnerCompanyCredentialConfigurationId =
    CredentialConfigurationId("urn:forest:owner-company:eaa:1:dc+sd-jwt-compact")
val ForestOwnerCompanyScope = Scope("urn:forest:owner-company:eaa:1:dc+sd-jwt")

data class ForestOwnerCompanyCredential(
    val companyName: String?,
    val leiCode: String,
    val euid: String?,
    val pefcNumber: String,
    val fscNumber: String,
) {
    init {
        require(companyName == null || companyName.isNotBlank())
        require(leiCode.isNotBlank())
        require(euid == null || euid.isNotBlank())
        require(pefcNumber.isNotBlank())
        require(fscNumber.isNotBlank())
    }
}

data class BoundForestOwnerCompanyCredential(
    val credential: ForestOwnerCompanyCredential,
    val issuerState: String,
    val subject: String,
)

fun interface CompleteForestIssuanceBinding {
    suspend operator fun invoke(issuerState: String, subject: String)
}

class ForestIssuanceBindingClient(
    private val webClient: WebClient,
    private val bindingsUrl: String,
    private val secret: String,
) : CompleteForestIssuanceBinding {
    suspend fun claim(issuerState: String?, subject: String): ClaimedForestIssuanceBinding {
        val response = webClient.post().uri("$bindingsUrl/claim")
            .contentType(MediaType.APPLICATION_JSON)
            .accept(MediaType.APPLICATION_JSON)
            .header("X-Forest-Binding-Secret", secret)
            .bodyValue(mapOf("issuerState" to issuerState.orEmpty(), "subject" to subject))
            .retrieve().awaitBody<BindingResponse>()
        return ClaimedForestIssuanceBinding(
            username = requireNotNull(response.username) { "Binding response did not contain a username" },
            issuerState = requireNotNull(response.issuerState) { "Binding response did not contain an issuer state" },
            credentialAttributes = response.credentialAttributes,
        )
    }

    override suspend fun invoke(issuerState: String, subject: String) {
        webClient.post().uri("$bindingsUrl/complete")
            .contentType(MediaType.APPLICATION_JSON)
            .accept(MediaType.APPLICATION_JSON)
            .header("X-Forest-Binding-Secret", secret)
            .bodyValue(mapOf("issuerState" to issuerState, "subject" to subject))
            .retrieve().awaitBody<Map<String, Any>>()
    }

    private data class BindingResponse(
        val username: String? = null,
        val issuerState: String? = null,
        val credentialAttributes: Map<String, String> = emptyMap(),
    )
}

data class ClaimedForestIssuanceBinding(
    val username: String,
    val issuerState: String,
    val credentialAttributes: Map<String, String>,
)

fun interface GetForestOwnerCompanyCredential {
    suspend operator fun invoke(context: AuthorizationContext): BoundForestOwnerCompanyCredential
}

class GetForestOwnerCompanyCredentialFromBinding(
    private val bindingClient: ForestIssuanceBindingClient,
) : GetForestOwnerCompanyCredential {
    override suspend fun invoke(context: AuthorizationContext): BoundForestOwnerCompanyCredential {
        val subject = requireNotNull(context.subject) { "Missing sub in the access token" }
        val binding = bindingClient.claim(context.issuerState, subject)
        require(binding.username == context.username) {
            "The mobile Keycloak username does not match the desktop issuance binding"
        }
        val attributes = binding.credentialAttributes
        fun requiredAttribute(name: String): String =
            requireNotNull(attributes[name]?.takeIf(String::isNotBlank)) {
                "Missing required approved EAA attribute '$name'"
            }

        return BoundForestOwnerCompanyCredential(
            credential = ForestOwnerCompanyCredential(
                companyName = attributes["company_name"]?.takeIf(String::isNotBlank),
                leiCode = requiredAttribute("lei_code"),
                euid = attributes["euid"]?.takeIf(String::isNotBlank),
                pefcNumber = requiredAttribute("pefc_number"),
                fscNumber = requiredAttribute("fsc_number"),
            ),
            issuerState = binding.issuerState,
            subject = subject,
        )
    }

}

private object ForestOwnerCompanyClaims {
    val CompanyName = claim("company_name", false, "Company Name")
    val LeiCode = claim("lei_code", true, "LEI Code")
    val Euid = claim("euid", false, "European Unique Identifier")
    val PefcNumber = claim("pefc_number", true, "PEFC Certificate Number")
    val FscNumber = claim("fsc_number", true, "FSC Certificate Number")

    private fun claim(name: String, mandatory: Boolean, label: String) = ClaimDefinition(
        path = ClaimPath.claim(name),
        mandatory = mandatory,
        display = mapOf(Locale.ENGLISH to label),
    )

    fun all(): NonEmptyList<ClaimDefinition> = nonEmptyListOf(CompanyName, LeiCode, Euid, PefcNumber, FscNumber)
}

private fun forestOwnerCompanyCredentialConfiguration(
    credentialSigningAlgorithm: JWSAlgorithm,
    proofsSupportedSigningAlgorithms: NonEmptySet<JWSAlgorithm>,
    keyAttestationRequirement: KeyAttestationRequirement,
    credentialReusePolicy: CredentialReusePolicy,
) = SdJwtVcCredentialConfiguration(
    ForestOwnerCompanyCredentialConfigurationId,
    ForestOwnerCompanyVct,
    ForestOwnerCompanyScope,
    nonEmptySetOf(CryptographicBindingMethod.Jwk),
    nonEmptySetOf(credentialSigningAlgorithm),
    nonEmptyListOf(
        CredentialDisplay(
            DisplayName("Forest Owner Company EAA", Locale.ENGLISH),
            description = "Forest Owner Company electronic attestation of attributes",
        ),
    ),
    ForestOwnerCompanyClaims.all(),
    ProofTypesSupported(ProofType.proofTypes(proofsSupportedSigningAlgorithms, keyAttestationRequirement)),
    attestationCategory = AttestationCategory.Eaa,
    credentialReusePolicy = credentialReusePolicy,
)

internal class EncodeForestOwnerCompanyCredential(
    digestsHashAlgorithm: HashAlgorithm,
    issuerSigningKey: IssuerSigningKey,
    private val credentialIssuerId: CredentialIssuerId,
) {
    val format: Format = SD_JWT_VC_FORMAT
    val type: String = ForestOwnerCompanyVct.value
    private val issuer: SdJwtIssuer<SignedJWT> by lazy { issuerSigningKey.sdJwtVcIssuer(digestsHashAlgorithm) }

    suspend operator fun invoke(
        credential: ForestOwnerCompanyCredential,
        holderKey: JWK,
        issuedAt: Instant,
        expiresAt: Instant,
    ): Either<IssueCredentialError, JsonElement> = either {
        val spec = sdJwt {
            claim(RFC7519.JWT_ID, Uuid.random().toHexDashString())
            claim(RFC7519.ISSUED_AT, issuedAt.epochSeconds)
            claim(RFC7519.EXPIRATION_TIME, expiresAt.epochSeconds)
            claim(RFC7519.ISSUER, credentialIssuerId.externalForm)
            claim(SdJwtVcSpec.VCT, ForestOwnerCompanyVct.value)
            cnf(holderKey.toPublicJWK())
            credential.companyName?.let { sdClaim("company_name", it) }
            sdClaim("lei_code", credential.leiCode)
            credential.euid?.let { sdClaim("euid", it) }
            sdClaim("pefc_number", credential.pefcNumber)
            sdClaim("fsc_number", credential.fscNumber)
        }
        val sdJwt = catch({ issuer.issue(spec).getOrThrow() }) {
            raise(IssueCredentialError.Unexpected("Unable to issue Forest Owner Company EAA", it))
        }
        with(NimbusSdJwtOps) { JsonPrimitive(sdJwt.serialize()) }
    }
}

internal class IssueForestOwnerCompanyCredential(
    override val supportedCredential: CredentialConfiguration,
    override val publicKey: JWK,
    override val keyAttestationRequirement: KeyAttestationRequirement,
    private val clock: Clock,
    private val validateProofs: ValidateProofs,
    private val getCredential: GetForestOwnerCompanyCredential,
    private val validity: Duration,
    private val encoder: EncodeForestOwnerCompanyCredential,
    private val generateNotificationId: GenerateNotificationId?,
    private val storeIssuedCredentials: StoreIssuedCredentials,
    private val completeBinding: CompleteForestIssuanceBinding,
) : IssueSpecificCredential {
    override suspend fun invoke(
        authorizationContext: AuthorizationContext,
        request: CredentialRequest,
        credentialIdentifier: CredentialIdentifier?,
    ): Either<IssueCredentialError, CredentialResponse> = either {
        log.info("Issuing Forest Owner Company EAA for {}", authorizationContext.username)
        val holderKeys = validateProofs(request.unvalidatedProofs, supportedCredential, clock.now()).bind()
        val boundCredential = getCredential(authorizationContext)
        val issuedAt = clock.now()
        val expiresAt = issuedAt + validity
        val issuedCredentials = holderKeys.parMap(Dispatchers.Default, 4) {
            encoder(boundCredential.credential, it, issuedAt, expiresAt).bind()
        }.toNonEmptyListOrNull()
        ensureNotNull(issuedCredentials) { IssueCredentialError.Unexpected("Unable to issue Forest Owner Company EAA") }
        val notificationId = generateNotificationId?.invoke()
        storeIssuedCredentials(
            IssuedCredentials(
                encoder.format,
                encoder.type,
                authorizationContext.username,
                holderKeys,
                issuedAt,
                notificationId,
            ),
        )
        completeBinding(boundCredential.issuerState, boundCredential.subject)
        CredentialResponse.Issued(issuedCredentials, notificationId)
    }

    companion object {
        fun sdJwtVcCompact(
            issuerSigningKey: IssuerSigningKey,
            proofsSupportedSigningAlgorithms: NonEmptySet<JWSAlgorithm>,
            keyAttestationRequirement: KeyAttestationRequirement,
            credentialIssuerId: CredentialIssuerId,
            clock: Clock,
            validateProofs: ValidateProofs,
            getCredential: GetForestOwnerCompanyCredential,
            validity: Duration,
            digestsHashAlgorithm: HashAlgorithm,
            generateNotificationId: GenerateNotificationId?,
            storeIssuedCredentials: StoreIssuedCredentials,
            completeBinding: CompleteForestIssuanceBinding,
            credentialReusePolicy: CredentialReusePolicy = CredentialReusePolicy.None,
        ): IssueForestOwnerCompanyCredential {
            val configuration = forestOwnerCompanyCredentialConfiguration(
                issuerSigningKey.signingAlgorithm,
                proofsSupportedSigningAlgorithms,
                keyAttestationRequirement,
                credentialReusePolicy,
            )
            return IssueForestOwnerCompanyCredential(
                configuration,
                issuerSigningKey.key.toPublicJWK(),
                keyAttestationRequirement,
                clock,
                validateProofs,
                getCredential,
                validity,
                EncodeForestOwnerCompanyCredential(digestsHashAlgorithm, issuerSigningKey, credentialIssuerId),
                generateNotificationId,
                storeIssuedCredentials,
                completeBinding,
            )
        }
    }
}

private val log = LoggerFactory.getLogger(IssueForestOwnerCompanyCredential::class.java)
