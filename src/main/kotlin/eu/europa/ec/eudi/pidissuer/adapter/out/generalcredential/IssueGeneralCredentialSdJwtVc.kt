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
package eu.europa.ec.eudi.pidissuer.adapter.out.generalcredential

import arrow.core.Either
import arrow.core.NonEmptySet
import arrow.core.nonEmptySetOf
import arrow.core.raise.either
import arrow.core.raise.ensureNotNull
import arrow.core.toNonEmptyListOrNull
import arrow.fx.coroutines.parMap
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.jose.ValidateProofs
import eu.europa.ec.eudi.pidissuer.adapter.out.signingAlgorithm
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.pidissuer.port.out.IssueSpecificCredential
import eu.europa.ec.eudi.pidissuer.port.out.persistence.GenerateNotificationId
import eu.europa.ec.eudi.pidissuer.port.out.persistence.StoreIssuedCredentials
import eu.europa.ec.eudi.sdjwt.HashAlgorithm
import kotlinx.coroutines.Dispatchers
import org.slf4j.LoggerFactory
import kotlin.time.Duration

/**
 * Generic replacement for the old `IssueForestOwnerCompanyCredential`: same
 * `IssueSpecificCredential` contract every credential type implements, but the
 * credential's shape (claims, id, vct, scope, display name) comes from a
 * [CredentialSchemaDefinition] instead of being compiled in.
 */
internal class IssueGeneralCredentialSdJwtVc(
    override val supportedCredential: CredentialConfiguration,
    override val publicKey: JWK,
    override val keyAttestationRequirement: KeyAttestationRequirement,
    private val schema: CredentialSchemaDefinition,
    private val clock: Clock,
    private val validateProofs: ValidateProofs,
    private val getCredential: GetGeneralCredential,
    private val validity: Duration,
    private val encoder: EncodeGeneralCredentialSdJwtVc,
    private val generateNotificationId: GenerateNotificationId?,
    private val storeIssuedCredentials: StoreIssuedCredentials,
    private val completeBinding: CompleteForestIssuanceBinding,
) : IssueSpecificCredential {
    override suspend fun invoke(
        authorizationContext: AuthorizationContext,
        request: CredentialRequest,
        credentialIdentifier: CredentialIdentifier?,
    ): Either<IssueCredentialError, CredentialResponse> = either {
        log.info("Issuing {} for {}", schema.displayName, authorizationContext.username)
        val holderKeys = validateProofs(request.unvalidatedProofs, supportedCredential, clock.now()).bind()
        val boundCredential = getCredential(authorizationContext)
        val issuedAt = clock.now()
        val expiresAt = issuedAt + validity
        val issuedCredentials = holderKeys.parMap(Dispatchers.Default, 4) {
            encoder(boundCredential, it, issuedAt, expiresAt).bind()
        }.toNonEmptyListOrNull()
        ensureNotNull(issuedCredentials) { IssueCredentialError.Unexpected("Unable to issue ${schema.displayName}") }
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
            schema: CredentialSchemaDefinition,
            issuerSigningKey: IssuerSigningKey,
            proofsSupportedSigningAlgorithms: NonEmptySet<JWSAlgorithm>,
            keyAttestationRequirement: KeyAttestationRequirement,
            credentialIssuerId: CredentialIssuerId,
            clock: Clock,
            validateProofs: ValidateProofs,
            getCredential: GetGeneralCredential,
            validity: Duration,
            digestsHashAlgorithm: HashAlgorithm,
            generateNotificationId: GenerateNotificationId?,
            storeIssuedCredentials: StoreIssuedCredentials,
            completeBinding: CompleteForestIssuanceBinding,
            credentialReusePolicy: CredentialReusePolicy = CredentialReusePolicy.None,
            style: CredentialStyle = CredentialStyle(),
        ): IssueGeneralCredentialSdJwtVc {
            val configuration = generalCredentialConfiguration(
                schema,
                issuerSigningKey.signingAlgorithm,
                proofsSupportedSigningAlgorithms,
                keyAttestationRequirement,
                credentialReusePolicy,
                style,
            )
            return IssueGeneralCredentialSdJwtVc(
                configuration,
                issuerSigningKey.key.toPublicJWK(),
                keyAttestationRequirement,
                schema,
                clock,
                validateProofs,
                getCredential,
                validity,
                EncodeGeneralCredentialSdJwtVc(schema, digestsHashAlgorithm, issuerSigningKey, credentialIssuerId),
                generateNotificationId,
                storeIssuedCredentials,
                completeBinding,
            )
        }

        internal fun generalCredentialConfiguration(
            schema: CredentialSchemaDefinition,
            credentialSigningAlgorithm: JWSAlgorithm,
            proofsSupportedSigningAlgorithms: NonEmptySet<JWSAlgorithm>,
            keyAttestationRequirement: KeyAttestationRequirement,
            credentialReusePolicy: CredentialReusePolicy,
            style: CredentialStyle,
        ) = SdJwtVcCredentialConfiguration(
            schema.credentialConfigurationId,
            schema.vct,
            schema.scope,
            nonEmptySetOf(CryptographicBindingMethod.Jwk),
            nonEmptySetOf(credentialSigningAlgorithm),
            style.locales.map { locale ->
                CredentialDisplay(
                    DisplayName(schema.displayName, locale),
                    logo = style.logo,
                    description = schema.description,
                    backgroundColor = style.backgroundColor,
                    backgroundImage = style.backgroundImage,
                    textColor = style.textColor,
                )
            }.toNonEmptyListOrNull()!!,
            schema.claims.map { claim ->
                ClaimDefinition(
                    path = ClaimPath.claim(claim.name),
                    mandatory = claim.mandatory,
                    display = style.locales.associateWith { claim.displayLabel },
                )
            },
            ProofTypesSupported(ProofType.proofTypes(proofsSupportedSigningAlgorithms, keyAttestationRequirement)),
            attestationCategory = AttestationCategory.Eaa,
            credentialReusePolicy = credentialReusePolicy,
        )

        private val log = LoggerFactory.getLogger(IssueGeneralCredentialSdJwtVc::class.java)
    }
}
