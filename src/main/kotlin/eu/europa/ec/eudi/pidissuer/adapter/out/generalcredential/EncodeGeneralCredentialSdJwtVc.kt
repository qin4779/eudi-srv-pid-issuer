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
import arrow.core.raise.catch
import arrow.core.raise.either
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.pidissuer.adapter.out.IssuerSigningKey
import eu.europa.ec.eudi.pidissuer.adapter.out.sdJwtVcIssuer
import eu.europa.ec.eudi.pidissuer.domain.*
import eu.europa.ec.eudi.pidissuer.port.input.IssueCredentialError
import eu.europa.ec.eudi.sdjwt.*
import eu.europa.ec.eudi.sdjwt.dsl.values.sdJwt
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlin.time.Instant
import kotlin.uuid.Uuid

/**
 * Generic replacement for the old `EncodeForestOwnerCompanyCredential`: the
 * per-field `sdClaim("lei_code", credential.leiCode)` calls become one loop
 * over [schema]'s claim list, driven by whatever attributes the binding
 * returned.
 */
internal class EncodeGeneralCredentialSdJwtVc(
    private val schema: CredentialSchemaDefinition,
    digestsHashAlgorithm: HashAlgorithm,
    issuerSigningKey: IssuerSigningKey,
    private val credentialIssuerId: CredentialIssuerId,
) {
    val format: Format = SD_JWT_VC_FORMAT
    val type: String = schema.vct.value
    private val issuer: SdJwtIssuer<SignedJWT> by lazy { issuerSigningKey.sdJwtVcIssuer(digestsHashAlgorithm) }

    suspend operator fun invoke(
        credential: BoundGeneralCredential,
        holderKey: JWK,
        issuedAt: Instant,
        expiresAt: Instant,
    ): Either<IssueCredentialError, JsonElement> = either {
        val spec = sdJwt {
            claim(RFC7519.JWT_ID, Uuid.random().toHexDashString())
            claim(RFC7519.ISSUED_AT, issuedAt.epochSeconds)
            claim(RFC7519.EXPIRATION_TIME, expiresAt.epochSeconds)
            claim(RFC7519.ISSUER, credentialIssuerId.externalForm)
            claim(SdJwtVcSpec.VCT, schema.vct.value)
            cnf(holderKey.toPublicJWK())
            for (claim in schema.claims) {
                credential.attributes[claim.name]?.takeIf(String::isNotBlank)?.let { value ->
                    sdClaim(claim.name, value)
                }
            }
        }
        val sdJwt = catch({ issuer.issue(spec).getOrThrow() }) {
            raise(IssueCredentialError.Unexpected("Unable to issue ${schema.displayName}", it))
        }
        with(NimbusSdJwtOps) { JsonPrimitive(sdJwt.serialize()) }
    }
}
