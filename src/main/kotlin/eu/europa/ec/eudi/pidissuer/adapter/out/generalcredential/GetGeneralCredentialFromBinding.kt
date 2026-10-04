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

import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext

/** A claimed offer binding's approved attributes, generic across credential types. */
data class BoundGeneralCredential(
    val schema: CredentialSchemaDefinition,
    val attributes: Map<String, String>,
    val issuerState: String,
    val subject: String,
)

fun interface GetGeneralCredential {
    suspend operator fun invoke(context: AuthorizationContext): BoundGeneralCredential
}

/**
 * Generic replacement for the old `GetForestOwnerCompanyCredentialFromBinding`:
 * instead of five named `requiredAttribute("lei_code")` calls, it walks
 * [schema]'s claim list and requires whichever ones are `mandatory`.
 *
 * The binding must also have been approved for this very credential type. A
 * wallet may add further optional scopes to its authorization request, so the
 * scope alone does not stop it from presenting one application's offer to
 * request a different credential type.
 */
class GetGeneralCredentialFromBinding(
    private val bindingClient: ClaimForestIssuanceBinding,
    private val schema: CredentialSchemaDefinition,
) : GetGeneralCredential {
    override suspend fun invoke(context: AuthorizationContext): BoundGeneralCredential {
        val subject = requireNotNull(context.subject) { "Missing sub in the access token" }
        val binding = bindingClient.claim(context.issuerState, subject)
        require(binding.username == context.username) {
            "The mobile Keycloak username does not match the desktop issuance binding"
        }
        require(binding.credentialConfigurationId == schema.credentialConfigurationId.value) {
            "The issuance binding was approved for '${binding.credentialConfigurationId}', " +
                "not '${schema.credentialConfigurationId.value}'"
        }
        val attributes = binding.credentialAttributes
        for (claim in schema.claims) {
            if (claim.mandatory) {
                requireNotNull(attributes[claim.name]?.takeIf(String::isNotBlank)) {
                    "Missing required approved attribute '${claim.name}' for ${schema.credentialConfigurationId.value}"
                }
            }
        }

        return BoundGeneralCredential(
            schema = schema,
            attributes = attributes,
            issuerState = binding.issuerState,
            subject = subject,
        )
    }
}
