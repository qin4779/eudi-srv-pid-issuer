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

import arrow.core.NonEmptyList
import eu.europa.ec.eudi.pidissuer.domain.BackgroundImage
import eu.europa.ec.eudi.pidissuer.domain.Color
import eu.europa.ec.eudi.pidissuer.domain.CredentialConfigurationId
import eu.europa.ec.eudi.pidissuer.domain.ImageUri
import eu.europa.ec.eudi.pidissuer.domain.Scope
import eu.europa.ec.eudi.pidissuer.domain.SdJwtVcType
import java.util.Locale

/** One claim in a credential schema's flat, string-valued claim set. */
data class CredentialClaimSpec(
    val name: String,
    val mandatory: Boolean,
    val displayLabel: String,
)

/**
 * The in-memory shape of one credential type: the claim set comes from an
 * unmodified JSON Schema, the issuance identifiers (vct, configuration id,
 * scope, display name) from issuer configuration or the conventions in
 * [CredentialSchemaLoader]. Adding a new credential type is "drop a schema into
 * `issuer.credential-schemas.location`", not "write a new Kotlin file".
 */
data class CredentialSchemaDefinition(
    val vct: SdJwtVcType,
    val credentialConfigurationId: CredentialConfigurationId,
    val scope: Scope,
    val displayName: String,
    val description: String?,
    val claims: NonEmptyList<CredentialClaimSpec>,
)

/**
 * How a wallet should render the credential card: the `logo`,
 * `background_color`, `background_image` and `text_color` of the credential
 * configuration's `display` entry. A JSON Schema has no place for these, so
 * they come from issuer configuration.
 *
 * The same display is published once per entry of [locales]: the German
 * wallet only shows the background image when an entry matches the phone's
 * language exactly, with no fallback to another language.
 */
data class CredentialStyle(
    val locales: List<Locale> = listOf(Locale.ENGLISH),
    val logo: ImageUri? = null,
    val backgroundColor: Color? = null,
    val backgroundImage: BackgroundImage? = null,
    val textColor: Color? = null,
) {
    init {
        require(locales.isNotEmpty()) { "At least one display locale is required" }
    }
}
