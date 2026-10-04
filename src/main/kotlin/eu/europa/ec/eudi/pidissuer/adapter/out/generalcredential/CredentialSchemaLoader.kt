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

import arrow.core.toNonEmptyListOrNull
import eu.europa.ec.eudi.pidissuer.domain.CredentialConfigurationId
import eu.europa.ec.eudi.pidissuer.domain.Scope
import eu.europa.ec.eudi.pidissuer.domain.SdJwtVcType
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.springframework.core.io.DefaultResourceLoader
import org.springframework.core.io.Resource
import org.springframework.core.io.support.PathMatchingResourcePatternResolver

/**
 * One schema file found by [CredentialSchemaLoader.discover]. [name] is the file
 * name without `.json`; issuer configuration addresses the credential by it.
 */
data class CredentialSchemaSource(val name: String, val resource: Resource)

/**
 * Issuance identifiers that a JSON Schema has no place for. Every field is
 * optional: anything left `null` is derived by convention in
 * [CredentialSchemaLoader.load].
 */
data class CredentialIssuanceOverrides(
    val vct: String? = null,
    val credentialConfigurationId: String? = null,
    val scope: String? = null,
    val displayName: String? = null,
)

/**
 * Reads a credential's claim set from a JSON Schema document exactly as it was
 * published (`file:`, `classpath:` or `http(s):` location). The schema is never
 * expected to carry issuer-specific extensions: only standard keywords
 * (`$id`, `title`, `description`, `properties`, `required`) are read, and
 * everything else is ignored.
 *
 * Conventions, each overridable through [CredentialIssuanceOverrides]:
 * - vct = schema `$id`
 * - credential configuration id = `<vct>:dc+sd-jwt-compact`
 * - scope = `<vct>:dc+sd-jwt`
 * - display name = schema `title`, falling back to the vct
 * - claim label = property `title`, falling back to the property name
 */
object CredentialSchemaLoader {

    private val json = Json { ignoreUnknownKeys = true }
    private val resourceLoader = DefaultResourceLoader()
    private val resourceResolver = PathMatchingResourcePatternResolver()

    /** Every `*.json` directly under [directory] (`file:` or `classpath:`), ordered by file name. */
    fun discover(directory: String): List<CredentialSchemaSource> =
        resourceResolver.getResources("${directory.trimEnd('/')}/*.json")
            .mapNotNull { resource -> resource.filename?.let { CredentialSchemaSource(it.removeSuffix(".json"), resource) } }
            .sortedBy { it.name }

    fun load(location: String, overrides: CredentialIssuanceOverrides = CredentialIssuanceOverrides()): CredentialSchemaDefinition =
        load(resourceLoader.getResource(location), overrides)

    fun load(resource: Resource, overrides: CredentialIssuanceOverrides = CredentialIssuanceOverrides()): CredentialSchemaDefinition {
        val location = resource.description
        require(resource.exists()) { "Credential schema not found at $location" }
        val text = resource.inputStream.use { it.readBytes().decodeToString() }
        return json.decodeFromString<JsonSchemaFile>(text).toDefinition(location, overrides)
    }

    private fun JsonSchemaFile.toDefinition(
        location: String,
        overrides: CredentialIssuanceOverrides,
    ): CredentialSchemaDefinition {
        val vct = requireNotNull(overrides.vct ?: id?.takeIf(String::isNotBlank)) {
            "Credential schema '$location' has no \$id; configure a vct for it explicitly"
        }
        val claims = properties.entries
            .map { (name, property) ->
                CredentialClaimSpec(
                    name = name,
                    mandatory = name in required,
                    displayLabel = property.title?.takeIf(String::isNotBlank) ?: name,
                )
            }
            .toNonEmptyListOrNull()
        requireNotNull(claims) { "Credential schema '$location' declares no properties" }

        return CredentialSchemaDefinition(
            vct = SdJwtVcType(vct),
            credentialConfigurationId = CredentialConfigurationId(
                overrides.credentialConfigurationId ?: "$vct:dc+sd-jwt-compact",
            ),
            scope = Scope(overrides.scope ?: "$vct:dc+sd-jwt"),
            displayName = overrides.displayName ?: title?.takeIf(String::isNotBlank) ?: vct,
            description = description?.takeIf(String::isNotBlank),
            claims = claims,
        )
    }

    @Serializable
    private data class JsonSchemaFile(
        @SerialName("\$id") val id: String? = null,
        val title: String? = null,
        val description: String? = null,
        val properties: Map<String, JsonSchemaProperty> = emptyMap(),
        val required: List<String> = emptyList(),
    )

    @Serializable
    private data class JsonSchemaProperty(
        val title: String? = null,
    )
}
