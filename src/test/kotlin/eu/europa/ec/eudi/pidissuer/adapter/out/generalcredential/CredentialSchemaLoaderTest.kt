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

import org.springframework.boot.context.properties.source.ConfigurationPropertySources
import org.springframework.core.env.PropertiesPropertySource
import org.springframework.core.env.StandardEnvironment
import org.springframework.core.env.SystemEnvironmentPropertySource
import java.io.File
import java.util.Properties
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class CredentialSchemaLoaderTest {

    @Test
    fun `derives issuance identifiers from an unmodified schema`() {
        val schema = CredentialSchemaLoader.load("file:../../schemas/forest_owner_schema.json")

        assertEquals("urn:forest:owner-company:eaa:1", schema.vct.value)
        assertEquals("urn:forest:owner-company:eaa:1:dc+sd-jwt-compact", schema.credentialConfigurationId.value)
        assertEquals("urn:forest:owner-company:eaa:1:dc+sd-jwt", schema.scope.value)
        assertEquals("Forest Owner Company Certificate (SD-JWT VC)", schema.displayName)
        assertEquals(
            listOf("company_name", "lei_code", "euid", "pefc_number", "fsc_number"),
            schema.claims.map { it.name },
        )
        assertEquals(setOf("lei_code", "pefc_number", "fsc_number"), schema.claims.filter { it.mandatory }.map { it.name }.toSet())
        // No property title in the schema: the label is the field name, never the description.
        assertEquals("company_name", schema.claims.first().displayLabel)
    }

    @Test
    fun `a public schema without $id needs an explicit vct`() {
        val location = "classpath:credential-schemas/graduation-certificate-1.0.2.schema.json"
        assertFailsWith<IllegalArgumentException> { CredentialSchemaLoader.load(location) }

        val vct = "http://eudi-docs.demo.xignin.tech/schemas/graduation-certificate-1.0.2.schema.json"
        val schema = CredentialSchemaLoader.load(location, CredentialIssuanceOverrides(vct = vct))

        assertEquals("$vct:dc+sd-jwt-compact", schema.credentialConfigurationId.value)
        assertEquals(vct, schema.displayName)
        assertNull(schema.description)
        assertEquals(6, schema.claims.count { it.mandatory })
    }

    @Test
    fun `every json file in the schema directory is one credential, named after the file`() {
        // The deployment's schemas/ directory, whatever credentials it currently holds.
        val deployed = File("../../schemas").listFiles { file -> file.extension == "json" }!!.map { it.nameWithoutExtension }
        assertEquals(deployed.sorted(), CredentialSchemaLoader.discover("file:../../schemas/").map { it.name })
        assertEquals(
            listOf("graduation-certificate-1.0.2.schema"),
            CredentialSchemaLoader.discover("classpath:credential-schemas").map { it.name },
        )
    }

    @Test
    fun `schema location and per-file overrides resolve from env vars and bracketed keys`() {
        val env = StandardEnvironment()
        env.propertySources.addFirst(
            PropertiesPropertySource(
                "credentials.properties",
                Properties().apply {
                    setProperty("issuer.credential-overrides[graduation-certificate-1.0.2.schema].vct", "urn:example:graduation")
                },
            ),
        )
        env.propertySources.addFirst(
            SystemEnvironmentPropertySource(
                StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME,
                mapOf("ISSUER_CREDENTIALSCHEMAS_LOCATION" to "file:/schemas/"),
            ),
        )
        ConfigurationPropertySources.attach(env)

        assertEquals("file:/schemas/", env.getProperty("issuer.credential-schemas.location"))
        assertEquals(
            "urn:example:graduation",
            env.getProperty("issuer.credential-overrides[graduation-certificate-1.0.2.schema].vct"),
        )
    }
}
