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

import arrow.core.nonEmptySetOf
import com.nimbusds.oauth2.sdk.token.BearerAccessToken
import eu.europa.ec.eudi.pidissuer.domain.Scope
import eu.europa.ec.eudi.pidissuer.port.input.AuthorizationContext
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class GetGeneralCredentialFromBindingTest {

    private val forest = CredentialSchemaLoader.load("file:../../schemas/forest_owner_schema.json")
    private val approvedAttributes = mapOf(
        "lei_code" to "529900FORESTOWNER001",
        "pefc_number" to "PEFC-DE-FOREST-001",
        "fsc_number" to "FSC-C123456",
    )

    private fun context(scope: Scope) = AuthorizationContext(
        username = "dy-k7m2",
        accessToken = BearerAccessToken("token"),
        scopes = nonEmptySetOf(scope),
        subject = "subject",
    )

    private fun binding(credentialConfigurationId: String) = ClaimForestIssuanceBinding { _ ->
        ClaimedForestIssuanceBinding("dy-k7m2", credentialConfigurationId, approvedAttributes)
    }

    @Test
    fun `returns the attributes approved for this credential type`() = runTest {
        val bound = GetGeneralCredentialFromBinding(binding(forest.credentialConfigurationId.value), forest)(context(forest.scope))

        assertEquals(approvedAttributes, bound.attributes)
    }

    @Test
    fun `rejects a binding approved for another credential type`() = runTest {
        // Same attributes, same token: only the approved type differs.
        val getCredential = GetGeneralCredentialFromBinding(binding("urn:forest:sawmill:eaa:1:dc+sd-jwt-compact"), forest)

        val error = assertFailsWith<IllegalArgumentException> { getCredential(context(forest.scope)) }
        assertEquals(true, error.message?.contains("urn:forest:sawmill:eaa:1:dc+sd-jwt-compact"))
    }
}
