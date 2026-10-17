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

import org.springframework.http.MediaType
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.awaitBody

/**
 * Callback into forest-portal, which owns the actual business data (who was
 * approved, and with which attributes). The wire protocol is credential-type
 * agnostic: `{subject}` in, `{credentialConfigurationId, credentialAttributes:
 * <map>}` out. The subject is the `sub` of the wallet's access token: every
 * approved offer gets its own temporary Keycloak account, so that subject names
 * exactly one binding. One instance of this client is shared by every
 * schema-driven credential.
 */
fun interface ClaimForestIssuanceBinding {
    suspend fun claim(subject: String): ClaimedForestIssuanceBinding
}

fun interface CompleteForestIssuanceBinding {
    suspend operator fun invoke(subject: String)
}

class ForestIssuanceBindingClient(
    private val webClient: WebClient,
    private val bindingsUrl: String,
    private val secret: String,
) : ClaimForestIssuanceBinding, CompleteForestIssuanceBinding {
    override suspend fun claim(subject: String): ClaimedForestIssuanceBinding {
        val response = webClient.post().uri("$bindingsUrl/claim")
            .contentType(MediaType.APPLICATION_JSON)
            .accept(MediaType.APPLICATION_JSON)
            .header("X-Forest-Binding-Secret", secret)
            .bodyValue(mapOf("subject" to subject))
            .retrieve().awaitBody<BindingResponse>()
        return ClaimedForestIssuanceBinding(
            username = requireNotNull(response.username) { "Binding response did not contain a username" },
            credentialConfigurationId = requireNotNull(response.credentialConfigurationId) {
                "Binding response did not contain the approved credential configuration id"
            },
            credentialAttributes = response.credentialAttributes,
        )
    }

    override suspend fun invoke(subject: String) {
        webClient.post().uri("$bindingsUrl/complete")
            .contentType(MediaType.APPLICATION_JSON)
            .accept(MediaType.APPLICATION_JSON)
            .header("X-Forest-Binding-Secret", secret)
            .bodyValue(mapOf("subject" to subject))
            .retrieve().awaitBody<Map<String, Any>>()
    }

    private data class BindingResponse(
        val username: String? = null,
        val credentialConfigurationId: String? = null,
        val credentialAttributes: Map<String, String> = emptyMap(),
    )
}

data class ClaimedForestIssuanceBinding(
    val username: String,
    /** The credential type the administrator approved for this binding. */
    val credentialConfigurationId: String,
    val credentialAttributes: Map<String, String>,
)
