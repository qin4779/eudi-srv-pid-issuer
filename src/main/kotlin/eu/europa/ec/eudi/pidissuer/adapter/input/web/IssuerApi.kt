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
package eu.europa.ec.eudi.pidissuer.adapter.input.web

import eu.europa.ec.eudi.pidissuer.domain.CredentialConfigurationId
import eu.europa.ec.eudi.pidissuer.port.input.CreateCredentialsOffer
import eu.europa.ec.eudi.pidissuer.port.input.CreateCredentialsOfferError
import eu.europa.ec.eudi.pidissuer.port.out.qr.Dimensions
import eu.europa.ec.eudi.pidissuer.port.out.qr.Format
import eu.europa.ec.eudi.pidissuer.port.out.qr.GenerateQqCode
import eu.europa.ec.eudi.pidissuer.port.out.qr.Pixels
import eu.europa.ec.eudi.pidissuer.adapter.out.util.getOrThrow
import kotlin.io.encoding.Base64
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.server.*
import java.net.URI

class IssuerApi(
    private val createCredentialsOffer: CreateCredentialsOffer,
    private val generateQrCode: GenerateQqCode,
) {
    val router: RouterFunction<ServerResponse> = coRouter {
        POST(
            CREATE_CREDENTIALS_OFFER,
            contentType(MediaType.APPLICATION_JSON) and accept(MediaType.APPLICATION_JSON),
            ::handleCreateCredentialsOffer,
        )
    }

    private suspend fun handleCreateCredentialsOffer(request: ServerRequest): ServerResponse {
        log.info("Generating Credentials Offer")
        val requestBody = request.awaitBodyOrNull<CreateCredentialsOfferRequestTO>()
        val credentialIds = requestBody
            ?.credentialIds
            .orEmpty()
            .map(::CredentialConfigurationId)
            .toSet()

        val issuerState = requestBody?.issuerState
        return createCredentialsOffer(
            credentialIds,
            issuerState = issuerState,
        ).fold(
            ifRight = { credentialsOffer ->
                val qrCode = generateQrCode(
                    credentialsOffer,
                    Format.PNG,
                    Dimensions(Pixels(300u), Pixels(300u)),
                ).getOrThrow()
                ServerResponse.ok().json()
                    .bodyValueAndAwait(CreateCredentialsOfferResponseTO.success(credentialsOffer, qrCode))
                    .also { log.info("Successfully generated Credentials Offer") }
            },
            ifLeft = { error ->
                ServerResponse.badRequest().json().bodyValueAndAwait(CreateCredentialsOfferResponseTO.error(error))
            },
        )
    }

    companion object {
        const val CREATE_CREDENTIALS_OFFER: String = "/issuer/credentialsOffer/create"
        private val log = LoggerFactory.getLogger(IssuerUi::class.java)
    }
}

@Serializable
private data class CreateCredentialsOfferRequestTO(
    @SerialName("credentialIds") val credentialIds: Set<String>? = null,
    @SerialName("issuerState") val issuerState: String? = null,
)

@Serializable
private data class CreateCredentialsOfferResponseTO(
    @SerialName("credentialsOffer") val credentialsOffer: String? = null,
    @SerialName("qrCodeBase64") val qrCodeBase64: String? = null,
    @SerialName("error") val error: String? = null,
) {
    companion object {
        fun success(credentialsOffer: URI, qrCode: ByteArray) =
            CreateCredentialsOfferResponseTO(
                credentialsOffer = credentialsOffer.toString(),
                qrCodeBase64 = Base64.encode(qrCode),
            )

        fun error(error: CreateCredentialsOfferError) =
            CreateCredentialsOfferResponseTO(error = error::class.java.simpleName)
    }
}
