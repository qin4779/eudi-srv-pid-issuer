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
import com.nimbusds.jose.JWSAlgorithm
import eu.europa.ec.eudi.pidissuer.domain.BackgroundImage
import eu.europa.ec.eudi.pidissuer.domain.CredentialReusePolicy
import eu.europa.ec.eudi.pidissuer.domain.CredentialDisplay
import eu.europa.ec.eudi.pidissuer.domain.DisplayName
import eu.europa.ec.eudi.pidissuer.domain.ImageUri
import eu.europa.ec.eudi.pidissuer.domain.KeyAttestationRequirement
import eu.europa.ec.eudi.pidissuer.port.input.toTransferObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import java.net.URI
import java.util.Locale
import javax.imageio.ImageIO
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class CredentialStyleTest {

    @Test
    fun `display metadata carries logo and background image with alt text`() {
        val display = CredentialDisplay(
            DisplayName("Forest Owner Company Certificate", Locale.ENGLISH),
            logo = ImageUri(URI.create("https://localhost/pid-issuer/public/credential-logo.png"), "Logo"),
            backgroundColor = "#DDE8D8",
            backgroundImage = BackgroundImage(
                URI.create("https://localhost/pid-issuer/public/credential-background.png"),
                "Alpine peak",
            ),
        ).toTransferObject()

        val logo = assertNotNull(display["logo"]).jsonObject
        assertEquals("Logo", logo["alt_text"]?.jsonPrimitive?.content)
        assertEquals("#DDE8D8", display["background_color"]?.jsonPrimitive?.content)
        val backgroundImage = assertNotNull(display["background_image"]).jsonObject
        assertEquals("Alpine peak", backgroundImage["alt_text"]?.jsonPrimitive?.content)
    }

    @Test
    fun `display and claim labels are published for every configured locale`() {
        val schema = CredentialSchemaLoader.load("file:../../schemas/forest_owner_schema.json")
        val configuration = IssueGeneralCredentialSdJwtVc.generalCredentialConfiguration(
            schema,
            JWSAlgorithm.ES256,
            nonEmptySetOf(JWSAlgorithm.ES256),
            KeyAttestationRequirement.NotRequired,
            CredentialReusePolicy.None,
            CredentialStyle(locales = listOf(Locale.ENGLISH, Locale.GERMAN)),
        )

        assertEquals(listOf(Locale.ENGLISH, Locale.GERMAN), configuration.display.map { it.name.locale })
        assertTrue(configuration.claims.all { it.display.keys == setOf(Locale.ENGLISH, Locale.GERMAN) })
    }

    @Test
    fun `card assets meet the wallet styling guidance`() {
        // The deployment's images, served under /public/ from config/pid-issuer/assets.
        val logoBytes = File("../../config/pid-issuer/assets/credential-logo.png").readBytes()
        assertTrue(logoBytes.size <= 150 * 1024, "logo must be at most 150 KB")
        val logo = ImageIO.read(logoBytes.inputStream())
        assertTrue(logo.width >= 80 && logo.height >= 60, "logo must be at least 80x60")
        assertTrue(logo.colorModel.hasAlpha(), "logo should have a transparent background")
        assertEquals(4 * logo.height, 3 * logo.width, "logo should be 4:3")

        val backgroundBytes = File("../../config/pid-issuer/assets/credential-background.png").readBytes()
        assertTrue(backgroundBytes.size <= 150 * 1024, "background image must be at most 150 KB")
        val background = ImageIO.read(backgroundBytes.inputStream())
        assertEquals(4 * background.height, 3 * background.width, "background image should be 4:3")
    }
}
