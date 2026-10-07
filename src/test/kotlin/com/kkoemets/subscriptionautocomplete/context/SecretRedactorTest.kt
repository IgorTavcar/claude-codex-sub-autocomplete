package com.kkoemets.subscriptionautocomplete.context

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SecretRedactorTest {
  @Test
  fun `redacts embedded authorization header before generic structured values`() {
    val redacted = SecretRedactor.redact("curl with Authorization: Bearer secret-value")

    assertFalse(redacted.contains("secret-value"))
    assertTrue(redacted.contains("<redacted>"))
  }

  @Test
  fun `redacts environment and structured secrets`() {
    val redacted = SecretRedactor.redact(
      """
        API_TOKEN=abc123
        password: hunter2
        normal: visible
        endpoint: https://alice:secret@example.com/api
      """.trimIndent(),
    )

    assertFalse(redacted.contains("abc123"))
    assertFalse(redacted.contains("hunter2"))
    assertFalse(redacted.contains("alice:secret"))
    assertTrue(redacted.contains("normal: visible"))
  }

  @Test
  fun `redacts provider tokens authorization headers JWTs and private keys`() {
    val aws = "AKIAIOSFODNN7EXAMPLE"
    val github = "ghp_123456789012345678901234567890123456"
    val jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature1234567890"
    val redacted = SecretRedactor.redact(
      """
        Authorization: Bearer bearer-secret-value
        aws = $aws
        github = $github
        jwt = $jwt
        -----BEGIN PRIVATE KEY-----
        private-material
        -----END PRIVATE KEY-----
      """.trimIndent(),
    )

    assertFalse(redacted.contains("bearer-secret-value"))
    assertFalse(redacted.contains(aws))
    assertFalse(redacted.contains(github))
    assertFalse(redacted.contains(jwt))
    assertFalse(redacted.contains("private-material"))
  }

  @Test
  fun `redacts the whole quoted value rather than its first word`() {
    val redacted = SecretRedactor.redact(
      """
        headers = {"Authorization": "Bearer opaque-bearer-credential"}
        legacy = {'Authorization': 'Basic dXNlcjpodW50ZXIy'}
        db.connect(user="app", password="correct horse battery staple", retries=3)
        fetch(url, { headers: { Cookie: "session=abc123; csrf=def456" } })
      """.trimIndent(),
    )

    listOf("opaque-bearer-credential", "dXNlcjpodW50ZXIy", "horse", "staple", "abc123", "def456")
      .forEach { assertFalse(redacted.contains(it), "Leaked $it in: $redacted") }
    assertTrue(redacted.contains("user=\"app\""))
    assertTrue(redacted.contains("retries=3"))
  }

  @Test
  fun `redacts header credentials for any scheme and every cookie pair`() {
    val redacted = SecretRedactor.redact(
      """
        curl -H 'Authorization: Token drf-token-value' https://example.com/api
        curl -H "Authorization: opaque-without-scheme" https://example.com/api
        curl -H "Cookie: session=abc123; csrf=def456" https://example.com/api
      """.trimIndent(),
    )

    listOf("drf-token-value", "opaque-without-scheme", "abc123", "def456")
      .forEach { assertFalse(redacted.contains(it), "Leaked $it in: $redacted") }
    assertEquals(3, redacted.lines().count { it.endsWith("https://example.com/api") })
  }

  @Test
  fun `redacts additional provider token formats`() {
    // Assembled at runtime so no secret-shaped literal is committed for scanners to flag.
    val tokens = listOf(
      "gho_" + "12".repeat(18),
      "ghs_" + "12".repeat(18),
      "xoxb-" + "12".repeat(6) + "-" + "ab".repeat(12),
      "AIza" + "B".repeat(35),
      "sk_live_" + "a1".repeat(12),
      "npm_" + "a1".repeat(18),
      "hf_" + "a1".repeat(17),
    )
    val redacted = SecretRedactor.redact(tokens.joinToString("\n") { "value = \"$it\"" })

    tokens.forEach { assertFalse(redacted.contains(it), "Leaked $it") }
  }

  @Test
  fun `leaves ordinary code that only resembles a cookie header intact`() {
    val code = "fun setCookie(cookie: Cookie, secure: Boolean) = store(cookie)"

    assertTrue(SecretRedactor.redact(code).endsWith("secure: Boolean) = store(cookie)"))
  }
}
